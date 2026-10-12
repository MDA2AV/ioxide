using System.Runtime.CompilerServices;
using static ioxide.Native;

namespace ioxide;

/// <summary>
/// <see cref="QuicRouting.KernelFilter"/>: a classic-BPF program on the QUIC port's
/// <c>SO_REUSEPORT</c> group, so the kernel picks the reactor by reading the connection id out of
/// the datagram rather than hashing the sender's address - which is what breaks when that address
/// changes. Every id this server mints carries its owner in the first byte (iq_stamp_shard in the
/// shim), chosen so <c>cid[0] % ReactorCount</c> is that reactor.
///
/// Two consequences. The filter answers with a position in the reuseport group and that position
/// is BIND ORDER, so reactors must open the QUIC socket in <see cref="ShardIndex"/> order - what
/// <see cref="QuicSteeringAwaitTurn"/> arranges, at startup only. And it cannot be attached until
/// every reactor has joined, or an index can point past the end; the last one out attaches it.
///
/// Any failure - the kernel refuses the program, a reactor fails to bind, the fleet never
/// assembles - abandons steering and leaves the 4-tuple hash, with forwarding still underneath.
/// </summary>
public sealed unsafe partial class Reactor
{
    /// <summary>Attach a reuseport-steering program (Linux 4.5+). Not in <c>SocketOptionName</c>.</summary>
    private const int SO_ATTACH_REUSEPORT_CBPF = 51;

    /// <summary>
    /// How long a reactor waits its turn before giving up on ordering. Generous: it only covers
    /// other reactors reaching the same point in startup.
    /// </summary>
    private const int QuicSteeringTurnTimeoutMs = 10_000;

    /// <summary>Beyond 256 reactors one byte cannot encode the owner, so steering is skipped.</summary>
    private const int QuicSteeringMaxShards = 256;

    // Keyed by the shared ServerConfig instance, so two servers in one process get independent
    // gates. ConditionalWeakTable keys on reference identity, not the record's value equality.
    private static readonly ConditionalWeakTable<ServerConfig, QuicSteeringGate> QuicSteeringGates = new();

    private sealed class QuicSteeringGate
    {
        public readonly object Lock = new();
        public int  Turn;            // the ShardIndex allowed to open right now
        public int  QuicFd = -1;     // any socket in the group; attaching to one sets it for all
        public bool Abandoned;       // ordering broke, so the indices cannot be trusted
        public bool Settled;         // attach (or the decision not to) already happened
    }

    /// <summary>QUIC only, and only when there is a fleet to steer across.</summary>
    private bool _quicSteeringAttached;

    /// <summary>
    /// True on the reactor that attached the steering program (the last one to bind, since the
    /// group has to be complete first). The filter is group-wide, so one reactor reporting this is
    /// the fleet reporting it. False everywhere under <see cref="QuicRouting.Forward"/>, and false
    /// when the kernel refused the program.
    /// </summary>
    public bool QuicKernelSteeringAttached => _quicSteeringAttached;

    private bool QuicSteeringActive =>
        _config.Quic is { Routing: QuicRouting.KernelFilter } &&
        ShardCount > 1 &&
        ShardCount <= QuicSteeringMaxShards;

    private QuicSteeringGate? QuicSteeringBegin()
    {
        if (!QuicSteeringActive)
        {
            return null;
        }

        QuicSteeringGate gate = QuicSteeringGates.GetValue(_config, static _ => new QuicSteeringGate());
        QuicSteeringAwaitTurn(gate);
        return gate;
    }

    /// <summary>
    /// Block until it is this reactor's turn, so group position equals <see cref="ShardIndex"/>.
    ///
    /// The timeout stops a misconfigured fleet becoming a hang - starting fewer reactors than
    /// <see cref="ServerConfig.ReactorCount"/> would strand everyone after the missing one. On
    /// expiry the gate is abandoned ONCE and all waiters released, so the delay is paid once.
    /// </summary>
    private void QuicSteeringAwaitTurn(QuicSteeringGate gate)
    {
        lock (gate.Lock)
        {
            long deadline = Native.MonotonicMs + QuicSteeringTurnTimeoutMs;

            while (gate.Turn != ShardIndex && !gate.Abandoned)
            {
                int remaining = (int)(deadline - Native.MonotonicMs);
                if (remaining <= 0 || !Monitor.Wait(gate.Lock, remaining))
                {
                    Console.Error.WriteLine(
                        $"[r{_id}] quic: waited {QuicSteeringTurnTimeoutMs} ms for reactor {gate.Turn} "
                        + "to bind; giving up on connection-id steering and falling back to "
                        + "cross-reactor forwarding");
                    gate.Abandoned = true;
                    Monitor.PulseAll(gate.Lock);
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Hand the turn on, and if this was the last reactor and all bound cleanly, attach the program.
    /// </summary>
    /// <param name="gate">The fleet's gate, or null when steering is not active.</param>
    /// <param name="quicFd">This reactor's QUIC socket, or -1 if opening it failed.</param>
    private void QuicSteeringRelease(QuicSteeringGate? gate, int quicFd)
    {
        if (gate is null)
        {
            return;
        }

        lock (gate.Lock)
        {
            if (quicFd < 0)
            {
                gate.Abandoned = true;   // never joined, so every later index is off by one
            }
            else if (gate.QuicFd < 0)
            {
                gate.QuicFd = quicFd;
            }

            gate.Turn++;
            Monitor.PulseAll(gate.Lock);

            if (gate.Turn < ShardCount || gate.Settled)
            {
                return;
            }

            gate.Settled = true;
            if (gate.Abandoned || gate.QuicFd < 0)
            {
                return;   // already reported; the port keeps the 4-tuple hash
            }

            QuicAttachSteering(gate.QuicFd, ShardCount);
        }
    }

    /// <summary>
    /// Attach the program to the QUIC reuseport group. Failure is reported and otherwise ignored -
    /// an old kernel, seccomp or a restricted container can refuse it, and forwarding still works.
    /// </summary>
    private void QuicAttachSteering(int fd, int shards)
    {
        // classic-BPF instruction: { u16 code; u8 jt; u8 jf; u32 k; }
        //
        //   0  ld len              A = datagram length
        //   1  jge #9 ? : ->8      too short for a connection id: fall through on the length,
        //                          which is in bounds and deterministic
        //   2  ldb [0]             QUIC first byte
        //   3  and #0x80           header-form bit
        //   4  jeq #0 ? ->7 :      clear = short header
        //   5  ldb [6]             long header: 1 first byte + 4 version + 1 dcid len, so DCID is
        //                          at 6. The client chose that id, so this acts as a stable hash -
        //                          every packet of a handshake still reaches one reactor.
        //   6  ja ->8
        //   7  ldb [1]             short header: DCID at 1, an id WE minted, so the byte is ours
        //   8  mod #shards         the reuseport index
        //   9  ret a
        //
        // Byte loads, not word loads: iq_stamp_shard controls exactly one byte, and reading more
        // would mix in bytes it does not constrain.
        (ushort code, byte jt, byte jf, uint k)[] program =
        [
            (0x80, 0, 0, 0),               // ld len
            (0x35, 0, 6, 9),               // jge #9
            (0x30, 0, 0, 0),               // ldb [0]
            (0x54, 0, 0, 0x80),            // and #0x80
            (0x15, 2, 0, 0),               // jeq #0
            (0x30, 0, 0, 6),               // ldb [6]
            (0x05, 0, 0, 1),               // ja
            (0x30, 0, 0, 1),               // ldb [1]
            (0x94, 0, 0, (uint)shards),    // mod #shards
            (0x16, 0, 0, 0),               // ret a
        ];

        byte* instructions = stackalloc byte[program.Length * 8];
        for (int i = 0; i < program.Length; i++)
        {
            byte* at = instructions + i * 8;
            *(ushort*)at = program[i].code;
            at[2]        = program[i].jt;
            at[3]        = program[i].jf;
            *(uint*)(at + 4) = program[i].k;
        }

        // struct sock_fprog { unsigned short len; struct sock_filter *filter; } - the pointer is
        // 8-aligned, so len sits in the first two bytes of 16.
        byte* fprog = stackalloc byte[16];
        new Span<byte>(fprog, 16).Clear();
        *(ushort*)fprog     = (ushort)program.Length;
        *(byte**)(fprog + 8) = instructions;

        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, fprog, 16) < 0)
        {
            Console.Error.WriteLine(
                $"[r{_id}] quic: could not attach connection-id steering; falling back to "
                + "cross-reactor forwarding, which is correct but costs a hop per datagram");
            return;
        }

        _quicSteeringAttached = true;
        Console.WriteLine($"[r{_id}] quic: connection-id steering attached across {shards} reactors");
    }
}
