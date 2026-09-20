using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace ioxide;

/// <summary>
/// Cross-reactor delivery for QUIC: a datagram that lands on a reactor which does not own the
/// connection it names is handed to the one that does. Issue #205.
///
/// Every reactor binds the QUIC port with SO_REUSEPORT and the kernel chooses between them by
/// hashing the sender's address, which stops being the right answer the moment that address changes
/// - a NAT rebind re-hashes to a reactor that has never heard of the connection, and its
/// short-header packets used to be dropped.
///
/// The connection cannot move to meet the packet: the ngtcp2 conn, the picotls session and the
/// streams are owned by one reactor thread. So the packet moves instead, over
/// <see cref="ScheduleOnReactor"/> - message passing, not shared state.
///
/// What crosses is a COPY of the bytes. The datagram lives in the receiving reactor's
/// provided-buffer ring, handed back the moment dispatch returns, so passing a pointer into it
/// would be a use-after-free under load.
///
/// Only short headers are forwarded: their id is one this server minted, so its first byte really
/// does name the owner (iq_stamp_shard in the shim). A long header's id is chosen by the CLIENT,
/// and routing on a byte the peer controls would let anyone aim traffic at a reactor.
/// </summary>
public sealed unsafe partial class Reactor
{
    /// <summary>
    /// Datagrams that may be in flight toward one reactor before further ones are dropped. Dropping
    /// is safe here: QUIC resends, so the ceiling costs a retransmit rather than a connection.
    /// </summary>
    private const int QuicForwardMaxOutstanding = 1024;

    /// <summary>
    /// The reactors sharing one ServerConfig. Keyed on the config INSTANCE, not a static, because a
    /// process can run several independent servers and they must not post into each other.
    /// ConditionalWeakTable keys by reference identity, not the record's value equality.
    /// </summary>
    private static readonly ConditionalWeakTable<ServerConfig, QuicFleet> QuicFleets = new();

    private sealed class QuicFleet
    {
        public readonly Reactor?[] Members;        // by ShardIndex; null until that reactor starts
        public readonly int[] Outstanding;         // datagrams in flight toward each member
        public readonly ConcurrentQueue<QuicForward> Spare = new();

        public QuicFleet(int count)
        {
            Members     = new Reactor?[count];
            Outstanding = new int[count];
        }
    }

    /// <summary>
    /// One datagram in transit between reactors. Pooled: an envelope per datagram would be a steady
    /// stream of garbage on the hot path.
    /// </summary>
    private sealed class QuicForward
    {
        public byte[] Payload = [];
        public int    Length;
        public byte[] PeerAddr = new byte[UdpNameCap];
        public int    PeerAddrLen;
        public int    SocketFd;
        public ushort LocalPort;
        public byte   Tos;
        public int    Owner;              // the ShardIndex this was addressed to
        public QuicFleet Fleet = null!;
        public Reactor   Target = null!;
    }

    private QuicFleet? _quicFleet;

    private long _quicForwardsSent;
    private long _quicForwardsReceived;
    private long _quicForwardsDropped;

    /// <summary>Datagrams this reactor handed to a sibling because it did not own the connection.</summary>
    public long QuicForwardsSent => Volatile.Read(ref _quicForwardsSent);

    /// <summary>Datagrams a sibling handed to this reactor.</summary>
    public long QuicForwardsReceived => Volatile.Read(ref _quicForwardsReceived);

    /// <summary>
    /// Datagrams dropped rather than forwarded - the owner was at
    /// <see cref="QuicForwardMaxOutstanding"/> or had stopped. Nonzero means a reactor is behind.
    /// </summary>
    public long QuicForwardsDropped => Volatile.Read(ref _quicForwardsDropped);

    // Join the fleet. Called from InitQuic, on the reactor's own thread, before the loop starts.
    private void QuicJoinFleet()
    {
        if (ShardCount <= 1 || (uint)_id >= (uint)ShardCount)
        {
            return;   // nothing to forward to, or an id outside the configured fleet
        }

        QuicFleet fleet = QuicFleets.GetValue(_config, static c => new QuicFleet(c.ReactorCount));
        _quicFleet = fleet;
        Volatile.Write(ref fleet.Members[_id], this);
    }

    /// <summary>
    /// Hand a datagram to the reactor that owns its connection. False when this reactor IS the
    /// owner (so the id is merely unknown - stale, retired or hostile) and the caller should drop.
    /// </summary>
    private bool QuicTryForward(in UdpDatagram datagram, in QuicCid dcid)
    {
        QuicFleet? fleet = _quicFleet;
        if (fleet is null || dcid.Length == 0)
        {
            return false;
        }

        int owner = dcid.FirstByte % fleet.Members.Length;
        if (owner == _id)
        {
            return false;   // addressed here and we do not have it: not a routing problem
        }

        Reactor? target = Volatile.Read(ref fleet.Members[owner]);
        if (target is null || target._stopRequested || target._wakeFd <= 0)
        {
            _quicForwardsDropped++;
            return true;    // nothing better to do with it than drop it
        }

        // Reserved before the copy, so a stalled owner cannot make its siblings do the work.
        if (Interlocked.Increment(ref fleet.Outstanding[owner]) > QuicForwardMaxOutstanding)
        {
            Interlocked.Decrement(ref fleet.Outstanding[owner]);
            _quicForwardsDropped++;
            return true;
        }

        if (!fleet.Spare.TryDequeue(out QuicForward? forward))
        {
            forward = new QuicForward();
        }

        int length = datagram.Payload.Length;
        if (forward.Payload.Length < length)
        {
            if (forward.Payload.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(forward.Payload);
            }
            forward.Payload = ArrayPool<byte>.Shared.Rent(length);
        }

        // The copy that makes this safe: Payload points into the recv slot, returned at dispatch.
        datagram.Payload.CopyTo(forward.Payload);
        forward.Length = length;

        int addrLen = Math.Min(datagram.PeerAddrLen, UdpNameCap);
        new ReadOnlySpan<byte>((void*)datagram.PeerAddr, addrLen).CopyTo(forward.PeerAddr);
        forward.PeerAddrLen = addrLen;

        forward.SocketFd  = datagram.SocketFd;
        forward.LocalPort = datagram.LocalPort;
        forward.Tos       = datagram.Tos;
        forward.Owner     = owner;
        forward.Fleet     = fleet;
        forward.Target    = target;

        _quicForwardsSent++;

        // Static lambda over the envelope alone - no closure, no per-datagram allocation.
        target.ScheduleOnReactor(
            static state =>
            {
                var envelope = (QuicForward)state!;
                envelope.Target.QuicReceiveForward(envelope);
            },
            forward);

        return true;
    }

    // Runs on the OWNING reactor's thread, out of its post queue.
    private void QuicReceiveForward(QuicForward forward)
    {
        QuicFleet fleet = forward.Fleet;

        try
        {
            _quicForwardsReceived++;

            fixed (byte* payload = forward.Payload)
            fixed (byte* addr = forward.PeerAddr)
            {
                // GRO size 0: trains are split before routing, so this is always one datagram.
                QuicDispatchDatagram(new UdpDatagram(forward.SocketFd, forward.LocalPort,
                    (nint)addr, forward.PeerAddrLen,
                    new ReadOnlySpan<byte>(payload, forward.Length), 0, forward.Tos));
            }
        }
        finally
        {
            Interlocked.Decrement(ref fleet.Outstanding[forward.Owner]);
            forward.Fleet  = null!;
            forward.Target = null!;
            fleet.Spare.Enqueue(forward);
        }
    }
}
