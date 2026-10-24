using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="ServerConfig.CqEntries"/>: the CQ's own depth (#95). It was always the kernel's default,
/// twice the SQ, though nothing bounds a reactor's completions by its submissions.
/// </summary>
/// <remarks>
/// Here rather than in E2E because whether completions overflowed the CQ is only visible from inside
/// the reactor (<see cref="Reactor.CqOverflowed"/>, internal).
/// </remarks>
internal static class CompletionQueueTests
{
    // A send completes as it is submitted, and the CQ holds the batch being dispatched until all of it
    // ran, so a handler's own sends - submitted each time the SQ fills - land behind that batch.
    private const uint SqEntries = 16;
    private const int Sends = 48;

    public static void Register(Runner runner)
    {
        runner.Test("ring: by default a pass that completes three times RingEntries fits the CQ", () =>
        {
            Assert.True(!SendInOnePass(cqEntries: 0), "the CQ overflowed: it is still sized from the SQ");
        });

        runner.Test("ring: control: the kernel's CQ, twice the SQ, overflows on the same pass", () =>
        {
            Assert.True(SendInOnePass(cqEntries: 2 * SqEntries), "nothing overflowed, so the pass above proves nothing");
        });
    }

    // Whether completions were ever waiting outside the CQ while a handler sent Sends single bytes in one pass.
    private static bool SendInOnePass(uint cqEntries)
    {
        nint bytes = Marshal.AllocHGlobal(Sends);
        var seen = new Seen();
        try
        {
            (int port, _, _) = TestServer.StartConfigured(SendOnAsk(bytes, seen), new ServerConfig
            {
                RingEntries = SqEntries,
                CqEntries = cqEntries,
                RecvBufferSize = 4096,
                RecvSlots = 64,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
            });

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5_000 };
            client.Connect(IPAddress.Loopback, port);
            client.Send("?"u8);

            var received = new byte[Sends];
            int got = 0;
            while (got < Sends)
            {
                int n = client.Receive(received, got, Sends - got, SocketFlags.None);
                Assert.True(n > 0, $"the connection ended after {got} of {Sends} bytes");
                got += n;
            }

            Assert.True(seen.Done.Wait(5_000), $"{seen.Completed} of {Sends} sends completed");
            return seen.Overflowed;
        }
        finally
        {
            if (seen.Done.IsSet)
            {
                Marshal.FreeHGlobal(bytes);   // otherwise a send may still point into it
            }
        }
    }

    private static Func<Reactor, TcpConnection, Task> SendOnAsk(nint bytes, Seen seen) => async (r, conn) =>
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                bool asked = false;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        asked = true;
                        conn.ReturnBuffer(in item);
                    }
                }

                if (asked)
                {
                    seen.Reactor = r;
                    for (int i = 0; i < Sends; i++)
                    {
                        r.SubmitSend(conn.ClientFd, bytes + i, 1, seen);
                    }
                    seen.Overflowed |= r.CqOverflowed;
                }

                if (snapshot.IsClosed)
                {
                    return;
                }
                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    };

    // On the reactor thread: counts the sends and notes completions held outside the CQ when they run.
    private sealed class Seen : IRingCompletion
    {
        public Reactor? Reactor;
        public bool Overflowed;
        public int Completed;
        public readonly ManualResetEventSlim Done = new();

        public void Complete(int result)
        {
            Overflowed |= Reactor!.CqOverflowed;
            if (result == 1 && ++Completed == Sends)
            {
                Done.Set();
            }
        }
    }
}
