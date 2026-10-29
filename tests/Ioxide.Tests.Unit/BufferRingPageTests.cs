using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Provided-buffer rings start on the kernel's page (#427). The kernel refuses a ring that does not, and
/// its page is 4 KiB on x86-64 but 4, 16 or 64 KiB on arm64, so a ring aligned to a fixed 4096 registers
/// on a 16 or 64 KiB-page kernel only when its allocation happens to land on a page.
/// </summary>
/// <remarks>
/// On 4 KiB pages, which every CI runner has, ioxide's rings pass either way. On a larger page a ring off
/// its boundary is refused when the reactor registers it, so the server these tests start fails, and with
/// several rings at once one landing on a page by chance does not hide the rest. The control shows the
/// kernel's check is real.
/// </remarks>
internal static class BufferRingPageTests
{
    // What IORING_REGISTER_PBUF_RING answers for a ring off a page boundary.
    private const int Einval = -22;

    private const int Rings = 4;

    public static unsafe void Register(Runner runner)
    {
        runner.Test("buffer ring: control: the kernel refuses a ring that does not start on a page", () =>
        {
            int page = Environment.SystemPageSize;
            using Ring ring = Ring.Create(8);
            byte* memory = (byte*)NativeMemory.AlignedAlloc((nuint)(2 * page), (nuint)page);
            try
            {
                Assert.Equal(0, RegisterRing(ring, memory, bgid: 1));
                Assert.Equal(Einval, RegisterRing(ring, memory + 64, bgid: 2));

                // ioxide's alignment: on a page larger than 4 KiB, 4096 bytes in is not a page boundary.
                if (page > 4096)
                {
                    Assert.Equal(Einval, RegisterRing(ring, memory + 4096, bgid: 3));
                }
            }
            finally
            {
                // A ring the kernel took is let go before its memory is.
                for (ushort bgid = 1; bgid <= 3; bgid++)
                {
                    var reg = new Native.io_uring_buf_reg { bgid = bgid };
                    Native.io_uring_register(ring.Fd, Native.IORING_UNREGISTER_PBUF_RING, &reg, 1);
                }
                NativeMemory.AlignedFree(memory);
            }
        });

        runner.Test("buffer ring: the shared and UDP rings start on the kernel's page", () =>
        {
            var starts = new List<(string Ring, nint Start)>();
            for (int i = 0; i < Rings; i++)
            {
                TestServer.StartConfigured(static (_, conn) =>
                {
                    conn.DecRef();
                    return Task.CompletedTask;
                }, new ServerConfig
                {
                    RecvBufferSize = 1024,
                    RecvSlots = 64,
                    Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
                    Udp = new UdpOptions { Ports = [(ushort)TestServer.NextPort()], RecvSlots = 16, SocketBufferBytes = 64 * 1024 },
                }, onStart: reactor =>
                {
                    lock (starts)
                    {
                        starts.Add(("shared", (nint)SharedRingOf(reactor)));
                        starts.Add(("UDP", (nint)UdpRingOf(reactor)));
                    }
                });
            }

            AssertOnPage(starts, 2 * Rings);
        });

        runner.Test("buffer ring: an incremental connection's ring starts on the kernel's page", () =>
        {
            var starts = new List<(string Ring, nint Start)>();
            (int port, _, _) = TestServer.StartConfigured(RecordRing(starts), new ServerConfig
            {
                Incremental = new IncrementalOptions { MaxConnections = 16, RecvSlots = 4, RecvBufferSize = 1024 },
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 16, RecvQueueEntries = 64 },
            });

            // Open together, so each has a ring of its own: a pooled connection reuses its allocation.
            var clients = new List<Socket>();
            try
            {
                for (int i = 0; i < 2 * Rings; i++)
                {
                    var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5_000 };
                    clients.Add(client);
                    client.Connect(IPAddress.Loopback, port);
                    client.Send("?"u8);
                    Assert.Equal(1, client.Receive(new byte[1]));   // its ring is recorded
                }
            }
            finally
            {
                foreach (Socket client in clients)
                {
                    client.Dispose();
                }
            }

            AssertOnPage(starts, 2 * Rings);
        }, skip: !TestServer.KernelAtLeast(6, 12));
    }

    // A four-entry ring at address, as the reactor registers its own.
    private static unsafe int RegisterRing(Ring ring, byte* address, ushort bgid)
    {
        NativeMemory.Clear(address, 4 * 16);
        var reg = new Native.io_uring_buf_reg { ring_addr = (ulong)address, ring_entries = 4, bgid = bgid };
        return Native.io_uring_register(ring.Fd, Native.IORING_REGISTER_PBUF_RING, &reg, 1);
    }

    private static void AssertOnPage(List<(string Ring, nint Start)> starts, int expected)
    {
        int page = Environment.SystemPageSize;
        Assert.Equal(expected, starts.Count);
        foreach ((string name, nint start) in starts)
        {
            Assert.True(start != 0, $"a {name} ring was never allocated");
            Assert.True(start % page == 0, $"a {name} ring starts at 0x{start:x}, {start % page} bytes into a {page}-byte page");
        }
    }

    // Records the ring of each connection that asks, answers so the client knows, and holds the
    // connection, and so its ring, until the client leaves. The readiness probe never asks.
    private static Func<Reactor, TcpConnection, Task> RecordRing(List<(string Ring, nint Start)> starts) => async (_, conn) =>
    {
        try
        {
            bool recorded = false;
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

                if (asked && !recorded)
                {
                    recorded = true;
                    lock (starts)
                    {
                        starts.Add(("connection", RingStart(conn)));
                    }
                    conn.Write("!"u8);
                    await conn.FlushAsync();
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

    private static unsafe nint RingStart(TcpConnection conn) => (nint)conn.BufRing;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_bufRing")]
    private static extern unsafe ref byte* SharedRingOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_udpBufRing")]
    private static extern unsafe ref byte* UdpRingOf(Reactor reactor);
}
