using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Core TCP: echo / keep-alive / churn, request framing edge cases (pipelined, fragmented), every
/// send path (plain, Grow, Segmented SENDMSG, SEND_ZC), incremental mode, ExtraPorts routing,
/// recv-queue overflow, the outside-contract handler fault, and clean Stop() teardown.
/// </summary>
internal static class CoreTests
{
    public static void Register(Runner runner)
    {
        runner.Test("core: raw echo", () =>
        {
            int port = TestServer.Start(Handlers.Raw);
            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        });

        runner.Test("core: keep-alive (5 requests, one connection)", () =>
        {
            int port = TestServer.Start(Handlers.Raw);
            var replies = Client.GetKeepAlive(port, "/", 5);
            Assert.Equal(5, replies.Count);
            foreach ((int status, string body) in replies)
            {
                Assert.Equal(200, status);
                Assert.Equal("ok", body);
            }
        });

        runner.Test("core: 50 fresh connections (accept + recycle)", () =>
        {
            int port = TestServer.Start(Handlers.Raw);
            for (int i = 0; i < 50; i++)
            {
                (int status, _) = Client.Get(port, "/");
                Assert.Equal(200, status);
            }
        });

        runner.Test("core: two pipelined requests in one write", () =>
        {
            int port = TestServer.Start(CountingHandler);

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 4000;
            NetworkStream stream = client.GetStream();

            stream.Write(Encoding.ASCII.GetBytes(
                "GET /a HTTP/1.1\r\nHost: t\r\n\r\nGET /b HTTP/1.1\r\nHost: t\r\n\r\n"));

            // Both responses may arrive in one burst, so count them in an accumulating buffer
            // instead of framing reads per response.
            byte[] buf = new byte[4096];
            int filled = 0;
            while (CountBodies(buf.AsSpan(0, filled)) < 2)
            {
                int n = stream.Read(buf, filled, buf.Length - filled);
                Assert.True(n > 0, "connection closed before both pipelined responses arrived");
                filled += n;
            }

            static int CountBodies(ReadOnlySpan<byte> s)
            {
                int count = 0, i;
                while ((i = s.IndexOf("\r\n\r\nok"u8)) >= 0)
                {
                    count++;
                    s = s[(i + 6)..];
                }
                return count;
            }
        });

        runner.Test("core: request fragmented across three writes", () =>
        {
            int port = TestServer.Start(CountingHandler);

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 4000;
            NetworkStream stream = client.GetStream();

            byte[] req = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
            stream.Write(req, 0, 8);
            Thread.Sleep(100);
            stream.Write(req, 8, 12);
            Thread.Sleep(100);
            stream.Write(req, 20, req.Length - 20);

            (int status, string body) = Client.ReadResponse(stream);
            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        });

        runner.Test("core: response larger than the write slab (Grow)",
            () => BigBodyRoundTrip(WriteOverflowStrategy.Grow));

        runner.Test("core: response larger than the write slab (Segmented SENDMSG)",
            () => BigBodyRoundTrip(WriteOverflowStrategy.Segmented));

        runner.Test("core: a span the write slab cannot grow to fails the write instead of spinning the reactor (Grow)", () =>
        {
            // Doubling the slab's int size past 1 GiB wrapped it to 0, so the growth never reached the size
            // asked for and the reactor spun inside GetSpan forever. Nothing is allocated before the refusal.
            string body = new string('x', 48 * 1024);
            var refusal = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, _, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    RecvSnapshot snap = await conn.ReadAsync();
                    Wire.ReadPath(conn, snap);
                    if (snap.IsClosed)
                    {
                        return;   // the harness's listen probe
                    }

                    try
                    {
                        conn.GetSpan((1 << 30) + 1);
                        refusal.TrySetResult("a span");
                    }
                    catch (OutOfMemoryException e)
                    {
                        refusal.TrySetResult("refused: " + e.Message);
                    }

                    Wire.Write(conn, 200, body);   // 48 KiB against the 4 KiB slab: it still grows for what it can hold
                    await conn.FlushAsync();
                }
                finally
                {
                    conn.DecRef();
                }
            }, new ServerConfig
            {
                RecvBufferSize = 4096, RecvSlots = 64,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 8000;
            NetworkStream stream = client.GetStream();
            Client.Send(stream, "/");

            Assert.True(refusal.Task.Wait(TimeSpan.FromSeconds(10)), "GetSpan never returned: the slab's growth spun on the reactor");
            Assert.True(refusal.Task.Result.StartsWith("refused", StringComparison.Ordinal),
                $"a span past 1 GiB came back as {refusal.Task.Result}");

            (int status, string got) = Client.ReadResponse(stream);
            Assert.Equal(200, status);
            Assert.Equal(body.Length, got.Length);
        });

        runner.Test("core: zero-copy send (SEND_ZC + notif), keep-alive", () =>
        {
            string body = new string('z', 8 * 1024);
            (int port, _, _) = TestServer.StartConfigured(BodyHandler(body),
                new ServerConfig
                {
                    RecvBufferSize = 4096, RecvSlots = 64,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 16 * 1024, PoolMax = 8, RecvQueueEntries = 64,
                        ZeroCopySend = true,
                    },
                });

            var replies = Client.GetKeepAlive(port, "/", 3);
            foreach ((int status, string got) in replies)
            {
                Assert.Equal(200, status);
                Assert.Equal(body.Length, got.Length);
                Assert.True(got.All(c => c == 'z'), "zero-copy body corrupted");
            }
        });

        runner.Test("core: incremental echo keep-alive", () =>
        {
            (int port, _, _) = TestServer.StartConfigured(Handlers.Raw,
                new ServerConfig
                {
                    Incremental = new IncrementalOptions { MaxConnections = 16, RecvSlots = 16, RecvBufferSize = 4096 },
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 16 * 1024, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            var replies = Client.GetKeepAlive(port, "/", 5);
            Assert.Equal(5, replies.Count);
            foreach ((int status, string body) in replies)
            {
                Assert.Equal(200, status);
                Assert.Equal("ok", body);
            }
        }, skip: !TestServer.KernelAtLeast(6, 12));

        runner.Test("core: ExtraPorts listeners route with ListenerPort", () =>
        {
            int extra = TestServer.NextPort();
            (int port, _, _) = TestServer.StartConfigured(PortEchoHandler,
                new ServerConfig
                {
                    RecvBufferSize = 4096, RecvSlots = 64,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                        ExtraPorts = [(ushort)extra],
                    },
                });

            (_, string mainBody) = Client.Get(port, "/");
            (_, string extraBody) = Client.Get(extra, "/");
            Assert.Equal(port.ToString(), mainBody);
            Assert.Equal(extra.ToString(), extraBody);
        });

        runner.Test("core: recv-queue overflow closes that connection, server survives", () =>
        {
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int parkerClaimed = 0;

            (int port, _, _) = TestServer.StartConfigured(
                async (_, conn) =>
                {
                    // The first connection that actually delivers data parks, so the SPSC queue
                    // fills behind it (WaitForListen's empty probe must not claim the slot); later
                    // connections behave like a normal echo server - the survival probe.
                    try
                    {
                        while (true)
                        {
                            RecvSnapshot snap = await conn.ReadAsync();
                            int drained = 0;
                            while (conn.TryGetItem(snap, out SpscRecvRing.Item item))
                            {
                                if (item.HasBuffer)
                                {
                                    drained++;
                                    conn.ReturnBuffer(in item);
                                }
                            }

                            if (drained > 0 && Interlocked.Exchange(ref parkerClaimed, 1) == 0)
                            {
                                parked.SetResult();   // the flood may start now, not 200 ms from now
                                await gate.Task;
                            }
                            else if (drained > 0 && !snap.IsClosed)
                            {
                                Wire.Write(conn, 200, "ok");
                                await conn.FlushAsync();
                            }

                            if (snap.IsClosed)
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
                },
                new ServerConfig
                {
                    RecvBufferSize = 64, RecvSlots = 256,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 8,
                    },
                });

            using var flood = new TcpClient();
            flood.Connect("127.0.0.1", port);
            flood.ReceiveTimeout = 4000;
            NetworkStream stream = flood.GetStream();

            stream.Write(new byte[64]);     // consumed; the handler parks

            // Wait for the park to actually happen. Sleeping a fixed 200 ms instead makes the test
            // fail on a loaded machine: the flood is drained by a handler that never parked, the
            // queue never overflows, and the read below waits out its timeout.
            Assert.True(parked.Task.Wait(TimeSpan.FromSeconds(10)), "handler never parked");

            stream.Write(new byte[4096]);   // 64-byte buffers -> 64 CQEs -> the 8-slot queue overflows

            bool closed;
            try
            {
                closed = stream.Read(new byte[1], 0, 1) == 0;
            }
            catch
            {
                closed = true;   // RST is an equally valid observation of the teardown
            }
            Assert.True(closed, "expected the overflowed connection to be closed");
            gate.SetResult();

            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        });

        runner.Test("core: handler DecRef-then-throw closes cleanly, pool uncorrupted", () =>
        {
            (int port, _, _) = TestServer.StartConfigured(
                async (_, conn) =>
                {
                    await Task.Yield();
                    conn.DecRef();
                    throw new InvalidOperationException("post-release boom (test)");
                },
                new ServerConfig
                {
                    RecvBufferSize = 1024, RecvSlots = 64,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            int before = FdCount.Stable();

            for (int i = 0; i < 10; i++)
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
                c.ReceiveTimeout = 2000;
                bool closed;
                try
                {
                    closed = c.GetStream().Read(new byte[1], 0, 1) == 0;
                }
                catch
                {
                    closed = true;
                }
                Assert.True(closed, $"connection {i} not closed after the faulting handler released it");
            }

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 3, $"{leaked} fds leaked across 10 DecRef-then-throw handlers");
        });

        runner.Test("core: Stop() tears down cleanly (thread exits, fds released)", () =>
        {
            // Waits for the count to stop moving, which is what the old fixed sleep approximated.
            int before = FdCount.Stable();

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(Handlers.Raw,
                new ServerConfig
                {
                    RecvBufferSize = 4096, RecvSlots = 64,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            (int status, _) = Client.Get(port, "/");
            Assert.Equal(200, status);

            // Leave one connection open across Stop() so teardown has live state to clean up.
            using var open = new TcpClient();
            open.Connect("127.0.0.1", port);

            reactor.Stop();
            Assert.True(thread.Join(3000), "reactor thread did not exit after Stop()");

            open.Close();

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 2, $"teardown leaked {leaked} fds (ring/listener/wake/conn not closed?)");

            bool refused = false;
            try
            {
                using var probe = new TcpClient();
                probe.Connect("127.0.0.1", port);
            }
            catch
            {
                refused = true;
            }
            Assert.True(refused, "listener still accepting after Stop()");
        });
    }

    // Accumulates bytes and answers once per complete request ("\r\n\r\n"-terminated), so pipelined
    // and fragmented requests both get exactly one response each.
    private static async Task CountingHandler(Reactor r, TcpConnection conn)
    {
        var carry = new List<byte>();
        try
        {
            while (true)
            {
                RecvSnapshot snap = await conn.ReadAsync();
                while (conn.TryGetItem(snap, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        carry.AddRange(item.AsSpan().ToArray());
                        conn.ReturnBuffer(in item);
                    }
                }

                int responded = 0;
                int idx;
                while ((idx = CollectionsMarshal.AsSpan(carry).IndexOf("\r\n\r\n"u8)) >= 0)
                {
                    carry.RemoveRange(0, idx + 4);
                    responded++;
                }
                for (int i = 0; i < responded; i++)
                {
                    Wire.Write(conn, 200, "ok");
                }
                if (responded > 0)
                {
                    await conn.FlushAsync();
                }

                if (snap.IsClosed)
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
    }

    // Answers every request with conn.ListenerPort, for the ExtraPorts routing test.
    private static async Task PortEchoHandler(Reactor r, TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snap = await conn.ReadAsync();
                Wire.ReadPath(conn, snap);
                Wire.Write(conn, 200, conn.ListenerPort.ToString());
                await conn.FlushAsync();

                if (snap.IsClosed)
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
    }

    private static Func<Reactor, TcpConnection, Task> BodyHandler(string body) => async (_, conn) =>
    {
        try
        {
            while (true)
            {
                RecvSnapshot snap = await conn.ReadAsync();
                Wire.ReadPath(conn, snap);
                Wire.Write(conn, 200, body);
                await conn.FlushAsync();

                if (snap.IsClosed)
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

    // A 48 KiB body against a 4 KiB write slab forces the overflow machinery; the strategy picks
    // Grow (realloc, one SEND) or Segmented (pooled slabs, vectored SENDMSG).
    private static void BigBodyRoundTrip(WriteOverflowStrategy strategy)
    {
        string body = new string('x', 48 * 1024);
        (int port, _, _) = TestServer.StartConfigured(BodyHandler(body),
            new ServerConfig
            {
                RecvBufferSize = 4096, RecvSlots = 64,
                Tcp = new TcpOptions
                {
                    WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    WriteOverflow = strategy,
                },
            });

        (int status, string got) = Client.Get(port, "/", timeoutMs: 8000);
        Assert.Equal(200, status);
        Assert.Equal(body.Length, got.Length);
        Assert.True(got.All(c => c == 'x'), $"{strategy} body corrupted");
    }
}
