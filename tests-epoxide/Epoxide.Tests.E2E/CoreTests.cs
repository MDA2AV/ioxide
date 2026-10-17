using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// Core TCP: echo / keep-alive / churn, request framing edge cases (pipelined, fragmented), both
/// overflow send paths (Grow, Segmented sendmsg), ExtraPorts routing, a reader that falls behind,
/// the outside-contract handler fault, and clean Stop() teardown.
/// </summary>
/// <remarks>
/// Not ported, because epoxide has no such thing: "zero-copy send (SEND_ZC + notif)" and
/// "incremental echo keep-alive" (IOU_PBUF_RING_INC).
/// </remarks>
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

        runner.Test("core: a request and the peer's FIN back to back end the next read at once, inline or on the thread pool", () =>
        {
            // A recv takes the peer's FIN along with the bytes in front of it and comes back short, and
            // the edge that reported both is spent. Were short still taken for drained, the read after
            // it would park until the read timeout - 30 s here - for an end that has already arrived.
            const int Connections = 100;
            foreach (bool onPool in new[] { false, true })
            {
                (int port, _, _) = TestServer.StartConfigured(async (_, conn) =>
                {
                    try
                    {
                        if (onPool)
                        {
                            await Hop.ToThreadPool();
                        }

                        while (true)
                        {
                            RecvSnapshot snap = await conn.ReadAsync();
                            Drain(conn, snap);
                            if (snap.IsClosed)
                            {
                                return;
                            }

                            conn.Write("."u8);
                            await conn.FlushAsync();
                            conn.ResetRead();
                        }
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, new ServerConfig { Tcp = new TcpOptions { ReadTimeoutMs = 30_000 } });

                int late = 0;
                for (int i = 0; i < Connections && late < 3; i++)
                {
                    using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                    {
                        NoDelay = true,
                        ReceiveTimeout = 3_000,
                    };
                    client.Connect(IPAddress.Loopback, port);
                    var one = new byte[1];

                    client.Send("a"u8);   // one round first, so the request below lands on a parked read
                    Assert.Equal(1, client.Receive(one));

                    client.Send("b"u8);
                    client.Shutdown(SocketShutdown.Send);
                    try
                    {
                        Assert.Equal(1, client.Receive(one));
                        Assert.Equal(0, client.Receive(one));   // the server's FIN, once its read saw ours
                    }
                    catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
                    {
                        late++;
                    }
                }

                Assert.True(late == 0, $"{late} {(onPool ? "thread-pool" : "inline")} handlers were still reading 3 s after their peer's FIN");
            }
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
                RecvBufferSize = 4096,
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

        runner.KnownCoreBug("core: a 32 MiB recv buffer serves a request instead of failing its first recv", () =>
        {
            // The recv pool sizes a chunk of 64 buffers as bufferSize << 6, in int arithmetic: at 32 MiB
            // that is 2^31, which wraps negative, and the allocation it asks for is about 16 EiB. Every
            // recv rents first, so the first one throws OutOfMemoryException out of the handler's read
            // (and a read that parked after one would throw it on the reactor, out of its loop).
            (int port, _, _) = TestServer.StartConfigured(Handlers.Raw, new ServerConfig
            {
                RecvBufferSize = 32 * 1024 * 1024,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
            });

            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        }, bug: "E2: BufferPool sizes its chunks in int");

        runner.Test("core: ExtraPorts listeners route with ListenerPort", () =>
        {
            int extra = TestServer.NextPort();
            (int port, _, _) = TestServer.StartConfigured(PortEchoHandler,
                new ServerConfig
                {
                    RecvBufferSize = 4096,
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

        runner.Test("core: a reader that falls behind back-pressures its peer instead of losing the connection, server survives", () =>
        {
            // ioxide's "recv-queue overflow closes that connection": its multishot recv keeps delivering
            // into a reader that stopped, so a full queue has to drop data and close. epoxide receives
            // only when the reader asks, so the same flood stays in the socket and TCP pushes back on
            // the peer - 64 deliveries' worth against an 8-entry queue of 64-byte buffers, and nothing
            // may be dropped or closed.
            const int FloodBytes = 4096;
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int parkerClaimed = 0;

            (int port, _, _) = TestServer.StartConfigured(
                async (_, conn) =>
                {
                    // The first connection that actually delivers data parks, so the flood arrives
                    // behind a reader that is not reading (WaitForListen's empty probe must not claim
                    // the slot); later connections behave like a normal echo server - the survival probe.
                    try
                    {
                        while (true)
                        {
                            RecvSnapshot snap = await conn.ReadAsync();
                            int drained = Drain(conn, snap);

                            if (drained > 0 && Interlocked.Exchange(ref parkerClaimed, 1) == 0)
                            {
                                parked.SetResult();
                                await gate.Task;

                                // Back to reading: the whole flood, then its size as the answer.
                                long flooded = 0;
                                while (flooded < FloodBytes && !snap.IsClosed)
                                {
                                    conn.ResetRead();
                                    snap = await conn.ReadAsync();
                                    flooded += Drain(conn, snap);
                                }
                                Wire.Write(conn, 200, flooded.ToString());
                                await conn.FlushAsync();
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
                    RecvBufferSize = 64,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 8,
                    },
                });

            using var flood = new TcpClient();
            flood.Connect("127.0.0.1", port);
            NetworkStream stream = flood.GetStream();

            stream.Write(new byte[64]);     // consumed; the handler parks

            // Wait for the park to actually happen, or the flood is drained by a handler that never
            // stopped reading and nothing is tested.
            Assert.True(parked.Task.Wait(TimeSpan.FromSeconds(10)), "handler never parked");

            stream.Write(new byte[FloodBytes]);   // 64-byte buffers: 64 deliveries against the 8-slot queue

            // The connection is still open while the reader is behind: no EOF, no reset, just silence.
            flood.ReceiveTimeout = 500;
            string state;
            try
            {
                state = stream.Read(new byte[1], 0, 1) == 0 ? "closed (EOF)" : "answered early";
            }
            catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
            {
                state = "open";
            }
            catch (IOException e)
            {
                state = $"closed ({e.InnerException?.Message ?? e.Message})";
            }
            Assert.Equal("open", state);

            gate.SetResult();

            // Every byte of the flood reached the reader once it read again.
            flood.ReceiveTimeout = 8000;
            (int floodStatus, string floodBody) = Client.ReadResponse(stream);
            Assert.Equal(200, floodStatus);
            Assert.Equal(FloodBytes.ToString(), floodBody);

            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        });

        runner.Test("core: handler DecRef-then-throw closes cleanly, pool uncorrupted", () =>
        {
            (int port, _, _) = TestServer.StartConfigured(
                async (_, conn) =>
                {
                    await Task.Yield();   // to the reactor's own context, not the thread pool
                    conn.DecRef();
                    throw new InvalidOperationException("post-release boom (test)");
                },
                new ServerConfig
                {
                    RecvBufferSize = 1024,
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

        runner.Test("core: accepted connections have TCP_NODELAY, over IPv4, IPv4-mapped and IPv6", () =>
        {
            (int v4, _, _) = TestServer.StartConfigured(NoDelayHandler, NoDelayConfig(dualStack: false));
            (int dual, _, _) = TestServer.StartConfigured(NoDelayHandler, NoDelayConfig(dualStack: true));

            Assert.Equal("1", AskNoDelay(IPAddress.Loopback, v4));
            Assert.Equal("1", AskNoDelay(IPAddress.Loopback, dual));
            Assert.Equal("1", AskNoDelay(IPAddress.IPv6Loopback, dual));
        });

        runner.Test("core: a flush from another thread that races the connection's close completes", () =>
        {
            // ioxide's flush armed its send, then reset the signal its caller waits on, and a close on the
            // reactor in between released the flush into that reset. epoxide resets before it parks, and
            // the park and the close's release meet on one CAS - this races them, each round one
            // off-reactor flush that has to park (its socket is full) against one close on the reactor,
            // landing before the flush, during its send, across its park, and after it.
            (_, Reactor reactor, _) = TestServer.StartConfigured(
                static (_, conn) => { conn.DecRef(); return Task.CompletedTask; },
                new ServerConfig
                {
                    RecvBufferSize = 64,
                    Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 8 },
                });

            (int full, int peer) = FullSocketPair();
            try
            {
                const int rounds = 200_000;
                var race = new FlushCloseRace();
                var timer = new ReactorTimer(reactor);
                reactor.ScheduleOnReactor(_ => _ = race.CloseSideAsync(timer, rounds), null);

                byte[] one = [1];
                int lost = 0, overlapped = 0, parked = 0;
                for (int i = 1; i <= rounds; i++)
                {
                    // Never registered with the reactor, so only the close can release its flush.
                    var conn = new TcpConnection(reactor, full, 64, 8);
                    conn.Write(one);
                    race.Conn = conn;
                    race.Skew = i / 8 * 3 % 8;
                    Volatile.Write(ref race.Go, i);
                    for (int s = i * 7 % 8; s > 0; s--)
                    {
                        Thread.SpinWait(1);
                    }

                    ValueTask flush = conn.FlushAsync();
                    if (Internals.FlushArmedMs(conn) != 0 && Volatile.Read(ref race.Closed) == i)
                    {
                        overlapped++;   // armed - past FlushAsync's closed check - and the close ran before FlushAsync returned
                    }
                    if (!flush.Equals(default(ValueTask)))
                    {
                        parked++;       // it parked, so the close had a parked flush to release
                    }
                    FlushCloseRace.WaitFor(ref race.Closed, i);

                    if (!flush.IsCompleted)
                    {
                        lost++;   // both sides are done, so it never will
                    }
                    conn.Dispose();
                }

                Assert.True(overlapped >= 1_000, $"only {overlapped} closes landed while a flush was arming: the race never ran");
                Assert.True(parked >= 1_000, $"only {parked} flushes parked, so a close almost never had a parked flush to release");
                Assert.True(lost == 0, $"{lost} of {rounds} flushes never completed after a close raced their park");
            }
            finally
            {
                close(full);
                close(peer);
            }
        }, skip: Environment.ProcessorCount < 2);   // the two sides must run at once

        runner.Test("core: Stop() tears down cleanly (thread exits, fds released)", () =>
        {
            // Waits for the count to stop moving, which is what the old fixed sleep approximated.
            int before = FdCount.Stable();

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(Handlers.Raw,
                new ServerConfig
                {
                    RecvBufferSize = 4096,
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
            Assert.True(leaked <= 2, $"teardown leaked {leaked} fds (epoll/listener/wake/conn not closed?)");

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

    // Takes every buffer of a snapshot back to the pool and says how many bytes they held.
    private static int Drain(TcpConnection conn, in RecvSnapshot snap)
    {
        int bytes = 0;
        while (conn.TryGetItem(snap, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                bytes += item.Len;
                conn.ReturnBuffer(in item);
            }
        }
        return bytes;
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

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(int fd, int level, int optname, out int optval, ref int optlen);

    [DllImport("libc", SetLastError = true)]
    private static extern unsafe int socketpair(int domain, int type, int protocol, int* sv);

    [DllImport("libc", SetLastError = true)]
    private static extern unsafe nint send(int fd, byte* buf, nuint len, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    // A connected AF_UNIX stream pair whose first end's send buffer is full: a send on it returns
    // EAGAIN until somebody reads the second end, which nobody does.
    private static unsafe (int Full, int Peer) FullSocketPair()
    {
        int* sv = stackalloc int[2];
        Assert.True(socketpair(1 /* AF_UNIX */, 1 | Native.SOCK_NONBLOCK | Native.SOCK_CLOEXEC, 0, sv) == 0,
            $"socketpair failed with errno {Marshal.GetLastPInvokeError()}");

        byte* chunk = stackalloc byte[4096];
        while (send(sv[0], chunk, 4096, Native.MSG_NOSIGNAL) > 0)
        {
        }
        Assert.Equal(Native.EAGAIN, Marshal.GetLastPInvokeError());
        return (sv[0], sv[1]);
    }

    // Answers with this connection's own TCP_NODELAY as the server sees it: "1", "0", or "error".
    private static async Task NoDelayHandler(Reactor r, TcpConnection conn)
    {
        try
        {
            RecvSnapshot snap = await conn.ReadAsync();
            Wire.ReadPath(conn, snap);
            int len = sizeof(int);
            Wire.Write(conn, 200, getsockopt(conn.ClientFd, 6 /* IPPROTO_TCP */, 1 /* TCP_NODELAY */, out int on, ref len) == 0
                ? on.ToString()
                : "error");
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static ServerConfig NoDelayConfig(bool dualStack) => new()
    {
        RecvBufferSize = 4096, DualStack = dualStack,
        Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
    };

    private static string AskNoDelay(IPAddress address, int port)
    {
        using var client = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 6000 };
        client.Connect(address, port);
        client.Send("GET / HTTP/1.1\r\nHost: x\r\n\r\n"u8);

        var response = new StringBuilder();
        var buffer = new byte[1024];
        int n;
        while ((n = client.Receive(buffer)) > 0)
        {
            response.Append(Encoding.ASCII.GetString(buffer, 0, n));
        }
        string text = response.ToString();
        int bodyAt = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        Assert.True(bodyAt >= 0, $"no response from {address}: '{text}'");
        return text[(bodyAt + 4)..];
    }

    // A 48 KiB body against a 4 KiB write slab forces the overflow machinery; the strategy picks
    // Grow (realloc, one send) or Segmented (pooled slabs, vectored sendmsg).
    private static void BigBodyRoundTrip(WriteOverflowStrategy strategy)
    {
        string body = new string('x', 48 * 1024);
        (int port, _, _) = TestServer.StartConfigured(BodyHandler(body),
            new ServerConfig
            {
                RecvBufferSize = 4096,
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

    // The reactor's side of the flush/close race: one close per round, on the reactor thread.
    private sealed class FlushCloseRace
    {
        public TcpConnection? Conn;
        public int Go, Closed, Skew;

        public async Task CloseSideAsync(ReactorTimer timer, int rounds)
        {
            for (int i = 1; i <= rounds; i++)
            {
                if (i % 1_000 == 0)
                {
                    await timer.DelayNanosecondsAsync(1);   // a loop pass now and then, so the reactor is not held for the whole run
                }
                WaitFor(ref Go, i);
                for (int s = Skew; s > 0; s--)
                {
                    Thread.SpinWait(1);
                }

                Internals.MarkClosed(Conn!);
                Volatile.Write(ref Closed, i);
            }
        }

        // Spins, so the two sides meet within nanoseconds; yields past that, so a busy machine still gets through.
        public static void WaitFor(ref int field, int value)
        {
            for (int spins = 0; Volatile.Read(ref field) != value; spins++)
            {
                if (spins < 1_000)
                {
                    Thread.SpinWait(1);
                }
                else
                {
                    Thread.Yield();
                }
            }
        }
    }
}
