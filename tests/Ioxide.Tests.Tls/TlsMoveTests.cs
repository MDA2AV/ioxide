using System.Buffers;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using ioxide;
using ioxide.tls;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// TLS connections that change reactors (<see cref="TcpOptions.Rebalance"/>): the session goes along, whoever decrypts,
/// encrypts or frees it does so on the reactor its connection is on, and a handshake is over before any of it.
/// </summary>
internal static class TlsMoveTests
{
    public static void Register(Runner runner, bool ktls)
    {
        (string Name, Func<TlsOptions> Options, bool Skip)[] modes =
        [
            ("BoringSSL", () => Options(), false),
            ("kTLS send", () => Options(kernelTx: true), !ktls),
            ("kTLS both ways", () => Options(kernelTx: true, kernelRx: true), !ktls),
        ];
        (string Name, Func<TlsService, TcpConnection, Task> Handle)[] handlers = [("pipes", Pipes), ("the raw session", Raw)];

        foreach ((string mode, Func<TlsOptions> options, bool skip) in modes)
        {
            foreach ((string how, Func<TlsService, TcpConnection, Task> handle) in handlers)
            {
                RegisterEcho(runner, $"{mode}, {how}", options, handle, MoveFleet.Shared(), skip);
            }
            RegisterEcho(runner, $"{mode}, {"pipes"}, a ring per connection", options, Pipes, MoveFleet.Incremental(size: 2048), skip || !TestServer.KernelAtLeast(6, 12));
            RegisterOne(runner, mode, options, skip);
        }
        RegisterOffReactor(runner);
        RegisterHandshake(runner);
    }

    private static void RegisterEcho(Runner runner, string name, Func<TlsOptions> options, Func<TlsService, TcpConnection, Task> handle,
        ServerConfig config, bool skip)
    {
        runner.Test($"tls move: every byte comes back, from connections moved all the time, their handshakes included ({name})", () =>
        {
            var services = new TlsService[3];
            using var fleet = new MoveFleet(3, conn => handle(services[Reactor.Current!.ShardIndex], conn), config,
                (i, reactor) => services[i] = TlsService.Start(reactor, options()));
            using var shuffle = new Moves.Shuffle(fleet.Reactors);

            // Connection after connection, so handshakes are going on throughout.
            Task[] clients = Enumerable.Range(0, 6).Select(id => Task.Run(() =>
            {
                for (int n = 0; n < 6; n++)
                {
                    Echo(fleet.Port, (id * 100) + n, 250_000);
                }
            })).ToArray();
            Assert.True(Task.WaitAll(clients, 90_000), "a client never got all it sent back");
            Assert.True(shuffle.Made > 20, $"only {shuffle.Made} moves were made");
        }, skip);
    }

    private static void RegisterOne(Runner runner, string mode, Func<TlsOptions> options, bool skip)
    {
        runner.Test($"tls move: a session goes along with its connection, there and back, and ends with a close_notify ({mode})", () =>
        {
            var services = new TlsService[2];
            using var fleet = new MoveFleet(2, conn => Tell(services[Reactor.Current!.ShardIndex], conn), null,
                (i, reactor) => services[i] = TlsService.Start(reactor, options()));
            (SslStream client, TcpConnection conn) = Connect(fleet);
            for (int i = 0; i < 20; i++)
            {
                Moves.To(conn, fleet.Reactors[i % 2]);
                Assert.Equal($"{i % 2}message {i:D2}", Exchange(client, $"message {i:D2}"));
            }
            Moves.To(conn, fleet.B);
            client.Write("bye"u8);
            Assert.Equal(0, client.Read(new byte[16]));   // a close_notify: an abrupt end throws
            client.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
        }, skip);

        runner.Test($"tls move: a session outlives the reactor its handshake was on, if its connection has moved away ({mode})", () =>
        {
            var services = new TlsService[2];
            using var fleet = new MoveFleet(2, conn => Tell(services[Reactor.Current!.ShardIndex], conn), null,
                (i, reactor) => services[i] = TlsService.Start(reactor, options()));
            (SslStream client, TcpConnection conn) = Connect(fleet);
            Assert.Equal("0hello", Exchange(client, "hello"));
            Moves.To(conn, fleet.B);
            fleet.A.Stop();
            Assert.True(fleet.Threads[0].Join(5_000), "the stop never ended");
            for (int i = 0; i < 10; i++)
            {
                Assert.Equal("1hello", Exchange(client, "hello"));
            }
            client.Dispose();
            MoveFleet.AwaitLive(fleet.B, 0);
        }, skip);
    }

    private static void RegisterOffReactor(Runner runner)
    {
        // SSL_write, SSL_read and SSL_free must not meet, and what is asked for from another thread lands on a reactor the
        // connection may have left by then.
        runner.Test("tls move: a pipe written from another thread, while its connection is moved all the time, keeps the session intact", () =>
        {
            const int Total = 4 << 20;
            TlsService[] services = new TlsService[3];
            using var fleet = new MoveFleet(3, async conn =>
            {
                try
                {
                    TlsSession session = await services[Reactor.Current!.ShardIndex].AcceptAsync(conn);
                    await using var pipe = new TlsConnectionDualPipe(conn, session);
                    Task writing = Task.Run(async () =>
                    {
                        for (int at = 0; at < Total; at += 1024)
                        {
                            Span<byte> span = pipe.Output.GetSpan(1024)[..1024];
                            for (int i = 0; i < span.Length; i++)
                            {
                                span[i] = (byte)((at + i) % 251);
                            }
                            pipe.Output.Advance(1024);
                            if ((await pipe.Output.FlushAsync()).IsCompleted)
                            {
                                return;
                            }
                            await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
                        }
                    });
                    while (true)
                    {
                        ReadResult read = await pipe.Input.ReadAsync();
                        pipe.Input.AdvanceTo(read.Buffer.End);
                        if (read.IsCompleted)
                        {
                            break;
                        }
                    }
                    await writing;
                }
                finally
                {
                    conn.DecRef();
                }
            }, null, (i, reactor) => services[i] = TlsService.Start(reactor, Options()));

            using var shuffle = new Moves.Shuffle(fleet.Reactors);
            Task[] clients = Enumerable.Range(0, 3).Select(_ => Task.Run(() =>
            {
                using SslStream client = Authenticate(Moves.Connect(fleet.Port));
                using var over = new ManualResetEventSlim();
                Task sending = Task.Run(() =>   // keeps the reactor decrypting, and the read from waiting all the time
                {
                    var up = new byte[700];
                    while (!over.IsSet)
                    {
                        client.Write(up);
                        Thread.Sleep(1);
                    }
                });
                var buffer = new byte[16 * 1024];
                for (int got = 0; got < Total;)
                {
                    int n = client.Read(buffer);
                    Assert.True(n > 0, $"closed after {got} of {Total} bytes");
                    for (int i = 0; i < n; i++)
                    {
                        Assert.True(buffer[i] == (byte)((got + i) % 251), $"byte {got + i} is wrong");
                    }
                    got += n;
                }
                over.Set();
                sending.Wait();
            })).ToArray();
            Assert.True(Task.WaitAll(clients, 90_000), "a client never got it all");
            Assert.True(shuffle.Made > 10, $"only {shuffle.Made} moves were made");
        });

        runner.Test("tls move: what another thread asks of a pipe while its connection is between two reactors is done on the second", () =>
        {
            TlsConnectionDualPipe? pipe = null;
            var flushedOn = new TaskCompletionSource<Reactor?>(TaskCreationOptions.RunContinuationsAsynchronously);
            TlsService[] services = new TlsService[2];
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    TlsSession session = await services[Reactor.Current!.ShardIndex].AcceptAsync(conn);
                    pipe = new TlsConnectionDualPipe(conn, session);
                    while (!(await pipe.Input.ReadAsync()).IsCompleted)
                    {
                    }
                }
                catch (IOException)
                {
                    // one that came to the other reactor, and was dropped
                }
                finally
                {
                    conn.DecRef();
                }
            }, null, (i, reactor) => services[i] = TlsService.Start(reactor, Options()));
            (SslStream client, TcpConnection conn) = Connect(fleet);
            Assert.True(SpinWait.SpinUntil(() => Moves.ReadParkedOf(conn) && Moves.HoldsNothingOf(conn) && !conn.Pinned && pipe is not null, 5_000), "the handler never got to wait");

            Task flushing;
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                flushing = Task.Run(async () =>
                {
                    pipe!.Output.Write("push"u8);
                    await pipe.Output.FlushAsync().ConfigureAwait(false);
                    flushedOn.SetResult(Reactor.Current);
                });
                Thread.Sleep(50);
                Assert.True(!flushing.IsCompleted, "the flush was made with the connection between two reactors");
            }
            var buffer = new byte[4];
            client.ReadExactly(buffer);
            Assert.Equal("push", Encoding.ASCII.GetString(buffer));
            Assert.True(flushing.Wait(5_000), "the flush never completed");
            Assert.True(ReferenceEquals(flushedOn.Task.Result, fleet.B), "it was made elsewhere");

            // And the end: the session is freed where it is read and written.
            Task disposing;
            using (Moves.Hold(fleet.A))
            {
                Assert.True(Moves.Begin(conn, fleet.A), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                pipe!.Output.Write("last"u8);   // not flushed: its end is to carry it out
                disposing = Task.Run(async () => await pipe.DisposeAsync());
                Thread.Sleep(50);
                Assert.True(!disposing.IsCompleted, "the session was freed with the connection between two reactors");
            }
            Assert.True(disposing.Wait(5_000), "the pipe was never disposed");
            client.ReadExactly(buffer);
            Assert.Equal("last", Encoding.ASCII.GetString(buffer));
            Assert.Equal(0, client.Read(new byte[16]));
            client.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
        });
    }

    private static void RegisterHandshake(Runner runner)
    {
        runner.Test("tls move: a connection stays until its handshake is over, and a pin of its handler's stays after it", () =>
        {
            foreach (bool pinned in new[] { false, true })
            {
                TlsService[] services = new TlsService[2];
                using var fleet = new MoveFleet(2, conn =>
                {
                    conn.Pinned = pinned;
                    return Tell(services[Reactor.Current!.ShardIndex], conn);
                }, null, (i, reactor) => services[i] = TlsService.Start(reactor, Options()));

                (Socket socket, TcpConnection conn) = fleet.Connect();
                Assert.True(SpinWait.SpinUntil(() => Moves.ReadParkedOf(conn), 5_000), "the handshake never got to wait");
                Assert.True(conn.Pinned && !Moves.Begin(conn, fleet.B), "a connection waiting for its handshake began to move");
                using SslStream client = Authenticate(socket);
                Assert.Equal("0hello", Exchange(client, "hello"));
                Assert.Equal(pinned, conn.Pinned);
                if (!pinned)
                {
                    Moves.To(conn, fleet.B);
                    Assert.Equal("1hello", Exchange(client, "hello"));
                }
                else
                {
                    Assert.True(!Moves.Begin(conn, fleet.B), "a pinned connection began to move");
                }
            }
        });

        runner.Test("tls move: a failed handshake leaves no pin behind", () =>
        {
            TlsService[] services = new TlsService[2];
            var failed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    await services[Reactor.Current!.ShardIndex].AcceptAsync(conn);
                }
                catch (IOException)
                {
                    failed.TrySetResult(conn.Pinned);
                }
                finally
                {
                    conn.DecRef();
                }
            }, null, (i, reactor) => services[i] = TlsService.Start(reactor, Options()));
            (Socket client, TcpConnection _) = fleet.Connect();
            client.Send("this is no ClientHello"u8);
            Assert.True(failed.Task.Wait(5_000), "the handshake never failed");
            Assert.True(!failed.Task.Result, "the connection is still pinned");
        });

        runner.Test("tls move: encrypting on a reactor the connection has left is refused", () =>
        {
            TlsSession? session = null;
            TlsService[] services = new TlsService[2];
            using var fleet = new MoveFleet(2, async conn =>
            {
                TlsSession? mine = null;
                try
                {
                    mine = await services[Reactor.Current!.ShardIndex].AcceptAsync(conn);
                    session = mine;
                    while (!(await conn.ReadAsync()).IsClosed)
                    {
                    }
                }
                catch (IOException)
                {
                    // one that came to the other reactor, and was dropped
                }
                finally
                {
                    mine?.Dispose();
                    conn.DecRef();
                }
            }, null, (i, reactor) => services[i] = TlsService.Start(reactor, Options()));
            (SslStream _, TcpConnection conn) = Connect(fleet);
            Assert.True(SpinWait.SpinUntil(() => Moves.ReadParkedOf(conn) && !conn.Pinned && session is not null, 5_000), "the handler never got to wait");
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                Moves.On(fleet.A, () => Assert.Throws<InvalidOperationException>(() => session!.Write(conn, "x"u8), "reactor"));
            }
            Moves.WaitFor(conn, Moves.None);
            Moves.On(fleet.A, () => Assert.Throws<InvalidOperationException>(() => session!.Write(conn, "x"u8), "reactor"));
        });
    }

    private static TlsOptions Options(bool kernelTx = false, bool kernelRx = false)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        return new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = kernelTx, KernelRx = kernelRx };
    }

    private static (SslStream Client, TcpConnection Conn) Connect(MoveFleet fleet)
    {
        (Socket socket, TcpConnection conn) = fleet.Connect();
        return (Authenticate(socket), conn);
    }

    private static SslStream Authenticate(Socket socket)
    {
        var client = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false, (_, _, _, _) => true) { ReadTimeout = 30_000 };
        client.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });
        return client;
    }

    private static string Exchange(SslStream client, string message)
    {
        client.Write(Encoding.ASCII.GetBytes(message));
        var answer = new byte[message.Length + 1];
        client.ReadExactly(answer);
        return Encoding.ASCII.GetString(answer);
    }

    private static void Echo(int port, int id, int total)
    {
        using SslStream client = Authenticate(Moves.Connect(port, 30_000));
        Task sending = Task.Run(() =>
        {
            var random = new Random(id);
            var message = new byte[6_000];
            for (int sent = 0; sent < total;)
            {
                int length = Math.Min(random.Next(1, message.Length), total - sent);
                for (int i = 0; i < length; i++)
                {
                    message[i] = (byte)((sent + i + id) % 251);
                }
                client.Write(message.AsSpan(0, length));
                sent += length;
                if (random.Next(8) == 0)
                {
                    Thread.Sleep(1);
                }
            }
        });
        var buffer = new byte[16 * 1024];
        for (int got = 0; got < total;)
        {
            int n = client.Read(buffer);
            Assert.True(n > 0, $"client {id}: closed after {got} of {total} bytes");
            for (int i = 0; i < n; i++)
            {
                Assert.True(buffer[i] == (byte)((got + i + id) % 251), $"client {id}: byte {got + i} is wrong");
            }
            got += n;
        }
        sending.Wait();
        client.ShutdownAsync().Wait(5_000);
    }

    private static async Task Pipes(TlsService service, TcpConnection conn)
    {
        try
        {
            TlsSession session = await service.AcceptAsync(conn);
            await using var pipe = new TlsConnectionDualPipe(conn, session);
            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();
                foreach (ReadOnlyMemory<byte> segment in read.Buffer)
                {
                    pipe.Output.Write(segment.Span);
                }
                pipe.Input.AdvanceTo(read.Buffer.End);
                await pipe.Output.FlushAsync();
                if (read.IsCompleted)
                {
                    return;
                }
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task Raw(TlsService service, TcpConnection conn)
    {
        TlsSession? session = null;
        try
        {
            session = await service.AcceptAsync(conn);
            if (session.DrainPlaintext() is { IsEmpty: false } first)
            {
                session.Write(conn, first);
                await conn.FlushAsync();
            }
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                bool any = false;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        any |= EchoItem(session, conn, item);
                        conn.ReturnBuffer(in item);
                    }
                }
                if (any)
                {
                    await conn.FlushAsync();
                }
                if (snapshot.IsClosed || session.Closed)
                {
                    return;
                }
            }
        }
        finally
        {
            session?.Dispose();
            conn.DecRef();
        }
    }

    private static unsafe bool EchoItem(TlsSession session, TcpConnection conn, in SpscRecvRing.Item item)
    {
        ReadOnlySpan<byte> plain = session.Decrypt(item.Ptr, item.Len);
        session.Write(conn, plain);
        return !plain.IsEmpty;
    }

    // MoveFleet.Tell over TLS, until it reads "bye".
    private static async Task Tell(TlsService service, TcpConnection conn)
    {
        try
        {
            TlsSession session;
            try
            {
                session = await service.AcceptAsync(conn);
            }
            catch (IOException)
            {
                return;   // one that came to the other reactor, and was dropped
            }
            await using var pipe = new TlsConnectionDualPipe(conn, session);
            Assert.True(ReferenceEquals(pipe.Connection, conn), "a pipe's Connection is not the one it was made over");
            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();
                string got = Encoding.ASCII.GetString(read.Buffer.ToArray());
                pipe.Input.AdvanceTo(read.Buffer.End);
                if (got == "bye" || read.IsCompleted)
                {
                    return;
                }
                if (got.Length > 0)
                {
                    pipe.Output.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                    await pipe.Output.FlushAsync();
                }
            }
        }
        finally
        {
            conn.DecRef();
        }
    }
}
