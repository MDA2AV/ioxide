using System.Buffers;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>The read timeout through TLS, OpenSSL decrypting on demand and kTLS alike.</summary>
internal static class ReadTimeoutTests
{
    private const int ReadTimeoutMs = 500;

    public static void Register(Runner runner, bool ktls)
    {
        foreach (bool kernelRx in new[] { false, true })
        {
            bool rx = kernelRx;
            string mode = rx ? "kTLS" : "OpenSSL";

            runner.Test($"tls read timeout ({mode}): a handler busy for longer than the read timeout still answers", () =>
            {
                int port = StartWith(rx, BusyHandler);

                (int status, string body) = Client.GetTls(port, "/", timeoutMs: 8_000);
                Assert.Equal(200, status);
                Assert.Equal("slow-but-here", body);
            }, skip: rx && !ktls);

            runner.Test($"tls read timeout ({mode}): a peer that never sends its request is closed", () =>
            {
                var woke = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                int port = StartWith(rx, WaitingHandler(woke));

                using var client = new TcpClient();
                client.Connect("127.0.0.1", port);
                client.ReceiveTimeout = 6_000;
                using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
                ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    EnabledSslProtocols = SslProtocols.Tls13,
                });

                Assert.True(woke.Task.Wait(4_000), "the handler's read was never ended - nothing timed out the silent peer");
                Assert.True(woke.Task.Result, "the handler woke, but not to the end of the stream");
            }, skip: rx && !ktls);
        }

        foreach (bool parkRead in new[] { false, true })
        {
            bool parked = parkRead;
            string how = parked ? "OpenSSL, a read parked" : "OpenSSL";
            runner.Test($"tls exit ({how}): a response still sending when its handler lets go reaches a slow reader whole", () =>
            {
                // The teardown close_notify is a raw send: inside a send the ring still has, it would
                // split a record, so it is skipped then.
                const int total = 16 * 1024 * 1024;
                int port = StartWith(false, LetGoMidFlush(total, parked), readTimeoutMs: 10_000);

                using var client = new TcpClient { ReceiveBufferSize = 4096 };
                client.Connect("127.0.0.1", port);
                client.ReceiveTimeout = 10_000;
                using SslStream ssl = Handshake(client);
                ssl.Write("GET / HTTP/1.1\r\n\r\n"u8);
                if (!parked)
                {
                    ssl.ShutdownAsync().GetAwaiter().GetResult();   // ours first - the reader never decrypts it
                }
                Thread.Sleep(1_500);   // not reading: the send is still in flight when the handler lets go

                long got = 0;
                string end = "EOF";
                var buffer = new byte[256 * 1024];
                try
                {
                    int n;
                    while ((n = ssl.Read(buffer)) > 0)
                    {
                        got += n;
                    }
                }
                catch (Exception e)
                {
                    end = $"{e.GetType().Name}: {e.Message}";
                }
                Assert.True(got == total, $"received {got} of {total} bytes, then {end}");
            });
        }
    }

    private static async Task BusyHandler(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
            pipe = new TlsConnectionDualPipe(connection, session);

            ReadResult read = await pipe.Input.ReadAsync();
            pipe.Input.AdvanceTo(read.Buffer.End);

            await Task.Delay(4 * ReadTimeoutMs);

            const string body = "slow-but-here";
            pipe.Output.Write(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
            await pipe.Output.FlushAsync();
        }
        catch
        {
            // The harness's listen probe hangs up mid-handshake; nothing to serve it.
        }
        finally
        {
            await Release(connection, session, pipe);
        }
    }

    private static Func<Reactor, TcpConnection, Task> WaitingHandler(TaskCompletionSource<bool> woke)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                pipe = new TlsConnectionDualPipe(connection, session);

                ReadResult read = await pipe.Input.ReadAsync();
                woke.TrySetResult(read.IsCompleted && read.Buffer.IsEmpty);
                pipe.Input.AdvanceTo(read.Buffer.End);
            }
            catch
            {
                // The listen probe again.
            }
            finally
            {
                await Release(connection, session, pipe);
            }
        };

    // Writes more than the peer will take, gives up on the flush after 300 ms and lets go mid-send.
    private static Func<Reactor, TcpConnection, Task> LetGoMidFlush(int total, bool parkRead)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                pipe = new TlsConnectionDualPipe(connection, session);

                ReadResult read = await pipe.Input.ReadAsync();
                pipe.Input.AdvanceTo(read.Buffer.End);
                if (parkRead)
                {
                    _ = pipe.Input.ReadAsync();   // waiting for a next request that never comes
                }

                byte[] chunk = new byte[64 * 1024];
                for (int written = 0; written < total; written += chunk.Length)
                {
                    pipe.Output.Write(chunk);
                }
                Task flush = pipe.Output.FlushAsync().AsTask();
                await Task.WhenAny(flush, Task.Delay(300));
            }
            catch
            {
                // The harness's port probe fails the handshake.
            }
            finally
            {
                await Release(connection, session, pipe);
            }
        };

    private static SslStream Handshake(TcpClient client)
    {
        var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });
        return ssl;
    }

    private static async Task Release(TcpConnection connection, TlsSession? session, TlsConnectionDualPipe? pipe)
    {
        if (pipe is not null)
        {
            await pipe.DisposeAsync();   // disposes the session too
        }
        else
        {
            session?.Dispose();
        }
        connection.DecRef();
    }

    private static int StartWith(bool kernelRx, Func<Reactor, TcpConnection, Task> handle, int readTimeoutMs = ReadTimeoutMs)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelRx = kernelRx, KernelTx = kernelRx };

        return TestServer.StartConfigured(handle, new ServerConfig
        {
            RecvBufferSize = 4096,
            RecvSlots = 256,
            Tcp = new TcpOptions
            {
                WriteSlabSize = 16 * 1024,
                PoolMax = 64,
                RecvQueueEntries = 64,
                ReadTimeoutMs = readTimeoutMs,
            },
        }, r => TlsService.Start(r, options)).Port;
    }
}
