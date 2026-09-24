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

    private static int StartWith(bool kernelRx, Func<Reactor, TcpConnection, Task> handle)
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
                ReadTimeoutMs = ReadTimeoutMs,
            },
        }, r => TlsService.Start(r, options)).Port;
    }
}
