using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using ioxide;
using ioxide.tls;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Handlers that let go of a TLS connection with its client still sending: having answered, through the pipes or the raw
/// session, on each backend; or because the handshake failed, or never finished. Nobody decrypts what follows.
/// </summary>
internal static class TlsLetGoBufferTests
{
    private static readonly byte[] Answer = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"u8.ToArray();

    private static ReadOnlySpan<byte> Request => "GET / HTTP/1.1\r\nHost: x\r\n\r\n"u8;

    public static void Register(Runner runner, bool ktls)
    {
        bool noIncremental = !TestServer.KernelAtLeast(6, 12);

        foreach ((LetGoDriver.Mode mode, LetGoDriver.Ending ending, string name) in LetGoDriver.Cases())
        {
            bool skip = noIncremental && mode == LetGoDriver.Incremental;

            runner.Test($"tls let-go, answered through the pipes: {name}", () =>
            {
                Run(Pipes, Options(), mode, ending, Answered);
            }, skip: skip);

            runner.Test($"tls let-go, answered through the raw session: {name}", () =>
            {
                Run(RawSession, Options(), mode, ending, Answered);
            }, skip: skip);

            runner.Test($"tls let-go, a failed handshake: {name}", () =>
            {
                Run(Pipes, Options(), mode, ending, port => LetGoDriver.Refused(port, Request));
            }, skip: skip);

            runner.Test($"tls let-go, a handshake that timed out: {name}", () =>
            {
                // A record header promising more than ever arrives.
                Run(Pipes, Options(handshakeTimeoutMs: 200), mode, ending, port => LetGoDriver.Refused(port, [0x16, 0x03, 0x01, 0x01, 0x00, 0x01]));
            }, skip: skip);

            runner.Test($"tls let-go, kTLS TX, answered through the pipes: {name}", () =>
            {
                Run(Pipes, Options(kernelTx: true), mode, ending, Answered);
            }, skip: skip || !ktls);

            runner.Test($"tls let-go, kTLS TX, answered through the raw session: {name}", () =>
            {
                Run(RawSession, Options(kernelTx: true), mode, ending, Answered);
            }, skip: skip || !ktls);

            runner.Test($"tls let-go, kTLS TX and RX, answered through the pipes: {name}", () =>
            {
                Run(Pipes, Options(kernelTx: true, kernelRx: true), mode, ending, Answered);
            }, skip: skip || !ktls);
        }
    }

    private static TlsOptions Options(bool kernelTx = false, bool kernelRx = false, int handshakeTimeoutMs = 2_000)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        return new TlsOptions
        {
            CertificatePath = certPath,
            KeyPath = keyPath,
            KernelTx = kernelTx,
            KernelRx = kernelRx,
            HandshakeTimeoutMs = handshakeTimeoutMs,
        };
    }

    private static void Run(Func<Reactor, TcpConnection, Task> handler, TlsOptions options, LetGoDriver.Mode mode, LetGoDriver.Ending ending, Func<int, Socket> letGoClient)
    {
        int port = TestServer.StartConfigured(handler, LetGoDriver.Configure(mode, ending), r => TlsService.Start(r, options)).Port;

        LetGoDriver.Check(() => letGoClient(port), () => LetGoDriver.Answers(() =>
            Client.GetTls(port, "/", LetGoDriver.GraceMs).Status == 200), mode, ending);
    }

    private static async Task Pipes(Reactor reactor, TcpConnection conn)
    {
        TlsSession? tls = null;
        try
        {
            tls = await reactor.GetService<TlsService>().AcceptAsync(conn);

            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);
            ReadResult read = await pipe.Input.ReadAsync();
            pipe.Input.AdvanceTo(read.Buffer.End);

            await pipe.Output.WriteAsync(Answer);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // A handshake that failed, as any handler would see it: it lets go below.
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    }

    private static async Task RawSession(Reactor reactor, TcpConnection conn)
    {
        TlsSession? tls = null;
        try
        {
            tls = await reactor.GetService<TlsService>().AcceptAsync(conn);

            // The request can ride in with the client's Finished.
            int plaintext = tls.DrainPlaintext().Length;
            while (true)
            {
                RecvSnapshot snapshot = plaintext > 0 ? default : await conn.ReadAsync();

                while (plaintext == 0 && conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        plaintext += Decrypted(tls, in item);
                        conn.ReturnBuffer(in item);
                    }
                }

                if (plaintext > 0)
                {
                    tls.Write(conn, Answer);
                    await conn.FlushAsync();
                    return;
                }

                if (snapshot.IsClosed || tls.Closed)
                {
                    return;
                }
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // A handshake that failed, as any handler would see it: it lets go below.
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    }

    private static unsafe int Decrypted(TlsSession tls, in SpscRecvRing.Item item) => tls.Decrypt(item.Ptr, item.Len).Length;

    private static Socket Answered(int port)
    {
        Socket client = LetGoDriver.Connect(port);
        using (var ssl = new SslStream(new NetworkStream(client), leaveInnerStreamOpen: true, (_, _, _, _) => true))
        {
            ssl.AuthenticateAsClient("localhost");
            ssl.Write(Request);

            var buffer = new byte[4096];
            try
            {
                while (ssl.Read(buffer) > 0)
                {
                }
            }
            catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset })
            {
                // A reset is an end too.
            }
        }

        return client;
    }
}
