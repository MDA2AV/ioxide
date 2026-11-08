using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// TLS on a listener bound to ::, which takes IPv4 clients as IPv4-mapped peers on an IPv6 socket. The kernel paths
/// are the ones to watch: kTLS is programmed on that socket whatever family the peer came in on.
/// </summary>
internal static class DualStackTlsTests
{
    private static readonly byte[] Answer = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"u8.ToArray();

    private static readonly bool NoIpv6 = !Socket.OSSupportsIPv6 || !File.Exists("/proc/net/tcp6");

    public static void Register(Runner runner, bool ktls)
    {
        foreach ((string name, bool kernelTx, bool kernelRx) in new[] { ("BoringSSL", false, false), ("kTLS TX", true, false), ("kTLS TX and RX", true, true) })
        {
            bool skip = NoIpv6 || (kernelTx && !ktls);

            runner.Test($"tls on ::, {name}: an IPv4 client is served", () =>
            {
                Assert.Equal($"ok {name}", Served(kernelTx, kernelRx, IPAddress.Loopback));
            }, skip: skip);

            runner.Test($"tls on ::, {name}: an IPv6 client is served", () =>
            {
                Assert.Equal($"ok {name}", Served(kernelTx, kernelRx, IPAddress.IPv6Loopback));
            }, skip: skip);
        }
    }

    // The answer, and which backend carried it, as the session reports it.
    private static string Served(bool kernelTx, bool kernelRx, IPAddress client)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = kernelTx, KernelRx = kernelRx };
        var backends = new ConcurrentQueue<string>();

        int port = TestServer.StartConfigured((r, conn) => Pipes(r, conn, backends), new ServerConfig
        {
            Tcp = new TcpOptions { Address = IPAddress.IPv6Any },
        }, r => TlsService.Start(r, options)).Port;

        using var tcp = new TcpClient(client.AddressFamily);
        tcp.ReceiveTimeout = 5_000;
        tcp.Connect(client, port);

        using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls13 });
        ssl.Write("GET / HTTP/1.1\r\nHost: x\r\n\r\n"u8);

        var received = new MemoryStream();
        var buffer = new byte[4096];
        int n;
        while ((n = ssl.Read(buffer)) > 0)
        {
            received.Write(buffer, 0, n);
        }

        string response = Encoding.ASCII.GetString(received.ToArray());
        string body = response[(response.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..];
        Assert.True(backends.TryDequeue(out string? backend), "the handler never answered");
        return $"{body} {backend}";
    }

    private static async Task Pipes(Reactor reactor, TcpConnection conn, ConcurrentQueue<string> backends)
    {
        TlsSession? tls = null;
        try
        {
            tls = await reactor.GetService<TlsService>().AcceptAsync(conn);

            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);
            ReadResult read = await pipe.Input.ReadAsync();
            pipe.Input.AdvanceTo(read.Buffer.End);

            await pipe.Output.WriteAsync(Answer);
            backends.Enqueue((tls.KernelTx, tls.KernelRx) switch
            {
                (true, true) => "kTLS TX and RX",
                (true, false) => "kTLS TX",
                _ => "BoringSSL",
            });
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // The harness's listen probe, which closes without a handshake.
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    }
}
