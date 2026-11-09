using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// IsValid on <see cref="TlsConnectionDualPipe"/>. A TcpConnection is pooled, so code that keeps a pipe past DecRef
/// calls it to tell whether the connection is still its client's.
/// </summary>
internal static class TlsPipeValidityTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tls: a dual pipe is valid in the connection's life it was made in, and a kept one is not in the next", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var firstReleased = new ManualResetEventSlim();
            TcpConnection? firstObject = null;
            TlsConnectionDualPipe? kept = null;

            int port = TestServer.Start(async (r, conn) =>
            {
                TlsSession session;
                try
                {
                    session = await r.GetService<TlsService>().AcceptAsync(conn);
                }
                catch (IOException)
                {
                    conn.DecRef();   // the harness's readiness probe never completes a handshake
                    return;
                }

                var pipe = new TlsConnectionDualPipe(conn, session);
                try
                {
                    if (!pipe.IsValid())
                    {
                        outcome.TrySetResult("a new pipe is not valid on its own connection");
                    }
                    else if (firstObject is null)
                    {
                        (firstObject, kept) = (conn, pipe);
                    }
                    else if (!ReferenceEquals(firstObject, conn))
                    {
                        outcome.TrySetResult("the pool did not hand on the same object, so this proves nothing");
                    }
                    else
                    {
                        outcome.TrySetResult(kept!.IsValid() ? "a kept pipe is still valid in the connection's next life" : "ok");
                    }
                }
                finally
                {
                    await pipe.DisposeAsync();
                    conn.DecRef();
                    if (ReferenceEquals(kept, pipe))
                    {
                        firstReleased.Set();
                    }
                }
            }, r => TlsService.Start(r, options));

            using (var first = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                first.Connect(IPAddress.Loopback, port);
                using var tls = new SslStream(new NetworkStream(first), leaveInnerStreamOpen: false, (_, _, _, _) => true);
                tls.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });
                Assert.True(firstReleased.Wait(10_000), "the server never released the first connection");
            }
            Thread.Sleep(100);   // its connection goes back to the pool

            using var second = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            second.Connect(IPAddress.Loopback, port);
            using var secondTls = new SslStream(new NetworkStream(second), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            secondTls.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            Assert.True(outcome.Task.Wait(10_000), "the second handler never reported");
            Assert.Equal("ok", outcome.Task.Result);
        });
    }
}
