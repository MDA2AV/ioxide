using ioxide;
using ioxide.tls;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// What <see cref="TlsSession.Decrypt"/> does when the stream is not merely incomplete but wrong.
///
/// This is the raw path - the one Kestrel's transport, GenHTTP's engine and every hand-written
/// handler already use - so the behaviour asserted here is what every existing caller gets, with no
/// adoption of anything new required.
/// </summary>
internal static class DecryptFaultTests
{
    public static void Register(Runner runner, bool ktls)
    {
        runner.Test("tls: a corrupt record faults the decrypt instead of looking incomplete", () =>
        {
            // Every non-ZERO_RETURN result used to be treated as "record incomplete, wait for more
            // bytes", so SSL_ERROR_SSL - a bad MAC, a malformed record - was indistinguishable from
            // a connection that had simply gone quiet. A handler would then wait forever on a
            // stream that was never going to recover, and a read on the pipe would never complete.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var reported = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(DecryptingHandler(reported), r => TlsService.Start(r, options));

            Client.SendTlsGarbageAfterHandshake(port);

            Assert.True(reported.Task.Wait(TimeSpan.FromSeconds(10)),
                "the handler should have observed something within 10 s");

            // Assert on WHAT happened. The harness probes the port with a raw TCP connection to
            // learn the server is listening, and that connection fails the handshake - so "an
            // exception reached the handler" is true before this test sends anything at all.
            string outcome = reported.Task.Result;
            Assert.True(outcome.Contains("TLS decrypt failed"),
                $"expected the decrypt to fault, got: {outcome}");
        });
        _ = ktls;   // the default path needs no kernel module; the parameter stays for symmetry
    }

    // Decrypts whatever arrives and publishes the first outcome that is not "more bytes needed":
    // either the fault, or a clean end of stream (which for this test is the wrong answer).
    private static Func<Reactor, TcpConnection, Task> DecryptingHandler(TaskCompletionSource<string> reported)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            try
            {
                // Outside the reporting path: the liveness probe's failed handshake is not what
                // this test is about, and counting it would let the test pass without the garbage.
                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;
                }

                while (true)
                {
                    RecvSnapshot snapshot = await connection.ReadAsync();

                    unsafe
                    {
                        while (connection.TryGetItem(snapshot, out SpscRecvRing.Item item))
                        {
                            try
                            {
                                if (item.HasBuffer)
                                {
                                    session.Decrypt(item.Ptr, item.Len);
                                }
                            }
                            finally
                            {
                                if (item.HasBuffer)
                                {
                                    connection.ReturnBuffer(in item);
                                }
                            }
                        }
                    }

                    connection.ResetRead();

                    if (session.Closed || snapshot.IsClosed)
                    {
                        reported.TrySetResult("clean end of stream");
                        return;
                    }
                }
            }
            catch (Exception e)
            {
                reported.TrySetResult(e.Message);
            }
            finally
            {
                session?.Dispose();
                connection.DecRef();
            }
        };
}
