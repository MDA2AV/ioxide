using epoxide;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// Rotation as a client that actually VALIDATES sees it. Split from <see cref="RotationTests"/>,
/// which drives SslStream with verification disabled and asserts on the subject that came back.
/// </summary>
/// <remarks>
/// The distinction is the point, and it is why these are worth their own file and their own
/// dependency. A test that trusts any certificate proves the server SWAPPED one; it cannot prove
/// the result is something a real client would accept - a chain served in the wrong order, a leaf
/// whose key no longer matches, a certificate published mid-write would all pass it. These drive
/// curl with an explicit CA, so the question becomes "would anyone accept this", which is a
/// different question and the one an operator cares about during a renewal.
///
/// They skip when that curl is absent rather than failing, so the suite stays runnable anywhere -
/// which does mean the strongest rotation assertions in the repo are the ones most likely to be
/// silently absent on a given machine. Worth knowing when reading a green run.
/// </remarks>
internal static class RotationValidatingClientTests
{
    public static void Register(Runner runner)
    {
        RegisterCurlRotation(runner);
    }

    private static void RegisterCurlRotation(Runner runner)
    {
        runner.Test("control: a validating client is served repeatedly with NO rotation", () =>
        {
            // The control, and it earns its place: when the rotation tests below first flaked, this
            // failed too - which said the problem was the suite's CPU contention rather than
            // anything about replacing certificates. Keep it, so the next person gets that answer
            // in one run instead of an afternoon.
            (string ca, string first, string firstKey) = TestCert.EnsureNamedFromCa("rotate.test");

            int port = TestServer.Start(TlsHandlers.TlsSendFirst, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = first,
                KeyPath = firstKey,
            }));

            for (int i = 0; i < 4; i++)
            {
                (int exit, string body, string stderr) = Curl.Get("rotate.test", port, ca);
                Assert.True(exit == 0, $"request {i} without any rotation failed: {stderr}");
                Assert.True(body.Contains("ok"), $"request {i} was not answered: {body}");
            }
        }, skip: !Curl.Available);

        runner.Test("rotate: a validating client is served correctly across repeated rotations", () =>
        {
            (string ca, string first, string firstKey) = TestCert.EnsureNamedFromCa("rotate.test");
            (_, string second, string secondKey) = TestCert.EnsureRenewedFromCa("rotate.test");

            TlsService? service = null;
            int port = TestServer.Start(TlsHandlers.TlsSendFirst, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = first,
                KeyPath = firstKey,
            }));

            // Rotate, then ask - so every single request is served by a set that was installed a
            // moment earlier, and any state a rotation leaves behind is what answers it.
            // Five is enough: each iteration installs a whole new set and the request that follows
            // is served by it. More only lengthens the window in which this suite's other reactors
            // can starve the request, which is a property of the suite and not of rotation.
            for (int i = 0; i < 5; i++)
            {
                bool even = i % 2 == 0;

                service!.ReplaceCertificates(new TlsCertificate
                {
                    CertificatePath = even ? second : first,
                    KeyPath = even ? secondKey : firstKey,
                });

                (int exit, string body, string stderr) = Curl.Get("rotate.test", port, ca);

                Assert.True(exit == 0, $"request {i} after a rotation was refused: {stderr}");
                Assert.True(body.Contains("ok"), $"request {i} after a rotation was not answered: {body}");
            }
        }, skip: !Curl.Available);

        // A curl-driven CONCURRENT rotation test used to live here and was removed: with every
        // test server in the suite still busy-polling, a rotator running underneath the requests
        // only ever measured CPU contention, and failed as a timeout that reads like a server bug.
        // Concurrency is covered in-process by the load test further down, which is far cheaper.

        runner.Test("rotate: a client certificate is still verified across repeated rotations", () =>
        {
            // Both halves at once. The server's certificate is renewed before every request; the
            // client's is checked on every one. Renewing must not disturb who may connect - and the
            // impostor must stay out throughout, or a rotation is a window with no verification.
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();
            (_, string renewed, string renewedKey) = TestCert.EnsureRenewedFromCa("localhost");

            TlsService? service = null;
            int port = TestServer.Start(TlsHandlers.TlsIdentitySendFirst, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = serverCert,
                KeyPath = serverKey,
                ClientCaPath = ca,
                RequireClientCertificate = true,
            }));

            for (int i = 0; i < 4; i++)
            {
                bool even = i % 2 == 0;

                service!.ReplaceCertificates(new TlsCertificate
                {
                    CertificatePath = even ? renewed : serverCert,
                    KeyPath = even ? renewedKey : serverKey,
                });

                (int exit, string body, string stderr) = Curl.Get("localhost", port, ca, "/who", clientCert, clientKey);

                Assert.True(exit == 0, $"the trusted client was refused after rotation {i}: {stderr}");
                Assert.True(body.Contains("alice"),
                    $"the trusted client should still be named after rotation {i}, got: {body}");

                (int rogueExit, _, _) = Curl.Get("localhost", port, ca, "/who", rogueCert, rogueKey);

                Assert.True(rogueExit != 0,
                    $"an untrusted client got in after rotation {i} - a rotation must never be a window with no client verification");
            }
        }, skip: !Curl.Available);
    }


    /// <summary>The identity response: who the client proved itself to be.</summary>
    private static byte[] Identity(TlsSession session)
    {
        byte[] who = System.Text.Encoding.ASCII.GetBytes(session.PeerSubject ?? "anonymous");
        byte[] head = System.Text.Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\ncontent-length: {who.Length}\r\n\r\n");

        return [.. head, .. who];
    }
}
