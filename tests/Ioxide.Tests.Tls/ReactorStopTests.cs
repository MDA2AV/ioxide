using System.Runtime.InteropServices;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// A TLS service's end of life (#543): the reactor it started on frees it when it stops, registered or not. Nothing
/// did, so a host starting servers again in one process kept every certificate and key it had loaded.
/// </summary>
internal static class ReactorStopTests
{
    public static void Register(Runner runner)
    {
        runner.Test("stop: a reactor started with a TLS service, rotated and stopped a hundred times leaves the native heap where it was", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            var byHost = new Dictionary<string, TlsCertificate>
            {
                ["alpha.test"] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
            };
            var options = new TlsOptions { CertificatePath = cert, KeyPath = key, CertificatesByHost = byHost, HandshakeTimeoutMs = 0 };
            TlsCertificate replacement = new() { CertificatePath = cert, KeyPath = key };

            // As a host runs one, with nothing to listen on: only its life is under test. Unregistered, as a host
            // serving several ports holds its services, and the reactor frees those too.
            void Cycle()
            {
                var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null, Udp = null });
                using var started = new ManualResetEventSlim();
                reactor.OnStart = r =>
                {
                    TlsService.Start(r, options, register: false).ReplaceCertificates(replacement, byHost);
                    started.Set();
                };

                var thread = new Thread(reactor.Run);
                thread.Start();
                Assert.True(started.Wait(10_000), "the reactor never started");
                reactor.Stop();
                thread.Join();
            }

            for (int i = 0; i < 10; i++)
            {
                Cycle();   // BoringSSL's and the runtime's one-time setup
            }

            long before = SettledHeap();
            for (int i = 0; i < 100; i++)
            {
                Cycle();
            }
            long grown = SettledHeap() - before;

            Assert.True(grown < 64 * 1024, $"a hundred reactors started with a TLS service, rotated and stopped left {grown / 1024} KiB behind");
        });

        runner.Test("stop: once its reactor has stopped, a TLS service, registered or not, answers for no names and refuses a rotation", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            var byHost = new Dictionary<string, TlsCertificate>
            {
                ["alpha.test"] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
            };
            var options = new TlsOptions { CertificatePath = cert, KeyPath = key, CertificatesByHost = byHost };
            TlsCertificate replacement = new() { CertificatePath = cert, KeyPath = key };

            // The second as a host serving several ports holds its services, out of the reactor's registry.
            TlsService? registered = null;
            TlsService? held = null;
            int port = TestServer.Start(Handlers.TlsSendFirst, r =>
            {
                registered = TlsService.Start(r, options);
                held = TlsService.Start(r, options, register: false);
            });

            Assert.True(Client.ServerCertificateSubject(port, "alpha.test").Contains("alpha.test"), "alpha.test before the rotation");
            registered!.ReplaceCertificates(replacement, byHost);
            Assert.True(Client.ServerCertificateSubject(port, "alpha.test").Contains("alpha.test"), "alpha.test after the rotation");
            Assert.Equal(1, registered.ServerNames.Count);
            Assert.Equal(1, held!.ServerNames.Count);

            TestServer.StopAll();

            foreach (TlsService service in new[] { registered, held })
            {
                Assert.Equal(0, service.ServerNames.Count);
                Assert.Throws<ObjectDisposedException>(() => service.ReplaceCertificates(replacement), nameof(TlsService));
            }
        });
    }

    // What malloc has handed out and not had back, over every arena, after a collection: BoringSSL allocates
    // through it, and a finished thread's runtime state is freed by its finalizer.
    private static long SettledHeap()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        MallInfo2 info = MallInfo();
        return (long)(info.Uordblks + info.Hblkhd);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MallInfo2
    {
        public nuint Arena, Ordblks, Smblks, Hblks, Hblkhd, Usmblks, Fsmblks, Uordblks, Fordblks, Keepcost;
    }

    [DllImport("libc", EntryPoint = "mallinfo2")]
    private static extern MallInfo2 MallInfo();
}
