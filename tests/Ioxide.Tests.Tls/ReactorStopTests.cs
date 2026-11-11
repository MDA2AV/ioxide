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
        runner.Test("stop: pairs of reactors sharing a TLS service's options, started, rotated and stopped, leave the native heap where it was", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            var byHost = new Dictionary<string, TlsCertificate>
            {
                ["alpha.test"] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
            };
            var options = new TlsOptions { CertificatePath = cert, KeyPath = key, CertificatesByHost = byHost, HandshakeTimeoutMs = 0 };
            TlsCertificate replacement = new() { CertificatePath = cert, KeyPath = key };

            // Two reactors sharing one options instance, as a host runs them, with nothing to listen on: only their life
            // is under test. Unregistered, as a host serving several ports holds its services, and the reactor frees
            // those too. The contexts go with the second to stop.
            void Cycle()
            {
                var services = new TlsService[2];
                var reactors = new Reactor[2];
                var threads = new Thread[2];
                for (int i = 0; i < 2; i++)
                {
                    int index = i;
                    using var started = new ManualResetEventSlim();
                    reactors[i] = new Reactor(i, new ServerConfig { ReactorCount = 2, Tcp = null, Udp = null })
                    {
                        OnStart = r =>
                        {
                            services[index] = TlsService.Start(r, options, register: false);
                            started.Set();
                        },
                    };

                    threads[i] = new Thread(reactors[i].Run);
                    threads[i].Start();
                    Assert.True(started.Wait(10_000), "a reactor never started");
                }

                services[0].ReplaceCertificates(replacement, byHost);
                for (int i = 0; i < 2; i++)
                {
                    reactors[i].Stop();
                    threads[i].Join();
                }
            }

            for (int i = 0; i < 10; i++)
            {
                Cycle();   // BoringSSL's and the runtime's one-time setup
            }

            // Two windows: a leak grows the heap in both, while the JIT tiering up the hot paths grows it once, by some
            // 500 KiB, in whichever window that lands.
            long Window()
            {
                long before = SettledHeap();
                for (int i = 0; i < 50; i++)
                {
                    Cycle();
                }
                return SettledHeap() - before;
            }

            long first = Window();
            long second = Window();
            Assert.True(Math.Min(first, second) < 64 * 1024,
                $"fifty pairs of reactors sharing TLS options, started, rotated and stopped, left {first / 1024} KiB behind, and fifty more {second / 1024} KiB");
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
