using ioxide.file;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="StaticAssets"/> leases: a snapshot stays open while leased and closes once it is retired and
/// released, a lease disposed twice cannot close the live one, and Acquire after Dispose throws.
/// </summary>
internal static class LeaseTests
{
    public static void Register(Runner runner)
    {
        // A lease is a struct: a copy handed to a helper that disposes it, plus the caller's own dispose,
        // releases one hold twice. Every request still leases the live snapshot, so its files must stay open.
        runner.Test("file: a lease disposed twice leaves the live snapshot's descriptors open", () =>
        {
            var assets = new StaticAssets(LeaseAssets());
            StaticAssets.Lease lease = assets.Acquire();
            Assert.True(lease.TryGet("/a.txt", out AssetCache.Asset asset), "the snapshot should hold /a.txt");

            StaticAssets.Lease copy = lease;
            copy.Dispose();
            lease.Dispose();

            Assert.Equal(asset.Path, ExecInheritance.Target(asset.Fd));
            Assert.Equal(1, assets.Count);
        });

        // Acquire retries a snapshot that refuses a lease, as one a Reload has swapped out does. A live
        // snapshot freed by a double dispose would refuse for good, with nothing to swap it out.
        runner.Test("file: Acquire returns after a lease was disposed twice", () =>
        {
            var assets = new StaticAssets(LeaseAssets());
            StaticAssets.Lease lease = assets.Acquire();
            StaticAssets.Lease copy = lease;
            copy.Dispose();
            lease.Dispose();

            (bool returned, Exception? thrown, bool found) = AcquireOnThread(assets);
            Assert.True(returned, "Acquire was still spinning 2 s later");
            Assert.True(thrown is null, $"Acquire threw {thrown?.GetType().Name}");
            Assert.True(found, "the lease Acquire returned should find /a.txt");
        });

        // After Dispose there is no snapshot left to lease, and a second Dispose changes nothing.
        runner.Test("file: Acquire after Dispose throws ObjectDisposedException, also after a second Dispose", () =>
        {
            var assets = new StaticAssets(LeaseAssets());

            assets.Dispose();
            (bool returned, Exception? thrown, _) = AcquireOnThread(assets);
            Assert.True(returned, "Acquire after Dispose was still spinning 2 s later");
            Assert.True(thrown is ObjectDisposedException,
                $"Acquire after Dispose: expected ObjectDisposedException, got {thrown?.GetType().Name ?? "a lease"}");

            assets.Dispose();
            (returned, thrown, _) = AcquireOnThread(assets);
            Assert.True(returned, "Acquire after a second Dispose was still spinning 2 s later");
            Assert.True(thrown is ObjectDisposedException,
                $"Acquire after a second Dispose: expected ObjectDisposedException, got {thrown?.GetType().Name ?? "a lease"}");
        });

        // What the live reference must not change: a reload keeps the old snapshot open for the lease still
        // on it and closes it when that lease goes, and with no lease out it closes it at once.
        runner.Test("file: a reload closes the old snapshot's descriptors once its last lease is disposed", () =>
        {
            var assets = new StaticAssets(LeaseAssets());
            StaticAssets.Lease lease = assets.Acquire();
            Assert.True(lease.TryGet("/a.txt", out AssetCache.Asset leased), "the snapshot should hold /a.txt");

            assets.Reload();
            Assert.Equal(leased.Path, ExecInheritance.Target(leased.Fd));

            lease.Dispose();
            Assert.True(ExecInheritance.Target(leased.Fd) != leased.Path,
                $"the old snapshot kept fd {leased.Fd} open after its last lease was disposed");

            AssetCache.Asset unleased;
            using (StaticAssets.Lease current = assets.Acquire())
            {
                Assert.True(current.TryGet("/a.txt", out unleased), "the reloaded snapshot should hold /a.txt");
            }

            assets.Reload();
            Assert.True(ExecInheritance.Target(unleased.Fd) != unleased.Path,
                $"a reload with no lease out kept the old snapshot's fd {unleased.Fd} open");
            assets.Dispose();
        });

        // A reload signalled during shutdown runs after Dispose, with a request's lease still out: it must revive nothing.
        runner.Test("file: after Dispose, Reload does nothing and Acquire throws, and a lease still out keeps its snapshot", () =>
        {
            var assets = new StaticAssets(LeaseAssets());
            StaticAssets.Lease held = assets.Acquire();
            Assert.True(held.TryGet("/a.txt", out AssetCache.Asset asset), "the snapshot should hold /a.txt");

            assets.Dispose();
            assets.Reload();
            Assert.Throws<ObjectDisposedException>(() => assets.Acquire().Dispose(), nameof(StaticAssets));
            Assert.Throws<ObjectDisposedException>(() => _ = assets.Count, nameof(StaticAssets));
            Assert.Throws<ObjectDisposedException>(() => _ = assets.RootDir, nameof(StaticAssets));
            Assert.Equal(asset.Path, ExecInheritance.Target(asset.Fd));   // the lease still reads its file

            held.Dispose();
            Assert.True(ExecInheritance.Target(asset.Fd) != asset.Path,
                $"the snapshot kept fd {asset.Fd} open after its last lease was released");
        });

        // Only the first Dispose may drop the live reference, or the lease held across the rest never frees its snapshot.
        runner.Test("file: Dispose can be called any number of times", () =>
        {
            string root = LeaseAssets();
            for (int times = 1; times <= 6; times++)
            {
                var assets = new StaticAssets(root);
                StaticAssets.Lease held = assets.Acquire();
                Assert.True(held.TryGet("/a.txt", out AssetCache.Asset asset), "the snapshot should hold /a.txt");
                for (int i = 0; i < times; i++)
                {
                    assets.Dispose();
                }
                Assert.Equal(asset.Path, ExecInheritance.Target(asset.Fd));   // the lease still reads its file

                held.Dispose();
                Assert.True(ExecInheritance.Target(asset.Fd) != asset.Path,
                    $"after {times} Dispose calls the snapshot kept fd {asset.Fd} open past its last lease");
                Assert.Throws<ObjectDisposedException>(() => assets.Acquire().Dispose(), nameof(StaticAssets));
            }
        });

        // They share a lock, so a reload in progress finishes first and its snapshot is the one dropped.
        runner.Test("file: Dispose racing Reload leaves no descriptor open and nothing to lease", () =>
        {
            string root = LeaseAssets();
            string file = new FileInfo(Path.Combine(root, "a.txt")).FullName;
            for (int round = 0; round < 300; round++)
            {
                var assets = new StaticAssets(root);
                int reloads = 0;
                bool stop = false;
                Exception? thrown = null;
                var reloader = new Thread(() =>
                {
                    try
                    {
                        while (!Volatile.Read(ref stop))
                        {
                            assets.Reload();
                            Interlocked.Increment(ref reloads);
                        }
                    }
                    catch (Exception e)
                    {
                        thrown = e;
                    }
                }) { IsBackground = true };
                reloader.Start();

                while (Volatile.Read(ref reloads) == 0 && reloader.IsAlive)
                {
                    Thread.SpinWait(16);                 // so the Dispose lands on a reload under way
                }
                assets.Dispose();
                Volatile.Write(ref stop, true);
                Assert.True(reloader.Join(TimeSpan.FromSeconds(5)), "a Reload racing Dispose never returned");

                Assert.True(thrown is null, $"Reload threw {thrown?.GetType().Name} in round {round}");
                Assert.Throws<ObjectDisposedException>(() => assets.Acquire().Dispose(), nameof(StaticAssets));
                HashSet<int> open = ExecInheritance.Referring(file);
                Assert.True(open.Count == 0, $"round {round} left fds {string.Join(", ", open)} open on the file");
            }
        });

        // A snapshot a concurrent Reload swapped out refuses the lease, and the next read finds the new one: no exception, no failed lookup.
        runner.Test("file: Acquire racing Reload always gets a lease on a whole snapshot", () =>
        {
            var assets = new StaticAssets(LeaseAssets());
            int failures = 0;
            long leases = 0;
            bool stop = false;

            var acquirers = new Thread[3];
            for (int t = 0; t < acquirers.Length; t++)
            {
                acquirers[t] = new Thread(() =>
                {
                    while (!Volatile.Read(ref stop))
                    {
                        try
                        {
                            using StaticAssets.Lease lease = assets.Acquire();
                            if (!lease.TryGet("/a.txt", out _))
                            {
                                Interlocked.Increment(ref failures);
                            }
                            Interlocked.Increment(ref leases);
                        }
                        catch
                        {
                            Interlocked.Increment(ref failures);
                        }
                    }
                }) { IsBackground = true };
                acquirers[t].Start();
            }

            for (int i = 0; i < 5_000; i++)
            {
                assets.Reload();
            }
            Volatile.Write(ref stop, true);
            foreach (Thread acquirer in acquirers)
            {
                Assert.True(acquirer.Join(TimeSpan.FromSeconds(5)), "an Acquire racing Reload never returned");
            }
            assets.Dispose();

            Assert.True(leases > 0, "no lease was taken while reloading");
            Assert.Equal(0, failures);
        });
    }

    // Acquire on its own thread, so a spin fails the test instead of hanging the run: whether it returned or
    // threw within 2 s, what it threw, and whether the lease it returned finds /a.txt.
    private static (bool Returned, Exception? Thrown, bool Found) AcquireOnThread(StaticAssets assets)
    {
        Exception? thrown = null;
        bool found = false;
        var acquirer = new Thread(() =>
        {
            try
            {
                using StaticAssets.Lease lease = assets.Acquire();
                found = lease.TryGet("/a.txt", out _);
            }
            catch (Exception e)
            {
                thrown = e;
            }
        }) { IsBackground = true };
        acquirer.Start();

        bool returned = acquirer.Join(TimeSpan.FromSeconds(2));
        if (!returned)
        {
            assets.Reload();   // ends a spin on a live instance, so the thread doesn't keep a core for the rest of the run
            acquirer.Join(TimeSpan.FromSeconds(2));
        }

        return (returned, thrown, found);
    }

    private static string LeaseAssets()
    {
        string dir = Directory.CreateTempSubdirectory("ioxide-lease-").FullName;
        File.WriteAllText(Path.Combine(dir, "a.txt"), "asset a");
        return dir;
    }
}
