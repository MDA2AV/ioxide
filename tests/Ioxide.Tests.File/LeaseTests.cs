using ioxide.file;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="StaticAssets"/> leases: a snapshot stays open while leased and closes once it is retired and
/// released, and a lease disposed twice cannot close the live one.
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

            bool found = false;
            var acquirer = new Thread(() =>
            {
                using StaticAssets.Lease next = assets.Acquire();
                found = next.TryGet("/a.txt", out _);
            }) { IsBackground = true };
            acquirer.Start();

            bool returned = acquirer.Join(TimeSpan.FromSeconds(2));
            if (!returned)
            {
                assets.Reload();   // the one thing that ends the spin, so the thread doesn't keep a core for the rest of the run
                acquirer.Join(TimeSpan.FromSeconds(2));
            }

            Assert.True(returned, "Acquire was still spinning 2 s later");
            Assert.True(found, "the lease Acquire returned should find /a.txt");
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
    }

    private static string LeaseAssets()
    {
        string dir = Directory.CreateTempSubdirectory("ioxide-lease-").FullName;
        File.WriteAllText(Path.Combine(dir, "a.txt"), "asset a");
        return dir;
    }
}
