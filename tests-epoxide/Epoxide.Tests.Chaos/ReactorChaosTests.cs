using System.Collections.Concurrent;
using System.Text;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// Chaos aimed squarely at the epoll reactor core. Malformed input is only the vehicle; the target
/// is the reactor's own bookkeeping: that torn-down connections are recycled and leak no
/// descriptors, that a pooled connection carries nothing into its next life, that both
/// write-overflow paths survive a large response, and that SO_REUSEPORT spreads connections over a
/// fleet of reactors.
/// </summary>
/// <remarks>
/// ioxide's "fragmentation and refusal hold on the incremental ring" has no counterpart: epoxide has
/// one recv path, a pooled buffer per recv, and no per-connection buffer ring.
/// </remarks>
internal static class ReactorChaosTests
{
    public static void Register(Runner runner)
    {
        runner.Test("reactor: a chaos storm leaks no file descriptors", () =>
        {
            int port = ChaosServer.Start();
            ChaosClient.AssertHealthy(port);   // warm the pool and settle before the baseline

            int before = FdCount.Stable();

            byte[] garbage = new byte[4096];
            new Random(5).NextBytes(garbage);
            byte[] oversize = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n" + new string('a', 96 * 1024));

            for (int i = 0; i < 25; i++)
            {
                ChaosClient.SendThenClose(port, garbage);                                    // garbage + FIN
                ChaosClient.Reset(port, preface: "GET / HTTP/1.1\r\nHost: ch"u8.ToArray());  // RST mid-request
                ChaosClient.Responses(port, oversize, settleMs: 80);                         // oversize, refused + closed
            }

            ChaosClient.AssertHealthy(port);

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 3,
                $"{leaked} fds leaked after a chaos storm - the reactor must recycle every torn-down connection");
        });

        runner.Test("reactor: a pooled connection carries no state into its next life", () =>
        {
            int port = ChaosServer.Start();

            // Alternate a connection that leaves partial, never-terminated bytes in the recv/slab
            // state (then closes, returning its pooled connection object) with a clean request. If
            // recycling leaked a predecessor's bytes, the clean request would see a corrupted
            // response instead of exactly "ok".
            for (int i = 0; i < 40; i++)
            {
                ChaosClient.SendThenClose(port, Encoding.ASCII.GetBytes($"GET /junk-{i} HTTP/1.1\r\nX-partial: "));
                (int status, string body) = Client.Get(port, "/");
                Assert.Equal(200, status);
                Assert.Equal("ok", body);
            }
        });

        runner.Test("reactor: a large response survives the write-overflow path", () =>
        {
            // 40 KiB is well past the 16 KiB write slab the test config uses, so the response spills
            // into the grown slab and returns through a different send than a small reply - it must
            // arrive whole and uncorrupted.
            const int bodyBytes = 40 * 1024;
            int port = ChaosServer.StartBig(bodyBytes);

            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal(bodyBytes, body.Length);
            Assert.True(body.All(c => c == 'x'), "large response corrupted through the overflow path");
        });

        runner.Test("reactor: a large response survives the segmented overflow path", () =>
        {
            // The other overflow strategy: rather than reallocating one slab (Grow), spill the excess
            // into a chain of pooled segments gathered into one vectored sendmsg - a distinct send
            // path (BuildIovec / AdvanceIov on a partial send). Same correctness bar: arrives whole.
            const int bodyBytes = 40 * 1024;
            var config = new ServerConfig
            {
                RecvBufferSize = 4096,
                Tcp = new TcpOptions
                {
                    WriteSlabSize = 16 * 1024,
                    PoolMax = 64,
                    RecvQueueEntries = 64,
                    WriteOverflow = WriteOverflowStrategy.Segmented,
                },
            };
            int port = TestServer.StartConfigured(ChaosServer.Big(bodyBytes), config).Port;

            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal(bodyBytes, body.Length);
            Assert.True(body.All(c => c == 'x'), "large response corrupted through the segmented overflow path");
        });

        runner.Test("reactor: SO_REUSEPORT shards connections across reactors", () =>
        {
            // Several reactors on one port, each answering with its own shard index. The kernel
            // load-balances accepts across the SO_REUSEPORT listeners, so a healthy shard set answers
            // every connection AND more than one shard shows up - the single-reactor Start() helpers
            // never exercise this.
            const int shards = 4;
            int port = TestServer.StartSharded(shards, static (shard, r, conn) => ChaosServer.RespondBody(conn, shard.ToString()));

            var seen = new ConcurrentDictionary<int, bool>();
            var errors = new ConcurrentBag<string>();
            Parallel.For(0, 200, _ =>
            {
                try
                {
                    (int status, string body) = Client.Get(port, "/");
                    if (status != 200)
                    {
                        errors.Add($"status {status}");
                        return;
                    }
                    seen[int.Parse(body)] = true;
                }
                catch (Exception e)
                {
                    errors.Add(e.Message);
                }
            });

            Assert.True(errors.IsEmpty, $"{errors.Count}/200 requests failed under sharding: {errors.FirstOrDefault()}");
            Assert.True(seen.Count > 1,
                $"200 connections landed on only {seen.Count} of {shards} shards - SO_REUSEPORT did not distribute");
        });
    }
}
