using System.Text;
using ioxide;
using ioxide.redis.stackexchange;
using StackExchange.Redis;

namespace Ioxide.Tests;

/// <summary>
/// StackExchange.Redis over the ioxide transport (<see cref="IoxideTunnel"/>): each test's handler
/// drives a multiplexer made on its reactor and answers with what it saw.
/// </summary>
internal static class StackExchangeTransportTests
{
    public static void Register(Runner runner, (string Host, int Port) redis, bool redisUp)
    {
        string run = Guid.NewGuid().ToString("N")[..8];   // keys of their own on a shared server

        runner.Test("redis over SE.Redis: SET then GET on the ring, completed on the reactor's thread", () =>
        {
            Assert.Equal("hello reactor reactor", Get(redis, run, "/get"));
        }, skip: !redisUp);

        runner.Test("redis over SE.Redis: 1000 concurrent INCRs - flushes queued behind a send in flight", () =>
        {
            Assert.Equal("1000", Get(redis, run, "/burst"));
        }, skip: !redisUp);

        runner.Test("redis over SE.Redis: a 1 MiB value arrives across several receives", () =>
        {
            Assert.Equal((1 << 20).ToString(), Get(redis, run, "/big"));
        }, skip: !redisUp);

        runner.Test("redis over SE.Redis: pub/sub through the transport", () =>
        {
            Assert.Equal("ping", Get(redis, run, "/pubsub"));
        }, skip: !redisUp);

        runner.Test("redis over SE.Redis: a connection the server kills comes back through the tunnel", () =>
        {
            Assert.Equal("killed 1, then hello", Get(redis, run, "/reconnect"));
        }, skip: !redisUp);

        // StackExchange.Redis 3.4.0's RecordConnectionFailed reports a failure only for a connection
        // with a Stream (PhysicalConnection.cs:571, `_ioStream is not null`), which a transport never
        // has: a command caught by the close is cancelled instead, and no ConnectionFailed is raised.
        // On its own sockets the same command fails with RedisConnectionException(SocketClosed).
        runner.Pending("redis over SE.Redis: a command caught by a server-side close fails with the connection's error", () =>
        {
            Assert.Equal("RedisConnectionException", Get(redis, run, "/stranded"));
        }, because: "StackExchange.Redis reports transport closes only for Stream-backed connections");

        runner.Test("redis over SE.Redis: TLS is refused with the transport's reason, not a timeout", () =>
        {
            string body = Get(redis, run, "/tls");
            Assert.True(body.Contains("does not do TLS yet"), $"the connect log should carry the refusal: {body}");
        }, skip: !redisUp);
    }

    private static string Get((string Host, int Port) redis, string run, string path)
    {
        int port = TestServer.Start((r, conn) => Handle(r, conn, redis, run),
            r => r.AddService(IoxideRedis.ConnectAsync(r, Options(redis))));
        (int status, string body) = Client.Get(port, path);
        Assert.Equal(200, status);
        return body;
    }

    private static ConfigurationOptions Options((string Host, int Port) redis)
    {
        var options = new ConfigurationOptions
        {
            EndPoints = { { redis.Host, redis.Port } },
            AllowAdmin = true,   // CLIENT KILL, for the reconnect test
            ConnectTimeout = 5000,
        };
        options.Password = Environment.GetEnvironmentVariable("EXAMPLES_REDIS_PASSWORD");
        return options;
    }

    private static async Task Handle(Reactor r, TcpConnection conn, (string Host, int Port) redis, string run)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            string path = Wire.ReadPath(conn, snapshot);
            string body;
            try
            {
                body = await Answer(r, path, redis, run);
            }
            catch (Exception e)
            {
                body = $"{e.GetType().Name}: {e.Message}";
            }

            Wire.Write(conn, 200, body);
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task<string> Answer(Reactor r, string path, (string Host, int Port) redis, string run)
    {
        int reactorThread = Environment.CurrentManagedThreadId;
        string where() => Environment.CurrentManagedThreadId == reactorThread ? "reactor" : "elsewhere";

        if (path == "/tls")
        {
            ConfigurationOptions options = Options(redis);
            options.Ssl = true;
            options.ConnectTimeout = 1500;
            options.Tunnel = new IoxideTunnel(r);
            var written = new StringWriter();
            TextWriter log = TextWriter.Synchronized(written);   // written from StackExchange.Redis's threads
            try
            {
                using ConnectionMultiplexer refused = await ConnectionMultiplexer.ConnectAsync(options, log);
                return "connected";
            }
            catch (RedisConnectionException e)
            {
                return $"{written} | {e.Message}";
            }
        }

        ConnectionMultiplexer mux = await r.GetService<Task<ConnectionMultiplexer>>();
        IDatabase db = mux.GetDatabase();
        string key = $"se:{run}:{path.Trim('/')}";

        switch (path)
        {
            case "/get":
            {
                await db.StringSetAsync(key, "hello", TimeSpan.FromMinutes(1));
                // Which thread StackExchange.Redis completes the command on: the transport pushes
                // replies on the reactor, so it should be the reactor's.
                // StackExchange.Redis completes its tasks with asynchronous continuations, so the
                // await posts to the context it captured - from the thread that completed it.
                var recorder = new PostRecorder(SynchronizationContext.Current!);
                SynchronizationContext.SetSynchronizationContext(recorder);
                RedisValue value;
                try
                {
                    value = await db.StringGetAsync(key);
                }
                finally
                {
                    SynchronizationContext.SetSynchronizationContext(recorder.Inner);
                }
                bool onReactor = recorder.PostedFrom is -1 || recorder.PostedFrom == reactorThread;   // -1: resumed inline, so on the reactor
                return $"{value} {(onReactor ? "reactor" : "elsewhere")} {where()}";
            }

            case "/burst":
            {
                await db.KeyDeleteAsync(key);
                var increments = new Task<long>[1000];
                for (int i = 0; i < increments.Length; i++)
                {
                    increments[i] = db.StringIncrementAsync(key);
                }
                await Task.WhenAll(increments);
                RedisValue final = await db.StringGetAsync(key);
                await db.KeyDeleteAsync(key);
                return final.ToString();
            }

            case "/big":
            {
                byte[] payload = new byte[1 << 20];
                Random.Shared.NextBytes(payload);
                await db.StringSetAsync(key, payload, TimeSpan.FromMinutes(1));
                byte[]? back = await db.StringGetAsync(key);
                await db.KeyDeleteAsync(key);
                return back is not null && back.AsSpan().SequenceEqual(payload) ? back.Length.ToString() : "mismatch";
            }

            case "/pubsub":
            {
                ISubscriber subscriber = mux.GetSubscriber();
                var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                RedisChannel channel = RedisChannel.Literal(key);
                await subscriber.SubscribeAsync(channel, (_, message) => received.TrySetResult(message.ToString()));
                await subscriber.PublishAsync(channel, "ping");
                string message = await received.Task;   // the runner's timeout bounds a message that never comes
                await subscriber.UnsubscribeAsync(channel);
                return message;
            }

            case "/reconnect":
            {
                await db.StringSetAsync(key, "hello", TimeSpan.FromMinutes(1));
                long id = (long)await db.ExecuteAsync("CLIENT", "ID");
                var restored = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                mux.ConnectionRestored += (_, e) =>
                {
                    if (e.ConnectionType == ConnectionType.Interactive) restored.TrySetResult();
                };

                // The interactive connection kills itself; StackExchange.Redis reconnects through
                // the tunnel, and the next command goes on the new connection.
                long killed = (long)await db.ExecuteAsync("CLIENT", "KILL", "ID", id, "SKIPME", "no");
                await restored.Task;
                RedisValue value = await db.StringGetAsync(key);
                await db.KeyDeleteAsync(key);
                return $"killed {killed}, then {value}";
            }

            case "/stranded":
            {
                long id = (long)await db.ExecuteAsync("CLIENT", "ID");
                await db.ExecuteAsync("CLIENT", "KILL", "ID", id, "SKIPME", "no");
                try
                {
                    await db.StringGetAsync(key);   // written behind the kill, as the server closes
                    return "answered";
                }
                catch (Exception e)
                {
                    return e.GetType().Name;
                }
            }

            default:
                return "unknown path";
        }
    }

    /// <summary>Forwards to the reactor's context, noting which thread posted.</summary>
    private sealed class PostRecorder(SynchronizationContext inner) : SynchronizationContext
    {
        public int PostedFrom = -1;
        public SynchronizationContext Inner => inner;

        public override void Post(SendOrPostCallback callback, object? state)
        {
            PostedFrom = Environment.CurrentManagedThreadId;
            inner.Post(callback, state);
        }

        public override void Send(SendOrPostCallback callback, object? state) => inner.Send(callback, state);

        public override SynchronizationContext CreateCopy() => this;
    }
}
