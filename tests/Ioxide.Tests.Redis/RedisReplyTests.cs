using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.redis;

namespace Ioxide.Tests;

/// <summary>Replies from a fake server that nests arrays without end. Needs no redis.</summary>
internal static class RedisReplyTests
{
    public static void Register(Runner runner)
    {
        // The parser recursed once per level, so a deep enough reply overflowed the reactor's stack and killed the process.
        runner.Test("redis: a reply nested 100,000 arrays deep fails the command instead of overflowing the stack", () =>
        {
            string outcome = Ping(100_000);
            Assert.True(outcome.StartsWith("RedisException") && outcome.Contains("deep"),
                $"expected a RedisException about the nesting, got [{outcome}]");
        });

        runner.Test("control: the same fake server's reply nested 8 arrays deep is parsed", () =>
        {
            Assert.Equal("depth 8", Ping(8));
        });
    }

    // PINGs a fake server that answers with :1 inside depth one-element arrays, and reports the depth it parsed.
    private static string Ping(int depth)
    {
        byte[] reply = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("*1\r\n", depth)) + ":1\r\n");
        using var fake = new FakeServer((_, socket) => Answer(socket, reply));
        var options = new RedisOptions { Port = (ushort)fake.Port };

        int port = TestServer.Start((r, conn) => Handle(r, conn, options));
        (int status, string body) = Client.Get(port, "/ping");
        Assert.Equal(200, status);
        return body;
    }

    private static void Answer(Socket socket, byte[] reply)
    {
        FakeServer.Receive(socket, "*1\r\n$4\r\nPING\r\n".Length);
        socket.Send(reply);
    }

    private static async Task Handle(Reactor r, TcpConnection conn, RedisOptions options)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            if (Wire.ReadPath(conn, snapshot) != "/ping")
            {
                return;   // the harness's listen probe
            }

            string outcome;
            try
            {
                using RedisConnection redis = await RedisConnection.ConnectAsync(r, options);
                RespValue reply = await redis.ExecuteAsync("PING");
                int depth = 0;
                for (; reply.Kind == RespKind.Array; depth++)
                {
                    reply = reply.Items[0];
                }

                outcome = $"depth {depth}";
            }
            catch (Exception e)
            {
                outcome = $"{e.GetType().Name}: {e.Message}";
            }

            Wire.Write(conn, 200, outcome);
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }
}
