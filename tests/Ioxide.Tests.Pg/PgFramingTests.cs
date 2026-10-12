using System.Buffers.Binary;
using System.Net.Sockets;
using ioxide;
using ioxide.pg;

namespace Ioxide.Tests;

/// <summary>Backend message framing from a server that lies about lengths. Needs no postgres.</summary>
internal static class PgFramingTests
{
    public static void Register(Runner runner)
    {
        // 1 + int.MaxValue wraps negative, which once read as "the whole message has arrived".
        runner.Test("pg: a backend message whose length overflows the frame fails the connection with a clear error", () =>
        {
            string outcome = Connect([(byte)'R', 0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
            Assert.True(outcome.StartsWith("PgException") && outcome.Contains("exceeds"),
                $"expected a PgException naming the oversized message, got [{outcome}]");
        });

        runner.Test("control: the same fake server's well-formed startup connects", () =>
        {
            string outcome = Connect([(byte)'R', 0, 0, 0, 8, 0, 0, 0, 0, (byte)'Z', 0, 0, 0, 5, (byte)'I']);
            Assert.Equal("connected", outcome);
        });
    }

    // Opens one connection to a fake server that answers the startup message with reply.
    private static string Connect(byte[] reply)
    {
        using var fake = new FakeServer((_, socket) => AnswerStartup(socket, reply));
        var options = new PgOptions { Port = (ushort)fake.Port, User = "fake", Database = "fake" };

        int port = TestServer.Start((r, conn) => Handle(r, conn, options));
        (int status, string body) = Client.Get(port, "/connect");
        Assert.Equal(200, status);
        return body;
    }

    private static void AnswerStartup(Socket socket, byte[] reply)
    {
        int length = BinaryPrimitives.ReadInt32BigEndian(FakeServer.Receive(socket, 4));
        FakeServer.Receive(socket, length - 4);   // protocol version and parameters
        socket.Send(reply);
    }

    private static async Task Handle(Reactor r, TcpConnection conn, PgOptions options)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            if (Wire.ReadPath(conn, snapshot) != "/connect")
            {
                return;   // the harness's listen probe
            }

            string outcome;
            try
            {
                using PgConnection pg = await PgConnection.ConnectAsync(r, options);
                outcome = "connected";
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
