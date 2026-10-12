using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ioxide;
using ioxide.pg;

namespace Ioxide.Tests;

/// <summary>SCRAM-SHA-256 against a fake server that sets the PBKDF2 cost. Needs no postgres.</summary>
internal static class PgScramTests
{
    private const string Password = "fake-password";

    public static void Register(Runner runner)
    {
        // The client derives the key on the reactor thread, so the server's count is how long the reactor stops.
        runner.Test("pg: a server that demands int.MaxValue SCRAM iterations is refused instead of stalling the reactor", () =>
        {
            string outcome = Connect(int.MaxValue);
            Assert.True(outcome.StartsWith("PgException") && outcome.Contains("iterations"),
                $"expected a PgException about the iteration count, got [{outcome}]");
        });

        runner.Test("control: a server that asks for postgres's default 4096 SCRAM iterations authenticates", () =>
        {
            Assert.Equal("connected", Connect(4096));
        });
    }

    // Opens one connection to a fake server that runs SCRAM-SHA-256 with the given iteration count.
    private static string Connect(int iterations)
    {
        using var fake = new FakeServer((_, socket) => Scram(socket, iterations));
        var options = new PgOptions { Port = (ushort)fake.Port, User = "fake", Database = "fake", Password = Password };

        int port = TestServer.Start((r, conn) => Handle(r, conn, options));
        (int status, string body) = Client.Get(port, "/connect", timeoutMs: 10_000);
        Assert.Equal(200, status);
        return body;
    }

    // The server side of RFC 5802 as postgres runs it, without checking the client's proof.
    private static void Scram(Socket socket, int iterations)
    {
        Receive(socket, BinaryPrimitives.ReadInt32BigEndian(FakeServer.Receive(socket, 4)) - 4);   // startup
        socket.Send(Authentication(10, "SCRAM-SHA-256\0\0"u8));

        byte[] initial = Receive(socket, ReadLength(socket));           // mechanism, length, client-first
        int afterName = Array.IndexOf(initial, (byte)0) + 1 + 4;
        string clientFirstBare = Encoding.UTF8.GetString(initial, afterName, initial.Length - afterName)["n,,".Length..];
        string nonce = clientFirstBare[(clientFirstBare.IndexOf("r=", StringComparison.Ordinal) + 2)..] + "fake";

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        string serverFirst = $"r={nonce},s={Convert.ToBase64String(salt)},i={iterations}";
        socket.Send(Authentication(11, Encoding.UTF8.GetBytes(serverFirst)));

        string clientFinal = Encoding.UTF8.GetString(Receive(socket, ReadLength(socket)));
        string withoutProof = clientFinal[..clientFinal.IndexOf(",p=", StringComparison.Ordinal)];

        byte[] salted = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(Password), salt, iterations, HashAlgorithmName.SHA256, 32);
        byte[] serverKey = HMACSHA256.HashData(salted, "Server Key"u8);
        byte[] signature = HMACSHA256.HashData(serverKey, Encoding.UTF8.GetBytes($"{clientFirstBare},{serverFirst},{withoutProof}"));
        socket.Send(Authentication(12, Encoding.UTF8.GetBytes($"v={Convert.ToBase64String(signature)}")));

        socket.Send([(byte)'R', 0, 0, 0, 8, 0, 0, 0, 0, (byte)'Z', 0, 0, 0, 5, (byte)'I']);   // AuthenticationOk, ReadyForQuery
    }

    // A frontend 'p' message's body length, from its tag and length.
    private static int ReadLength(Socket socket) => BinaryPrimitives.ReadInt32BigEndian(FakeServer.Receive(socket, 5).AsSpan(1)) - 4;

    private static byte[] Receive(Socket socket, int count) => FakeServer.Receive(socket, count);

    private static byte[] Authentication(int code, ReadOnlySpan<byte> data)
    {
        var message = new byte[1 + 4 + 4 + data.Length];
        message[0] = (byte)'R';
        BinaryPrimitives.WriteInt32BigEndian(message.AsSpan(1), 4 + 4 + data.Length);
        BinaryPrimitives.WriteInt32BigEndian(message.AsSpan(5), code);
        data.CopyTo(message.AsSpan(9));
        return message;
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
