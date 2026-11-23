using System.Net.Sockets;
using System.Text;

namespace Epoxide.Tests;

/// <summary>
/// TCP transport chaos: the ways bytes arrive on a raw socket that a naive reader gets wrong -
/// split across recvs, coalesced into one, oversized, undersized, garbage, reset, or dribbled. The
/// framing server (<see cref="ChaosServer"/>) answers per request; each test asserts the right
/// answer AND that a fresh connection is still served afterwards.
/// </summary>
internal static class TcpChaosTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tcp: byte-by-byte fragmentation reassembles to one response", () =>
        {
            int port = ChaosServer.Start();
            int responses = ChaosClient.ResponsesFragmented(port, ChaosClient.Request(), chunk: 1, pauseMs: 2);
            Assert.Equal(1, responses);
            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: a pipelined burst is answered once per request", () =>
        {
            int port = ChaosServer.Start();

            const int n = 20;
            var burst = new List<byte>();
            for (int i = 0; i < n; i++)
            {
                burst.AddRange(ChaosClient.Request($"/{i}"));
            }

            int responses = ChaosClient.Responses(port, burst.ToArray());
            Assert.Equal(n, responses);
            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: headers spanning many recv buffers get one response", () =>
        {
            int port = ChaosServer.Start();

            // ~32 KB of header lines - well past the 4 KB recv buffer, so the request crosses many
            // recvs and the server must accumulate, but under the refusal cap so it completes.
            var sb = new StringBuilder("GET / HTTP/1.1\r\nHost: chaos\r\n");
            for (int i = 0; sb.Length < 32 * 1024; i++)
            {
                sb.Append($"X-Pad-{i}: {new string('y', 64)}\r\n");
            }
            sb.Append("\r\n");

            int responses = ChaosClient.Responses(port, Encoding.ASCII.GetBytes(sb.ToString()));
            Assert.Equal(1, responses);
            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: never-terminated headers are refused, not buffered without bound", () =>
        {
            int port = ChaosServer.Start();

            // 128 KB with no CRLFCRLF: a real slow-loris memory sink. The server must bound the
            // buffer and refuse rather than grow it, and must keep serving other clients.
            byte[] flood = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n" + new string('a', 128 * 1024));

            int okResponses = ChaosClient.Responses(port, flood);
            Assert.Equal(0, okResponses);   // refused (431), never answered 200
            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: binary garbage doesn't crash the server", () =>
        {
            int port = ChaosServer.Start();

            byte[] garbage = new byte[8 * 1024];
            new Random(1).NextBytes(garbage);

            ChaosClient.SendThenClose(port, garbage);
            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: NUL bytes in the request line are framed, not fatal", () =>
        {
            int port = ChaosServer.Start();

            byte[] withNuls = [.. "GET /"u8, 0, 0, 0, .. " HTTP/1.1\r\nHost: chaos\r\n\r\n"u8];
            Assert.Equal(1, ChaosClient.Responses(port, withNuls));
            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: bare-LF line endings never frame but don't wedge the server", () =>
        {
            int port = ChaosServer.Start();

            // LF without CR: this framing never matches CRLFCRLF, so no response is due - the point
            // is that an unmatched framing does not hang or crash the reactor.
            byte[] bareLf = "GET / HTTP/1.1\nHost: chaos\n\n"u8.ToArray();
            Assert.Equal(0, ChaosClient.Responses(port, bareLf, settleMs: 400));
            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: connect then immediate close (no bytes) is handled", () =>
        {
            int port = ChaosServer.Start();

            for (int i = 0; i < 20; i++)
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
            }   // dispose closes with no bytes sent: the server sees a bare accept then EOF

            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: abortive RST mid-request leaves the server serving", () =>
        {
            int port = ChaosServer.Start();

            for (int i = 0; i < 20; i++)
            {
                ChaosClient.Reset(port, preface: "GET / HTTP/1.1\r\nHost: ch"u8.ToArray());
            }

            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: rapid connect/disconnect churn", () =>
        {
            int port = ChaosServer.Start();

            for (int i = 0; i < 100; i++)
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
                c.GetStream().Write("x"u8);
            }

            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: a slow-loris drip cannot starve other connections", () =>
        {
            int port = ChaosServer.Start();

            using var slow = new TcpClient();
            slow.Connect("127.0.0.1", port);
            slow.NoDelay = true;
            NetworkStream drip = slow.GetStream();
            drip.Write("GET / HTTP/1.1\r\n"u8);
            drip.Flush();

            // Dribble header bytes, never the terminator, and prove a fresh client is still served
            // each time - the slow connection is parked, not blocking the reactor.
            for (int i = 0; i < 5; i++)
            {
                drip.Write(Encoding.ASCII.GetBytes($"X-Drip-{i}: y\r\n"));
                drip.Flush();
                Thread.Sleep(40);
                ChaosClient.AssertHealthy(port);
            }
        });

        runner.Test("tcp: a half-closing client is torn down cleanly, server keeps serving", () =>
        {
            int port = ChaosServer.Start();

            // epoxide reads a peer's FIN (recv EOF) as the end of the connection, as ioxide does,
            // but only once the handler reads again: a request that arrived before it is answered
            // first. Whether the answer reaches a client that already shut its send side down is
            // best-effort; the invariant the chaos suite pins is that half-close NEVER wedges or
            // kills the reactor. Whatever this client sees, a fresh connection is still answered.
            for (int i = 0; i < 10; i++)
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
                c.ReceiveTimeout = 2000;
                NetworkStream stream = c.GetStream();
                stream.Write(ChaosClient.Request());
                stream.Flush();
                c.Client.Shutdown(SocketShutdown.Send);   // FIN right after the request

                try
                {
                    stream.Read(new byte[256]);   // the response is best-effort under teardown
                }
                catch (IOException)
                {
                }
            }

            ChaosClient.AssertHealthy(port);
        });

        runner.Test("tcp: many concurrent connections are all answered", () =>
        {
            int port = ChaosServer.Start();
            ChaosClient.Concurrent(port, count: 50);
        });
    }
}
