using System.Runtime.InteropServices;
using System.Text;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// The plaintext HTTP/1.1 server the chaos clients attack. A minimal but CORRECT framing loop:
/// accumulate bytes across recvs, answer once per complete request (terminated by CRLFCRLF), and -
/// crucially for chaos - refuse a request whose headers grow past a cap instead of buffering
/// without bound. That last part is what turns a slow-loris or a never-terminated header from an
/// unbounded memory sink into one bounded refusal.
///
/// It frames on end-of-headers and does not read bodies, so a request carrying a large body reads
/// as an unterminated header once the headers are consumed - which the cap then refuses. The tests
/// are written to that model: "large request" means large HEADERS under the cap, and a body-bearing
/// flood is a survival test, not a 200.
/// </summary>
public static class ChaosServer
{
    /// <summary>Header bytes buffered before a request is refused as oversized (mirrors a real
    /// server's request-header cap; deliberately small so tests hit it quickly).</summary>
    public const int MaxRequestBytes = 64 * 1024;

    private static readonly byte[] Ok = Build(200, "ok");
    private static readonly byte[] TooLarge = Build(431, "too large");

    public static int Start() => TestServer.Start(Http);

    /// <summary>
    /// A server whose response body is <paramref name="bodyBytes"/> bytes of 'x' - large enough to
    /// spill past the write slab and come back through the overflow send path rather than a plain
    /// one, so tests can check a big response is framed and sent uncorrupted.
    /// </summary>
    public static int StartBig(int bodyBytes) => TestServer.Start(Big(bodyBytes));

    /// <summary>The big-response handler on its own, so a test can start it under a custom config
    /// (e.g. a segmented write-overflow strategy).</summary>
    public static Func<Reactor, TcpConnection, Task> Big(int bodyBytes)
    {
        byte[] response = Build(200, new string('x', bodyBytes));
        return (_, conn) => Serve(conn, response);
    }

    public static Task Http(Reactor r, TcpConnection conn) => Serve(conn, Ok);

    /// <summary>Answer every request with a fixed body - the sharding test has each reactor answer
    /// with its own shard index so the client can see the spread.</summary>
    public static Task RespondBody(TcpConnection conn, string body) => Serve(conn, Build(200, body));

    private static async Task Serve(TcpConnection conn, byte[] response)
    {
        var carry = new List<byte>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        carry.AddRange(item.AsSpan().ToArray());
                        conn.ReturnBuffer(in item);
                    }
                }

                // Answer per REQUEST, not per recv: fragmentation and coalescing both resolve here.
                int responded = 0;
                int idx;
                while ((idx = CollectionsMarshal.AsSpan(carry).IndexOf("\r\n\r\n"u8)) >= 0)
                {
                    carry.RemoveRange(0, idx + 4);
                    responded++;
                }

                // Headers that never terminate must not grow the buffer forever - bound it.
                if (responded == 0 && carry.Count > MaxRequestBytes)
                {
                    conn.Write(TooLarge);
                    await conn.FlushAsync();
                    return;
                }

                for (int i = 0; i < responded; i++)
                {
                    conn.Write(response);
                }

                if (responded > 0)
                {
                    await conn.FlushAsync();
                }

                if (snapshot.IsClosed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static byte[] Build(int status, string body) => Encoding.ASCII.GetBytes(
        $"HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}");
}
