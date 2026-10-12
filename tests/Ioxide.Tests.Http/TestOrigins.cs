using System.Text;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>A request as a test origin saw it, and which of its connections it came on.</summary>
internal sealed record OriginRequest(string Method, string Path, Dictionary<string, string> Headers, string Body,
    int Connection, int ClientPort);

/// <summary>Origins for the client tests, answering each request through a route.</summary>
internal static class TestOrigins
{
    /// <summary>
    /// Answer every request with <paramref name="route"/>'s status, extra field lines (each ending in
    /// CRLF) and body, after <paramref name="delayMs"/> on the ring. Connections are numbered once they
    /// carry a request, so TestServer's readiness probe is not counted.
    /// </summary>
    public static Func<Reactor, TcpConnection, Task> Route(Func<OriginRequest, (int Status, string Fields, string Body)> route,
        int delayMs = 0)
    {
        int numbered = 0;
        return async (reactor, connection) =>
        {
            try
            {
                int number = 0;
                while (true)
                {
                    RecvSnapshot snapshot = await connection.ReadAsync();
                    if (snapshot.IsClosed)
                    {
                        return;
                    }

                    var raw = new StringBuilder();
                    while (connection.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            raw.Append(Encoding.Latin1.GetString(item.AsSpan()));
                            connection.ReturnBuffer(in item);
                        }
                    }

                    if (raw.Length > 0)
                    {
                        if (number == 0)
                        {
                            number = Interlocked.Increment(ref numbered);
                        }

                        OriginRequest request = Parse(raw.ToString(), number, PeerPort(connection));
                        if (delayMs > 0)
                        {
                            await new RingTimer(reactor).DelayAsync(delayMs);
                        }

                        (int status, string fields, string body) = route(request);
                        connection.Write(Encoding.Latin1.GetBytes(
                            $"HTTP/1.1 {status} X\r\n{fields}content-length: {Encoding.Latin1.GetByteCount(body)}\r\n\r\n{body}"));
                        await connection.FlushAsync();
                    }
                    connection.ResetRead();
                }
            }
            finally
            {
                connection.DecRef();
            }
        };
    }

    // Each request arrives whole in one read here: the client sends a small one in a single send.
    private static OriginRequest Parse(string raw, int connection, int clientPort)
    {
        int headEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string[] lines = (headEnd >= 0 ? raw[..headEnd] : raw).Split("\r\n");
        string[] requestLine = lines[0].Split(' ');

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon > 0)
            {
                headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
            }
        }

        return new OriginRequest(requestLine[0], requestLine[1], headers, headEnd >= 0 ? raw[(headEnd + 4)..] : "",
            connection, clientPort);
    }

    private static unsafe int PeerPort(TcpConnection connection)
    {
        byte* address = stackalloc byte[28];   // sin_port / sin6_port, big-endian, at offset 2 in both
        uint length = 28;
        getpeername(connection.ClientFd, address, &length);
        return (address[2] << 8) | address[3];
    }

    [System.Runtime.InteropServices.DllImport("libc")]
    private static extern unsafe int getpeername(int fd, byte* address, uint* length);
}
