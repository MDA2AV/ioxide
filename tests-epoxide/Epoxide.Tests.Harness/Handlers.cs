using System.Text;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// Server-side HTTP helpers for the test handlers (local copy so the suite depends only on the
/// runtime). Partial, so a suite with a protocol of its own - TLS - adds its writer beside these.
/// </summary>
public static partial class Wire
{
    public static string ReadPath(TcpConnection conn, RecvSnapshot snapshot)
    {
        string path = "/";

        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                if (path == "/")
                {
                    path = ParsePath(item.AsSpan());
                }

                conn.ReturnBuffer(in item);
            }
        }

        return path;
    }

    /// <summary>Stage a plaintext response; the caller flushes.</summary>
    public static void Write(TcpConnection conn, int status, string body)
    {
        conn.Write(Response(status, body));
    }

    /// <summary>The bytes <see cref="Write"/> stages, for a handler that writes them some other way.</summary>
    public static byte[] Response(int status, string body) => Encoding.ASCII.GetBytes(
        $"HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}");

    private static string ParsePath(ReadOnlySpan<byte> request)
    {
        int firstSpace = request.IndexOf((byte)' ');
        if (firstSpace < 0)
        {
            return "/";
        }

        ReadOnlySpan<byte> rest = request[(firstSpace + 1)..];
        int secondSpace = rest.IndexOf((byte)' ');
        ReadOnlySpan<byte> target = secondSpace > 0 ? rest[..secondSpace] : rest;
        return Encoding.ASCII.GetString(target);
    }
}

/// <summary>
/// Generic connection handlers, so a test does not hand-roll one to answer 200. Partial, so a suite
/// whose handlers need a module of their own (TLS) keeps them in a file beside this one rather than
/// making the harness reference that module.
/// </summary>
public static partial class Handlers
{
    // core: echo "ok" - exercises accept, the recv path, send, and the keep-alive read loop.
    public static async Task Raw(Reactor r, TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                Wire.ReadPath(conn, snapshot);
                Wire.Write(conn, 200, "ok");
                await conn.FlushAsync();

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
}
