using System.Net.Sockets;
using System.Text;

namespace Epoxide.Tests;

/// <summary>
/// Low-level TCP attack helpers - a raw socket with no HTTP niceties, so a test can put exactly the
/// bytes it wants on the wire, in exactly the fragments it wants, and count what comes back. The
/// health check reuses the harness's well-formed <see cref="Client"/>; only the assaults live here.
/// </summary>
public static class ChaosClient
{
    /// <summary>The well-formed request the health check and several assaults reuse.</summary>
    public static byte[] Request(string path = "/") =>
        Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: chaos\r\n\r\n");

    /// <summary>A fresh, well-formed request must still be answered "200 ok" after any assault.</summary>
    public static void AssertHealthy(int port)
    {
        (int status, string body) = Client.Get(port, "/");
        Assert.Equal(200, status);
        Assert.Equal("ok", body);
    }

    /// <summary>Write bytes in one go, let the server settle, then drain and count "200" responses.</summary>
    public static int Responses(int port, byte[] payload, int settleMs = 800, int timeoutMs = 6000)
    {
        using var client = Connect(port, timeoutMs);
        NetworkStream stream = client.GetStream();
        stream.Write(payload);
        stream.Flush();
        return CountResponses(stream, settleMs);
    }

    /// <summary>
    /// Write the payload in <paramref name="chunk"/>-byte pieces, each flushed, with a pause between
    /// them - so the bytes land in the server as separate recvs and reassembly is actually exercised
    /// (TCP_NODELAY stops the sender batching; the pause stops the receiver coalescing).
    /// </summary>
    public static int ResponsesFragmented(int port, byte[] payload, int chunk, int pauseMs,
        int settleMs = 1200, int timeoutMs = 15000)
    {
        using var client = Connect(port, timeoutMs);
        client.NoDelay = true;
        NetworkStream stream = client.GetStream();

        for (int i = 0; i < payload.Length; i += chunk)
        {
            stream.Write(payload, i, Math.Min(chunk, payload.Length - i));
            stream.Flush();
            if (i + chunk < payload.Length && pauseMs > 0)
            {
                Thread.Sleep(pauseMs);
            }
        }

        return CountResponses(stream, settleMs);
    }

    /// <summary>Write bytes and close the connection without reading - fire and forget.</summary>
    public static void SendThenClose(int port, byte[] payload, int timeoutMs = 6000)
    {
        using var client = Connect(port, timeoutMs);
        NetworkStream stream = client.GetStream();
        stream.Write(payload);
        stream.Flush();
    }

    /// <summary>
    /// Abortive close (RST): SO_LINGER at 0 makes Close send a reset rather than a FIN, so the
    /// server sees the connection torn down mid-stream rather than gracefully ended.
    /// </summary>
    public static void Reset(int port, byte[]? preface = null, int timeoutMs = 6000)
    {
        var client = Connect(port, timeoutMs);
        try
        {
            if (preface is { Length: > 0 })
            {
                client.GetStream().Write(preface);
                client.GetStream().Flush();
            }
            client.LingerState = new LingerOption(true, 0);
        }
        finally
        {
            client.Close();
        }
    }

    /// <summary>Open <paramref name="count"/> connections, each sending one request, and assert
    /// every one is answered - concurrent accept and per-connection state under load.</summary>
    public static void Concurrent(int port, int count)
    {
        var errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        Parallel.For(0, count, _ =>
        {
            try
            {
                (int status, string body) = Client.Get(port, "/");
                if (status != 200 || body != "ok")
                {
                    errors.Add($"got {status}/{body}");
                }
            }
            catch (Exception e)
            {
                errors.Add(e.Message);
            }
        });

        Assert.True(errors.IsEmpty, $"{errors.Count}/{count} concurrent requests failed: {errors.FirstOrDefault()}");
    }

    private static TcpClient Connect(int port, int timeoutMs)
    {
        var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;
        return client;
    }

    // Drain until the read times out, then count complete "HTTP/1.1 200" status lines.
    private static int CountResponses(NetworkStream stream, int settleMs)
    {
        Thread.Sleep(settleMs);
        stream.ReadTimeout = 500;

        var seen = new StringBuilder();
        byte[] buffer = new byte[16 * 1024];
        try
        {
            while (true)
            {
                int n = stream.Read(buffer, 0, buffer.Length);
                if (n <= 0)
                {
                    break;
                }
                seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
            }
        }
        catch (IOException)
        {
            // read timeout - everything the server sent is already collected
        }

        int count = 0, at = 0;
        string text = seen.ToString();
        while ((at = text.IndexOf("HTTP/1.1 200", at, StringComparison.Ordinal)) >= 0)
        {
            count++;
            at += 12;
        }
        return count;
    }
}
