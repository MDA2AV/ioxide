
namespace ioxide.httpclient;

/// <summary>
/// The byte pipe a client connection speaks over: the ring socket itself for cleartext, or a TLS
/// session layered on it for <c>https://</c>.
///
/// The three results have the same meaning either way - a positive count, 0 for end of stream, a
/// negative errno for a socket failure - which is what lets the HTTP/1.1 and HTTP/2 connections use
/// one without knowing which they hold.
/// </summary>
internal interface IClientTransport : IDisposable
{
    /// <summary>Bytes accepted, which may be fewer than asked for; callers loop.</summary>
    ValueTask<int> SendAsync(nint buffer, int length);

    /// <summary>Bytes read, 0 at end of stream, or a negative errno.</summary>
    ValueTask<int> RecvAsync(nint buffer, int length);

    /// <summary>The ALPN protocol the origin selected, or null for cleartext or no ALPN.</summary>
    string? NegotiatedAlpn { get; }

    /// <summary>True when this pipe is wrapped in TLS. Decides h2's :scheme pseudo-header.</summary>
    bool IsSecure { get; }

    /// <summary>The socket underneath, for checking an idle connection without reading from it.</summary>
    int Fd { get; }
}

/// <summary>Cleartext: the ring socket, unwrapped.</summary>
internal sealed class RingSocketTransport(RingSocket socket) : IClientTransport
{
    public string? NegotiatedAlpn => null;

    public bool IsSecure => false;

    public int Fd => socket.Fd;

    public ValueTask<int> SendAsync(nint buffer, int length) => socket.SendAsync(buffer, length);

    public ValueTask<int> RecvAsync(nint buffer, int length) => socket.RecvAsync(buffer, length);

    public void Dispose() => socket.Dispose();
}

/// <summary>TLS: the same pipe, with records in between.</summary>
internal sealed class TlsClientTransport(TlsClientStream stream) : IClientTransport
{
    public string? NegotiatedAlpn => stream.NegotiatedAlpn;

    public bool IsSecure => true;

    public int Fd => stream.Socket.Fd;

    public ValueTask<int> SendAsync(nint buffer, int length) => stream.SendAsync(buffer, length);

    public ValueTask<int> RecvAsync(nint buffer, int length) => stream.RecvAsync(buffer, length);

    public void Dispose() => stream.Dispose();   // closes the socket underneath
}

/// <summary>
/// Connect a transport for an origin: plain TCP, or TCP plus a TLS handshake when the caller
/// supplied <see cref="TlsClientOptions"/>.
/// </summary>
internal static class ClientTransport
{
    public static async ValueTask<IClientTransport> ConnectAsync(IRingHost host, string ip, ushort port,
        TlsClientContext? tls)
    {
        RingSocket socket = RingSocket.CreateTcp(host);
        try
        {
            int result = await socket.ConnectAsync(ip, port);
            if (result < 0)
            {
                throw new HttpClientException($"connect to {ip}:{port} failed: errno {-result}");
            }
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        if (tls is null)
        {
            return new RingSocketTransport(socket);
        }

        // The TLS stream takes ownership of the socket, including closing it if the handshake
        // fails, so there is nothing to unwind here.
        TlsClientStream stream = await tls.ConnectAsync(socket);
        return new TlsClientTransport(stream);
    }
}
