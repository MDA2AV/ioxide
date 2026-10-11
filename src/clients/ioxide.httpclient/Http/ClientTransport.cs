using System.Net;
using System.Net.Sockets;

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
/// supplied <see cref="TlsClientOptions"/>. The origin is an IPv4 or IPv6 address, or a name to resolve.
/// </summary>
internal static class ClientTransport
{
    private const int TCP_USER_TIMEOUT = 18;
    private const int ETIMEDOUT = 110;

    public static async ValueTask<IClientTransport> ConnectAsync(IRingHost host, string origin, ushort port,
        TlsClientContext? tls, int connectTimeoutMs)
    {
        string name = Unbracketed(origin);
        string? serverName = ServerNameFor(tls, name);
        return await ConnectAsync(host, await ResolveAsync(name), port, tls, serverName, connectTimeoutMs);
    }

    // Each address in the resolver's order, the next only when a connect fails or times out. A failed TLS
    // handshake is not retried elsewhere: the origin was reached and refused.
    internal static async ValueTask<IClientTransport> ConnectAsync(IRingHost host, IPAddress[] addresses,
        ushort port, TlsClientContext? tls, string? serverName, int connectTimeoutMs)
    {
        for (int i = 0; ; i++)
        {
            IPAddress address = addresses[i];
            RingSocket socket = RingSocket.CreateTcp(host, address.AddressFamily);
            try
            {
                // The kernel's own bound on the SYN retries, cleared once connected: no timer to race the connect.
                if (connectTimeoutMs > 0)
                {
                    SetUserTimeout(socket.Fd, connectTimeoutMs);
                }

                int result = await socket.ConnectAsync(address, port);
                if (result < 0)
                {
                    throw new HttpClientException(result == -ETIMEDOUT && connectTimeoutMs > 0
                        ? $"connect to {new IPEndPoint(address, port)} timed out after {connectTimeoutMs} ms"
                        : $"connect to {new IPEndPoint(address, port)} failed: errno {-result}");
                }

                if (connectTimeoutMs > 0)
                {
                    SetUserTimeout(socket.Fd, 0);
                }
            }
            catch (HttpClientException) when (i < addresses.Length - 1)
            {
                socket.Dispose();
                continue;
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
            TlsClientStream stream = await tls.ConnectAsync(socket, serverName!);
            return new TlsClientTransport(stream);
        }
    }

    private static async ValueTask<IPAddress[]> ResolveAsync(string name)
    {
        if (IPAddress.TryParse(name, out IPAddress? literal))
        {
            return [literal];
        }

        // The system resolver (hosts file, resolv.conf) runs off the reactor thread; the await comes
        // back to the reactor through its synchronization context. Once per connection, never per request.
        IPAddress[] found;
        try
        {
            found = await Dns.GetHostAddressesAsync(name);
        }
        catch (SocketException e)
        {
            throw new HttpClientException($"could not resolve {name}: {e.Message}", e);
        }

        return found.Length > 0 ? found : throw new HttpClientException($"{name} resolved to no address");
    }

    // The name the certificate is checked against: the configured one, else the one the connection
    // was opened to. An address alone gives nothing to check.
    private static string? ServerNameFor(TlsClientContext? tls, string name)
    {
        if (tls is null || tls.Options.ServerName is { } configured)
        {
            return tls?.Options.ServerName;
        }

        return IPAddress.TryParse(name, out _)
            ? throw new HttpClientException(
                $"connecting to {name} by address: set TlsClientOptions.ServerName to the name its certificate carries")
            : name;
    }

    private static unsafe void SetUserTimeout(int fd, int ms)
        => Native.setsockopt(fd, Native.IPPROTO_TCP, TCP_USER_TIMEOUT, &ms, sizeof(int));

    internal static string Unbracketed(string origin) => origin is ['[', .., ']'] ? origin[1..^1] : origin;
}
