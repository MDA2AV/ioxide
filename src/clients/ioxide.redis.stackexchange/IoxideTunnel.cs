using System.Net;
using RESPite.Transports;
using StackExchange.Redis;
using StackExchange.Redis.Configuration;

namespace ioxide.redis.stackexchange;

/// <summary>
/// A StackExchange.Redis <see cref="Tunnel"/> that puts every connection of a multiplexer on one
/// reactor's ring: connect, sends and receives are io_uring operations on that reactor, and
/// StackExchange.Redis parses replies and completes commands on its thread. Give each reactor its own
/// multiplexer, made in <c>OnStart</c>, and a handler's commands never leave its thread.
/// </summary>
/// <remarks>
/// TCP without TLS: a configuration that asks for TLS is refused when the connection is made, with a
/// message saying so. Built on StackExchange.Redis's experimental transport seam (SER009), which may
/// change in any release - this package pins the StackExchange.Redis version it was built against.
/// </remarks>
public sealed class IoxideTunnel : Tunnel
{
    private readonly Reactor _reactor;
    private readonly int _receiveBufferSize;

    /// <param name="reactor">The reactor whose ring carries the connections.</param>
    /// <param name="receiveBufferSize">Bytes per connection for one receive; a reply larger than this
    /// arrives in several.</param>
    public IoxideTunnel(Reactor reactor, int receiveBufferSize = 64 * 1024)
    {
        ArgumentNullException.ThrowIfNull(reactor);
        ArgumentOutOfRangeException.ThrowIfLessThan(receiveBufferSize, 1024);

        _reactor = reactor;
        _receiveBufferSize = receiveBufferSize;
    }

    // StackExchange.Redis calls this for every connection it opens; refuses TLS, connects on the ring.
    public override async ValueTask<DuplexTransport?> ConnectTransportAsync(
        EndPoint endpoint, ConnectionType connectionType, TlsOptions tls, CancellationToken cancellationToken)
    {
        if (tls.IsEnabled)
        {
            throw new NotSupportedException(
                "the ioxide transport does not do TLS yet: connect without TLS, or leave Tunnel unset for StackExchange.Redis's own sockets");
        }

        return await IoxideTransport.ConnectAsync(_reactor, endpoint, _receiveBufferSize, cancellationToken).ConfigureAwait(false);
    }

    // A short name for the tunnel wherever it is printed.
    public override string ToString() => "ioxide";
}
