using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ioxide.Kestrel;

/// <summary>
/// Kestrel transport that runs each connection on an ioxide reactor fleet. Kestrel calls
/// <see cref="BindAsync"/> once per configured endpoint; each call spins up its own set of reactors.
/// </summary>
internal sealed class IoxideTransportFactory : IConnectionListenerFactory
{
    private readonly IoxideTransportOptions _options;
    private readonly ILoggerFactory _loggerFactory;

    public IoxideTransportFactory(IOptions<IoxideTransportOptions> options, ILoggerFactory loggerFactory)
    {
        _options = options.Value;
        _loggerFactory = loggerFactory;
    }

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not IPEndPoint ipEndpoint)
        {
            throw new NotSupportedException($"ioxide transport only supports {nameof(IPEndPoint)} (got {endpoint.GetType().Name}).");
        }

        // If this port terminates TLS, build the ioxide.tls options the listener hands to its reactors.
        ioxide.tls.TlsOptions? tlsOptions = null;
        if (_options.Tls is { } tls && tls.Ports.Contains(ipEndpoint.Port))
        {
            tlsOptions = new ioxide.tls.TlsOptions
            {
                CertificatePath = tls.CertificatePath,
                KeyPath = tls.KeyPath,
                Alpn = tls.Alpn,
                KernelTx = tls.KernelTx,
            };
        }

        Socket portHold = HoldPort(ipEndpoint);
        try
        {
            var logger = _loggerFactory.CreateLogger<IoxideConnectionListener>();
            IConnectionListener listener = new IoxideConnectionListener((IPEndPoint)portHold.LocalEndPoint!, portHold, _options, tlsOptions, logger);
            return ValueTask.FromResult(listener);
        }
        catch
        {
            portHold.Dispose();
            throw;
        }
    }

    // Linux's values, on every architecture this runs on.
    private const int SolSocket = 1;
    private const int SoReusePort = 15;

    // The reactors bind on their own threads, too late to fail this call, and Kestrel goes by what this call throws: a
    // port in use stops the host, while a family the machine lacks falls back to IPv4. So the address is bound here
    // first, the way they will bind it. Kept bound, it settles a port of 0 for all of them; it doesn't listen, so it
    // takes no connections.
    private static Socket HoldPort(IPEndPoint endpoint)
    {
        var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.SetRawSocketOption(SolSocket, SoReusePort, BitConverter.GetBytes(1));
            if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = true;
            }

            socket.Bind(endpoint);
            return socket;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            socket.Dispose();
            throw new AddressInUseException(e.Message, e);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
