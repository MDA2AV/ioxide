using System.Net;

namespace ioxide.redis.stackexchange;

internal sealed partial class IoxideTransport
{
    /// <summary>Resolve <paramref name="endpoint"/> and connect to its addresses in turn, on
    /// <paramref name="reactor"/>'s ring.</summary>
    internal static async ValueTask<IoxideTransport> ConnectAsync(
        Reactor reactor, EndPoint endpoint, int receiveBufferSize, CancellationToken cancellationToken)
    {
        (IPAddress[] addresses, int port) = await ResolveAsync(endpoint, cancellationToken).ConfigureAwait(false);
        string? failure = null;

        foreach (IPAddress address in addresses)
        {
            RingSocket ringSocket = RingSocket.CreateTcp(reactor, address.AddressFamily);
            Task<int> connect = ringSocket.ConnectAsync(address, (ushort)port).AsTask();
            int result;
            try
            {
                result = await connect.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // A ring connect cannot be cancelled: the socket goes once the connect completes.
                _ = connect.ContinueWith(static (_, state) => ((RingSocket)state!).Dispose(), ringSocket,
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                throw;
            }

            if (result == 0)
            {
                return new IoxideTransport(reactor, ringSocket, receiveBufferSize);
            }

            ringSocket.Dispose();
            failure = $"connect to {new IPEndPoint(address, port)} failed: errno {-result}";
        }

        throw new IOException(failure ?? $"{endpoint} resolved to no address");
    }

    private static async ValueTask<(IPAddress[] Addresses, int Port)> ResolveAsync(
        EndPoint endpoint, CancellationToken cancellationToken)
    {
        if (endpoint is IPEndPoint ip)
        {
            return ([ip.Address], ip.Port);
        }

        if (endpoint is DnsEndPoint dns)
        {
            if (IPAddress.TryParse(dns.Host, out IPAddress? literal))
            {
                return ([literal], dns.Port);
            }

            // Off the reactor: a lookup blocks its thread.
            return (await Dns.GetHostAddressesAsync(dns.Host, cancellationToken).ConfigureAwait(false), dns.Port);
        }

        throw new NotSupportedException($"the ioxide transport connects over TCP only, not to a {endpoint.GetType().Name}");
    }
}
