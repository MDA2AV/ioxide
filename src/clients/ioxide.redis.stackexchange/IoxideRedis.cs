using StackExchange.Redis;

namespace ioxide.redis.stackexchange;

/// <summary>Multiplexers whose connections live on a reactor's ring.</summary>
public static class IoxideRedis
{
    /// <summary>
    /// Connect a multiplexer on <paramref name="reactor"/>'s ring: sets <see cref="ConfigurationOptions.Tunnel"/>
    /// to an <see cref="IoxideTunnel"/> and connects. Call it from <c>OnStart</c> and keep the task -
    /// never wait on it there, since the connect completes on the loop that starts after
    /// <c>OnStart</c> returns.
    /// </summary>
    public static Task<ConnectionMultiplexer> ConnectAsync(Reactor reactor, ConfigurationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Tunnel = new IoxideTunnel(reactor);
        return ConnectionMultiplexer.ConnectAsync(options);
    }

    /// <inheritdoc cref="ConnectAsync(Reactor, ConfigurationOptions)"/>
    public static Task<ConnectionMultiplexer> ConnectAsync(Reactor reactor, string configuration)
        => ConnectAsync(reactor, ConfigurationOptions.Parse(configuration));
}
