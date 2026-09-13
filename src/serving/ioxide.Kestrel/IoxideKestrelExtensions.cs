using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ioxide.Kestrel;

/// <summary>Hosting extensions for the ioxide Kestrel transport.</summary>
public static class IoxideKestrelExtensions
{
    /// <summary>
    /// Replaces Kestrel's default sockets transport with the ioxide io_uring transport. Call after
    /// <c>UseKestrel</c> (or rely on the implicit Kestrel registration that <c>WebApplication.CreateBuilder</c>
    /// performs) - this evicts any previously-registered <see cref="IConnectionListenerFactory"/>.
    /// </summary>
    public static IWebHostBuilder UseIoxide(this IWebHostBuilder builder, Action<IoxideTransportOptions>? configure = null)
    {
        return builder.ConfigureServices(services => services.AddIoxideTransport(configure));
    }

    /// <summary>
    /// <see cref="UseIoxide"/> against the service collection, for apps that wire everything through
    /// <c>builder.Services</c>: <c>builder.Services.AddIoxideTransport()</c>. Same precedence rule - it
    /// evicts any previously-registered <see cref="IConnectionListenerFactory"/>, so Kestrel has to be
    /// registered first, which <c>WebApplication.CreateBuilder</c> has already done by the time it returns.
    /// </summary>
    public static IServiceCollection AddIoxideTransport(this IServiceCollection services, Action<IoxideTransportOptions>? configure = null)
    {
        services.AddOptions<IoxideTransportOptions>();
        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.RemoveAll<IConnectionListenerFactory>();
        services.AddSingleton<IConnectionListenerFactory, IoxideTransportFactory>();
        return services;
    }
}
