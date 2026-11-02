using ioxide;

namespace ioxide.Kestrel;

/// <summary>
/// Access to the reactor running the current request, so a Kestrel endpoint - which runs pinned to the
/// reactor thread under this transport - can reach that reactor's ring-native services, e.g.
/// <c>IoxideReactor.Current.GetService&lt;PgPool&gt;()</c>. Start those services per reactor via
/// <see cref="IoxideTransportOptions.OnReactorStart"/>.
///
/// Only valid on a reactor thread. It relies on awaited continuations resuming inline on the same reactor
/// thread (which the transport guarantees for the request loop) - under a thread-hopping scheduler the
/// slot could point at the wrong reactor, so resolve the service before the first off-reactor await.
/// </summary>
public static class IoxideReactor
{
    /// <summary>The reactor handling the current request. Throws when read off a reactor thread.</summary>
    public static Reactor Current =>
        Reactor.Current ?? throw new InvalidOperationException(
            "IoxideReactor.Current is only available on an ioxide reactor thread (inside request handling).");
}
