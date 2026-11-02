using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;
using ioxide;

namespace ioxide.Kestrel;

/// <summary>
/// Helpers for running ring-native work (ioxide.pg / ioxide.file) on the connection's reactor from a Kestrel
/// endpoint, so DB and file I/O stay thread-per-core regardless of which thread Kestrel ran the endpoint on.
/// </summary>
public static class IoxideHttpExtensions
{
    /// <summary>The reactor that owns this connection (from <see cref="IReactorFeature"/>).</summary>
    public static Reactor GetReactor(this HttpContext context)
        => (context.Features.Get<IReactorFeature>()
            ?? throw new InvalidOperationException(
                "No ioxide reactor on this connection - is the app running on the ioxide transport (UseIoxide())?"))
            .Reactor;

    /// <summary>
    /// Runs <paramref name="work"/> on this connection's reactor and returns its result. Kestrel's request loop
    /// runs on the reactor from the first request, so this usually runs inline; from another thread (after an
    /// await that resumed on the ThreadPool, say) it switches to the reactor first, and throws
    /// <see cref="ObjectDisposedException"/> if the reactor has stopped.
    /// Materialize ring-native results (PgRow, file buffers) into your own objects inside <paramref name="work"/>.
    /// </summary>
    public static Task<T> OnReactor<T>(this HttpContext context, Func<Reactor, Task<T>> work)
    {
        Reactor reactor = context.GetReactor();

        if (reactor.OnReactorThread)
        {
            return work(reactor);
        }

        return RunOnReactor(reactor, work);
    }

    // Out of line, so the on-reactor path stays a bare call.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<T> RunOnReactor<T>(Reactor reactor, Func<Reactor, Task<T>> work)
    {
        await new ReactorSwitch(reactor);
        return await work(reactor);
    }
}
