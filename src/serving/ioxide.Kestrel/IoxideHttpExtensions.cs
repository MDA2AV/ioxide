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
    /// Runs <paramref name="work"/> on this connection's reactor and returns its result. When the endpoint is
    /// already on that reactor (the common keep-alive case) it runs inline - ioxide's inline resume is
    /// preserved. Otherwise (e.g. the first request of a connection, which Kestrel may dispatch to the
    /// ThreadPool) the work is marshaled onto the reactor. Either way the ring I/O runs on the reactor.
    /// Materialize ring-native results (PgRow, file buffers) into your own objects inside <paramref name="work"/>.
    /// </summary>
    public static Task<T> OnReactor<T>(this HttpContext context, Func<Reactor, Task<T>> work)
    {
        Reactor reactor = context.GetReactor();

        if (IoxideReactor.TryCurrent() == reactor)
        {
            return work(reactor);
        }

        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        reactor.ScheduleOnReactor(_ => _ = RunAsync(reactor, work, tcs), null);
        return tcs.Task;
    }

    private static async Task RunAsync<T>(Reactor reactor, Func<Reactor, Task<T>> work, TaskCompletionSource<T> tcs)
    {
        try
        {
            tcs.SetResult(await work(reactor));
        }
        catch (Exception e)
        {
            tcs.SetException(e);
        }
    }
}
