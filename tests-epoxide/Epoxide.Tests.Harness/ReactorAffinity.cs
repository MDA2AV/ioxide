using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// Records whether a handler is still running on the reactor that started it, at points the test
/// picks.
///
/// The invariant this exists to protect: <b>epoxide's own code must never be the reason a handler
/// leaves its reactor.</b> A handler that leaves keeps working - any thread may read and write a
/// connection - which is exactly why nothing would report it: every read and flush that parks would
/// resume through the thread pool instead of inline, for the life of the connection, and the only
/// symptom is the cost. Leaving is the handler's choice (ConfigureAwait(false), Task.Run), never a
/// side effect of an adapter.
///
/// The check is deliberately <see cref="Reactor.OnReactorThread"/> - the very predicate
/// <c>Continuations.OnCompleted</c> branches on to pick inline or not - rather than a thread name or
/// a SynchronizationContext, so a passing test means precisely "the inline path was taken here".
/// </summary>
public sealed class ReactorAffinity
{
    private readonly object _gate = new();
    private readonly List<string> _drift = [];
    private int _checks;

    /// <summary>
    /// Assert-and-record. Never throws: a handler that threw here would look like a connection
    /// fault and the test would report the wrong thing.
    /// </summary>
    public void Check(Reactor reactor, string where)
    {
        lock (_gate)
        {
            _checks++;

            if (reactor.OnReactorThread)
            {
                return;
            }

            Thread thread = Thread.CurrentThread;
            _drift.Add($"{where}: tid={Environment.CurrentManagedThreadId} "
                     + $"name={thread.Name ?? "<none>"} pool={thread.IsThreadPoolThread} "
                     + $"ctx={SynchronizationContext.Current?.GetType().Name ?? "<null>"}");
        }
    }

    /// <summary>How many observations were taken - zero means the handler never ran.</summary>
    public int Checks
    {
        get { lock (_gate) { return _checks; } }
    }

    /// <summary>Every point that ran off-reactor, for the failure message.</summary>
    public IReadOnlyList<string> Drift
    {
        get { lock (_gate) { return _drift.ToArray(); } }
    }
}
