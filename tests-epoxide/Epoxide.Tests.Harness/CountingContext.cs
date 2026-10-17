namespace Epoxide.Tests;

/// <summary>
/// The reactor's own SynchronizationContext, counting what is posted through it - for telling a
/// continuation the reactor ran inline from one it sent back through its context. Installed from
/// OnStart, it is the reactor thread's context for good, so every await there captures it, and the
/// posts counted across one await say how that await resumed: none, inline.
/// </summary>
/// <remarks>
/// Not a stack inspection: once the JIT has promoted the reactor's dispatch to tier 1 it inlines
/// TcpConnection.OnReadable and OnWritable, and the frames an inline resume would show are gone.
///
/// OnStart, not inside a handler: an async method's MoveNext puts the thread's context back when it
/// returns, and a Task continuation runs inline only when the context it captured is still the
/// thread's current one when the task completes - so a wrapper installed for one await would itself
/// turn an inline resume into a post.
/// </remarks>
public sealed class CountingContext : SynchronizationContext
{
    private readonly SynchronizationContext _inner;
    private int _posts;

    private CountingContext(SynchronizationContext inner) => _inner = inner;

    /// <summary>Continuations posted through this context so far.</summary>
    public int Posts => Volatile.Read(ref _posts);

    /// <summary>Wrap the calling thread's context - a reactor's, from its OnStart - and make the wrapper current.</summary>
    public static CountingContext Install()
    {
        var counting = new CountingContext(Current ?? throw new InvalidOperationException("no SynchronizationContext to count: not on a reactor thread"));
        SetSynchronizationContext(counting);
        return counting;
    }

    public override void Post(SendOrPostCallback d, object? state)
    {
        Interlocked.Increment(ref _posts);
        _inner.Post(d, state);
    }

    public override void Send(SendOrPostCallback d, object? state) => _inner.Send(d, state);

    public override SynchronizationContext CreateCopy() => this;
}
