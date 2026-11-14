using System.Collections.Concurrent;
using System.IO.Pipelines;
using ioxide;

namespace ioxide.Kestrel;

/// <summary>
/// A <see cref="PipeScheduler"/> that runs pipe continuations on a reactor's loop thread, so the BCL
/// pipes in <see cref="HopDuplexPipe"/> keep Kestrel's read → parse → handle → send loop pinned to the
/// reactor (no ThreadPool hop). One per reactor, shared by its connections.
/// </summary>
/// <remarks>
/// Continuations wait in a queue of its own, drained by one post made the way a <see cref="ReactorSwitch"/>
/// posts: a stopped reactor runs that on the thread pool, and drops a plain post, which would leave the
/// pipe's reader or writer waiting forever. After a stop they therefore run off the reactor, and the pumps
/// they resume check where they are before touching the connection.
/// </remarks>
internal sealed class ReactorPipeScheduler : PipeScheduler
{
    private readonly ConcurrentQueue<(Action<object?> Action, object? State)> _queue = new();
    private readonly Action _drain;

    // 1 from a post of the drain until a drain finds the queue empty: a burst of continuations costs one post.
    private int _posted;

    public ReactorPipeScheduler(Reactor reactor)
    {
        Reactor = reactor;
        _drain = Drain;
    }

    public Reactor Reactor { get; }

    public override void Schedule(Action<object?> action, object? state)
    {
        _queue.Enqueue((action, state));
        if (Interlocked.Exchange(ref _posted, 1) == 0)
        {
            new ReactorSwitch(Reactor).UnsafeOnCompleted(_drain);
        }
    }

    private void Drain()
    {
        do
        {
            while (_queue.TryDequeue(out (Action<object?> Action, object? State) item))
            {
                // One that throws must not strand the rest: nothing would post for them again.
                try
                {
                    item.Action(item.State);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"[ioxide] reactor {Reactor.ShardIndex}: a pipe continuation threw: {e}");
                }
            }

            Interlocked.Exchange(ref _posted, 0);
        }
        // One queued between the last dequeue and the clear found _posted set, and posted nothing.
        while (!_queue.IsEmpty && Interlocked.Exchange(ref _posted, 1) == 0);
    }
}
