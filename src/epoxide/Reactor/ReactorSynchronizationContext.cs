namespace epoxide;

/// <summary>
/// Per-reactor <see cref="SynchronizationContext"/>, installed on the loop thread by
/// <see cref="Reactor.Run"/>. Awaits made from reactor code capture it, so continuations that
/// complete elsewhere (Task.Delay, HttpClient, Task.Run results) are posted back and resume on
/// the reactor instead of the thread pool. Posted work runs in the loop's post-queue drain,
/// before the loop waits. <c>ConfigureAwait(false)</c> opts an await out - and unlike in ioxide,
/// code that does so may keep using its connection from the thread pool.
/// <para>
/// Never block the reactor thread on a posted continuation (<c>.Result</c> / <c>.Wait()</c>):
/// the loop cannot drain its own mailbox while blocked inside a handler, so the wait can never
/// complete - a single-thread deadlock, not starvation.
/// </para>
/// </summary>
public sealed class ReactorSynchronizationContext : SynchronizationContext
{
    private readonly Reactor _reactor;

    internal ReactorSynchronizationContext(Reactor reactor) => _reactor = reactor;

    /// <summary>The reactor whose loop thread this context posts to.</summary>
    public Reactor Reactor => _reactor;

    /// <summary>Always queues, never invokes inline - Post is contractually asynchronous.</summary>
    public override void Post(SendOrPostCallback d, object? state) => _reactor.SchedulePost(d, state);

    public override void Send(SendOrPostCallback d, object? state)
    {
        if (_reactor.OnReactorThread)
        {
            d(state);
            return;
        }

        using var done = new ManualResetEventSlim();
        Exception? ex = null;
        _reactor.SchedulePost(_ =>
        {
            try
            {
                d(state);
            }
            catch (Exception e)
            {
                ex = e;
            }
            finally
            {
                done.Set();

            }
        }, null);

        done.Wait();

        if (ex is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex).Throw();
        }
    }

    public override SynchronizationContext CreateCopy() => this;
}
