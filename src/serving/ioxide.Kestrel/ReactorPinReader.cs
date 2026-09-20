using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using ioxide;

namespace ioxide.Kestrel;

/// <summary>
/// Wraps the inbound <see cref="PipeReader"/> so the FIRST read of a connection resumes on the connection's
/// reactor thread. Kestrel dispatches each new connection to the ThreadPool, and the first read usually
/// completes synchronously (the recv pump pre-buffered the request), which would run the whole first
/// request - application code included - off the reactor. Hopping once here pins Kestrel's parse + request
/// loop to the reactor from request one, so endpoints can use ring-native services (ioxide.pg, ioxide.file)
/// reliably on every request. Warm requests (read parks, resumes via the reactor scheduler) are already
/// on-reactor, so this only costs one hop per connection.
/// </summary>
internal sealed class ReactorPinReader : PipeReader
{
    private readonly PipeReader _inner;
    private readonly Reactor _reactor;
    private bool _pinned;

    public ReactorPinReader(PipeReader inner, Reactor reactor)
    {
        _inner = inner;
        _reactor = reactor;
    }

    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
        => _pinned ? _inner.ReadAsync(cancellationToken) : FirstReadAsync(cancellationToken);

    private async ValueTask<ReadResult> FirstReadAsync(CancellationToken cancellationToken)
    {
        ReadResult result = await _inner.ReadAsync(cancellationToken).ConfigureAwait(false);

        if (IoxideReactor.TryCurrent() != _reactor)
        {
            await new ReactorSwitch(_reactor);
        }
        _pinned = true;
        return result;
    }

    // Force the first read through ReadAsync (which pins) by reporting no synchronous data the first time.
    public override bool TryRead(out ReadResult result)
    {
        if (!_pinned)
        {
            result = default;
            return false;
        }
        return _inner.TryRead(out result);
    }

    public override void AdvanceTo(SequencePosition consumed) => _inner.AdvanceTo(consumed);
    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined) => _inner.AdvanceTo(consumed, examined);
    public override void CancelPendingRead() => _inner.CancelPendingRead();
    public override void Complete(Exception? exception = null) => _inner.Complete(exception);
    public override ValueTask CompleteAsync(Exception? exception = null) => _inner.CompleteAsync(exception);
}

/// <summary>Awaiter that resumes its continuation on the given reactor's thread (via the reactor post queue).</summary>
internal readonly struct ReactorSwitch : ICriticalNotifyCompletion
{
    private readonly Reactor _reactor;
    public ReactorSwitch(Reactor reactor) => _reactor = reactor;
    public ReactorSwitch GetAwaiter() => this;
    public bool IsCompleted => false;
    public void OnCompleted(Action continuation) => _reactor.ScheduleOnReactor(static s => ((Action)s!)(), continuation);
    public void UnsafeOnCompleted(Action continuation) => _reactor.ScheduleOnReactor(static s => ((Action)s!)(), continuation);
    public void GetResult() { }
}
