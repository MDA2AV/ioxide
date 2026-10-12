using ioxide.utils;
using RESPite.Transports;

namespace ioxide.redis.stackexchange;

internal sealed partial class IoxideTransport
{
    private readonly nint _received;                        // native: Release frees it once nothing is in flight
    private readonly UnmanagedMemoryManager _receivedView;  // spans over _received for StackExchange.Redis
    private TransportReceiver? _receiver;
    private bool _batchEndPosted;   // reactor thread only

    // StackExchange.Redis hands over its receiver once, after the connect; starts the receive loop.
    public override void Start(TransportReceiver receiver)
    {
        if (Interlocked.CompareExchange(ref _receiver, receiver, null) is not null)
        {
            throw new InvalidOperationException("the transport already has its receiver");
        }

        if (!TryAddRef())
        {
            return;   // closed before it started: the receiver was never going to hear anything
        }

        _ = ReceiveAsync();
    }

    // Receives on the ring until closed, pushing each chunk into StackExchange.Redis on the reactor.
    private async Task ReceiveAsync()
    {
        Exception? fault = null;
        try
        {
            int capacity = _receivedView.Memory.Length;
            while (Volatile.Read(ref _closing) == 0)
            {
                // Resumes inline on the reactor thread when the receive completes.
                int received = await _ringSocket.RecvAsync(_received, capacity);
                if (received <= 0)
                {
                    if (received < 0 && Volatile.Read(ref _closing) == 0)
                    {
                        fault = new IOException($"receive failed: errno {-received}");
                    }
                    break;
                }

                if (!_receiver!.OnReceived(_receivedView.GetSpan()[..received]))
                {
                    break;   // the receiver asked to close
                }

                if (!_batchEndPosted)
                {
                    // A post from the reactor thread runs after this turn's completions, which is
                    // where the burst ends.
                    _batchEndPosted = true;
                    _reactor.ScheduleOnReactor(static state => ((IoxideTransport)state!).EndBatch(), this);
                }
            }
        }
        catch (Exception e)
        {
            fault = e;
        }

        Close(fault);
        Release();
    }

    // After the turn's completions: tells StackExchange.Redis the burst is over, so it flushes once.
    private void EndBatch()
    {
        _batchEndPosted = false;
        if (Volatile.Read(ref _closing) == 0)
        {
            _receiver?.OnBatchEnd();
        }
    }
}
