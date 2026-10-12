using RESPite.Transports;

namespace ioxide.redis.stackexchange;

internal sealed partial class IoxideTransport
{
    private readonly byte[] _received;
    private TransportReceiver? _receiver;
    private bool _batchEndPosted;   // reactor thread only

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

    private async Task ReceiveAsync()
    {
        Exception? fault = null;
        try
        {
            nint buffer = Address(_received);
            while (Volatile.Read(ref _closing) == 0)
            {
                // Resumes inline on the reactor thread when the receive completes.
                int received = await _socket.RecvAsync(buffer, _received.Length);
                if (received <= 0)
                {
                    if (received < 0 && Volatile.Read(ref _closing) == 0)
                    {
                        fault = new IOException($"receive failed: errno {-received}");
                    }
                    break;
                }

                if (!_receiver!.OnReceived(_received.AsSpan(0, received)))
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

    private void EndBatch()
    {
        _batchEndPosted = false;
        if (Volatile.Read(ref _closing) == 0)
        {
            _receiver?.OnBatchEnd();
        }
    }
}
