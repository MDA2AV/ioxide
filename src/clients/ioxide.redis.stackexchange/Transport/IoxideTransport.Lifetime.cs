namespace ioxide.redis.stackexchange;

internal sealed partial class IoxideTransport
{
    private int _closing;
    private Exception? _fault;

    // The transport's own reference, the receive loop's and a send's: the socket is disposed, and the
    // receiver told, when the last of them lets go - never under an operation still in flight.
    private int _refs = 1;
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public override ValueTask DisposeAsync()
    {
        Close(null);
        return new ValueTask(_closed.Task);
    }

    private void Close(Exception? fault)
    {
        if (Interlocked.Exchange(ref _closing, 1) != 0)
        {
            return;
        }

        _fault = fault;
        Native.shutdown(_socket.Fd, Native.SHUT_RDWR);   // ends the receive in flight, and a stuck send
        Release();                                       // the transport's own reference
    }

    private bool TryAddRef()
    {
        int refs;
        do
        {
            refs = Volatile.Read(ref _refs);
            if (refs == 0)
            {
                return false;
            }
        }
        while (Interlocked.CompareExchange(ref _refs, refs + 1, refs) != refs);
        return true;
    }

    private void Release()
    {
        if (Interlocked.Decrement(ref _refs) != 0)
        {
            return;
        }

        _socket.Dispose();
        Interlocked.Exchange(ref _receiver, null)?.OnClosed(_fault);
        _closed.TrySetResult();
    }
}
