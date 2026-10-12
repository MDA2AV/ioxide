namespace ioxide.redis.stackexchange;

internal sealed partial class IoxideTransport
{
    private const int InitialOutbound = 16 * 1024;

    // The send side. The writer owns _stage; a send in flight owns _wire; bytes flushed while it is
    // in flight wait in _queued and go next. Only the swaps between them take the lock.
    private readonly Lock _gate = new();
    private Outbound _stage = new(), _wire = new(), _queued = new();
    private bool _sending;
    private int _sent;

    // StackExchange.Redis writes its next command here: room at the end of the stage buffer.
    public override Memory<byte> GetMemory(int sizeHint = 0) => _stage.Reserve(sizeHint).AsMemory(_stage.Length);

    // The same room as GetMemory, as a span.
    public override Span<byte> GetSpan(int sizeHint = 0) => _stage.Reserve(sizeHint).AsSpan(_stage.Length);

    // StackExchange.Redis wrote count bytes into that room; they join the stage.
    public override void Advance(int count) => _stage.Length += count;

    // Hands the staged bytes to the ring as one send, or queues them behind the send in flight.
    public override bool Flush()
    {
        if (Volatile.Read(ref _closing) != 0)
        {
            _stage.Length = 0;
            return false;
        }

        if (_stage.Length == 0)
        {
            return true;
        }

        lock (_gate)
        {
            if (_sending)
            {
                _queued.Append(_stage.Bytes.AsSpan(0, _stage.Length));   // goes when the send in flight is done
                _stage.Length = 0;
                return true;
            }

            // The staged bytes become the send, and the writer stages into the idle buffer.
            (_stage, _wire) = (_wire, _stage);
            _stage.Length = 0;
            _sent = 0;
            _sending = true;
        }

        if (!TryAddRef())
        {
            lock (_gate)
            {
                _sending = false;
            }
            return false;
        }

        _ = SendAsync();
        return true;
    }

    // Sends _wire until it is all out, then whatever queued meanwhile; stops when nothing is left.
    private async Task SendAsync()
    {
        try
        {
            while (true)
            {
                byte[] bytes;
                int head, tail;
                lock (_gate)
                {
                    (bytes, head, tail) = (_wire.Bytes, _sent, _wire.Length);
                }

                int sent = await _ringSocket.SendAsync(Address(bytes) + head, tail - head);
                if (sent <= 0)
                {
                    Close(sent < 0 ? new IOException($"send failed: errno {-sent}") : null);
                    break;
                }

                lock (_gate)
                {
                    _sent += sent;
                    if (_sent < _wire.Length)
                    {
                        continue;   // a partial send: the rest goes next
                    }

                    if (_queued.Length == 0)
                    {
                        _sending = false;
                        break;
                    }

                    (_wire, _queued) = (_queued, _wire);
                    _queued.Length = 0;
                    _sent = 0;
                }
            }
        }
        catch (Exception e)
        {
            Close(e);
        }

        Release();
    }

    /// <summary>A growable outbound buffer on the pinned object heap, so the ring can read it in place.</summary>
    private sealed class Outbound
    {
        public byte[] Bytes = GC.AllocateUninitializedArray<byte>(InitialOutbound, pinned: true);
        public int Length;

        // Room for at least sizeHint more bytes; grows by doubling, copying what is there.
        public byte[] Reserve(int sizeHint)
        {
            int needed = Length + Math.Max(sizeHint, 1);
            if (needed > Bytes.Length)
            {
                byte[] grown = GC.AllocateUninitializedArray<byte>(Math.Max(needed, Bytes.Length * 2), pinned: true);
                Bytes.AsSpan(0, Length).CopyTo(grown);
                Bytes = grown;
            }
            return Bytes;
        }

        // Copies bytes onto the end, growing first if needed.
        public void Append(ReadOnlySpan<byte> bytes)
        {
            bytes.CopyTo(Reserve(bytes.Length).AsSpan(Length));
            Length += bytes.Length;
        }
    }
}
