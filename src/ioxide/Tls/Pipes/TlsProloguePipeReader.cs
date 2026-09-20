using System.Buffers;
using System.IO.Pipelines;

namespace ioxide.tls;

/// <summary>
/// Bridges the one gap kTLS RX leaves: plaintext the <i>handshake</i> decrypted lives in the
/// session, not in ring memory, so a reader that only knows about ring memory would never yield it.
///
/// The client's first request routinely rides in with its Finished flight - for HTTP/2 that is the
/// connection preface, so it is the common case rather than an edge one. Miss it and the peer waits
/// forever on a response to a request the server dropped.
///
/// This serves that carry first, then <b>gets out of the way</b>: once the caller has consumed past
/// it, every later read delegates straight to <c>inner</c> with no copy and no
/// bookkeeping. It is a startup detour, not a pump.
/// </summary>
/// <remarks>Reactor thread only.</remarks>
public sealed class TlsProloguePipeReader : PipeReader
{
    /// <summary>
    /// How far the carry may grow before the connection is faulted. While the carry is live this
    /// class copies ring bytes into it and hands the ring buffers straight back, so recv never
    /// stalls - there is no backpressure on this path at all, unlike the OpenSSL column where the
    /// inbound Pipe's pause threshold applies. A peer that sends a partial head and then dribbles
    /// forever kept a caller examining without consuming, and the carry grew for the life of the
    /// connection. Generous next to the 64 KB the OpenSSL column pauses at, because a legitimate
    /// caller does examine a whole request head without consuming it - but bounded.
    /// </summary>
    private const int MaxCarryBytes = 1 << 20;

    private readonly PipeReader _inner;

    private byte[] _carry;
    private int _length;
    private int _consumed;
    private bool _needMore;         // the caller examined the whole carry without consuming it all
    private bool _cancelRequested;  // CancelPendingRead arrived while the carry was live
    private bool _awaitingInner;    // a carry-mode read is parked on the inner reader right now
    private bool _drained;      // the carry is gone; pure delegation from here
    private bool _completed;

    public TlsProloguePipeReader(PipeReader inner, ReadOnlySpan<byte> prologue)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));

        if (prologue.IsEmpty)
        {
            _carry = [];
            _drained = true;
            return;
        }

        _carry = ArrayPool<byte>.Shared.Rent(prologue.Length);
        prologue.CopyTo(_carry);
        _length = prologue.Length;
    }

    /// <summary>True once this is a pass-through and costs nothing.</summary>
    public bool Drained => _drained;

    public override async ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (_drained)
        {
            return await _inner.ReadAsync(cancellationToken);
        }

        // A cancel that arrived while the carry was live is served here, not latched into the
        // inner reader to pop out as a surprise after the carry drains.
        if (_cancelRequested)
        {
            _cancelRequested = false;
            return new ReadResult(Sequence(), isCanceled: true, isCompleted: false);
        }

        // Unconsumed carry first - unless the caller already examined it all without consuming,
        // which per the PipeReader contract means it needs MORE bytes to make progress. Handing the
        // identical buffer back would spin that caller hot forever.
        if (_consumed < _length && !_needMore)
        {
            return new ReadResult(Sequence(), isCanceled: false, isCompleted: false);
        }

        ReadResult next;
        _awaitingInner = true;
        try
        {
            next = await _inner.ReadAsync(cancellationToken);
        }
        finally
        {
            _awaitingInner = false;
        }

        _needMore = false;
        Append(next.Buffer);
        _inner.AdvanceTo(next.Buffer.End);

        return new ReadResult(Sequence(), next.IsCanceled, next.IsCompleted);
    }

    public override bool TryRead(out ReadResult result)
    {
        if (_drained)
        {
            return _inner.TryRead(out result);
        }

        if (_cancelRequested)
        {
            _cancelRequested = false;
            result = new ReadResult(Sequence(), isCanceled: true, isCompleted: false);
            return true;
        }

        if (_consumed < _length && !_needMore)
        {
            result = new ReadResult(Sequence(), isCanceled: false, isCompleted: false);
            return true;
        }

        // The caller needs more than the carry; see whether the inner reader has it right now.
        if (_inner.TryRead(out ReadResult next))
        {
            _needMore = false;
            Append(next.Buffer);
            _inner.AdvanceTo(next.Buffer.End);
            result = new ReadResult(Sequence(), next.IsCanceled, next.IsCompleted);
            return true;
        }

        result = default;
        return false;
    }

    public override void AdvanceTo(SequencePosition consumed) => AdvanceTo(consumed, consumed);

    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
    {
        if (_drained)
        {
            _inner.AdvanceTo(consumed, examined);
            return;
        }

        // Single segment while the carry is live, and its positions carry the ABSOLUTE offset into
        // the backing array - a sequence built over carry[9..] reports Start.GetInteger() == 9, not
        // 0 - so this is an assignment. Adding it would double-count every partial consume after
        // the first and silently skip the bytes in between.
        _consumed = consumed.GetInteger();

        // Examined to the end without consuming everything = "wake me when there is MORE". The
        // next read must pull from the connection and append, not replay the same bytes.
        _needMore = _consumed < _length && examined.GetInteger() >= _length;

        if (_consumed < _length)
        {
            return;
        }

        // Fully consumed. Release the carry and become a pass-through; anything that arrives from
        // here on is ring memory the inner reader hands out directly.
        Release();
    }

    public override void CancelPendingRead()
    {
        // While the carry is live the next read is served here, synchronously - a cancel latched
        // into the inner reader would not be observed until the carry drains, then surface as a
        // wake-up nobody asked for. Only a read actually parked on the inner reader (or pure
        // pass-through) forwards.
        if (_drained || _awaitingInner)
        {
            _inner.CancelPendingRead();
            return;
        }

        _cancelRequested = true;
    }

    public override void Complete(Exception? exception = null)
    {
        if (_completed)
        {
            return;
        }
        _completed = true;

        Release();
        _inner.Complete(exception);
    }

    private ReadOnlySequence<byte> Sequence() => new(_carry.AsMemory(_consumed, _length - _consumed));

    private void Append(in ReadOnlySequence<byte> more)
    {
        int extra = (int)more.Length;
        if (extra == 0)
        {
            return;
        }

        // Compact first: the consumed prefix is dead weight and this only happens while the
        // prologue is still being worked through.
        if (_consumed > 0)
        {
            _carry.AsSpan(_consumed, _length - _consumed).CopyTo(_carry);
            _length -= _consumed;
            _consumed = 0;
        }

        if (_length + extra > MaxCarryBytes)
        {
            // Faulting rather than silently growing. The OpenSSL column would simply stop reading
            // here, but the ring buffers behind these bytes have already been handed back, so there
            // is nothing left to apply backpressure with - the only honest answers are to bound it
            // or to keep buffering, and this transport does not get to keep buffering.
            throw new IOException(
                $"the handshake carry reached {MaxCarryBytes} bytes without the reader consuming any of it; "
                + "refusing to buffer more");
        }

        if (_carry.Length - _length < extra)
        {
            byte[] grown = ArrayPool<byte>.Shared.Rent(Math.Max(_carry.Length * 2, _length + extra));
            _carry.AsSpan(0, _length).CopyTo(grown);
            ArrayPool<byte>.Shared.Return(_carry);
            _carry = grown;
        }

        more.CopyTo(_carry.AsSpan(_length));
        _length += extra;
    }

    private void Release()
    {
        // A cancel that arrived while the carry was live has not been served yet, and from here on
        // reads go straight to the inner reader - so it has to travel with us. Dropping it left the
        // caller waiting on a read it had already asked to cancel.
        if (_cancelRequested)
        {
            _cancelRequested = false;
            _inner.CancelPendingRead();
        }

        if (_carry.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_carry);
        }
        _carry = [];
        _length = 0;
        _consumed = 0;
        _drained = true;
    }
}
