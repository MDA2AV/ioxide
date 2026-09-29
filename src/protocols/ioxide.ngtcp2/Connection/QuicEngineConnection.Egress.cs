namespace ioxide.ngtcp2;

/// <summary>Egress pump and GSO batching: replay deferred stream bytes, drain the engine's
/// own frames, and coalesce produced datagrams into one UDP_SEGMENT send per cycle.</summary>
public unsafe partial class QuicEngineConnection
{
    // --- GSO send batching ----------------------------------------------------------------------
    // One sendmsg per engine cycle instead of one per datagram: ngtcp2 emits runs of equal-size
    // (MTU-full) datagrams under load, which is exactly the UDP_SEGMENT shape. A shorter datagram
    // may only END a batch (GSO semantics: equal segments, the last may be short). All datagrams
    // in a batch are this connection's, and the batch is flushed whenever the peer address moves
    // (FlushBatchBeforePathChange), so the destination is single for the life of a batch. That
    // qualifier matters since migration landed: a connection can have more than one live path
    // while one is being validated, and ngtcp2 addresses a PATH_RESPONSE to the path its
    // challenge arrived on rather than to the current one.

    private readonly byte[] _gsoBuf = new byte[63 * 1024];   // < 65507, the UDP payload ceiling
    private int  _gsoLen;
    private int  _gsoSeg;      // segment size = first datagram's length; 0 = batch empty
    private bool _gsoClosed;   // a short (final) segment landed - flush before accepting more
    private bool _inEngineCycle;

    /// <summary>
    /// Run <paramref name="send"/> inside an engine cycle, so every datagram it produces is
    /// coalesced into one UDP_SEGMENT sendmsg instead of a syscall per datagram. Server
    /// connections get this implicitly - their sends happen while an inbound datagram is being
    /// processed - but a CLIENT sends from its own loop, outside any cycle, and would otherwise
    /// pay one syscall per request. Reactor thread only; nesting is safe (the outer cycle wins).
    /// </summary>
    public void SendBatched(Action send)
    {
        if (_inEngineCycle)
        {
            send();   // already batching (nested call from inside a cycle)
            return;
        }

        _inEngineCycle = true;
        try
        {
            send();
        }
        finally
        {
            EndEngineCycle();
        }
    }

    /// <summary>
    /// Leaves an engine cycle. ngtcp2's frames have unwound by the time this runs, which is what
    /// makes both halves legal: flushing the coalesced GSO batch, and acting on a fault that was
    /// recorded from inside a callback. Every entry into the engine ends here, so a callback has
    /// exactly one way to ask for teardown and exactly one place where it happens.
    /// </summary>
    private void EndEngineCycle()
    {
        _inEngineCycle = false;
        FlushGso();
        ApplyKeepAlive();

        if (_deferredFault is null || _closed)
        {
            return;
        }

        Console.Error.WriteLine($"[ioxide.ngtcp2] {_deferredFault}; closing connection.");

        // Our own fault, not the peer's, so it hears INTERNAL_ERROR rather than nothing at all.
        Teardown(WriteTransportFarewell(Ngtcp2.NGTCP2_ERR_INTERNAL));
    }

    private void QueueSend(ReadOnlySpan<byte> datagram)
    {
        if (!_inEngineCycle)
        {
            Send(datagram);   // outside a cycle (mailbox-resumed handler): direct, unbatched
            return;
        }

        int len = datagram.Length;
        if (_gsoSeg != 0 && (len > _gsoSeg || _gsoClosed || _gsoLen + len > _gsoBuf.Length))
        {
            FlushGso();
        }
        if (_gsoSeg == 0)
        {
            _gsoSeg = len;
        }
        datagram.CopyTo(_gsoBuf.AsSpan(_gsoLen));
        _gsoLen += len;
        if (len < _gsoSeg)
        {
            _gsoClosed = true;
        }
    }

    /// <summary>
    /// Send what is queued before the peer address moves. The batch is addressed at send time, not
    /// at queue time, so a path change with datagrams still coalesced would readdress them.
    /// </summary>
    internal void FlushBatchBeforePathChange() => FlushGso();

    private void FlushGso()
    {
        if (_gsoLen == 0)
        {
            return;
        }
        Send(_gsoBuf.AsSpan(0, _gsoLen), _gsoLen > _gsoSeg ? _gsoSeg : 0);
        _gsoLen = 0;
        _gsoSeg = 0;
        _gsoClosed = false;
    }

    // --- engine egress pump -------------------------------------------------------------------

    // Replay deferred stream bytes now that the window may have opened, then drain the engine's
    // own frames. Runs after every inbound datagram (ACKs open the window) and every timer.
    private void FlushEgress()
    {
        ReplayOut();
        FlushConnection();

        // Acks (processed just before this on the inbound path) freed retention: if a producer
        // paused at the high-water, tell it to resume queueing. The read loop never sees these acks,
        // so this is the resume trigger for a response larger than the retention window.
        if (_sendAtCapacity && !_closed && _outRetained < _maxSendRetention)
        {
            _sendAtCapacity = false;
            OnSendCapacityAvailable?.Invoke();
        }
    }

    // Drain ngtcp2's own frames (ACKs, handshake, CRYPTO, MAX_STREAMS) until it has nothing more.
    private void FlushConnection()
    {
        while (!_closed)
        {
            long consumed;
            nint n;
            fixed (byte* dest = _sendBuf)
            {
                n = Ngtcp2.iq_conn_write(_conn, dest, (nuint)_sendBuf.Length, -1, null, 0, 0, &consumed, NowNs());
            }
            if ((int)n < 0)
            {
                CloseFromEngine((int)n);
                return;
            }
            if (n == 0)
            {
                return;
            }
            QueueSend(_sendBuf.AsSpan(0, (int)n));
        }
    }
}
