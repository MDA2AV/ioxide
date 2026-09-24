using System.Runtime.InteropServices;

namespace ioxide.ngtcp2;

/// <summary>Application send surface: per-stream retention chunks (ngtcp2 retains pointers
/// until acked), the pump that feeds them to the engine, and ack-driven reclamation.</summary>
public unsafe partial class QuicEngineConnection
{
    // --- application-facing send --------------------------------------------------------------

    // Outgoing stream bytes, copied into native chunks that stay alive until ngtcp2 ACKNOWLEDGES
    // them. iq_conn_write does not copy: ngtcp2 retains pointers into the caller's buffers for
    // retransmission until acked_stream_data_offset - handing it spans of reused managed buffers
    // is a use-after-free the first time a loss forces a retransmit. The chunk chain doubles as
    // the never-drop backlog: unsent tail bytes are replayed from FlushEgress as the window opens.
    private sealed class OutStream
    {
        public readonly Queue<(nint Ptr, int Len)> Chunks = new();
        public long Base;      // freed (acked) up to this stream offset - first retained byte
        public long Sent;      // handed to the engine up to this offset
        public long End;       // queued up to this offset
        public bool Fin;       // fin follows the last queued byte
        public bool FinSent;
        public bool Dead;      // reset/refused: stop feeding; chunks freed at stream close
        public bool Pending;   // in the replay list
    }

    private readonly Dictionary<long, OutStream> _outStreams = new();
    private readonly List<long> _outPending = [];
    private long _outRetained;

    // Send-retention high-water (retained = sent-but-unacked + unsent, across all streams). A
    // cooperative producer checks CanQueueSend and pauses here, so a response of any size streams
    // through in ~this much memory. Seeded from the engine; the client ctor keeps the default.
    private long _maxSendRetention = 16 << 20;

    // Hard backstop: a producer that ignores CanQueueSend and keeps pushing gets closed rather than
    // buffered without bound. Set well above the high-water so cooperative producers never hit it.
    private long OutRetainedCeiling => _maxSendRetention * 2;

    /// <summary>False once retained send data reaches the high-water: pause queueing more and let
    /// acks drain it (the egress pump re-runs on every inbound datagram).</summary>
    public override bool CanQueueSend => !_closed && _outRetained < _maxSendRetention;

    // Set when a producer filled retention to the high-water; FlushEgress fires the resume callback
    // and clears it once acks bring retention back down.
    private bool _sendAtCapacity;

    /// <summary>Queue bytes on a stream and flush. streamId must come from a delivered item or
    /// <see cref="OpenUniStream"/>. fin closes the send side. Never discards: bytes are retained
    /// until the peer acknowledges them (retransmission reads from this copy) and what the engine
    /// can't take now is replayed as the window opens.</summary>
    public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin)
    {
        if (_closed)
        {
            return;
        }

        if (fin)
        {
            SettleResponse(streamId);
            if (!_inEngineCycle)
            {
                ApplyKeepAlive();
            }
        }

        if (!_outStreams.TryGetValue(streamId, out OutStream? os))
        {
            os = new OutStream();
            _outStreams[streamId] = os;
        }
        if (os.Dead || (os.Fin && !fin && data.Length > 0))
        {
            return;   // refused or already finished - nowhere for more bytes to go
        }

        if (data.Length > 0)
        {
            void* chunk = NativeMemory.Alloc((nuint)data.Length);
            data.CopyTo(new Span<byte>(chunk, data.Length));
            os.Chunks.Enqueue(((nint)chunk, data.Length));
            os.End += data.Length;
            _outRetained += data.Length;
        }
        os.Fin |= fin;

        if (_outRetained >= _maxSendRetention)
        {
            _sendAtCapacity = true;   // arms the resume: FlushEgress fires it once acks drain below
        }

        if (_outRetained > OutRetainedCeiling)
        {
            Console.Error.WriteLine("[ioxide.ngtcp2] send retention backstop exceeded (producer ignored backpressure); closing connection.");

            // Through Teardown, so the peer is told. The abort is ours, not the peer's, so it
            // hears INTERNAL_ERROR rather than waiting out a timeout for silence.
            Teardown(WriteTransportFarewell(Ngtcp2.NGTCP2_ERR_INTERNAL));
            return;
        }

        PumpOut(streamId, os);
        if (_closed)
        {
            return;
        }
        FlushConnection();
        if (!OutDone(os) && !os.Pending)
        {
            os.Pending = true;
            _outPending.Add(streamId);
        }
    }

    /// <summary>Open a server-initiated unidirectional stream (H3 control / QPACK); id, or negative.</summary>
    public override long OpenUniStream()
    {
        if (_closed)
        {
            return -1;
        }
        return Ngtcp2.iq_conn_open_uni(_conn);
    }

    /// <summary>Stop auto-crediting this stream's receive window; the app credits via
    /// <see cref="ConsumeStreamData"/> as it consumes (the streaming-body backpressure seam).</summary>
    public override void SetStreamPaced(long streamId, bool paced)
    {
        if (!_closed)
        {
            Ngtcp2.iq_conn_set_stream_paced(_conn, streamId, paced ? 1 : 0);
        }
    }

    /// <summary>Open the peer's window (stream + connection) for consumed paced-stream bytes.</summary>
    public override void ConsumeStreamData(long streamId, long bytes)
    {
        if (!_closed && bytes > 0)
        {
            Ngtcp2.iq_conn_consume(_conn, streamId, (ulong)bytes);
        }
    }

    private static bool OutDone(OutStream os)
        => os.Dead || (os.Sent == os.End && (!os.Fin || os.FinSent));

    private void ReplayOut()
    {
        if (_outPending.Count == 0)
        {
            return;
        }
        int keep = 0;
        for (int i = 0; i < _outPending.Count; i++)
        {
            long sid = _outPending[i];
            if (_closed || !_outStreams.TryGetValue(sid, out OutStream? os))
            {
                continue;   // conn or stream torn down meanwhile
            }
            PumpOut(sid, os);
            if (!_closed && !OutDone(os))
            {
                _outPending[keep++] = sid;
            }
            else
            {
                os.Pending = false;
            }
        }

        // PumpOut can end the connection (a fatal engine error tears down), and Destroy clears
        // _outPending - so Count is 0 while keep still counts survivors, and RemoveRange would be
        // asked for a negative count. That throws, and on the timer path it used to escape into
        // the reactor loop and take the whole thread with it.
        if (_closed)
        {
            return;
        }

        _outPending.RemoveRange(keep, _outPending.Count - keep);
    }

    // Feed one stream's unsent bytes (pointers into the retained chunks - stable until acked) into
    // the engine, sending each produced datagram, until done or the engine can't take more.
    private void PumpOut(long sid, OutStream os)
    {
        while (!_closed && !OutDone(os))
        {
            // Locate the first unsent byte inside the chunk chain.
            byte* ptr = null;
            int len = 0;
            if (os.Sent < os.End)
            {
                long skip = os.Sent - os.Base;
                foreach ((nint p, int l) in os.Chunks)
                {
                    if (skip < l)
                    {
                        ptr = (byte*)p + skip;
                        len = (int)(l - skip);
                        break;
                    }
                    skip -= l;
                }
            }
            bool fin = os.Fin && os.Sent + len == os.End;

            long consumed;
            nint n;
            fixed (byte* dest = _sendBuf)
            {
                n = Ngtcp2.iq_conn_write(_conn, dest, (nuint)_sendBuf.Length,
                    sid, ptr, (nuint)len, fin ? 1 : 0, &consumed, NowNs());
            }

            int code = (int)n;
            if (code < 0)
            {
                if (code is Ngtcp2.NGTCP2_ERR_STREAM_SHUT_WR or Ngtcp2.NGTCP2_ERR_STREAM_NOT_FOUND)
                {
                    os.Dead = true;   // finished or reset - chunks are freed at stream close
                    return;
                }
                if (code == Ngtcp2.NGTCP2_ERR_STREAM_DATA_BLOCKED)
                {
                    return;           // stream-level flow control - retry on a later flush
                }
                CloseFromEngine(code);
                return;
            }

            if (consumed > 0)
            {
                os.Sent += consumed;
                if (fin && os.Sent == os.End)
                {
                    os.FinSent = true;
                }
            }
            else if (fin && len == 0 && n > 0)
            {
                os.FinSent = true;   // bare-fin frame went out
            }
            if (n > 0)
            {
                QueueSend(_sendBuf.AsSpan(0, (int)n));
            }
            if (n == 0 && consumed <= 0)
            {
                return;   // engine can't take more now (cwnd/pacing/amplification)
            }
        }
    }

    // The peer acknowledged [offset, offset+datalen): retained chunks below the new watermark can
    // never be retransmitted again and are freed.
    private void OnAckedStreamData(long sid, ulong offset, ulong datalen)
    {
        if (!_outStreams.TryGetValue(sid, out OutStream? os))
        {
            return;
        }
        long ackedTo = (long)(offset + datalen);
        while (os.Chunks.Count > 0)
        {
            (nint p, int l) = os.Chunks.Peek();
            if (os.Base + l > ackedTo)
            {
                break;
            }
            os.Chunks.Dequeue();
            NativeMemory.Free((void*)p);
            os.Base += l;
            _outRetained -= l;
        }
    }

    // Stream fully closed (or the connection is going down): nothing can be retransmitted anymore.
    private void PurgeOutStream(long sid)
    {
        if (!_outStreams.Remove(sid, out OutStream? os))
        {
            return;
        }
        while (os.Chunks.Count > 0)
        {
            (nint p, int l) = os.Chunks.Dequeue();
            NativeMemory.Free((void*)p);
            _outRetained -= l;
        }
    }
}
