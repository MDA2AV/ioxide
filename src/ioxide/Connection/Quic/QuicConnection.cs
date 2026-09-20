using System.Buffers;
using System.Threading.Tasks.Sources;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// A logical QUIC connection tracked by the transport's CID demux. The QUIC engine binding
/// (ngtcp2/quicly - the sans-I/O protocol state machine) subclasses this: datagrams routed by
/// DCID arrive via <see cref="OnDatagram"/>, replies leave via <see cref="Send"/>, and the timer
/// sweep drives loss/handshake deadlines. All members run on the owning reactor thread unless
/// noted - the read surface below is the exception, built for a handler on any thread.
///
/// The read surface mirrors TcpConnection's (arm flag + sticky _pending + IVTS, two-owner
/// refcount) but shares no code with it - the transports are deliberately independent. The engine
/// enqueues decrypted stream events with <see cref="EnqueueStreamData"/> (a pooled copy, since
/// ngtcp2's spans die when iq_conn_read returns) and fires <see cref="SignalDataArrived"/> ONCE
/// after iq_conn_read returns, so a resumed handler can never re-enter the engine mid-read.
/// </summary>
public abstract class QuicConnection : IValueTaskSource<QuicRecvSnapshot>
{
    public Reactor Reactor { get; internal set; } = null!;
    public int SocketFd { get; internal set; }

    // Peer sockaddr snapshot, transport-owned native memory (freed on eviction). Updated only via
    // UpdatePeerAddress - the engine decides when a migration is validated, not the transport.
    internal nint PeerAddr;
    internal int  PeerAddrLen;

    internal readonly List<QuicCid> Cids = [];
    internal long LastSeenMs;

    // TODO: 256? This should not be hardcoded
    protected QuicConnection(int recvQueueEntries = 256)
    {
        _recv = new QuicRecvRing(recvQueueEntries);
    }

    /// <summary>
    /// One wire datagram for this connection - the transport pre-splits GRO trains before demux
    /// (see Reactor.QuicDispatch), so one call is always exactly one datagram. The span is valid
    /// only during the call.
    /// </summary>
    public abstract void OnDatagram(ReadOnlySpan<byte> payload, byte tos);

    /// <summary>
    /// The same delivery, plus the address it actually came FROM. An engine that supports
    /// connection migration needs this: a peer that changed network sends on the same connection
    /// id from a new address, and the transport is the only layer that can see the difference.
    /// </summary>
    /// <remarks>
    /// Virtual rather than abstract, forwarding to the two-argument form, so a binding that does
    /// not care about paths - and every existing subclass - keeps working untouched. The address
    /// points into the recv slot and is valid only for the duration of the call; anything keeping
    /// it must copy.
    ///
    /// Being told an address is NOT permission to answer it freely. An engine that adopts a peer
    /// address on the strength of a datagram claiming it becomes an amplification reflector for
    /// whoever spoofed it, so an engine must bound what it sends on a path until that path has
    /// been validated - which is what QUIC's PATH_CHALLENGE and the 3x anti-amplification limit
    /// are for. Adoption and validation are not the same event and do not happen in that order.
    /// </remarks>
    public virtual void OnDatagram(ReadOnlySpan<byte> payload, byte tos, nint peerAddr, int peerAddrLen)
        => OnDatagram(payload, tos);

    /// <summary>Next engine deadline in <see cref="Environment.TickCount64"/> ms; long.MaxValue = none.</summary>
    public abstract long GetNextTimeout(long nowMs);

    /// <summary>Deadline passed - run loss/handshake/idle processing and flush whatever it produced.</summary>
    public abstract void OnTimer(long nowMs);

    /// <summary>The transport dropped this connection (it is already unregistered when this runs).</summary>
    public abstract void OnEvicted(QuicEvictReason reason);

    /// <summary>
    /// Queue application bytes on a stream and pump the engine (framing, encryption and pacing are
    /// its job - there is no flush to await, unlike TCP). streamId comes from a delivered item or a
    /// server-opened stream; fin closes the send side. Reactor thread only - the inline-resume
    /// handler already runs there.
    /// </summary>
    public abstract void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin);

    /// <summary>
    /// False when this connection's unacknowledged send data has reached its retention high-water:
    /// a producer feeding a large response should pause queueing more <see cref="SendStream"/> bytes
    /// and resume once acks drain it (the egress pump re-runs on every inbound datagram). This is
    /// backpressure, not a hard limit - overshooting is still accepted - but a producer that ignores
    /// it without bound eventually gets the connection closed. Base default is always true (no
    /// backpressure); a real engine connection reports its retention state.
    /// </summary>
    public virtual bool CanQueueSend => true;

    /// <summary>
    /// Invoked on the reactor thread when send retention drains back below the high-water after
    /// <see cref="CanQueueSend"/> had gone false - the signal for a paused producer (e.g. an h3
    /// response pump) to resume queueing. Fires from the ack/timer egress path, which the read loop
    /// does not see (a downloading peer sends only acks), so it is the only resume trigger for a
    /// response larger than the retention window.
    /// </summary>
    public Action? OnSendCapacityAvailable { get; set; }

    /// <summary>
    /// Open a server-initiated unidirectional stream (H3 control / QPACK); returns its id, or a
    /// negative value if the engine can't (peer allowance exhausted, or no engine). Reactor thread
    /// only.
    /// </summary>
    public virtual long OpenUniStream() => -1;

    /// <summary>The ALPN token the handshake negotiated (e.g. "h3"); null before completion.</summary>
    public string? NegotiatedProtocol { get; protected set; }

    /// <summary>
    /// Pace a stream's receive window: the engine stops auto-crediting flow control for its bytes,
    /// so the peer can send at most a window's worth beyond what <see cref="ConsumeStreamData"/>
    /// has credited - real backpressure for slow consumers. Reactor thread only.
    /// </summary>
    public virtual void SetStreamPaced(long streamId, bool paced) { }

    /// <summary>
    /// Open the peer's flow-control window (stream + connection) for consumed bytes of a paced
    /// stream. Extending is permission, never obligation - over-crediting is harmless. Reactor
    /// thread only.
    /// </summary>
    public virtual void ConsumeStreamData(long streamId, long bytes) { }

    /// <summary>
    /// Close the connection from the application side: a CONNECTION_CLOSE carrying
    /// <paramref name="applicationErrorCode"/> goes to the peer and the connection tears down
    /// (parked reads resume with a closed snapshot). The graceful path for h3 is
    /// Nghttp3Connection.Shutdown, which drains in-flight requests first and then calls this
    /// with H3_NO_ERROR. Reactor thread only. Idempotent.
    /// </summary>
    public virtual void Close(ulong applicationErrorCode) { }

    /// <summary>Send one datagram (or a GSO batch) to the connection's current peer address.</summary>
    protected void Send(ReadOnlySpan<byte> payload, int gsoSegmentSize = 0)
    {
        if (PeerAddr == 0)
        {
            return;   // torn down - a late handler resume must not send through freed memory
        }
        Reactor.UdpSendTo(SocketFd, PeerAddr, PeerAddrLen, payload, gsoSegmentSize);
    }

    /// <summary>fd-table index of the socket claiming this peer, or -1. See Reactor.Quic.Pin.cs.</summary>
    internal int PinSlot = -1;

    /// <summary>What the claim names, so a repeat of the same path does not rebuild it.</summary>
    internal readonly byte[] PinnedAddr = new byte[Reactor.UdpNameCap];
    internal int PinnedAddrLen;

    /// <summary>
    /// Set once the peer address has moved. Only a migrated connection is worth claiming: one still
    /// where it was accepted is already delivered here by the hash.
    /// </summary>
    internal bool PeerAddressMoved;

    /// <summary>Adopt a validated peer migration (copies the sockaddr out of the datagram).</summary>
    public unsafe void UpdatePeerAddress(nint addr, int addrLen)
    {
        // Same guard Send() carries, and for the same reason: QuicRemoveConnection frees this
        // block and zeroes the field, so a late call must not write through it. A null destination
        // here would be an access violation rather than an exception, which no catch upstream
        // could contain.
        if (PeerAddr == 0 || addr == 0 || addrLen <= 0 || addrLen > Reactor.UdpNameCap)
        {
            return;
        }

        Buffer.MemoryCopy((void*)addr, (void*)PeerAddr, Reactor.UdpNameCap, addrLen);
        PeerAddrLen = addrLen;
        PeerAddressMoved = true;

        // The address is NOT claimed here: ngtcp2 reports a path repeatedly while validating it,
        // so claiming per report churns sockets. The sweep does it once the address settles.
    }

    // --- read surface: engine enqueues on the reactor thread, the handler awaits from anywhere.
    //     Coordination is the arm flag + sticky _pending; QUIC connections are not pooled, so
    //     _generation only guards awaiters that outlive a teardown. ---

    private readonly QuicRecvRing _recv;

    private ManualResetValueTaskSourceCore<QuicRecvSnapshot> _readSignal = new()
    {
        RunContinuationsAsynchronously = false,
    };
    private int _armed;
    private int _pending;
    private int _closed;
    private int _generation;

    // Two owners: the reactor (engine side) and the handler. Init 2 on adopt; teardown runs only
    // at 0, so a connection is never freed under a live handler.
    private int _refs;

    // Guards the framework's fault-path release of the handler ref (mirror of TCP's #94 guard).
    private int _handlerRefReleased;

    internal int Generation => Volatile.Read(ref _generation);

    /// <summary>Invalidate awaiter tokens from a finished life; the eviction path runs this at teardown.</summary>
    internal void BumpGeneration() => Interlocked.Increment(ref _generation);

    public ValueTask<QuicRecvSnapshot> ReadAsync()
    {
        if (!_recv.IsEmpty() || Volatile.Read(ref _pending) == 1)
        {
            Volatile.Write(ref _pending, 0);
            return new ValueTask<QuicRecvSnapshot>(
                new QuicRecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0));
        }

        if (Volatile.Read(ref _closed) != 0)
        {
            return new ValueTask<QuicRecvSnapshot>(QuicRecvSnapshot.Closed());
        }

        if (Interlocked.Exchange(ref _armed, 1) == 1)
        {
            throw new InvalidOperationException("ReadAsync already armed.");
        }

        int gen = Volatile.Read(ref _generation);

        // Race recovery: re-check between arming and returning the task.
        if (!_recv.IsEmpty() || Volatile.Read(ref _pending) == 1 || Volatile.Read(ref _closed) != 0)
        {
            Volatile.Write(ref _pending, 0);
            Interlocked.Exchange(ref _armed, 0);

            return new ValueTask<QuicRecvSnapshot>(
                new QuicRecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0));
        }

        return new ValueTask<QuicRecvSnapshot>(this, (short)gen);
    }

    /// <summary>Drain the snapshot one event at a time; hand each buffer back with <see cref="ReturnBuffer"/>.</summary>
    public bool TryGetDelivery(in QuicRecvSnapshot snap, out QuicRecvRing.Delivery item)
        => _recv.TryDequeueUntil(snap.Tail, out item);

    /// <summary>Return a consumed item's pooled buffer.</summary>
    public void ReturnBuffer(in QuicRecvRing.Delivery item)
    {
        if (item.Buf is not null)
        {
            ArrayPool<byte>.Shared.Return(item.Buf);
        }
    }

    public void ResetRead() => _readSignal.Reset();

    /// <summary>
    /// Copy one decrypted stream event into the queue (engine-facing, reactor thread, called per
    /// OnStreamData inside iq_conn_read). Does NOT wake the handler - the engine fires
    /// <see cref="SignalDataArrived"/> once after iq_conn_read returns. Returns false on queue
    /// overflow; the engine then closes the connection.
    /// </summary>
    public bool EnqueueStreamData(long streamId, ReadOnlySpan<byte> data, bool fin)
    {
        byte[]? buf = null;
        if (data.Length > 0)
        {
            buf = ArrayPool<byte>.Shared.Rent(data.Length);
            data.CopyTo(buf);
        }

        if (!_recv.TryEnqueue(new QuicRecvRing.Delivery
                 {
                     StreamId = streamId,
                     Fin = fin,
                     Buf = buf,
                     Len = data.Length,
                 }))
        {
            if (buf is not null)
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
            return false;
        }

        return true;
    }

    /// <summary>
    /// Queue one stream lifecycle event (engine-facing, reactor thread): closed / reset /
    /// stop-sending, ordered with the data that preceded it. Same overflow contract as
    /// <see cref="EnqueueStreamData"/>.
    /// </summary>
    public bool EnqueueStreamEvent(long streamId, QuicStreamEvent kind, ulong appError)
        => _recv.TryEnqueue(new QuicRecvRing.Delivery
           {
               StreamId = streamId,
               Kind = kind,
               AppError = appError,
           });

    /// <summary>
    /// Wake the armed reader inline, or leave a sticky _pending for the next ReadAsync
    /// (engine-facing, reactor thread, once per iq_conn_read that enqueued anything).
    /// </summary>
    public void SignalDataArrived()
    {
        if (Interlocked.Exchange(ref _armed, 0) == 1)
        {
            _readSignal.SetResult(new QuicRecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0));
        }
        else
        {
            Volatile.Write(ref _pending, 1);
        }
    }

    /// <summary>Wake awaiters with closed=1. Engine close/drain or transport eviction paths only.</summary>
    public void MarkClosed()
    {
        Volatile.Write(ref _closed, 1);

        if (Interlocked.Exchange(ref _armed, 0) == 1)
        {
            _readSignal.SetResult(new QuicRecvSnapshot(_recv.SnapshotTail(), isClosed: true));
        }
        else
        {
            Volatile.Write(ref _pending, 1);
        }
    }

    internal void InitRefs() => Volatile.Write(ref _refs, 2);

    /// <summary>
    /// Release one owner's ref. Whoever hits 0 returns the leftover pooled buffers; the transport
    /// teardown off refcount zero is wired together with the handler launch.
    /// </summary>
    public void DecRef()
    {
        if (Interlocked.Decrement(ref _refs) == 0)
        {
            DrainRecv();
        }
    }

    /// <summary>
    /// Release the handler's ref on behalf of a handler that faulted before its own DecRef.
    /// Generation-guarded and idempotent, mirroring the TCP fault guard.
    /// </summary>
    internal void ReleaseHandlerRefOnFault(int generationAtStart)
    {
        if (Volatile.Read(ref _generation) == generationAtStart &&
            Interlocked.Exchange(ref _handlerRefReleased, 1) == 0)
        {
            DecRef();
        }
    }

    private void DrainRecv()
    {
        while (_recv.TryDequeue(out QuicRecvRing.Delivery item))
        {
            ReturnBuffer(in item);
        }
    }

    // --- IValueTaskSource<QuicRecvSnapshot>: token = generation snapshot; the core's own Version
    //     is passed through for the dispatch. ---

    QuicRecvSnapshot IValueTaskSource<QuicRecvSnapshot>.GetResult(short token)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            return QuicRecvSnapshot.Closed();
        }

        return _readSignal.GetResult(_readSignal.Version);
    }

    ValueTaskSourceStatus IValueTaskSource<QuicRecvSnapshot>.GetStatus(short token)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            return ValueTaskSourceStatus.Succeeded;
        }

        return _readSignal.GetStatus(_readSignal.Version);
    }

    void IValueTaskSource<QuicRecvSnapshot>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            // Stale - unblock now; GetResult returns Closed().
            continuation(state);

            return;
        }

        // Completes on the reactor thread only - strip the context-post so resumes stay inline
        // (see ReactorSynchronizationContext).
        _readSignal.OnCompleted(continuation, state, _readSignal.Version,
            flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }
}
