using System.Runtime.InteropServices;
using ioxide;

namespace ioxide.ngtcp2;

/// <summary>Unmanaged callbacks from the shim (reactor thread, inside iq_conn_read /
/// handle_expiry / iq_accept).</summary>
/// <remarks>
/// Every one of these is an ABI boundary, and an exception that reaches it does not fault the
/// connection - it aborts the PROCESS, uncatchably, because there are native frames between here
/// and any managed caller. Two of them dispatch to <c>protected virtual</c> methods, which is to
/// say user code, and the rest allocate. So each body is guarded and each failure goes to one
/// place: the connection is marked faulted and torn down at the next opportunity, which is the
/// only thing that can be done here because the shim's callback ABI returns void and there is no
/// way to tell ngtcp2 that this went wrong.
/// </remarks>
public unsafe partial class QuicEngineConnection
{
    private static QuicEngineConnection? From(void* user)
    {
        try
        {
            return (QuicEngineConnection)GCHandle.FromIntPtr((nint)user).Target!;
        }
        catch (Exception)
        {
            // A handle that is gone or was never ours. Nothing to fault, nothing to report to.
            return null;
        }
    }

    /// <summary>
    /// Records a callback failure. Deliberately does neither of the two things that look right
    /// here: it does not rethrow, because the caller is native, and it does not tear the
    /// connection down, because ngtcp2 is still on the stack below us and freeing the conn from
    /// inside its own callback is a use-after-free. EndEngineCycle does that once we are out.
    /// </summary>
    private void OnCallbackFault(Exception e, string where)
    {
        // The exception in full here; the deferred reason is only a line in the teardown log.
        Console.Error.WriteLine($"[ioxide.ngtcp2] {where} threw, connection will be closed: {e}");
        _deferredFault ??= $"{where} threw {e.GetType().Name}";
    }

    [UnmanagedCallersOnly]
    internal static void CbStreamData(void* user, long streamId, byte* data, nuint len, int fin)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try { c.OnStreamData(streamId, new ReadOnlySpan<byte>(data, (int)len), fin != 0); }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbStreamData)); }
    }

    [UnmanagedCallersOnly]
    internal static void CbStreamClose(void* user, long streamId, ulong appError)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try
        {
            c.SettleResponse(streamId);
            c.PurgeOutStream(streamId);
            c.EnqueueLifecycle(streamId, QuicStreamEvent.Closed, appError);
            c.OnStreamClosed(streamId, appError);
        }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbStreamClose)); }
    }

    [UnmanagedCallersOnly]
    internal static void CbAckedStreamData(void* user, long streamId, ulong offset, ulong datalen)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try { c.OnAckedStreamData(streamId, offset, datalen); }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbAckedStreamData)); }
    }

    [UnmanagedCallersOnly]
    internal static void CbStreamReset(void* user, long streamId, ulong appError)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try
        {
            c.SettleResponse(streamId);
            c.EnqueueLifecycle(streamId, QuicStreamEvent.Reset, appError);
        }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbStreamReset)); }
    }

    [UnmanagedCallersOnly]
    internal static void CbStreamStopSending(void* user, long streamId, ulong appError)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try
        {
            c.SettleResponse(streamId);
            c.MarkOutStreamDead(streamId);
            c.EnqueueLifecycle(streamId, QuicStreamEvent.StopSending, appError);
        }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbStreamStopSending)); }
    }

    [UnmanagedCallersOnly]
    internal static void CbHandshakeCompleted(void* user)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try
        {
            // Established flips in OnDatagram too; this fires it precisely at the engine's signal.
            if (!c._handshakeDone)
            {
                c.HandshakeCompletedOnce();
            }
        }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbHandshakeCompleted)); }
    }

    /// <summary>
    /// ngtcp2 moved this connection to a new peer address, and the transport must follow - it owns
    /// the socket, which is the half ngtcp2 cannot do for itself.
    /// </summary>
    [UnmanagedCallersOnly]
    internal static void CbPathChange(void* user, void* remoteAddr, nuint len)
    {
        QuicEngineConnection? c = From(user);
        if (c is null)
        {
            return;
        }

        try
        {
            // Flush FIRST. Anything already coalesced in the GSO batch was built for the address
            // in force when it was queued, and this call is what changes that address - sending
            // the batch afterwards would deliver those datagrams to a different peer address than
            // ngtcp2 addressed them to. Egress.cs states the batch is single-destination "by
            // construction"; that holds only because this flush keeps it true.
            c.FlushBatchBeforePathChange();
            c.UpdatePeerAddress((nint)remoteAddr, (int)len);
        }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbPathChange)); }
    }

    [UnmanagedCallersOnly]
    internal static void CbNewCid(void* user, byte* cid, nuint len)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try { c._reactor.QuicRegisterCid(c, new QuicCid(new ReadOnlySpan<byte>(cid, (int)len))); }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbNewCid)); }
    }

    [UnmanagedCallersOnly]
    internal static void CbRetireCid(void* user, byte* cid, nuint len)
    {
        QuicEngineConnection? c = From(user);
        if (c is null) return;

        try { c._reactor.QuicUnregisterCid(new QuicCid(new ReadOnlySpan<byte>(cid, (int)len))); }
        catch (Exception e) { c.OnCallbackFault(e, nameof(CbRetireCid)); }
    }
}
