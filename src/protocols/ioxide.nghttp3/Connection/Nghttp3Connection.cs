using System.Runtime.InteropServices;
using ioxide;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide.nghttp3;

/// <summary>
/// HTTP/3 over any <see cref="QuicConnection"/>: feeds the connection's stream items into nghttp3
/// and drains its egress back through SendStream. Use from a <c>Reactor.QuicHandle</c>:
///
/// <code>
/// reactor.QuicHandle = (r, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
///     static request => Nghttp3Response.Text("hello"));
/// </code>
///
/// One instance per connection, two dispatch flavors: the sync overload assembles each request in
/// full (headers + body) and dispatches at end-of-stream; the async overload dispatches at
/// end-of-headers and streams the body through <see cref="Nghttp3Request.BodyReader"/> under
/// flow-control pacing. Everything runs on the reactor thread; request objects (arena, header
/// lists, body buffer) are pooled per connection and recycled when the handler's
/// valid-until-return contract ends.
///
/// File layout: this file owns state, the run loop and pooling; PushToEngine (ingress into nghttp3),
/// Dispatch (handler invocation), Egress (queue/pump/pack) and Callbacks (the unmanaged shim
/// entry points) live in the sibling partials.
/// </summary>
public sealed partial class Nghttp3Connection : IDisposable
{
    private readonly QuicConnection _quicConnection;
    // The native ih3_conn* from the shim (wraps the nghttp3_conn plus per-stream body state).
    // 0 = not stood up yet (setup is lazy, first post-handshake wake) or already disposed - the
    // guard Submit/Drain check before touching native memory.
    private nint _nghttp3Handle;
    private GCHandle _self;
    private bool _protocolFailed;

    // The first exception a native callback raised, kept for the log line. Teardown cannot happen
    // inside a callback (nghttp3 is on the stack below it), so the callbacks record here and
    // _protocolFailed carries the decision out to the run loops - see Callbacks.Fault.
    private Exception? _callbackFault;
    private bool _streaming;
    private bool _draining;

    // RFC 9114 H3_NO_ERROR - the application error code a graceful close carries.
    private const ulong H3NoError = 0x100;

    // RFC 9114 H3_INTERNAL_ERROR: what a failure that cannot name itself closes with.
    private const ulong H3InternalError = 0x102;

    // What the peer must be told, or null when there is nothing to tell it. Deliberately NOT
    // _protocolFailed: that flag also means "stop looping", and one site sets it on a perfectly
    // clean streamed response purely to unpark waiters - closing on it would send an error code to
    // every client that received a streamed body successfully.
    //
    // A connection that dies without a code leaves the client waiting on a request that will never
    // be answered, and no idle bound rescues it: the shim sets no max_idle_timeout, and the
    // transport's 60 s sweep is refreshed by ANY inbound datagram, including ones ngtcp2 discards.
    private ulong? _peerCode;

    /// <summary>
    /// A failure nghttp3 reported, and the h3 code it means. The mapping is nghttp3's own
    /// (<c>nghttp3_err_infer_quic_app_error_code</c>) rather than a table kept here: it owns which
    /// of its errors are H3_FRAME_ERROR, H3_MESSAGE_ERROR or QPACK_DECOMPRESSION_FAILED, and
    /// anything it does not recognise becomes H3_INTERNAL_ERROR.
    /// </summary>
    private void FailProtocol(int libError)
    {
        // First failure wins - later ones are usually consequences of it, and the peer can only be
        // told once.
        _peerCode ??= Nghttp3.ih3_app_error_code(libError);
        _protocolFailed = true;
    }

    /// <summary>
    /// A failure of ours rather than of the protocol - a control stream that would not open, a
    /// callback that threw. H3_INTERNAL_ERROR is the honest code for it.
    /// </summary>
    private void FailInternal()
    {
        _peerCode ??= H3InternalError;
        _protocolFailed = true;
    }

    /// <summary>
    /// Tell the peer why, if there is a why. Called from every run loop's finally, where the
    /// connection is being let go: without it the transport keeps the connection registered and
    /// routable, and the client's request never completes.
    /// </summary>
    private void CloseWithPeerCode()
    {
        if (_peerCode is ulong code)
        {
            _quicConnection.Close(code);
        }
    }

    private readonly Dictionary<long, Nghttp3Request> _requests = new();
    private readonly List<long> _readyStreamIds = [];
    private readonly byte[] _egress = new byte[16 * 1024];

    // Streaming mode: per-request body sinks (paced streams) and their deferred wakes.
    private readonly Dictionary<long, Nghttp3BodyReader> _sinks = new();
    private readonly List<Nghttp3BodyReader> _bodyWakes = [];

    // Retired Nghttp3Request instances, reused verbatim (arena array, list capacities). A bound, not
    // an obligation: overflow falls to the GC.
    private readonly Stack<Nghttp3Request> _requestPool = new();
    private const int RequestPoolMax = 64;

    private readonly Nghttp3Options _options;

    public Nghttp3Connection(QuicConnection quicConnection, Nghttp3Options? options = null)
    {
        _quicConnection = quicConnection;
        _options = options ?? Nghttp3Options.Default;

        // A response larger than the QUIC send-retention window is drained in PumpEgress under
        // backpressure (it stops at the high-water); this resumes it as acks free retention, since
        // the run loop only wakes on inbound request data - not on the acks of a download.
        _quicConnection.OnSendCapacityAvailable = () => PumpEgress();
    }

    /// <summary>
    /// Begin graceful shutdown: a GOAWAY rides out on the control stream, NEW request streams are
    /// rejected, in-flight requests complete normally, and once nghttp3 reports the connection
    /// drained the run loop closes the QUIC connection with H3_NO_ERROR. Reactor thread only -
    /// callable from inside a handler. Idempotent. The hard deadline is the host's job: keep the
    /// QuicConnection and call its Close() directly if the drain outlasts your grace period.
    /// </summary>
    public void Shutdown()
    {
        if (_draining || _protocolFailed || _nghttp3Handle == 0)
        {
            return;
        }
        _draining = true;

        int shutdownResult = Nghttp3.ih3_shutdown(_nghttp3Handle);
        if (shutdownResult != 0)
        {
            Console.Error.WriteLine($"[ioxide.nghttp3] shutdown failed: {Nghttp3.StrError(shutdownResult)}");
            FailProtocol(shutdownResult);
            return;
        }
        PumpEgress();   // the GOAWAY leaves now, ahead of any in-flight responses
    }

    // Run from each loop pass after Drain: once every accepted stream has completed, say goodbye
    // at the transport level. Close -> MarkClosed wakes the next ReadAsync with a closed snapshot,
    // which exits the loop.
    private void CloseIfShutdownComplete()
    {
        if (_draining && !_protocolFailed && _nghttp3Handle != 0 && Nghttp3.ih3_is_drained(_nghttp3Handle) != 0)
        {
            _quicConnection.Close(H3NoError);
        }
    }

    // request pooling

    private Nghttp3Request RentRequest(long streamId)
    {
        if (_requestPool.TryPop(out Nghttp3Request? request))
        {
            request.Pooled = false;
            request.StreamId = streamId;

            return request;
        }
        return new Nghttp3Request { StreamId = streamId };
    }

    // Legal exactly when the valid-until-return contract has ended (sync: handler returned;
    // streaming: handler task completed AND the stream is out of the dictionaries). Idempotent.
    private void ReleaseRequest(Nghttp3Request request)
    {
        if (request.Pooled)
        {
            return;
        }
        request.Reset(0);   // returns the pooled body buffer, clears ranges/lists, keeps the arena
        request.Pooled = true;
        if (_requestPool.Count < RequestPoolMax)
        {
            _requestPool.Push(request);
        }
    }

    // engine setup / teardown

    // Open the server's uni streams (control + QPACK enc/dec) and stand up nghttp3. Runs on the
    // first post-handshake wake; the SETTINGS preface rides out on this wake's Drain.
    private unsafe bool TrySetup()
    {
        long controlStreamId = _quicConnection.OpenUniStream();
        long qpackEncoderStreamId = _quicConnection.OpenUniStream();
        long qpackDecoderStreamId = _quicConnection.OpenUniStream();
        if (controlStreamId < 0 || qpackEncoderStreamId < 0 || qpackDecoderStreamId < 0)
        {
            Console.Error.WriteLine("[ioxide.nghttp3] failed to open control/QPACK uni streams");
            return false;
        }

        _self = GCHandle.Alloc(this);
        var callbacks = new Nghttp3.Callbacks
        {
            OnBeginHeaders    = &CallbackBeginHeaders,
            OnHeader          = &CallbackHeader,
            OnEndHeaders      = &CallbackEndHeaders,
            OnData            = &CallbackData,
            OnEndStream       = &CallbackEndStream,
            OnDeferredConsume = &CallbackDeferredConsume,
            OnReadBody = &CallbackReadBody,
        };

        _nghttp3Handle = Nghttp3.ih3_server_new(callbacks, (void*)GCHandle.ToIntPtr(_self),
            (ulong)_options.QpackDynamicTableCapacity, (ulong)_options.QpackBlockedStreams);
        if (_nghttp3Handle == 0)
        {
            Console.Error.WriteLine("[ioxide.nghttp3] engine init failed");
            return false;
        }

        int bindResult = Nghttp3.ih3_bind_streams(_nghttp3Handle, controlStreamId, qpackEncoderStreamId, qpackDecoderStreamId);
        if (bindResult != 0)
        {
            Console.Error.WriteLine($"[ioxide.nghttp3] bind streams failed: {Nghttp3.StrError(bindResult)}");
            return false;
        }
        return true;
    }

    public void Dispose()
    {
        if (_nghttp3Handle != 0)
        {
            Nghttp3.ih3_free(_nghttp3Handle);
            _nghttp3Handle = 0;
        }
        if (_self.IsAllocated)
        {
            _self.Free();
        }
    }
}
