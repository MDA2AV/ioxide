using System.Runtime.InteropServices;

namespace ioxide.nghttp3;

/// <summary>
/// P/Invoke surface of the bundled native library: the ioxide.nghttp3 shim (native/ioxide_nghttp3_shim.c)
/// over nghttp3, linked into one shared library (scripts/build-nghttp3-native.sh) with no external
/// dependencies. The shim owns every nghttp3 struct layout in C, so this surface stays small and
/// stable.
/// </summary>
internal static unsafe class Nghttp3
{
    // Resolves runtimes/linux-x64/native/libioxide_nghttp3.so from the package (or beside the app for
    // ProjectReference builds).
    internal const string Lib = "ioxide_nghttp3";

    // Mirrors ih3_callbacks in the shim: request events delivered on the reactor thread. Blittable
    // function pointers (UnmanagedCallersOnly statics) - no per-call marshalling.
    [StructLayout(LayoutKind.Sequential)]
    internal struct Callbacks
    {
        public delegate* unmanaged<void*, long, void>                          OnBeginHeaders;
        public delegate* unmanaged<void*, long, byte*, nuint, byte*, nuint, void> OnHeader;
        public delegate* unmanaged<void*, long, int, void>                     OnEndHeaders;
        public delegate* unmanaged<void*, long, byte*, nuint, void>            OnData;
        public delegate* unmanaged<void*, long, void>                          OnEndStream;
        public delegate* unmanaged<void*, long, nuint, void>                   OnDeferredConsume;

        /// <summary>
        /// Pull the next chunk of a STREAMED response body. The pointer handed back must stay
        /// valid until the stream closes - nghttp3 does not copy it - and fin marks the last
        /// chunk. Reporting nothing (len 0, fin 0) defers the stream until ih3_resume_stream.
        /// </summary>
        public delegate* unmanaged<void*, long, byte**, nuint*, int*, void>    OnReadBody;
    }

    /// <summary>Create the server-side nghttp3 connection; request events fire through
    /// <paramref name="callbacks"/> with <paramref name="user"/> passed back. 0 on failure.</summary>
    [DllImport(Lib)] internal static extern nint ih3_server_new(Callbacks callbacks, void* user, ulong qpackMaxDtableCapacity, ulong qpackBlockedStreams);

    /// <summary>Free the connection and every live stream's retained state (queued response
    /// bodies included). Null-tolerant.</summary>
    [DllImport(Lib)] internal static extern void ih3_free(nint connection);

    /// <summary>Register the three server-opened uni streams (control + QPACK encoder/decoder).
    /// nghttp3 queues its SETTINGS/QPACK prefaces on them; the next <see cref="ih3_writev"/>
    /// drain carries the bytes out. 0 or a negative nghttp3 error.</summary>
    [DllImport(Lib)] internal static extern int  ih3_bind_streams(nint connection, long ctrl, long qenc, long qdec);

    /// <summary>PushToEngine one recv item's bytes into nghttp3 - any stream, it demuxes uni stream types
    /// itself; fin marks the peer's half-close. Callbacks fire inline during the call. Returns
    /// bytes consumed; negative = fatal connection error.</summary>
    [DllImport(Lib)] internal static extern long ih3_read_stream(nint connection, long streamId, byte* data, nuint dataLen, int fin);

    /// <summary>Queue a complete response on a request stream. Headers ride a packed
    /// [u16 namelen][name][u16 valuelen][value] buffer; the body is copied by the shim and freed
    /// at stream close. 0 or a negative nghttp3 error.</summary>
    [DllImport(Lib)] internal static extern int  ih3_submit_response(nint connection, long streamId, byte* headers, nuint headersLen, byte* body, nuint bodyLen);

    /// <summary>Drain one egress chunk into <paramref name="buf"/>: returns the byte count
    /// (0 = fully drained) and sets the stream id + fin flag for those bytes. fin only survives
    /// when the chunk fit whole - a truncated chunk clears it and the next call carries the
    /// rest. Negative = fatal.</summary>
    [DllImport(Lib)] internal static extern long ih3_writev(nint connection, long* streamId, int* fin, byte* buf, nuint bufLen);

    /// <summary>Peer aborted its sending side (RESET_STREAM): stop expecting request bytes and
    /// release the stream's QPACK decode state. 0 or a negative nghttp3 error.</summary>
    [DllImport(Lib)] internal static extern int  ih3_shutdown_stream_read(nint connection, long streamId);

    /// <summary>Peer refused our response (STOP_SENDING): stop generating output for the stream.
    /// The queued body is NOT freed here - nghttp3 may still hold references into it -
    /// <see cref="ih3_close_stream"/> (which always follows) is the single free point.</summary>
    [DllImport(Lib)] internal static extern int  ih3_shutdown_stream_write(nint connection, long streamId);

    /// <summary>Retire a fully-closed stream and free its retained state (response body, header
    /// block). Unknown/already-closed ids (e.g. uni streams) are tolerated and return 0.</summary>
    [DllImport(Lib)] internal static extern int  ih3_close_stream(nint connection, long streamId, ulong appError);

    /// <summary>The h3 application error code a library error means. nghttp3 owns this mapping -
    /// which of its errors are H3_FRAME_ERROR, H3_MESSAGE_ERROR, QPACK_DECOMPRESSION_FAILED - so a
    /// connection that must tell its peer why it died asks rather than keeping a table.</summary>
    [DllImport(Lib)] internal static extern ulong ih3_app_error_code(int libError);

    // --- client side (ioxide.httpclient) ------------------------------------------------------

    /// <summary>
    /// Submit a response whose body arrives over time through <see cref="Callbacks.OnReadBody"/>.
    /// Nothing is copied here, unlike <c>ih3_submit_response</c>.
    /// </summary>
    [DllImport(Lib)] internal static extern int ih3_submit_response_stream(nint connection, long streamId, byte* headers, nuint headersLen);

    /// <summary>Undefer a stream that answered a body pull with "nothing yet".</summary>
    [DllImport(Lib)] internal static extern int ih3_resume_stream(nint connection, long streamId);

    /// <summary>Create the client-side nghttp3 connection; same event surface as the server one,
    /// requests out instead of responses. 0 on failure.</summary>
    [DllImport(Lib)] internal static extern nint ih3_client_new(Callbacks callbacks, void* user);

    /// <summary>Submit a request on a client-opened bidi stream: packed headers, optional body
    /// (copied by the shim, freed at stream close). 0 or a negative nghttp3 error.</summary>
    [DllImport(Lib)] internal static extern int  ih3_submit_request(
        nint connection, long streamId, byte* headers, nuint headersLength, byte* body, nuint bodyLength);

    /// <summary>Queue the GOAWAY pair on the control stream (carried out by the next
    /// <see cref="ih3_writev"/> drain) and start rejecting NEW request streams; in-flight
    /// streams complete normally. 0 or a negative nghttp3 error.</summary>
    [DllImport(Lib)] internal static extern int  ih3_shutdown(nint connection);

    /// <summary>Nonzero once a shutdown finished draining: every accepted stream completed.</summary>
    [DllImport(Lib)] internal static extern int  ih3_is_drained(nint connection);

    /// <summary>nghttp3's message for a negative error code - a static string, never freed.
    /// Use <see cref="StrError"/> for the marshalled form.</summary>
    [DllImport(Lib)] internal static extern nint ih3_strerror(int liberr);

    /// <summary>Version string of the bundled nghttp3 build. Use <see cref="Version"/> for the
    /// marshalled form.</summary>
    [DllImport(Lib)] internal static extern nint ih3_version();

    internal static string StrError(int liberr) => Marshal.PtrToStringUTF8(ih3_strerror(liberr)) ?? liberr.ToString();
    internal static string Version() => Marshal.PtrToStringUTF8(ih3_version()) ?? "unknown";
}
