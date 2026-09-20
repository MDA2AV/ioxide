using System.Runtime.InteropServices;

namespace ioxide.ngtcp2;

/// <summary>
/// P/Invoke surface of the bundled native engine: the ioxide.ngtcp2 shim (native/ioxide_ngtcp2_shim.c)
/// over ngtcp2 + its picotls crypto backend, linked into one shared library
/// (scripts/build-ngtcp2-native.sh) whose only external dependency is libcrypto.so.3. The shim owns
/// every ngtcp2/picotls struct layout in C, so this surface stays small and stable.
/// </summary>
internal static unsafe class Ngtcp2
{
    // Resolves runtimes/linux-x64/native/libioxide_ngtcp2.so from the package (or beside the app for
    // ProjectReference builds).
    internal const string Lib = "ioxide_ngtcp2";

    // Mirrors iq_callbacks in the shim: engine events delivered on the reactor thread. Blittable
    // function pointers (UnmanagedCallersOnly statics) - no per-call marshalling.
    [StructLayout(LayoutKind.Sequential)]
    internal struct Callbacks
    {
        /// <summary>sizeof(iq_callbacks) as THIS side compiled it. The shim refuses a table it
        /// does not recognise, because the struct is passed by value and mirrored by hand - a
        /// member added on one side only is otherwise a silent read past the caller's buffer.</summary>
        public nuint StructSize;

        public delegate* unmanaged<void*, long, byte*, nuint, int, void> OnStreamData;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamClose;
        public delegate* unmanaged<void*, void>                         OnHandshakeCompleted;
        public delegate* unmanaged<void*, byte*, nuint, void>           OnNewCid;
        public delegate* unmanaged<void*, byte*, nuint, void>           OnRetireCid;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamReset;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamStopSending;
        public delegate* unmanaged<void*, long, ulong, ulong, void>     OnAckedStreamData;

        /// <summary>ngtcp2 moved this connection to a new peer address. NOT a statement that the
        /// address was validated first - adoption happens on the first non-probing 1-RTT packet
        /// from it, and validation follows. The protection is ngtcp2's 3x anti-amplification limit
        /// on an unvalidated path, plus the packet having decrypted under 1-RTT keys.</summary>
        public delegate* unmanaged<void*, void*, nuint, void>           OnPathChange;
    }


    [DllImport(Lib)] internal static extern void iq_engine_set_handshake_timeout(nint engine, ulong ns);

    /// <summary>
    /// Engine with client-certificate verification. Client certificates are validated against
    /// <paramref name="clientCaPemPath"/>, a bundle on disk, or <paramref name="clientCaPem"/>, the
    /// same bundle as PEM text - pass at most one. Both null leaves mTLS off and the handshake
    /// unchanged. <paramref name="requireClientCert"/> decides whether a client offering none is
    /// refused outright or merely arrives unauthenticated.
    /// </summary>
    [DllImport(Lib)] internal static extern nint iq_engine_new_mtls(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string certPemPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyPemPath,
        nuint cidLen, byte* alpn, nuint alpnLen,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? clientCaPemPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? clientCaPem,
        int requireClientCert,
        Callbacks cbs);

    /// <summary>The verified client identity, or 0 written when the peer offered none.</summary>
    [DllImport(Lib)] internal static extern nuint iq_conn_peer_subject(nint conn, byte* outBuf, nuint outLen);
    [DllImport(Lib)] internal static extern nuint iq_conn_peer_cn(nint conn, byte* outBuf, nuint outLen);

    /// <summary>
    /// Registers a certificate for one SNI name, served instead of the default when a client asks
    /// for that host. Returns 0, or -1 with the reason on stderr. Call before accepting: the table
    /// is read from the handshake without a lock.
    /// </summary>
    [DllImport(Lib)] internal static extern int iq_engine_add_host(nint engine,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string host,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string certPemPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyPemPath);

    /// <summary>
    /// Replaces every certificate the engine serves, on a running server: the default, then one per
    /// entry of the three parallel arrays. Returns 0, or -1 with the reason on stderr. Nothing is
    /// published unless all of it built, so a failure leaves the engine serving what it had.
    /// </summary>
    /// <remarks>
    /// The three host arrays are passed as raw pointers rather than <c>string[]</c>: the runtime
    /// marshaller cannot pair an array with UTF-8 elements, and everything else in this shim takes
    /// UTF-8. The caller owns the strings for the length of the call and nothing outlives it - the
    /// shim copies what it keeps.
    /// </remarks>
    [DllImport(Lib)] internal static extern int iq_engine_replace_certificates(nint engine,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string certPemPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyPemPath,
        nint* hosts, nint* hostCerts, nint* hostKeys, nuint hostCount);

    [DllImport(Lib)] internal static extern void iq_engine_free(nint engine);

    /// <summary>The shim's exported-surface revision; checked against <see cref="Abi"/> at engine
    /// construction so a stale native library fails loudly instead of mis-routing in silence.</summary>
    [DllImport(Lib)] internal static extern uint iq_abi();

    /// <summary>What this managed binding was written against. Bump both together.</summary>
    internal const uint Abi = 2;

    /// <summary>
    /// Refuse to run against a native library this binding was not built for.
    ///
    /// Worth an explicit check rather than trusting the package: the shim and this assembly ship
    /// together, so a mismatch means a stale libioxide_ngtcp2.so has been picked up out of a build
    /// output - which has silently invalidated whole test runs here before. The failure it prevents
    /// is not a crash but arguments landing in the wrong parameters, which looks like a logic bug
    /// somewhere else entirely.
    /// </summary>
    internal static void RequireAbi()
    {
        uint native;
        try
        {
            native = iq_abi();
        }
        catch (EntryPointNotFoundException)
        {
            native = 0;   // predates the counter, so certainly too old
        }

        if (native != Abi)
        {
            throw new InvalidOperationException(
                $"ioxide.ngtcp2: the native library reports ABI {native}, this binding needs {Abi}. " +
                "A stale libioxide_ngtcp2.so is being loaded - rebuild it with scripts/build-ngtcp2-native.sh.");
        }
    }

    [DllImport(Lib)] internal static extern nint iq_accept(
        nint engine,
        void* localSa, nuint localSaLen,
        void* remoteSa, nuint remoteSaLen,
        byte* pkt, nuint pktLen,
        ulong ts, void* user,
        uint shard, uint shardCount, byte* scidOut);

    [DllImport(Lib)] internal static extern void iq_conn_free(nint conn);

    [DllImport(Lib)] internal static extern int iq_conn_read(
        nint conn, void* remoteSa, nuint remoteSaLen,
        byte* pkt, nuint pktLen, byte ecn, ulong ts);

    [DllImport(Lib)] internal static extern nint iq_conn_write(
        nint conn, byte* dest, nuint destLen,
        long streamId, byte* data, nuint dataLen, int fin,
        long* pConsumed, ulong ts);

    [DllImport(Lib)] internal static extern nint iq_conn_close(
        nint conn, ulong appErrorCode, byte* dest, nuint destLen, ulong ts);

    [DllImport(Lib)] internal static extern nint iq_conn_close_liberr(
        nint conn, int libError, byte* dest, nuint destLen, ulong ts);

    [DllImport(Lib)] internal static extern ulong iq_conn_expiry(nint conn);
    [DllImport(Lib)] internal static extern int   iq_conn_handle_expiry(nint conn, ulong ts);
    [DllImport(Lib)] internal static extern int   iq_conn_is_established(nint conn);
    [DllImport(Lib)] internal static extern long  iq_conn_open_uni(nint conn);
    [DllImport(Lib)] internal static extern void  iq_conn_set_stream_paced(nint conn, long streamId, int on);
    [DllImport(Lib)] internal static extern void  iq_conn_consume(nint conn, long streamId, ulong n);
    [DllImport(Lib)] internal static extern nuint iq_conn_get_alpn(nint conn, byte* buf, nuint bufLen);

    // --- client side (ioxide.httpclient / QuicClientEngine) ---------------------------------

    /// <summary>
    /// Client engine. The certificate and key are what this client PRESENTS when a server asks for
    /// one - both null to present nothing, which is the ordinary case.
    /// </summary>
    /// <remarks>
    /// This client does not authenticate the server: it accepts whatever certificate it is sent.
    /// </remarks>
    [DllImport(Lib)] internal static extern nint iq_client_engine_new_mtls(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? certPemPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPemPath,
        Callbacks cbs);

    [DllImport(Lib)] internal static extern void iq_client_engine_free(nint engine);

    /// <summary>Open a client connection. scidLen must equal the demux slice of whoever routes our
    /// inbound datagrams (the reactor's QuicOptions.LocalCidLength); scidOut receives the CID to
    /// register for that routing.</summary>
    [DllImport(Lib)] internal static extern nint iq_client_connect(
        nint engine, byte* localSockaddr, nuint localLen, byte* remoteSockaddr, nuint remoteLen,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string serverName, [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn,
        nuint scidLen, ulong ts, void* user, byte* scidOut);

    [DllImport(Lib)] internal static extern long iq_client_open_bidi(nint conn);

    [DllImport(Lib)] internal static extern nint iq_version();
    [DllImport(Lib)] internal static extern nint iq_strerror(int liberr);

    // ngtcp2 error codes the write/read loops branch on (include/ngtcp2/ngtcp2.h).
    //
    // Hand-copied from a header the build script fetches by ref, so a wrong value here is silent:
    // it does not fail to compile, it makes a branch match the wrong error. Every constant below is
    // asserted against iq_strerror by 'quic: the ngtcp2 error constants match the shipped library'.
    internal const int NGTCP2_ERR_STREAM_DATA_BLOCKED   = -208;
    internal const int NGTCP2_ERR_STREAM_SHUT_WR        = -219;
    internal const int NGTCP2_ERR_STREAM_NOT_FOUND      = -220;
    internal const int NGTCP2_ERR_CLOSING               = -223;
    internal const int NGTCP2_ERR_DRAINING              = -224;
    internal const int NGTCP2_ERR_INTERNAL              = -228;
    internal const int NGTCP2_ERR_IDLE_CLOSE            = -238;

    internal static string StrError(int liberr) => Marshal.PtrToStringUTF8(iq_strerror(liberr)) ?? liberr.ToString();
}
