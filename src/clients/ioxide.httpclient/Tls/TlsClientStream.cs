using System.Runtime.InteropServices;

namespace ioxide.httpclient;

/// <summary>
/// A TLS connection to an origin, over a ring socket. Send and receive take the same
/// <c>(pointer, length)</c> shape as <see cref="RingSocket"/> itself and mean the same thing, so a
/// client that already speaks to a raw socket can speak to this instead with no other change.
///
/// BoringSSL sees only memory BIOs; every byte that reaches the network still goes through the
/// reactor's ring, and every await resumes inline on the reactor thread like the rest of ioxide.
/// </summary>
/// <remarks>
/// Reactor thread only, and one operation at a time in each direction - the same contract the
/// underlying <see cref="RingSocket"/> has, since each direction owns a single completion source.
///
/// The BoringSSL calls live in small synchronous helpers rather than inline: an <c>unsafe</c> method
/// cannot contain an await, and the alternative (pointers held across a suspension) is exactly the
/// shape that goes wrong when a continuation resumes on a different stack.
/// </remarks>
public sealed class TlsClientStream : IDisposable
{
    // Staging for ciphertext moving between the socket and the BIOs. A TLS record maxes out at
    // 16 KiB of plaintext plus overhead, so this holds at least a full record either way.
    private const int CiphertextBufferSize = 20 * 1024;

    private readonly RingSocket _socket;
    private readonly nint _ssl;
    private readonly nint _rbio;   // ciphertext IN: socket -> BoringSSL
    private readonly nint _wbio;   // ciphertext OUT: BoringSSL -> socket

    // One staging buffer PER DIRECTION, which is not an optimisation - it is required. RingSocket
    // deliberately allows one send and one recv to be in flight at once (separate completion
    // sources), and HTTP/2 uses exactly that: its pump sits parked in RecvAsync while a request
    // submitted from elsewhere drains egress. With a single shared buffer those two hand the
    // kernel the same address for a recv and a send simultaneously, so inbound record bytes land
    // in the middle of an outbound record. The corruption only appears under concurrent
    // multiplexed load, which is the one workload h2 exists for.
    private readonly nint _inbound;
    private readonly nint _outbound;

    private bool _disposed;
    private bool _peerClosed;

    /// <summary>The ALPN protocol the origin selected, or null when none was negotiated.</summary>
    public string? NegotiatedAlpn { get; private set; }

    /// <summary>The socket underneath, for callers that need its descriptor.</summary>
    public RingSocket Socket => _socket;

    private TlsClientStream(RingSocket socket, nint ssl, nint rbio, nint wbio)
    {
        _socket = socket;
        _ssl = ssl;
        _rbio = rbio;
        _wbio = wbio;
        _inbound = AllocateCiphertextBuffer();
        _outbound = AllocateCiphertextBuffer();
    }

    internal static async ValueTask<TlsClientStream> HandshakeAsync(RingSocket socket, TlsClientContext context,
        string serverName)
    {
        TlsClientOptions options = context.Options;

        // Everything from here to the constructor is unowned: the stream that would free it does
        // not exist yet, and ClientTransport hands the socket over on the understanding that the
        // stream closes it on failure. So each step that can throw unwinds explicitly.
        nint ssl = BoringSsl.SSL_new(context.Handle);
        if (ssl == 0)
        {
            socket.Dispose();
            throw new IOException($"SSL_new: {BoringSsl.LastError()}");
        }

        TlsClientStream stream;
        try
        {
            nint rbio = BoringSsl.BIO_new(BoringSsl.BIO_s_mem());
            nint wbio = BoringSsl.BIO_new(BoringSsl.BIO_s_mem());
            if (rbio == 0 || wbio == 0)
            {
                // Free whichever one succeeded; SSL_set_bio never ran, so neither is owned yet.
                if (rbio != 0)
                {
                    BoringSsl.BIO_free(rbio);
                }
                if (wbio != 0)
                {
                    BoringSsl.BIO_free(wbio);
                }
                throw new IOException($"BIO_new: {BoringSsl.LastError()}");
            }

            BoringSsl.SSL_set_bio(ssl, rbio, wbio);   // ssl owns both BIOs from here
            BoringSsl.SSL_set_connect_state(ssl);

            ConfigureNames(ssl, options, serverName);   // throws when SSL_set1_host rejects the name

            stream = new TlsClientStream(socket, ssl, rbio, wbio);
        }
        catch
        {
            BoringSsl.SSL_free(ssl);   // frees the BIOs too, once set_bio has run
            socket.Dispose();
            throw;
        }

        try
        {
            await stream.RunHandshakeAsync(options, serverName);
            return stream;
        }
        catch
        {
            stream.Dispose();   // owns the SSL, both BIOs, both buffers and the socket
            throw;
        }
    }

    // SNI and the verification name are two different things and both are needed: SNI tells the
    // origin which certificate to send, SSL_set1_host checks the one it actually sent. Setting only
    // the first is the classic way to end up with encryption and no authentication.
    private static unsafe void ConfigureNames(nint ssl, TlsClientOptions options, string serverName)
    {
        // An address is not a host name: it is checked against the certificate's iPAddress names
        // (SSL_set1_host would compare it with dNSNames) and not sent as SNI, which RFC 6066 3
        // reserves for host names. Only the full forms count, so a numeric host name stays a name.
        if ((serverName.Contains(':') || serverName.Count(c => c == '.') == 3)
            && System.Net.IPAddress.TryParse(serverName, out System.Net.IPAddress? address))
        {
            if (options.VerifyCertificate)
            {
                byte[] bytes = address.GetAddressBytes();
                fixed (byte* p = bytes)
                {
                    if (BoringSsl.X509_VERIFY_PARAM_set1_ip(BoringSsl.SSL_get0_param(ssl), p, (nuint)bytes.Length) != 1)
                    {
                        throw new IOException($"X509_VERIFY_PARAM_set1_ip('{serverName}'): {BoringSsl.LastError()}");
                    }
                }
            }
            return;
        }

        if (BoringSsl.SSL_set_tlsext_host_name(ssl, serverName) != 1)
        {
            throw new IOException($"SSL_set_tlsext_host_name('{serverName}'): {BoringSsl.LastError()}");
        }

        // BoringSSL matches a wildcard only as a whole leftmost label, so 'ww*.example.com' never
        // matches 'www.example.com': a partial wildcard names a prefix, not a host.
        if (options.VerifyCertificate && BoringSsl.SSL_set1_host(ssl, serverName) != 1)
        {
            throw new IOException($"SSL_set1_host('{serverName}'): {BoringSsl.LastError()}");
        }
    }

    private async ValueTask RunHandshakeAsync(TlsClientOptions options, string serverName)
    {
        var deadline = new HandshakeDeadline(this);
        _socket.Host.SubmitTimeout(options.HandshakeTimeoutMs * 1_000_000L, deadline);

        while (true)
        {
            int ret = BoringSsl.Connect(_ssl, out int err);

            // Read before the alert's flush, during which other connections' BoringSSL calls clear this thread's queue.
            string? failure = ret != 1 && err != BoringSsl.SSL_ERROR_WANT_READ && err != BoringSsl.SSL_ERROR_WANT_WRITE
                ? HandshakeFailure(options)
                : null;

            try
            {
                await FlushCiphertextAsync();
            }
            catch (IOException) when (failure is not null)
            {
                // The alert after a failed handshake is best-effort: a peer that already closed
                // refuses it, and that refusal must not stand in for the handshake's own failure.
            }

            if (ret == 1)
            {
                break;
            }
            if (failure is not null)
            {
                throw new IOException($"TLS handshake to '{serverName}' failed: {failure}");
            }

            int n = await _socket.RecvAsync(_inbound, CiphertextBufferSize);
            if (deadline.Expired)
            {
                throw new IOException(
                    $"TLS handshake to '{serverName}' did not complete within {options.HandshakeTimeoutMs} ms");
            }
            if (n <= 0)
            {
                throw new IOException(n == 0
                    ? "connection closed during the TLS handshake"
                    : $"recv failed during the TLS handshake: errno {-n}");
            }
            FeedCiphertext(n);
        }

        if (options.VerifyCertificate)
        {
            long verify = BoringSsl.SSL_get_verify_result(_ssl);
            if (verify != BoringSsl.X509_V_OK)
            {
                throw new IOException(
                    $"certificate for '{serverName}' was not accepted (X509 verify result {verify})");
            }
        }

        NegotiatedAlpn = ReadNegotiatedAlpn(_ssl);
    }

    // The queue says the handshake failed; a refused certificate's verify result says which check refused it.
    // BoringSSL's error for that is CERTIFICATE_VERIFY_FAILED, so the words callers match on are written out.
    // INVALID_CALL is not a verdict: the handshake failed before there was a session to verify.
    private string HandshakeFailure(TlsClientOptions options)
    {
        string error = BoringSsl.LastError();
        long verify = BoringSsl.SSL_get_verify_result(_ssl);
        return options.VerifyCertificate && verify is not (BoringSsl.X509_V_OK or BoringSsl.X509_V_ERR_INVALID_CALL)
            ? $"certificate verify failed: {BoringSsl.VerifyResultText(verify)} ({error})"
            : error;
    }

    /// <summary>
    /// Encrypt and send. Returns the number of PLAINTEXT bytes accepted, matching
    /// <see cref="RingSocket.SendAsync"/>, so a caller looping until everything is sent works
    /// unchanged.
    /// </summary>
    public async ValueTask<int> SendAsync(nint buffer, int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        int written = SslWrite(buffer, length, out int err);
        if (written <= 0)
        {

            // WANT_READ on a WRITE means TLS 1.3 post-handshake traffic (a KeyUpdate, a session
            // ticket) has to be read before the write can proceed. Deliberately not handled by
            // reading here: RingSocket has ONE receive completion source, and in a full-duplex
            // client the read side belongs to someone else - h2's pump sits parked on it. Issuing
            // a recv from the send path would alias that source, which is the same class of bug as
            // sharing a staging buffer. Whoever owns the read side feeds the BIO; the caller
            // retries.
            if (err == BoringSsl.SSL_ERROR_WANT_READ)
            {
                throw new IOException(
                    "SSL_write needs inbound data first (post-handshake message); retry once the "
                    + "read side has been pumped");
            }

            throw new IOException($"SSL_write failed (error {err}): {BoringSsl.LastError()}");
        }

        // The records exist only in the write BIO until this runs, so it is not optional.
        await FlushCiphertextAsync();
        return written;
    }

    /// <summary>
    /// Receive and decrypt. Returns the number of plaintext bytes, 0 once the peer has closed, and
    /// a negative errno on a socket failure - the same three cases
    /// <see cref="RingSocket.RecvAsync"/> reports, so callers need no new branch.
    /// </summary>
    public async ValueTask<int> RecvAsync(nint buffer, int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (true)
        {
            int n = SslRead(buffer, length, out int err);
            if (n > 0)
            {
                return n;
            }

            if (err == BoringSsl.SSL_ERROR_ZERO_RETURN)
            {
                _peerClosed = true;
                return 0;   // clean close_notify
            }
            if (err == BoringSsl.SSL_ERROR_WANT_WRITE)
            {
                // A key update or renegotiation needs to put bytes on the wire before it can
                // produce more plaintext.
                await FlushCiphertextAsync();
                continue;
            }
            if (err != BoringSsl.SSL_ERROR_WANT_READ)
            {
                throw new IOException($"SSL_read failed (error {err}): {BoringSsl.LastError()}");
            }

            // Incomplete record: pull more ciphertext.
            int received = await _socket.RecvAsync(_inbound, CiphertextBufferSize);
            if (received <= 0)
            {
                // A peer that vanished without close_notify is a truncation, but callers already
                // treat 0 as end-of-stream and the HTTP layers above detect a short response
                // themselves, so it is reported the same way rather than thrown.
                _peerClosed = true;
                return received;
            }
            FeedCiphertext(received);
        }
    }

    // Drain whatever BoringSSL staged into the write BIO out to the socket. Partial sends loop:
    // the ring reports what it took, not what we asked for.
    private async ValueTask FlushCiphertextAsync()
    {
        while (PendingCiphertext() > 0)
        {
            int chunk = TakeCiphertext();
            if (chunk <= 0)
            {
                return;
            }

            int sent = 0;
            while (sent < chunk)
            {
                int n = await _socket.SendAsync(_outbound + sent, chunk - sent);
                if (n <= 0)
                {
                    throw new IOException(n == 0
                        ? "connection closed while sending TLS records"
                        : $"send failed: errno {-n}");
                }
                sent += n;
            }
        }
    }

    // --- the pointer-facing edge ----------------------------------------------------------------

    private static unsafe nint AllocateCiphertextBuffer() => (nint)NativeMemory.Alloc(CiphertextBufferSize);

    private unsafe void FeedCiphertext(int length)
        => BoringSsl.BIO_write(_rbio, (byte*)_inbound, length);

    private unsafe int TakeCiphertext()
        => BoringSsl.BIO_read(_wbio, (byte*)_outbound, CiphertextBufferSize);

    private unsafe nuint PendingCiphertext() => BoringSsl.BIO_ctrl_pending(_wbio);

    private unsafe int SslRead(nint buffer, int length, out int error)
        => BoringSsl.Read(_ssl, (byte*)buffer, length, out error);

    private unsafe int SslWrite(nint buffer, int length, out int error)
        => BoringSsl.Write(_ssl, (byte*)buffer, length, out error);

    private static unsafe string? ReadNegotiatedAlpn(nint ssl)
    {
        byte* data;
        uint length;
        BoringSsl.SSL_get0_alpn_selected(ssl, &data, &length);
        return data == null || length == 0
            ? null
            : System.Text.Encoding.ASCII.GetString(data, (int)length);
    }

    private static unsafe void FreeCiphertextBuffer(nint buffer) => NativeMemory.Free((void*)buffer);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        // A best-effort close_notify so the peer can tell a finished stream from a truncated one.
        // It reaches the write BIO but is not flushed: this is teardown, and nothing here awaits.
        //
        // Not on a handshake that never finished, though. There is no session to end, and
        // SSL_shutdown says so by failing and leaving "shutdown while in init" on the error queue -
        // which belongs to the reactor, not to this connection, so it becomes the next pooled
        // connection's fatal error.
        if (!_peerClosed && BoringSsl.SSL_in_init(_ssl) == 0)
        {
            if (BoringSsl.SSL_shutdown(_ssl) < 0)
            {
                BoringSsl.ERR_clear_error();   // whatever it queued is ours to clean up
            }
        }

        BoringSsl.SSL_free(_ssl);   // frees both BIOs
        FreeCiphertextBuffer(_inbound);
        FreeCiphertextBuffer(_outbound);
        _socket.Dispose();
    }

    // Shuts down a handshake still running at HandshakeTimeoutMs, which completes the recv it is parked on.
    private sealed class HandshakeDeadline(TlsClientStream stream) : IRingCompletion
    {
        public bool Expired { get; private set; }

        public void Complete(int result)
        {
            // -ETIME: the wait ran its course. Disposed is checked first: by then SSL_free has run.
            if (result is -62 or 0 && !stream._disposed && BoringSsl.SSL_in_init(stream._ssl) != 0)
            {
                Expired = true;
                Native.shutdown(stream._socket.Fd, Native.SHUT_RDWR);
            }
        }
    }
}
