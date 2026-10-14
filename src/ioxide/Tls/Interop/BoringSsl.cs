using System.Runtime.InteropServices;

namespace ioxide.tls;

/// <summary>
/// Minimal BoringSSL surface: server context, memory-BIO handshake, keylog. The library ships with
/// this package as libioxide_boringssl.so (scripts/build-boringssl-native.sh): libssl and libcrypto
/// in one object, so both names below are the same file.
/// </summary>
internal static unsafe partial class BoringSsl
{
    private const string Ssl = "libioxide_boringssl.so";
    private const string Crypto = "libioxide_boringssl.so";

    public const int SSL_FILETYPE_PEM = 1;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_ZERO_RETURN = 6;
    public const ushort TLS1_2_VERSION = 0x0303;
    public const ushort TLS1_3_VERSION = 0x0304;

    /// <summary>The RFC 8446 protocol id of the one suite kTLS is programmed for.</summary>
    public const ushort TLS_AES_128_GCM_SHA256 = 0x1301;
    public const int SSL_TLSEXT_ERR_OK = 0;
    public const int SSL_TLSEXT_ERR_NOACK = 3;
    public const int TLSEXT_NAMETYPE_host_name = 0;

    // Client-certificate verification (mutual TLS).
    public const int SSL_VERIFY_PEER = 0x01;
    public const int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
    public const long X509_V_OK = 0;

    [LibraryImport(Ssl)] public static partial nint TLS_server_method();
    [LibraryImport(Ssl)] public static partial nint SSL_CTX_new(nint method);
    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_use_certificate_chain_file(nint ctx, string file);
    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_use_PrivateKey_file(nint ctx, string file, int type);

    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_min_proto_version(nint ctx, ushort version);
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_max_proto_version(nint ctx, ushort version);

    /// <summary>
    /// TLS 1.3 suites by protocol id, in server preference order. Only the listed suites are
    /// negotiated; an empty list means BoringSSL's built-in order, so callers refuse empty first.
    /// </summary>
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set1_tls13_ciphers(nint ctx, ushort* ids, uint* flags, nuint count);

    [LibraryImport(Ssl)] public static partial nint SSL_get_cipher_by_value(ushort value);
    [LibraryImport(Ssl)] public static partial nint SSL_CIPHER_standard_name(nint cipher);

    /// <summary>
    /// The protocol id of the TLS 1.3 suite called <paramref name="name"/> (its RFC 8446 name), or
    /// null when this BoringSSL does not implement it. Asks the library rather than a table here:
    /// the TLS 1.3 ids are 0x1301-0x1305, and BoringSSL knows the three it offers.
    /// </summary>
    public static ushort? Tls13SuiteId(string name)
    {
        for (ushort id = 0x1301; id <= 0x1305; id++)
        {
            nint cipher = SSL_get_cipher_by_value(id);
            if (cipher != 0 && Marshal.PtrToStringUTF8(SSL_CIPHER_standard_name(cipher)) == name)
            {
                return id;
            }
        }
        return null;
    }

    /// <summary>TLS 1.2 and below. A separate list from the 1.3 one, in BoringSSL and here.</summary>
    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_set_cipher_list(nint ctx, string list);
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_num_tickets(nint ctx, nuint num);

    /// <summary>Takes ownership of <paramref name="x509"/> on success.</summary>
    [LibraryImport(Ssl)] public static partial int SSL_CTX_add_extra_chain_cert(nint ctx, nint x509);

    public const uint SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000;

    /// <summary>PEM's "the BIO holds no further object", i.e. an ordinary end of bundle.</summary>
    public const int PEM_R_NO_START_LINE = 110;
    public const int ERR_LIB_PEM = 9;

    [LibraryImport(Ssl)] public static partial uint SSL_CTX_set_options(nint ctx, uint options);

    /// <summary>
    /// Drops one reference. Contexts that are SERVING are never freed - a handshake may be between
    /// reading one and using it - so this is for contexts that were built and then not published,
    /// which nothing can have a reference to.
    /// </summary>
    [LibraryImport(Ssl)] public static partial void SSL_CTX_free(nint ctx);

    [LibraryImport(Ssl)] public static partial void SSL_CTX_set_keylog_callback(nint ctx, nint cb);
    [LibraryImport(Ssl)] public static partial void SSL_CTX_set_alpn_select_cb(nint ctx, nint cb, nint arg);

    // Server Name Indication (RFC 6066 3.1). The callback fires mid-handshake, after the
    // ClientHello is parsed and before a certificate is chosen, which is the only point at which
    // the name is known and the choice is still open.
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_tlsext_servername_callback(nint ctx, nint cb);
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_tlsext_servername_arg(nint ctx, nint arg);

    /// <summary>
    /// Install the callback asked for a private key's passphrase. ioxide never has one, and says so
    /// explicitly rather than relying on the library default, so an encrypted key always fails the
    /// same way: at load, with an error, instead of whatever a default might try.
    /// </summary>
    [LibraryImport(Ssl)] public static partial void SSL_CTX_set_default_passwd_cb(nint ctx, nint cb);

    /// <summary>The name the client asked for, or null when it sent no SNI extension.</summary>
    [LibraryImport(Ssl)] public static partial nint SSL_get_servername(nint ssl, int type);

    /// <summary>
    /// Swaps the context a handshake in progress will answer from, which is how one listener serves
    /// several certificates. Valid from the servername callback, before the certificate is picked.
    /// </summary>
    [LibraryImport(Ssl)] public static partial nint SSL_set_SSL_CTX(nint ssl, nint ctx);

    // --- client certificates (mutual TLS) ---------------------------------------------------------

    /// <summary>
    /// Ask for a client certificate and decide what a failed chain means. Mode
    /// <see cref="SSL_VERIFY_PEER"/> alone requests one and accepts a client that sends none;
    /// adding <see cref="SSL_VERIFY_FAIL_IF_NO_PEER_CERT"/> refuses that client at the handshake.
    /// With no callback, a chain that does not validate fails the handshake outright - there is
    /// nothing to prompt and nowhere to fall back to.
    /// </summary>
    [LibraryImport(Ssl)] public static partial void SSL_CTX_set_verify(nint ctx, int mode, nint callback);

    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_load_verify_locations(nint ctx, string? caFile, string? caPath);

    /// <summary>The context's trust store, for adding anchors parsed from memory.</summary>
    [LibraryImport(Ssl)] public static partial nint SSL_CTX_get_cert_store(nint ctx);

    [LibraryImport(Crypto)] public static partial int X509_STORE_add_cert(nint store, nint x509);

    /// <summary>
    /// Names sent in the CertificateRequest so a client holding several certificates can pick the
    /// one this server will accept. Without it the client guesses.
    /// </summary>
    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint SSL_load_client_CA_file(string file);

    [LibraryImport(Ssl)] public static partial void SSL_CTX_set_client_CA_list(nint ctx, nint list);

    /// <summary>Appends one issuer to the CertificateRequest hint. Takes its own reference.</summary>
    [LibraryImport(Ssl)] public static partial int SSL_CTX_add_client_CA(nint ctx, nint x509);

    /// <summary>The hint as it stands: a stack of X509_NAME, borrowed.</summary>
    [LibraryImport(Ssl)] public static partial nint SSL_CTX_get_client_CA_list(nint ctx);

    /// <summary>Zero when two names are the same name, compared canonically.</summary>
    [LibraryImport(Crypto)] public static partial int X509_NAME_cmp(nint a, nint b);

    [LibraryImport(Ssl)] private static partial nint SSL_get_peer_certificate(nint ssl);

    /// <summary>The peer's leaf certificate, borrowed: the session keeps its own reference.</summary>
    public static nint PeerCertificate(nint ssl)
    {
        nint cert = SSL_get_peer_certificate(ssl);
        X509_free(cert);
        return cert;
    }

    // What the handshake actually settled on, for callers that have to REPORT it rather than
    // assume it - ASP.NET reads both off ITlsHandshakeFeature.
    [LibraryImport(Ssl)] public static partial int SSL_version(nint ssl);
    [LibraryImport(Ssl)] public static partial nint SSL_get_current_cipher(nint ssl);
    [LibraryImport(Ssl)] public static partial ushort SSL_CIPHER_get_protocol_id(nint cipher);
    [LibraryImport(Crypto)] public static partial int i2d_X509(nint x509, byte** outBuf);

    /// <summary>X509_V_OK, or why the chain was rejected.</summary>
    [LibraryImport(Ssl)] public static partial long SSL_get_verify_result(nint ssl);

    [LibraryImport(Crypto)] public static partial nint X509_get_subject_name(nint x509);

    /// <summary>
    /// The legacy one-line rendering of a DN. Called with a NULL buffer it allocates the exact
    /// size and the caller frees it with <see cref="OPENSSL_free"/>; called with a buffer too small
    /// it reports SUCCESS and writes a truncated prefix, which is why nothing here passes one.
    /// </summary>
    [LibraryImport(Crypto)] public static partial nint X509_NAME_oneline(nint name, byte* buf, int size);

    [LibraryImport(Crypto)] public static partial void OPENSSL_free(nint ptr);

    /// <summary>The element at <paramref name="index"/> of a stack, borrowed, or 0 past its end.</summary>
    [LibraryImport(Crypto)] public static partial nint OPENSSL_sk_value(nint stack, nuint index);

    // Structural access to one attribute of a DN, so an identity can be compared as a value
    // instead of matched inside a rendered string. See TlsSession.PeerCommonName.
    public const int NID_commonName = 13;

    [LibraryImport(Crypto)] public static partial int  X509_NAME_get_index_by_NID(nint name, int nid, int lastpos);
    [LibraryImport(Crypto)] public static partial nint X509_NAME_get_entry(nint name, int loc);
    [LibraryImport(Crypto)] public static partial nint X509_NAME_ENTRY_get_data(nint entry);

    /// <summary>Decodes an ASN.1 string to UTF-8 whatever it was encoded as. Returns the length
    /// and allocates through <paramref name="outBuf"/>, which the caller frees.</summary>
    [LibraryImport(Crypto)] public static partial int ASN1_STRING_to_UTF8(nint* outBuf, nint asn1Str);

    [LibraryImport(Ssl)] public static partial nint SSL_new(nint ctx);
    [LibraryImport(Ssl)] public static partial void SSL_free(nint ssl);
    [LibraryImport(Ssl)] public static partial void SSL_set_accept_state(nint ssl);
    [LibraryImport(Ssl)] public static partial void SSL_set_bio(nint ssl, nint rbio, nint wbio);
    [LibraryImport(Ssl)] private static partial int SSL_accept(nint ssl);
    [LibraryImport(Ssl)] private static partial int SSL_read(nint ssl, byte* buf, int num);
    [LibraryImport(Ssl)] private static partial int SSL_write(nint ssl, byte* buf, int num);
    [LibraryImport(Ssl)] public static partial int SSL_shutdown(nint ssl);

    /// <summary>
    /// The three operations whose result has to be classified, each performed from a clean error
    /// queue and returning what the classification said.
    /// </summary>
    /// <remarks>
    /// The clear, the call and the classify are one operation and are deliberately not offered
    /// apart - the raw entry points above are private so that they cannot be.
    ///
    /// The reason is that the error queue belongs to the THREAD, and here a thread is a reactor
    /// shared by every connection it serves. SSL_get_error consults that queue BEFORE it asks the
    /// SSL whether it merely wants more data, so a residue any other connection left - an aborted
    /// handshake, a refused client, a port scan - is read as THIS connection's fatal error and
    /// kills it. Clearing at each call site works until someone adds the next call site; this shape
    /// means there is no next call site to forget.
    /// </remarks>
    public static unsafe int Accept(nint ssl, out int error)
    {
        ERR_clear_error();
        int ret = SSL_accept(ssl);
        error = ret == 1 ? 0 : SSL_get_error(ssl, ret);
        return ret;
    }

    /// <inheritdoc cref="Accept"/>
    public static unsafe int Read(nint ssl, byte* buf, int num, out int error)
    {
        ERR_clear_error();
        int n = SSL_read(ssl, buf, num);
        error = n > 0 ? 0 : SSL_get_error(ssl, n);
        return n;
    }

    /// <inheritdoc cref="Accept"/>
    public static unsafe int Write(nint ssl, byte* buf, int num, out int error)
    {
        ERR_clear_error();
        int n = SSL_write(ssl, buf, num);
        error = n > 0 ? 0 : SSL_get_error(ssl, n);
        return n;
    }

    /// <summary>Whether the handshake is still running - SSL_shutdown on one that is has nothing
    /// to say and only raises an error nobody asked for.</summary>
    [LibraryImport(Ssl)] public static partial int SSL_in_init(nint ssl);

    /// <summary>
    /// Scopes a session to this server, so a resumption offered to a different one is declined.
    /// </summary>
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_session_id_context(nint ctx, byte* sid, nuint len);
    [LibraryImport(Ssl)] private static partial int SSL_get_error(nint ssl, int ret);


    /// <summary>What ALPN settled on, or nothing when the client offered none we serve.</summary>
    [LibraryImport(Ssl)] public static partial void SSL_get0_alpn_selected(nint ssl, byte** data, uint* length);

    // Per-SSL user data: associate a managed object (a GCHandle) with an SSL so the static keylog
    // callback can find the right session without a global, pointer-keyed map.
    [LibraryImport(Ssl)] public static partial int SSL_set_ex_data(nint ssl, int idx, nint data);
    [LibraryImport(Ssl)] public static partial nint SSL_get_ex_data(nint ssl, int idx);
    [LibraryImport(Ssl)] public static partial int SSL_get_ex_new_index(long argl, nint argp, nint unused, nint dupUnused, nint freeFunc);

    [LibraryImport(Crypto)] public static partial nint BIO_new(nint type);
    [LibraryImport(Crypto)] public static partial nint BIO_s_mem();
    [LibraryImport(Crypto)] public static partial nint BIO_new_mem_buf(byte* buf, nint len);
    [LibraryImport(Crypto)] public static partial int BIO_free(nint bio);

    // PEM-from-memory loading: the same certificate/key material a chain file carries, read
    // through a memory BIO instead. The password-callback arguments are always null here.
    [LibraryImport(Crypto)] public static partial nint PEM_read_bio_X509(nint bio, nint x, nint cb, nint u);
    /// <summary>Reads TRUSTED CERTIFICATE blocks as well as CERTIFICATE ones, as a CA file is read.</summary>
    [LibraryImport(Crypto)] public static partial nint PEM_read_bio_X509_AUX(nint bio, nint x, nint cb, nint u);
    [LibraryImport(Crypto)] public static partial nint PEM_read_bio_PrivateKey(nint bio, nint pkey, nint cb, nint u);
    [LibraryImport(Crypto)] public static partial void X509_free(nint x509);
    [LibraryImport(Crypto)] public static partial void EVP_PKEY_free(nint pkey);
    [LibraryImport(Crypto)] public static partial void ERR_clear_error();
    [LibraryImport(Ssl)] public static partial int SSL_CTX_use_certificate(nint ctx, nint x509);
    [LibraryImport(Ssl)] public static partial int SSL_CTX_use_PrivateKey(nint ctx, nint pkey);
    [LibraryImport(Ssl)] public static partial int SSL_CTX_check_private_key(nint ctx);
    [LibraryImport(Crypto)] public static partial int BIO_write(nint bio, byte* data, int dlen);
    [LibraryImport(Crypto)] public static partial int BIO_read(nint bio, byte* data, int dlen);
    [LibraryImport(Crypto)] public static partial nuint BIO_ctrl_pending(nint bio);

    /// <summary>
    /// BIO_CTRL_INFO on a memory BIO hands back a pointer to its buffer without consuming it - the
    /// only way to inspect pending ciphertext, which kTLS RX needs in order to count how many
    /// complete records the handshake already swallowed.
    /// </summary>
    public const int BIO_CTRL_INFO = 3;

    [LibraryImport(Crypto)] public static partial long BIO_ctrl(nint bio, int cmd, long larg, byte** parg);
    [LibraryImport(Crypto)] public static partial uint ERR_get_error();
    [LibraryImport(Crypto)] private static partial uint ERR_peek_error();
    [LibraryImport(Crypto)] public static partial void ERR_error_string_n(uint e, byte* buf, nuint len);

    private const int ERR_LIB_X509 = 11;
    private const int X509_R_KEY_TYPE_MISMATCH = 115;
    private const int X509_R_KEY_VALUES_MISMATCH = 116;

    /// <summary>Whether the queued error says a key does not belong to the certificate loaded.</summary>
    public static bool ErrorIsKeyMismatch()
    {
        uint code = ERR_peek_error();
        return (code >> 24) == ERR_LIB_X509
            && (code & 0xFFF) is X509_R_KEY_TYPE_MISMATCH or X509_R_KEY_VALUES_MISMATCH;
    }

    /// <summary>
    /// Drains the queue and reports whether it held ONLY "no start line" - PEM's way of saying the
    /// BIO is exhausted. Anything else means the read stopped on a malformed block, which is the
    /// difference between "that was the last certificate in the bundle" and "the rest of the bundle
    /// was silently dropped".
    /// </summary>
    public static bool ErrorIsEndOfPem()
    {
        bool sawEnd = false;
        bool sawOther = false;

        uint code;
        while ((code = ERR_get_error()) != 0)
        {
            if ((code >> 24) == ERR_LIB_PEM && (code & 0xFFF) == PEM_R_NO_START_LINE)
            {
                sawEnd = true;
            }
            else
            {
                sawOther = true;   // keep draining: a half-read queue becomes the next caller's bug
            }
        }

        return sawEnd && !sawOther;
    }

    public static string LastError()
    {
        uint code = ERR_get_error();
        if (code == 0) return "no BoringSSL error";

        Span<byte> buf = stackalloc byte[256];
        string message;
        fixed (byte* p = buf)
        {
            ERR_error_string_n(code, p, (nuint)buf.Length);
            message = Marshal.PtrToStringUTF8((nint)p) ?? code.ToString();
        }

        // Drain any piggy-backed errors so the next LastError() isn't stale.
        while (ERR_get_error() != 0)
        {
        }
        return message;
    }
}
