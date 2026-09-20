using System.Runtime.InteropServices;

namespace ioxide.httpclient;

/// <summary>
/// The OpenSSL 3 surface a TLS CLIENT needs: connect state, SNI, peer verification, the ALPN offer,
/// and the memory-BIO plumbing the handshake rides on.
/// </summary>
/// <remarks>
/// Deliberately separate from the one in ioxide.tls rather than shared. That package terminates TLS
/// for inbound connections and its whole shape serves kernel-TLS offload - TLS 1.3 only, a single
/// ciphersuite, no session tickets, a keylog callback to extract the traffic secret. None of that
/// applies to a client, and the two halves have zero logic in common: what they genuinely share is
/// about sixteen ABI declarations of memory-BIO boilerplate that have not changed since OpenSSL
/// 3.0. Duplicating those is cheaper than making a client package depend on a server one.
/// </remarks>
internal static unsafe partial class OpenSsl
{
    private const string Ssl = "libssl.so.3";
    private const string Crypto = "libcrypto.so.3";

    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_ZERO_RETURN = 6;

    public const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
    public const int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    public const int TLSEXT_NAMETYPE_host_name = 0;

    public const int SSL_VERIFY_NONE = 0x00;
    public const int SSL_VERIFY_PEER = 0x01;
    public const long X509_V_OK = 0;

    // --- context ---------------------------------------------------------------------------------

    [LibraryImport(Ssl)] public static partial nint TLS_client_method();
    [LibraryImport(Ssl)] public static partial nint SSL_CTX_new(nint method);
    [LibraryImport(Ssl)] public static partial void SSL_CTX_free(nint ctx);
    [LibraryImport(Ssl)] public static partial long SSL_CTX_ctrl(nint ctx, int cmd, long arg, nint parg);

    /// <summary>Trust anchors from the system store (/etc/ssl/certs and friends).</summary>
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_default_verify_paths(nint ctx);

    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_load_verify_locations(nint ctx, string? caFile, string? caPath);

    [LibraryImport(Ssl)] public static partial void SSL_CTX_set_verify(nint ctx, int mode, nint callback);

    // --- client certificate (mutual TLS) ----------------------------------------------------------

    /// <summary>
    /// Our own certificate, PEM. The "chain" form because an origin verifying us needs the
    /// intermediates too: leaf-only works against a store that already holds them and fails
    /// everywhere else, which is the worst way for this to break.
    /// </summary>
    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_use_certificate_chain_file(nint ctx, string file);

    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_use_PrivateKey_file(nint ctx, string file, int type);

    /// <summary>Confirms the key matches the certificate, rather than failing mid-handshake.</summary>
    [LibraryImport(Ssl)] public static partial int SSL_CTX_check_private_key(nint ctx);

    /// <summary>PEM, for <see cref="SSL_CTX_use_PrivateKey_file"/>.</summary>
    public const int SSL_FILETYPE_PEM = 1;

    /// <summary>Protocols we offer, as a length-prefixed wire list. Returns 0 on SUCCESS.</summary>
    [LibraryImport(Ssl)] public static partial int SSL_CTX_set_alpn_protos(nint ctx, byte* protos, uint length);

    // --- connection ------------------------------------------------------------------------------

    [LibraryImport(Ssl)] public static partial nint SSL_new(nint ctx);
    [LibraryImport(Ssl)] public static partial void SSL_free(nint ssl);
    [LibraryImport(Ssl)] public static partial void SSL_set_connect_state(nint ssl);
    [LibraryImport(Ssl)] public static partial void SSL_set_bio(nint ssl, nint rbio, nint wbio);
    [LibraryImport(Ssl)] private static partial int SSL_connect(nint ssl);
    [LibraryImport(Ssl)] private static partial int SSL_read(nint ssl, byte* buf, int num);
    [LibraryImport(Ssl)] private static partial int SSL_write(nint ssl, byte* buf, int num);
    [LibraryImport(Ssl)] public static partial int SSL_shutdown(nint ssl);
    [LibraryImport(Ssl)] private static partial int SSL_get_error(nint ssl, int ret);
    [LibraryImport(Ssl)] public static partial int SSL_in_init(nint ssl);
    [LibraryImport(Crypto)] public static partial void ERR_clear_error();

    /// <summary>
    /// The three operations whose result has to be classified, each performed from a CLEAN error
    /// queue and returning what the classification said.
    /// </summary>
    /// <remarks>
    /// The clear, the call and the classify are one operation and are deliberately not offered
    /// apart - the raw entry points above are private so that they cannot be.
    ///
    /// OpenSSL's error queue belongs to the THREAD, which here is a reactor shared by every pooled
    /// upstream connection on it, and SSL_get_error consults that queue BEFORE asking the SSL
    /// whether it merely wants more data. So a residue left by any other connection - most
    /// reliably by a teardown calling SSL_shutdown on a handshake that never finished - is read as
    /// THIS connection's fatal error and kills it.
    /// </remarks>
    public static unsafe int Connect(nint ssl, out int error)
    {
        ERR_clear_error();
        int ret = SSL_connect(ssl);
        error = ret == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl, ret);
        return ret;
    }

    /// <inheritdoc cref="Connect"/>
    public static unsafe int Read(nint ssl, byte* buf, int num, out int error)
    {
        ERR_clear_error();
        int n = SSL_read(ssl, buf, num);
        error = n > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl, n);
        return n;
    }

    /// <inheritdoc cref="Connect"/>
    public static unsafe int Write(nint ssl, byte* buf, int num, out int error)
    {
        ERR_clear_error();
        int n = SSL_write(ssl, buf, num);
        error = n > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl, n);
        return n;
    }
    [LibraryImport(Ssl)] public static partial long SSL_ctrl(nint ssl, int cmd, long larg, nint parg);

    /// <summary>
    /// The hostname the peer certificate must match. Distinct from SNI: SNI tells the server which
    /// certificate to send, this checks the one it sent. Both are needed.
    /// </summary>
    [LibraryImport(Ssl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_set1_host(nint ssl, string hostname);

    [LibraryImport(Ssl)] public static partial long SSL_get_verify_result(nint ssl);
    [LibraryImport(Ssl)] public static partial void SSL_get0_alpn_selected(nint ssl, byte** data, uint* length);

    // --- memory BIOs -----------------------------------------------------------------------------

    [LibraryImport(Crypto)] public static partial nint BIO_new(nint type);
    [LibraryImport(Crypto)] public static partial nint BIO_s_mem();
    [LibraryImport(Crypto)] public static partial int BIO_free(nint bio);
    [LibraryImport(Crypto)] public static partial int BIO_write(nint bio, byte* data, int dlen);
    [LibraryImport(Crypto)] public static partial int BIO_read(nint bio, byte* data, int dlen);
    [LibraryImport(Crypto)] public static partial nuint BIO_ctrl_pending(nint bio);

    // --- errors ----------------------------------------------------------------------------------

    [LibraryImport(Crypto)] public static partial ulong ERR_get_error();
    [LibraryImport(Crypto)] public static partial void ERR_error_string_n(ulong e, byte* buf, nuint len);

    public static string LastError()
    {
        ulong code = ERR_get_error();
        if (code == 0)
        {
            return "no OpenSSL error";
        }

        Span<byte> buffer = stackalloc byte[256];
        string message;
        fixed (byte* p = buffer)
        {
            ERR_error_string_n(code, p, (nuint)buffer.Length);
            message = Marshal.PtrToStringUTF8((nint)p) ?? code.ToString();
        }

        // Drain any piggy-backed errors so the next LastError() isn't stale.
        while (ERR_get_error() != 0)
        {
        }
        return message;
    }
}
