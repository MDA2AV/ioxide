using System.IO.Pipelines;

namespace epoxide.tls;

/// <summary>
/// A duplex pipe over a TLS connection, for the frameworks that serve from <see cref="IDuplexPipe"/>
/// rather than from the raw connection.
///
/// This composes rather than implements. Each direction has exactly two possible halves, and which
/// one applies is not a choice the caller makes - it is what the handshake actually achieved:
///
/// <code>
///                  kTLS (opt-in)                   BoringSSL (default)
///   read     TcpConnectionPipeReader         TlsDecryptingPipeReader
///   write    TcpConnectionPipeWriter         TlsEncryptingPipeWriter
///
/// The kTLS column is the plaintext connection's own reader and writer, reused unchanged: with the
/// kernel doing the crypto there is nothing for a TLS-specific half to do. The BoringSSL column is
/// the pair that has to exist - one decrypts into a Pipe it owns, the other encrypts before the
/// bytes reach the slab.
/// </code>
///
/// <see cref="TlsOptions.KernelRx"/> and <see cref="TlsOptions.KernelTx"/> express intent;
/// <see cref="TlsService"/> decides per connection at the handoff, because intent is not always
/// achievable - a connection whose records keep arriving cut past the handoff's bound never hands
/// off to kTLS RX, and keeps the userspace reader. <see cref="TlsSession"/> then reports the
/// OUTCOME, which is what this reads.
/// </summary>
/// <remarks>
/// Any thread, like the connection: one reader and one writer at a time, and the two may be on
/// different threads at once - the session serializes the crypto between them.
/// </remarks>
public sealed class TlsConnectionDualPipe : IDuplexPipe, IAsyncDisposable
{
    private readonly TcpConnection _conn;
    private readonly TlsSession _tls;
    private readonly bool _ownsSession;

    private readonly TlsDecryptingPipeReader? _decrypting;   // only when BoringSSL decrypts
    private readonly PipeWriter _writer;

    /// <summary>
    /// Wrap a connection whose TLS handshake has already completed (see
    /// <see cref="TlsService.AcceptAsync"/>).
    /// </summary>
    /// <param name="connection">The accepted connection, post-handshake.</param>
    /// <param name="session">The session that handshake produced.</param>
    /// <param name="ownsSession">
    /// When true (the default) disposing this also disposes <paramref name="session"/>, which is
    /// what sends the closing close_notify.
    /// </param>
    public TlsConnectionDualPipe(TcpConnection connection, TlsSession session, bool ownsSession = true)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(session);

        _conn = connection;
        _tls = session;
        _ownsSession = ownsSession;

        if (session.KernelRx)
        {
            // The kernel decrypted, so plaintext is in the recv buffers and the ordinary zero-copy
            // reader serves it. The one thing it cannot know about is plaintext the HANDSHAKE
            // decrypted - that lives in the session, and for h2 it is the connection preface.
            Input = new TlsProloguePipeReader(new TcpConnectionPipeReader(connection),
                session.DrainPlaintext());
        }
        else
        {
            _decrypting = new TlsDecryptingPipeReader(connection, session);
            Input = _decrypting;
        }

        // Default is BoringSSL: encrypt before the bytes reach the slab. With kTLS opted in the
        // kernel makes the records instead, so the plaintext connection's own writer is enough.
        _writer = session.KernelTx
            ? new TcpConnectionPipeWriter(connection)
            : new TlsEncryptingPipeWriter(connection, session);
    }

    /// <summary>Decrypted request bytes.</summary>
    public PipeReader Input { get; }

    /// <summary>Response bytes. Plaintext under kTLS TX; encrypted here otherwise.</summary>
    public PipeWriter Output => _writer;

    public async ValueTask DisposeAsync()
    {
        // Write side first, while the connection still sends: Complete() commits any advanced-but-
        // unflushed plaintext into the slab, and the flush carries it out, before the session's
        // close_notify goes out behind it.
        //
        // FlushIfIdleAsync rather than FlushAsync, because this flush is the connection's, not the
        // application's. A handler that left a flush in flight - wrote, stopped waiting on a peer
        // that was not draining, and tore down - met the one-flush-at-a-time guard here and had
        // the InvalidOperationException come out of its teardown as a faulted connection handler.
        // There is nothing to carry out in that state anyway: the in-flight send owns the whole
        // slab, and the write guards have refused everything since it armed.
        try
        {
            _writer.Complete();
            await _conn.FlushIfIdleAsync();
        }
        finally
        {
            // Releasing the connection is not conditional on the write side having gone well. It
            // used to be: a decrypt fault leaves the session unable to encrypt, Complete threw from
            // the first line, and everything below - the reader, the session, the fd - was skipped.
            if (_decrypting is not null)
            {
                await _decrypting.DisposeAsync();
            }
            else
            {
                Input.Complete();
            }

            if (_ownsSession)
            {
                _tls.Dispose();   // sends close_notify when the peer has not already closed, both modes
            }
        }
    }
}
