using System.IO.Pipelines;

namespace ioxide.tls;

/// <summary>
/// A duplex pipe over a TLS connection, for the frameworks that serve from <see cref="IDuplexPipe"/>
/// rather than from the raw ring.
///
/// This composes rather than implements. Each direction has exactly two possible halves, and which
/// one applies is not a choice the caller makes - it is what the handshake actually achieved:
///
/// <code>
///                  kTLS (opt-in)                   OpenSSL (default)
///   read     TcpConnectionPipeReader         TlsDecryptingPipeReader
///   write    TcpConnectionPipeWriter         TlsEncryptingPipeWriter
///
/// The kTLS column is the plaintext connection's own reader and writer, reused unchanged: with the
/// kernel doing the crypto there is nothing for a TLS-specific half to do. The OpenSSL column is
/// the pair that has to exist - one decrypts into a Pipe it owns, the other encrypts before the
/// bytes reach the slab.
/// </code>
///
/// <see cref="TlsOptions.KernelRx"/> and <see cref="TlsOptions.KernelTx"/> express intent;
/// <see cref="TlsService"/> decides per connection at the handoff, because intent is not always
/// achievable - a handshake that left a partial record in the BIO cannot hand off to kTLS RX at
/// all, and that connection silently keeps the userspace reader. <see cref="TlsSession"/> then
/// reports the OUTCOME, which is what this reads.
/// </summary>
/// <remarks>Reactor thread only, like everything else that touches a connection.</remarks>
public sealed class TlsConnectionDualPipe : ITcpConnectionPipe, IAsyncDisposable
{
    private readonly TcpConnection _conn;
    private readonly TlsSession _tls;
    private readonly bool _ownsSession;

    private readonly TlsDecryptingPipeReader? _pump;      // only when OpenSSL decrypts
    private readonly PipeWriter _writer;

    /// <summary>
    /// Wrap a connection whose TLS handshake has already completed (see
    /// <see cref="TlsService.AcceptAsync"/>).
    /// </summary>
    /// <param name="connection">The accepted connection, post-handshake.</param>
    /// <param name="session">The session that handshake produced.</param>
    /// <param name="options">
    /// Buffering for the inbound pipe, when there is one - pool, thresholds and segment size.
    /// Schedulers are NOT taken from it: the pipe forces Inline both ways, because anything else
    /// hands the connection to a pool thread the reactor never gets back. Ignored under kTLS RX,
    /// which needs no buffer of its own: its pause threshold is the ring.
    /// </param>
    /// <param name="ownsSession">
    /// When true (the default) disposing this also disposes <paramref name="session"/>, which is
    /// what sends the closing close_notify.
    /// </param>
    public TlsConnectionDualPipe(TcpConnection connection, TlsSession session,
        PipeOptions? options = null, bool ownsSession = true)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(session);

        _conn = connection;
        _tls = session;
        _ownsSession = ownsSession;

        if (session.KernelRx)
        {
            // The kernel decrypted, so plaintext is in ring memory and the ordinary zero-copy
            // reader serves it. The one thing it cannot know about is plaintext the HANDSHAKE
            // decrypted - that lives in the session, and for h2 it is the connection preface.
            Input = new TlsProloguePipeReader(new TcpConnectionPipeReader(connection),
                session.DrainPlaintext());
        }
        else
        {
            _pump = new TlsDecryptingPipeReader(connection, session, options);
            Input = _pump;
        }

        // Default is OpenSSL: encrypt before the bytes reach the slab. With kTLS opted in the
        // kernel makes the records instead, so the plaintext connection's own writer is enough.
        _writer = session.KernelTx
            ? new TcpConnectionPipeWriter(connection)
            : new TlsEncryptingPipeWriter(connection, session);
    }

    /// <summary>Decrypted request bytes.</summary>
    public PipeReader Input { get; }

    /// <summary>Response bytes. Plaintext under kTLS TX; encrypted here otherwise.</summary>
    public PipeWriter Output => _writer;

    /// <summary>The connection underneath, carrying ciphertext.</summary>
    public TcpConnection Connection => _conn;

    public async ValueTask DisposeAsync()
    {
        // Write side first, while the connection still sends: Complete() commits any advanced-but-
        // unflushed plaintext into the slab, and the flush carries it out. The read side's disposal
        // marks the connection closed (nothing else releases a pump parked on a quiet peer), and
        // after that a flush is a no-op - so this order is load-bearing, not stylistic.
        //
        // FlushIfIdleAsync rather than FlushAsync, because this flush is the connection's, not the
        // application's. A handler that left a flush in flight - wrote, stopped waiting on a peer
        // that was not draining, and tore down - met the one-flush-at-a-time guard here and had
        // the InvalidOperationException come out of its teardown as a faulted connection handler
        // (#234). There is nothing to carry out in that state anyway: the in-flight send owns the
        // whole slab, and the write guards have refused everything since it armed.
        try
        {
            _writer.Complete();
            await _conn.FlushIfIdleAsync();
        }
        finally
        {
            // Releasing the connection is not conditional on the write side having gone well. It
            // used to be: a decrypt fault leaves the session unable to encrypt, Complete threw from
            // the first line, and everything below - the pump, the session, the fd - was skipped.
            if (_pump is not null)
            {
                await _pump.DisposeAsync();
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
