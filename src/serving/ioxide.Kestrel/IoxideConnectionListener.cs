using System.Net;
using System.Threading.Channels;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using ioxide;
using ioxide.tls;

namespace ioxide.Kestrel;

/// <summary>
/// Runs a fleet of ioxide reactors (one io_uring ring + thread each, SO_REUSEPORT load-balanced) and
/// bridges ioxide's push model (per-connection <c>Handle</c> callback on the reactor thread) to Kestrel's
/// pull model (<see cref="AcceptAsync"/>). The Handle callback wraps each connection, pushes it onto a
/// channel for Kestrel to dequeue, starts the transport pumps, and then parks until Kestrel disposes the
/// connection - keeping the connection's handler-side ref alive for its whole Kestrel lifetime.
/// </summary>
internal sealed class IoxideConnectionListener : IConnectionListener
{
    private readonly ILogger<IoxideConnectionListener> _logger;
    private readonly Channel<ConnectionContext> _accepted;
    private readonly Reactor[] _reactors;
    private readonly Thread[] _threads;
    private readonly TlsOptions? _tlsOptions;
    private long _connectionCounter;
    private int _stopped;

    public EndPoint EndPoint { get; }

    public IoxideConnectionListener(IPEndPoint endpoint, IoxideTransportOptions options, TlsOptions? tlsOptions, ILogger<IoxideConnectionListener> logger)
    {
        EndPoint = endpoint;
        _logger = logger;
        _tlsOptions = tlsOptions;

        _accepted = Channel.CreateUnbounded<ConnectionContext>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });

        var reactorCount = Math.Max(1, options.ReactorCount);

        var cfg = new ServerConfig { ReactorCount = reactorCount, Tcp = new TcpOptions { Port = (ushort)endpoint.Port } };
        if (options.ConfigureServer is not null)
        {
            cfg = options.ConfigureServer(cfg);
        }
        // ConfigureServer may have nulled Tcp out; Kestrel always needs a listener, so re-establish
        // one rather than silently binding nothing.
        cfg = cfg with
        {
            Tcp = (cfg.Tcp ?? new TcpOptions()) with { Port = (ushort)endpoint.Port },
            ReactorCount = reactorCount,
        };

        _reactors = new Reactor[reactorCount];
        _threads = new Thread[reactorCount];

        for (var i = 0; i < reactorCount; i++)
        {
            var reactor = new Reactor(i, cfg)
            {
                TcpHandle = HandleConnectionAsync,
            };
            // Per-reactor startup, on the reactor's own thread: bind the current-reactor seam (so Kestrel
            // endpoints can resolve ring-native services), start the TLS service if configured, then run
            // the user's hook (PgPool.Start, AssetReader.CreatePool, ...).
            var tls = _tlsOptions;
            var onReactorStart = options.OnReactorStart;
            reactor.OnStart = r =>
            {
                IoxideReactor.Bind(r);
                if (tls is not null)
                {
                    TlsService.Start(r, tls);
                }
                onReactorStart?.Invoke(r);
            };
            _reactors[i] = reactor;
            _threads[i] = new Thread(reactor.Run)
            {
                Name = $"ioxide-reactor-{i}",
                IsBackground = true,
            };
        }

        foreach (var thread in _threads)
        {
            thread.Start();
        }

        _logger.LogInformation("[ioxide] Bound {Endpoint} with {ReactorCount} reactor(s)", endpoint, reactorCount);
    }

    // Runs on the reactor thread, fire-and-forget, once per accepted connection.
    private async Task HandleConnectionAsync(Reactor reactor, TcpConnection conn)
    {
        var id = Interlocked.Increment(ref _connectionCounter);

        // TLS handshake (TLS endpoints only) runs here on the reactor thread, before Kestrel sees the
        // connection; the returned session decrypts inbound records - Kestrel gets plaintext.
        TlsSession? session = null;
        if (_tlsOptions is not null)
        {
            try
            {
                session = await reactor.GetService<TlsService>().AcceptAsync(conn).ConfigureAwait(false);
            }
            catch
            {
                // Handshake failed (bad client, peer closed mid-handshake): drop the connection.
                conn.DecRef();
                return;
            }
        }

        // What ALPN actually settled on, not what was advertised. Passing the configured value
        // made ITlsApplicationProtocolFeature report a protocol even when the client offered none
        // of ours and the handshake completed without the extension.
        var ctx = new IoxideConnectionContext(conn, reactor, EndPoint, id, session, session?.NegotiatedAlpn);

        if (!_accepted.Writer.TryWrite(ctx))
        {
            // Listener is shutting down: nobody will dequeue this. Release immediately.
            await ctx.DisposeAsync().ConfigureAwait(false);
            conn.DecRef();
            return;
        }

        ctx.StartPumps();

        // Park until Kestrel disposes the connection, then release the handler-side ref (-> recycle).
        await ctx.Completion.ConfigureAwait(false);
        conn.DecRef();
    }

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await _accepted.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (ChannelClosedException)
        {
            return null;
        }
    }

    public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _stopped, 1) == 0)
        {
            _accepted.Writer.TryComplete();
            _logger.LogInformation("[ioxide] Unbound listener on {Endpoint}", EndPoint);
        }
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _accepted.Writer.TryComplete();

        await Task.Run(() =>
        {
            foreach (var reactor in _reactors)
            {
                reactor.Stop();
            }
            foreach (var thread in _threads)
            {
                thread.Join(TimeSpan.FromSeconds(5));
            }
        }).ConfigureAwait(false);

        _logger.LogInformation("[ioxide] Stopped {ReactorCount} reactor(s) on {Endpoint}", _reactors.Length, EndPoint);
    }
}
