using System.IO.Pipelines;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using ioxide;
using ioxide.tls;

namespace ioxide.Kestrel;

/// <summary>
/// Adapts a single ioxide <see cref="TcpConnection"/> to Kestrel's <see cref="ConnectionContext"/>. The
/// transport is a <see cref="HopDuplexPipe"/> (BCL pipes whose reader schedulers route to the reactor),
/// so Kestrel's read → parse → handle → send loop runs pinned to the reactor thread.
/// </summary>
internal sealed class IoxideConnectionContext : ConnectionContext,
    IConnectionIdFeature,
    IConnectionTransportFeature,
    IConnectionItemsFeature,
    IConnectionLifetimeFeature,
    IConnectionEndPointFeature,
    IReactorFeature
{
    private readonly HopDuplexPipe _pipe;
    private readonly Reactor _reactor;
    private readonly CancellationTokenSource _connectionClosedCts = new();
    private readonly FeatureCollection _features = new();

    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private int _disposed;

    public IoxideConnectionContext(TcpConnection connection, Reactor reactor, EndPoint localEndPoint, long id, TlsSession? session = null, string? alpn = null)
    {
        _pipe = new HopDuplexPipe(connection, reactor, session);
        _reactor = reactor;

        ConnectionId = $"ioxide-{id:x}";
        LocalEndPoint = localEndPoint;
        RemoteEndPoint = null;
        Items = new ConnectionItems();
        ConnectionClosed = _connectionClosedCts.Token;

        _features.Set<IConnectionIdFeature>(this);
        _features.Set<IConnectionTransportFeature>(this);
        _features.Set<IConnectionItemsFeature>(this);
        _features.Set<IConnectionLifetimeFeature>(this);
        _features.Set<IConnectionEndPointFeature>(this);
        _features.Set<IReactorFeature>(this);

        if (session is not null)
        {
            // TLS terminated in the transport (kTLS): present the connection to Kestrel as HTTPS with the
            // negotiated ALPN, in place of UseHttps()/SslStream.
            var tlsFeature = new IoxideTlsFeature(Encoding.ASCII.GetBytes(alpn ?? "http/1.1"), session);
            _features.Set<ITlsConnectionFeature>(tlsFeature);
            _features.Set<ITlsHandshakeFeature>(tlsFeature);
            _features.Set<ITlsApplicationProtocolFeature>(tlsFeature);
        }
    }

    /// <summary>Resolves once Kestrel has finished with this connection; the reactor's Handle callback awaits it.</summary>
    public Task Completion => _completion.Task;

    /// <summary>Launches the transport pumps. Must be called on the reactor thread (from the Handle callback).</summary>
    public void StartPumps() => _pipe.Start();

    /// <summary>The reactor that owns this connection (<see cref="IReactorFeature"/>).</summary>
    public Reactor Reactor => _reactor;

    public override string ConnectionId { get; set; }
    public override IFeatureCollection Features => _features;
    public override IDictionary<object, object?> Items { get; set; }

    public override IDuplexPipe Transport
    {
        get => _pipe;
        set => throw new NotSupportedException("Transport is owned by the ioxide transport adapter.");
    }

    public override CancellationToken ConnectionClosed { get; set; }
    public override EndPoint? LocalEndPoint { get; set; }
    public override EndPoint? RemoteEndPoint { get; set; }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        // Forced close: signal the lifetime token. The pumps are unwound (reactor-safely) in DisposeAsync,
        // which Kestrel calls during connection cleanup after Abort.
        try
        {
            _connectionClosedCts.Cancel();
        } catch { /* ignore */ }
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        try
        {
            _connectionClosedCts.Cancel();
        } catch { /* ignore */ }

        // Unwind the recv/send pumps (returns held recv buffers, stops the send loop).
        await _pipe.DisposeAsync().ConfigureAwait(false);

        _connectionClosedCts.Dispose();

        // Release the reactor's Handle callback, which DecRefs the connection (-> recycle).
        _completion.TrySetResult();
    }
}
