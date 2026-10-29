using System.Diagnostics.CodeAnalysis;
using System.Text;
using Grpc.Core;
using ioxide.http2;
using ioxide.nghttp2;

namespace ioxide.grpc;

/// <summary>
/// gRPC services served over ioxide's HTTP/2: the table a connection's streams dispatch into. Services
/// are the base classes Grpc.Tools generates, bound through the BindService it generates with them.
///
/// <code>
/// var grpc = new GrpcServices().Add(Greeter.BindService, new GreeterService());
///
/// reactor.TcpHandle = (r, conn) =>
///     new Http2Connection(conn, GrpcServices.Http2Options).RunAsync(grpc.HandleAsync);
/// </code>
///
/// Either HTTP/2 stack serves it - <c>new Nghttp2Connection(conn, GrpcServices.Nghttp2Options)</c>
/// takes the same <see cref="HandleAsync(Nghttp2Request, Nghttp2ResponseWriter)"/> - over h2c or
/// over TLS with ALPN h2, and a connection that serves other HTTP/2 traffic too routes the streams
/// <see cref="IsGrpc(Http2Request)"/> picks out.
/// </summary>
/// <remarks>
/// Bind every service before serving: the table is read by every reactor at once and is only safe
/// to read. Calls run on the reactor that owns their connection, like any other ioxide handler, so a
/// service method that blocks stalls every connection on that reactor. Deadlines are reported in
/// <see cref="ServerCallContext.Deadline"/> and are kept by the client, which cancels the call when
/// it passes; a cancellation reaches the method through <see cref="ServerCallContext.CancellationToken"/>.
/// </remarks>
public sealed class GrpcServices
{
    /// <summary>
    /// For an <c>ioxide.http2</c> connection serving gRPC: request bodies stream, which client and
    /// bidirectional streaming need. A buffered connection still serves unary and server-streaming calls.
    /// </summary>
    public static Http2Options Http2Options { get; } = new() { StreamRequestBodies = true };

    /// <summary>The same for an <c>ioxide.nghttp2</c> connection.</summary>
    public static Nghttp2Options Nghttp2Options { get; } = new() { StreamRequestBodies = true };

    private readonly Dictionary<byte[], MethodHandler> _methods = new(PathComparer.Instance);
    private readonly Dictionary<byte[], MethodHandler>.AlternateLookup<ReadOnlySpan<byte>> _byPath;

    public GrpcServices(GrpcOptions? options = null)
    {
        Options = options ?? new GrpcOptions();
        _byPath = _methods.GetAlternateLookup<ReadOnlySpan<byte>>();
    }

    public GrpcOptions Options { get; }

    /// <summary>
    /// Bind a service: <c>Add(Greeter.BindService, new GreeterService())</c>. Each of its methods is
    /// served at <c>/package.Service/Method</c>.
    /// </summary>
    public GrpcServices Add<TService>(Action<ServiceBinderBase, TService> bindService, TService service)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(bindService);
        ArgumentNullException.ThrowIfNull(service);

        bindService(new Binder(this), service);
        return this;
    }

    /// <summary>True for a request whose content-type is application/grpc, or one of its +format forms.</summary>
    public static bool IsGrpc(Http2Request request)
        => request.TryGetHeader(GrpcProtocol.ContentTypeName, out ReadOnlyMemory<byte> value)
           && GrpcProtocol.IsGrpcContentType(value.Span);

    /// <inheritdoc cref="IsGrpc(Http2Request)"/>
    public static bool IsGrpc(Nghttp2Request request)
        => request.TryGetHeader(GrpcProtocol.ContentTypeName, out ReadOnlyMemory<byte> value)
           && GrpcProtocol.IsGrpcContentType(value.Span);

    /// <summary>Serve one stream of an <c>ioxide.http2</c> connection as a gRPC call.</summary>
    public ValueTask HandleAsync(Http2Request request, Http2ResponseWriter writer)
        => ServeAsync(new Http2Call(Options, request, writer));

    /// <summary>Serve one stream of an <c>ioxide.nghttp2</c> connection as a gRPC call.</summary>
    public ValueTask HandleAsync(Nghttp2Request request, Nghttp2ResponseWriter writer)
        => ServeAsync(new Nghttp2Call(Options, request, writer));

    internal bool TryFind(ReadOnlySpan<byte> path, [NotNullWhen(true)] out MethodHandler? method)
        => _byPath.TryGetValue(path, out method);

    private async ValueTask ServeAsync(GrpcCall call)
    {
        try
        {
            await call.ServeAsync(this);
        }
        finally
        {
            call.Release();
        }
    }

    private void Map(string fullName, MethodHandler? handler)
    {
        // The generated binder passes null when it only describes a service; there is nothing to serve then.
        if (handler is not null && !_methods.TryAdd(Encoding.ASCII.GetBytes(fullName), handler))
        {
            throw new InvalidOperationException($"{fullName} is already bound.");
        }
    }

    private sealed class Binder(GrpcServices services) : ServiceBinderBase
    {
        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            UnaryServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, handler is null ? null : new UnaryHandler<TRequest, TResponse>(method, handler));

        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            ClientStreamingServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, handler is null ? null : new ClientStreamingHandler<TRequest, TResponse>(method, handler));

        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            ServerStreamingServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, handler is null ? null : new ServerStreamingHandler<TRequest, TResponse>(method, handler));

        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            DuplexStreamingServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, handler is null ? null : new DuplexStreamingHandler<TRequest, TResponse>(method, handler));
    }

    // Routes by the :path bytes as they arrived, so finding a method decodes and allocates nothing.
    private sealed class PathComparer : IEqualityComparer<byte[]>, IAlternateEqualityComparer<ReadOnlySpan<byte>, byte[]>
    {
        public static readonly PathComparer Instance = new();

        public bool Equals(byte[]? x, byte[]? y) => x.AsSpan().SequenceEqual(y);

        public int GetHashCode(byte[] path) => GetHashCode(path.AsSpan());

        public bool Equals(ReadOnlySpan<byte> alternate, byte[] other) => alternate.SequenceEqual(other);

        public int GetHashCode(ReadOnlySpan<byte> alternate)
        {
            var hash = new HashCode();
            hash.AddBytes(alternate);
            return hash.ToHashCode();
        }

        public byte[] Create(ReadOnlySpan<byte> alternate) => alternate.ToArray();
    }
}
