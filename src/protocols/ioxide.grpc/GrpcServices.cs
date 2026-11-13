using System.Diagnostics.CodeAnalysis;
using System.Text;
using Grpc.Core;
using ioxide.http2;

namespace ioxide.grpc;

/// <summary>
/// gRPC services served over <c>ioxide.http2</c>: the table a connection's streams dispatch into.
/// Services are the base classes Grpc.Tools generates, bound through the BindService it generates with them.
///
/// <code>
/// var grpc = new GrpcServices().Add(Greeter.BindService, new GreeterService());
///
/// reactor.TcpHandle = (r, conn) =>
///     new Http2Connection(conn).RunAsync(grpc.HandleAsync);
/// </code>
///
/// It serves h2c, or h2 over TLS negotiated by ALPN, and a connection that serves other HTTP/2 traffic
/// too routes the streams <see cref="IsGrpc"/> picks out. The handler takes a body reader, as client
/// and bidirectional streaming need the request while it still arrives.
/// </summary>
/// <remarks>
/// Bind every service before serving: the table is read by every reactor at once and is only safe
/// to read. A call starts on the reactor that owns its connection, like any other ioxide handler, so
/// a service method that blocks there stalls every connection on that reactor. Deadlines are reported in
/// <see cref="ServerCallContext.Deadline"/> and are kept by the client, which cancels the call when
/// it passes; a cancellation reaches the method through <see cref="ServerCallContext.CancellationToken"/>.
/// </remarks>
public sealed class GrpcServices
{
    private readonly GrpcOptions _options;
    private readonly Dictionary<byte[], MethodHandler> _methods = new(PathComparer.Instance);
    private readonly Dictionary<byte[], MethodHandler>.AlternateLookup<ReadOnlySpan<byte>> _byPath;

    public GrpcServices(GrpcOptions? options = null)
    {
        _options = options ?? new GrpcOptions();
        _byPath = _methods.GetAlternateLookup<ReadOnlySpan<byte>>();
    }

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

    /// <summary>Serve one stream of an <c>ioxide.http2</c> connection as a gRPC call.</summary>
    public ValueTask HandleAsync(Http2Request request, Http2BodyReader body, Http2ResponseWriter writer)
        => new GrpcCall(_options, request, body, writer).ServeAsync(this);

    internal bool TryFind(ReadOnlySpan<byte> path, [NotNullWhen(true)] out MethodHandler? method)
        => _byPath.TryGetValue(path, out method);

    private void Map(string fullName, MethodHandler handler)
    {
        if (!_methods.TryAdd(Encoding.ASCII.GetBytes(fullName), handler))
        {
            throw new InvalidOperationException($"{fullName} is already bound.");
        }
    }

    // The generated binder passes a null handler only for a null service, which Add refuses.
    private sealed class Binder(GrpcServices services) : ServiceBinderBase
    {
        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            UnaryServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, new UnaryHandler<TRequest, TResponse>(method, handler!));

        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            ClientStreamingServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, new ClientStreamingHandler<TRequest, TResponse>(method, handler!));

        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            ServerStreamingServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, new ServerStreamingHandler<TRequest, TResponse>(method, handler!));

        public override void AddMethod<TRequest, TResponse>(Method<TRequest, TResponse> method,
            DuplexStreamingServerMethod<TRequest, TResponse>? handler)
            => services.Map(method.FullName, new DuplexStreamingHandler<TRequest, TResponse>(method, handler!));
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
