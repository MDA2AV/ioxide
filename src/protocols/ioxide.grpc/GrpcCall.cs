using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Runtime.ExceptionServices;
using System.Text;
using Grpc.Core;

namespace ioxide.grpc;

/// <summary>
/// One gRPC call on one HTTP/2 stream, and the <see cref="ServerCallContext"/> its service method
/// sees. Framing, status and metadata live here; the stream is reached through the members each
/// HTTP/2 stack's subclass implements.
/// </summary>
/// <remarks>Reactor thread only, like the stream under it.</remarks>
internal abstract class GrpcCall : ServerCallContext
{
    private readonly GrpcOptions _options;
    private MethodHandler? _method;

    // Request side: the rest of the body chunk being parsed, and a message that straddled chunks.
    private ReadOnlyMemory<byte> _chunk;
    private byte[]? _partial;
    private int _partialLength;
    private bool _requestEnded;
    private string? _requestEncoding;   // grpc-encoding, when the client named one other than identity

    // Response side.
    private bool _headersSent;
    private bool _completed;
    private bool _torn;   // a message failed half-written, so only a reset ends the stream honestly
    private Metadata? _responseHeaders;
    private Metadata? _responseTrailers;

    private Metadata? _requestHeaders;
    private DateTime _deadline = DateTime.MaxValue;
    private string? _host;
    private AuthContext? _authContext;

    protected GrpcCall(GrpcOptions options) => _options = options;

    // ---- the stream, one implementation per HTTP/2 stack ----

    private protected abstract ReadOnlyMemory<byte> HttpMethod { get; }
    private protected abstract ReadOnlyMemory<byte> Path { get; }
    private protected abstract ReadOnlyMemory<byte> Authority { get; }
    private protected abstract ReadOnlySpan<KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>> RequestFields { get; }

    /// <summary>The next request body chunk; empty at its end, or once the stream is aborted.</summary>
    private protected abstract ValueTask<ReadOnlyMemory<byte>> ReadBodyAsync();

    private protected abstract IBufferWriter<byte> Body { get; }
    private protected abstract ValueTask<FlushResult> FlushBodyAsync();
    private protected abstract bool IsAborted { get; }
    private protected abstract CancellationToken Aborted { get; }

    /// <summary>:status 200 and content-type application/grpc, then <paramref name="metadata"/>.</summary>
    private protected abstract void SendHeaders(Metadata? metadata, bool acceptEncoding);

    private protected abstract ValueTask SendTrailersAsync(Status status, Metadata? trailers);

    /// <summary>A request that is no gRPC call at all: its HTTP status, with a gRPC status beside it.</summary>
    private protected abstract ValueTask RefuseAsync(int httpStatus, Status status);

    // ---- dispatch ----

    /// <summary>Check the request is a call, find its method and run it.</summary>
    internal ValueTask ServeAsync(GrpcServices services)
    {
        if (!HttpMethod.Span.SequenceEqual("POST"u8))
        {
            return RefuseAsync(405, new Status(StatusCode.Internal, "gRPC calls are POST requests."));
        }

        bool grpc = false;
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in RequestFields)
        {
            ReadOnlySpan<byte> name = field.Key.Span;
            if (name.SequenceEqual(GrpcProtocol.ContentTypeName))
            {
                grpc = GrpcProtocol.IsGrpcContentType(field.Value.Span);
            }
            else if (name.SequenceEqual("grpc-timeout"u8) && GrpcProtocol.TryParseTimeout(field.Value.Span, out TimeSpan timeout))
            {
                DateTime now = DateTime.UtcNow;
                _deadline = timeout >= DateTime.MaxValue - now ? DateTime.MaxValue : now + timeout;
            }
            else if (name.SequenceEqual("grpc-encoding"u8) && !field.Value.Span.SequenceEqual(GrpcProtocol.Identity))
            {
                _requestEncoding = Encoding.ASCII.GetString(field.Value.Span);
            }
        }

        if (!grpc)
        {
            return RefuseAsync(415, new Status(StatusCode.Internal, "The content-type is not application/grpc."));
        }

        if (!services.TryFind(Path.Span, out MethodHandler? method))
        {
            return FinishAsync(new Status(StatusCode.Unimplemented, "Method is unimplemented."));
        }

        _method = method;
        return method.HandleAsync(this);
    }

    /// <summary>The call is over: its request buffer goes back.</summary>
    internal void Release()
    {
        if (_partial is not null)
        {
            ArrayPool<byte>.Shared.Return(_partial);
            _partial = null;
        }
        _chunk = default;
    }

    // ---- request messages ----

    /// <summary>The next request message, or false once the client has half-closed.</summary>
    internal async ValueTask<(bool Read, T Message)> ReadMessageAsync<T>(Marshaller<T> marshaller)
    {
        while (true)
        {
            if (TryTakeMessage(out ReadOnlyMemory<byte> payload))
            {
                return (true, MessageReader.Deserialize(marshaller, payload));
            }

            if (_requestEnded)
            {
                if (_partialLength > 0)
                {
                    throw new RpcException(new Status(StatusCode.Internal, "The request ended inside a message."));
                }
                return (false, default!);
            }

            await NextChunkAsync();
        }
    }

    /// <summary>A unary request: exactly one message, then the end of the request.</summary>
    internal async ValueTask<T> ReadSingleMessageAsync<T>(Marshaller<T> marshaller)
    {
        (bool read, T message) = await ReadMessageAsync(marshaller);
        if (!read)
        {
            throw new RpcException(new Status(StatusCode.Internal, "The request carried no message."));
        }

        while (!_requestEnded)
        {
            if (!_chunk.IsEmpty)
            {
                break;
            }
            await NextChunkAsync();
        }
        if (!_chunk.IsEmpty || _partialLength > 0)
        {
            throw new RpcException(new Status(StatusCode.Internal, "The request carried more than one message."));
        }
        return message;
    }

    private async ValueTask NextChunkAsync()
    {
        ReadOnlyMemory<byte> chunk = await ReadBodyAsync();
        if (!chunk.IsEmpty)
        {
            _chunk = chunk;
            return;
        }

        // Empty is the end of the body - or the stream gone, and then the call ends with it rather
        // than passing a cut-off stream of messages off as complete.
        if (IsAborted)
        {
            throw new OperationCanceledException("The client cancelled the call.", Aborted);
        }
        _requestEnded = true;
    }

    // Whole messages come straight out of the chunk; only one split across chunks is copied.
    private bool TryTakeMessage(out ReadOnlyMemory<byte> payload)
    {
        payload = default;

        if (_partialLength == 0)
        {
            ReadOnlySpan<byte> span = _chunk.Span;
            if (span.Length >= GrpcProtocol.PrefixLength)
            {
                int length = ReadPrefix(span);
                if (span.Length - GrpcProtocol.PrefixLength >= length)
                {
                    payload = _chunk.Slice(GrpcProtocol.PrefixLength, length);
                    _chunk = _chunk[(GrpcProtocol.PrefixLength + length)..];
                    return true;
                }
            }
            if (_chunk.IsEmpty)
            {
                return false;
            }
        }

        if (_partialLength < GrpcProtocol.PrefixLength)
        {
            Gather(GrpcProtocol.PrefixLength - _partialLength);
            if (_partialLength < GrpcProtocol.PrefixLength)
            {
                return false;
            }
        }

        int declared = ReadPrefix(_partial.AsSpan(0, GrpcProtocol.PrefixLength));
        Gather(GrpcProtocol.PrefixLength + declared - _partialLength);
        if (_partialLength < GrpcProtocol.PrefixLength + declared)
        {
            return false;
        }

        // Read before the next chunk overwrites it, which is the only way it can change.
        payload = _partial.AsMemory(GrpcProtocol.PrefixLength, declared);
        _partialLength = 0;
        return true;
    }

    private void Gather(int wanted)
    {
        int take = Math.Min(wanted, _chunk.Length);
        if (take == 0)
        {
            return;
        }

        int needed = _partialLength + take;
        if (_partial is null || _partial.Length < needed)
        {
            byte[] grown = ArrayPool<byte>.Shared.Rent(Math.Max(needed, 4096));
            if (_partial is not null)
            {
                _partial.AsSpan(0, _partialLength).CopyTo(grown);
                ArrayPool<byte>.Shared.Return(_partial);
            }
            _partial = grown;
        }

        _chunk.Span[..take].CopyTo(_partial.AsSpan(_partialLength));
        _partialLength += take;
        _chunk = _chunk[take..];
    }

    private int ReadPrefix(ReadOnlySpan<byte> prefix)
    {
        if (prefix[0] != 0)
        {
            throw new RpcException(prefix[0] != 1
                ? new Status(StatusCode.Internal, "A message carried an invalid compressed flag.")
                : _requestEncoding is null
                    ? new Status(StatusCode.Internal, "A message was compressed but the request named no grpc-encoding.")
                    : new Status(StatusCode.Unimplemented, $"Unsupported grpc-encoding value '{_requestEncoding}'. Supported encodings: identity"));
        }

        uint length = BinaryPrimitives.ReadUInt32BigEndian(prefix[1..]);
        if (length > (uint)_options.MaxReceiveMessageSize)
        {
            throw new RpcException(new Status(StatusCode.ResourceExhausted,
                $"Received message exceeds the maximum configured message size ({length} > {_options.MaxReceiveMessageSize})."));
        }
        return (int)length;
    }

    // ---- response messages ----

    /// <summary>Frame one response message into the body. The headers go first if they have not.</summary>
    internal void WriteMessage<T>(T message, Marshaller<T> marshaller)
    {
        if (_completed)
        {
            throw new InvalidOperationException("Can't write the message because the call is complete.");
        }
        if (IsAborted)
        {
            throw new OperationCanceledException("The client cancelled the call.", Aborted);
        }

        EnsureHeaders();

        MessageWriter writer = MessageWriter.Rent(Body);
        try
        {
            marshaller.ContextualSerializer(message, writer);
            writer.Finish();
        }
        catch when (writer.Started)
        {
            _torn = true;
            throw;
        }
        finally
        {
            writer.Return();
        }
    }

    /// <summary>Send what is framed. False once the peer is gone: nothing written reaches anyone now.</summary>
    internal ValueTask<FlushResult> FlushAsync() => FlushBodyAsync();

    private void EnsureHeaders()
    {
        if (_headersSent)
        {
            return;
        }
        _headersSent = true;
        SendHeaders(_responseHeaders, acceptEncoding: _requestEncoding is not null);
    }

    // ---- the end of the call ----

    /// <summary>The method returned: its status - OK unless it set one - in the trailers.</summary>
    internal ValueTask CompleteAsync() => FinishAsync(Status);

    /// <summary>
    /// The method threw. An <see cref="RpcException"/> is its status; anything else is UNKNOWN. A
    /// client that went away needs no answer, and a torn message can only be reset.
    /// </summary>
    internal ValueTask FailAsync(Exception exception)
    {
        if (_torn)
        {
            ExceptionDispatchInfo.Throw(exception);   // the stack resets the stream
        }
        if (_completed || IsAborted)
        {
            return default;
        }

        Status status;
        if (exception is RpcException rpc)
        {
            status = rpc.Status;
            foreach (Metadata.Entry entry in rpc.Trailers)
            {
                ResponseTrailers.Add(entry);
            }
        }
        else
        {
            Console.Error.WriteLine($"[ioxide.grpc] {Method} faulted: {exception.GetBaseException().Message}");
            status = new Status(StatusCode.Unknown, _options.EnableDetailedErrors
                ? $"Exception was thrown by handler. {exception.GetType().Name}: {exception.Message}"
                : "Exception was thrown by handler.");
        }
        return FinishAsync(status);
    }

    private ValueTask FinishAsync(Status status)
    {
        if (_completed || IsAborted)
        {
            return default;
        }
        _completed = true;

        EnsureHeaders();
        return SendTrailersAsync(status, _responseTrailers);
    }

    // ---- ServerCallContext ----

    protected override string MethodCore => _method?.FullName ?? Encoding.ASCII.GetString(Path.Span);

    protected override string HostCore => _host ??= Encoding.ASCII.GetString(Authority.Span);

    // The stream knows no address; a server that needs one maps it from the connection.
    protected override string PeerCore => "unknown";

    protected override DateTime DeadlineCore => _deadline;

    protected override Metadata RequestHeadersCore => _requestHeaders ??= GrpcProtocol.ReadMetadata(RequestFields);

    protected override CancellationToken CancellationTokenCore => Aborted;

    protected override Metadata ResponseTrailersCore => _responseTrailers ??= new Metadata();

    protected override Status StatusCore { get; set; } = Status.DefaultSuccess;

    protected override WriteOptions? WriteOptionsCore { get; set; }

    protected override AuthContext AuthContextCore
        => _authContext ??= new AuthContext(null, new Dictionary<string, List<AuthProperty>>());

    protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options)
        => throw new NotSupportedException("Propagation tokens belong to Grpc.Core's channel; pass Deadline and CancellationToken on instead.");

    protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders)
    {
        if (_headersSent)
        {
            throw new InvalidOperationException("Response headers can only be sent once per call.");
        }

        _responseHeaders = responseHeaders;
        EnsureHeaders();

        ValueTask<FlushResult> flush = FlushBodyAsync();
        return flush.IsCompletedSuccessfully ? Task.CompletedTask : flush.AsTask();
    }
}
