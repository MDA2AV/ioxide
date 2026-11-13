using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using Grpc.Core;
using ioxide.http2;

namespace ioxide.grpc;

/// <summary>
/// One gRPC call on one <c>ioxide.http2</c> stream, and the <see cref="ServerCallContext"/> its
/// service method sees: framing, status and metadata.
/// </summary>
/// <remarks>One reader and one writer at a time, each on any thread, like the stream under it.</remarks>
internal sealed class GrpcCall : ServerCallContext
{
    // Shared by every call that adds nothing of its own; only ever read, so every reactor can at once.
    private static readonly Http2Response GrpcHeaders = NewGrpcHeaders();

    private readonly GrpcOptions _options;
    private readonly Http2Request _request;
    private readonly Http2BodyReader _requestBody;
    private readonly Http2ResponseWriter _writer;
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

    // Taken from the writer once: the writer goes back to its pool when the call ends, to serve another stream.
    private CancellationToken _cancellation;

    private static readonly AuthContext NoAuth = new(null, new Dictionary<string, List<AuthProperty>>());

    internal GrpcCall(GrpcOptions options, Http2Request request, Http2BodyReader requestBody, Http2ResponseWriter writer)
    {
        _options = options;
        _request = request;
        _requestBody = requestBody;
        _writer = writer;
    }

    /// <summary>True once a message failed half-written: only a reset can end the call now.</summary>
    internal bool IsTorn => _torn;

    // ---- dispatch ----

    /// <summary>Check the request is a call, find its method and run it.</summary>
    internal ValueTask ServeAsync(GrpcServices services)
    {
        if (!_request.Method.Span.SequenceEqual("POST"u8))
        {
            return EndOnHeadersAsync(405, new Status(StatusCode.Internal, "gRPC calls are POST requests."), trailers: null, acceptEncoding: false);
        }

        bool grpc = false;
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in _request.Headers.AsSpan())
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
            return EndOnHeadersAsync(415, new Status(StatusCode.Internal, "The content-type is not application/grpc."), trailers: null, acceptEncoding: false);
        }

        if (!services.TryFind(_request.Path.Span, out MethodHandler? method))
        {
            return FinishAsync(new Status(StatusCode.Unimplemented, "Method is unimplemented."));
        }

        _method = method;
        return method.HandleAsync(this);
    }

    // ---- request messages ----

    /// <summary>The next request message, or false once the client has half-closed.</summary>
    internal async ValueTask<(bool Read, T Message)> ReadMessageAsync<T>(Marshaller<T> marshaller)
    {
        while (true)
        {
            if (TryTakeMessage(out ReadOnlyMemory<byte> payload))
            {
                T message = MessageReader.Deserialize(marshaller, payload);
                ReturnPartial();
                return (true, message);
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
        // A cardinality violation is UNIMPLEMENTED (statuscodes.md).
        (bool read, T message) = await ReadMessageAsync(marshaller);
        if (!read)
        {
            throw new RpcException(new Status(StatusCode.Unimplemented, "The request carried no message."));
        }

        while (!_requestEnded && _chunk.IsEmpty)
        {
            await NextChunkAsync();
        }
        if (!_chunk.IsEmpty || _partialLength > 0)
        {
            throw new RpcException(new Status(StatusCode.Unimplemented, "The request carried more than one message."));
        }
        return message;
    }

    private async ValueTask NextChunkAsync()
    {
        ReadOnlyMemory<byte> chunk;
        try
        {
            chunk = await _requestBody.ReadAsync();
        }
        catch (IOException)
        {
            // The stream was reset or the connection lost: the call ends, rather than passing the messages so far off as all.
            throw new OperationCanceledException("The client cancelled the call.", CancellationTokenCore);
        }

        if (chunk.IsEmpty)
        {
            _requestEnded = true;
            return;
        }
        _chunk = chunk;
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

        // Points into _partial, which goes back once the caller has deserialized it.
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

        if (_partial is null || _partial.Length < _partialLength + take)
        {
            // Sized for all that is wanted, so a message split over many chunks is rented once.
            byte[] grown = ArrayPool<byte>.Shared.Rent(Math.Max(_partialLength + wanted, 4096));
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

    // A message gathered across chunks is deserialized: its buffer goes back now, not when the call ends,
    // when a read the method left parked could still resume into it.
    private void ReturnPartial()
    {
        if (_partial is not null && _partialLength == 0)
        {
            ArrayPool<byte>.Shared.Return(_partial);
            _partial = null;
        }
    }

    private int ReadPrefix(ReadOnlySpan<byte> prefix)
    {
        if (prefix[0] != 0)
        {
            ThrowCompressed(prefix[0]);
        }

        uint length = BinaryPrimitives.ReadUInt32BigEndian(prefix[1..]);
        if (length > (uint)_options.MaxReceiveMessageSize)
        {
            throw new RpcException(new Status(StatusCode.ResourceExhausted,
                $"Received message exceeds the maximum configured message size ({length} > {_options.MaxReceiveMessageSize})."));
        }
        return (int)length;
    }

    [DoesNotReturn, MethodImpl(MethodImplOptions.NoInlining)]
    private void ThrowCompressed(byte flag)
    {
        if (flag != 1)
        {
            throw new RpcException(new Status(StatusCode.Internal, "A message carried an invalid compressed flag."));
        }
        if (_requestEncoding is null)
        {
            throw new RpcException(new Status(StatusCode.Internal, "A message was compressed but the request named no grpc-encoding."));
        }
        throw new RpcException(new Status(StatusCode.Unimplemented, $"Unsupported grpc-encoding value '{_requestEncoding}'. Supported encodings: identity"));
    }

    // ---- response messages ----

    /// <summary>Frame one response message into the body. The headers go first if they have not.</summary>
    internal void WriteMessage<T>(T message, Marshaller<T> marshaller)
    {
        if (_completed)
        {
            throw new InvalidOperationException("Can't write the message because the call is complete.");
        }
        ThrowIfTorn();

        EnsureHeaders();

        MessageWriter writer = MessageWriter.Rent(_writer);
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

    // A method that caught the failed write and went on must not frame after the torn message, or end it as whole.
    private void ThrowIfTorn()
    {
        if (_torn)
        {
            throw new InvalidOperationException("A response message was cut off half-written; only a reset can end the call.");
        }
    }

    /// <summary>The method returned: its status - OK unless it set one - in the trailers.</summary>
    internal ValueTask CompleteAsync()
    {
        ThrowIfTorn();
        return FinishAsync(Status);
    }

    /// <summary>
    /// The method threw. An <see cref="RpcException"/> is its status, a cancellation through the call's
    /// own token is CANCELLED, and anything else is UNKNOWN. A stream already gone drops the trailers.
    /// </summary>
    internal ValueTask FailAsync(Exception exception)
    {
        if (_completed)
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
        else if (exception is OperationCanceledException cancelled && cancelled.CancellationToken == CancellationTokenCore)
        {
            status = new Status(StatusCode.Cancelled, "The call was cancelled.");   // by its client, or the connection: no fault of the server's
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
        if (_completed)
        {
            return default;
        }
        _completed = true;

        // Nothing sent yet: the status rides the headers, the trailers-only response a client may still retry (gRFC A6).
        if (!_headersSent)
        {
            _headersSent = true;
            return EndOnHeadersAsync(200, status, _responseTrailers, acceptEncoding: _requestEncoding is not null);
        }
        return SendTrailersAsync(status, _responseTrailers);
    }

    /// <summary>Send what is framed. Completed once the peer is gone: nothing written reaches anyone now.</summary>
    internal ValueTask<FlushResult> FlushAsync() => _writer.FlushAsync();

    // :status 200 and content-type application/grpc, then the method's response headers.
    private void SendHeaders(Metadata? metadata, bool acceptEncoding)
    {
        if (metadata is not { Count: > 0 } && !acceptEncoding)
        {
            _writer.WriteHeaders(GrpcHeaders);
            return;
        }

        var response = new Http2Response();
        GrpcProtocol.AddHeaders(response.Headers, metadata, acceptEncoding);
        _writer.WriteHeaders(response);
    }

    private ValueTask SendTrailersAsync(Status status, Metadata? trailers)
        => _writer.CompleteAsync(GrpcProtocol.Trailers(status, trailers));

    // One HEADERS frame that ends the stream: httpStatus, the gRPC status and the trailers.
    private ValueTask EndOnHeadersAsync(int httpStatus, Status status, Metadata? trailers, bool acceptEncoding)
    {
        var response = new Http2Response { Status = httpStatus };
        GrpcProtocol.AddHeadersOnly(response.Headers, httpStatus, status, trailers, acceptEncoding);
        return _writer.CompleteAsync(response);
    }

    private static Http2Response NewGrpcHeaders()
    {
        var response = new Http2Response();
        GrpcProtocol.AddHeaders(response.Headers, metadata: null, acceptEncoding: false);
        return response;
    }

    // ---- ServerCallContext ----

    protected override string MethodCore => _method!.FullName;   // a method only ever sees a call that found it

    protected override string HostCore => _host ??= Encoding.ASCII.GetString(_request.Authority.Span);

    // The stream knows no address; a server that needs one maps it from the connection.
    protected override string PeerCore => "unknown";

    protected override DateTime DeadlineCore => _deadline;

    protected override Metadata RequestHeadersCore => _requestHeaders ??= GrpcProtocol.ReadMetadata(_request.Headers.AsSpan());

    protected override CancellationToken CancellationTokenCore
    {
        get
        {
            if (!_cancellation.CanBeCanceled)
            {
                _cancellation = _writer.Aborted;
            }
            return _cancellation;
        }
    }

    protected override Metadata ResponseTrailersCore => _responseTrailers ??= new Metadata();

    protected override Status StatusCore { get; set; } = Status.DefaultSuccess;

    protected override WriteOptions? WriteOptionsCore { get; set; }

    protected override AuthContext AuthContextCore => NoAuth;

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

        ValueTask<FlushResult> flush = FlushAsync();
        return flush.IsCompletedSuccessfully ? Task.CompletedTask : flush.AsTask();
    }
}
