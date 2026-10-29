using System.Buffers;
using System.IO.Pipelines;
using Grpc.Core;
using ioxide.http2;

namespace ioxide.grpc;

/// <summary>A call on an <c>ioxide.http2</c> stream.</summary>
internal sealed class Http2Call(GrpcOptions options, Http2Request request, Http2ResponseWriter writer) : GrpcCall(options)
{
    // Shared by every call that adds nothing of its own; only ever read, so every reactor can at once.
    private static readonly Http2Response GrpcHeaders = NewHeaders();
    private static readonly KeyValueList OkTrailers = NewOkTrailers();

    private bool _bodyTaken;

    private protected override ReadOnlyMemory<byte> HttpMethod => request.Method;

    private protected override ReadOnlyMemory<byte> Path => request.Path;

    private protected override ReadOnlyMemory<byte> Authority => request.Authority;

    private protected override ReadOnlySpan<KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>> RequestFields
        => request.Headers.AsSpan();

    private protected override ValueTask<ReadOnlyMemory<byte>> ReadBodyAsync()
    {
        if (request.BodyReader is { } reader)
        {
            return reader.ReadAsync();
        }

        // A connection that buffers bodies hands this one over whole, once.
        ReadOnlyMemory<byte> body = _bodyTaken ? default : request.Body;
        _bodyTaken = true;
        return new ValueTask<ReadOnlyMemory<byte>>(body);
    }

    private protected override IBufferWriter<byte> Body => writer;

    private protected override ValueTask<FlushResult> FlushBodyAsync() => writer.FlushAsync();

    private protected override bool IsAborted => writer.IsAborted;

    private protected override CancellationToken Aborted => writer.Aborted;

    private protected override void SendHeaders(Metadata? metadata, bool acceptEncoding)
    {
        if (metadata is not { Count: > 0 } && !acceptEncoding)
        {
            writer.WriteHeaders(GrpcHeaders);
            return;
        }

        var response = new Http2Response();
        var fields = new Fields(response.Headers);
        fields.Add(GrpcProtocol.ContentTypeName, GrpcProtocol.ContentTypeGrpc);
        if (acceptEncoding)
        {
            fields.Add(GrpcProtocol.AcceptEncodingName, GrpcProtocol.Identity);
        }
        if (metadata is not null)
        {
            GrpcProtocol.AppendMetadata(ref fields, metadata);
        }
        writer.WriteHeaders(response);
    }

    private protected override ValueTask SendTrailersAsync(Status status, Metadata? trailers)
    {
        if (status.StatusCode == StatusCode.OK && string.IsNullOrEmpty(status.Detail) && trailers is not { Count: > 0 })
        {
            return writer.CompleteAsync(OkTrailers);
        }

        var list = new KeyValueList();
        var fields = new Fields(list);
        GrpcProtocol.AppendStatus(ref fields, status);
        if (trailers is not null)
        {
            GrpcProtocol.AppendMetadata(ref fields, trailers);
        }
        return writer.CompleteAsync(list);
    }

    private protected override ValueTask RefuseAsync(int httpStatus, Status status)
    {
        var response = new Http2Response { Status = httpStatus };
        var fields = new Fields(response.Headers);
        GrpcProtocol.AppendStatus(ref fields, status);
        writer.WriteHeaders(response);
        return writer.CompleteAsync();
    }

    private static Http2Response NewHeaders()
    {
        var response = new Http2Response();
        response.Headers.Add(GrpcProtocol.ContentTypeName, GrpcProtocol.ContentTypeGrpc);
        return response;
    }

    private static KeyValueList NewOkTrailers()
    {
        var trailers = new KeyValueList();
        var fields = new Fields(trailers);
        GrpcProtocol.AppendStatus(ref fields, Status.DefaultSuccess);
        return trailers;
    }

    private readonly struct Fields(KeyValueList list) : IFieldSink
    {
        public void Add(ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value) => list.Add(name, value);
    }
}
