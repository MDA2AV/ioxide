using Grpc.Core;

namespace ioxide.grpc;

/// <summary>One bound method: reads its request the way its kind does, runs it, and ends the call with its status.</summary>
internal abstract class MethodHandler(string fullName)
{
    public string FullName { get; } = fullName;

    public async ValueTask HandleAsync(GrpcCall call)
    {
        try
        {
            await InvokeAsync(call);
            await call.CompleteAsync();
        }
        catch (Exception exception)
        {
            await call.FailAsync(exception);
        }
    }

    protected abstract ValueTask InvokeAsync(GrpcCall call);
}

internal sealed class UnaryHandler<TRequest, TResponse>(Method<TRequest, TResponse> method, UnaryServerMethod<TRequest, TResponse> invoker)
    : MethodHandler(method.FullName)
    where TRequest : class
    where TResponse : class
{
    protected override async ValueTask InvokeAsync(GrpcCall call)
    {
        TRequest request = await call.ReadSingleMessageAsync(method.RequestMarshaller);
        TResponse response = await invoker(request, call);
        call.WriteMessage(response, method.ResponseMarshaller);   // leaves with the trailers, in one write
    }
}

internal sealed class ClientStreamingHandler<TRequest, TResponse>(Method<TRequest, TResponse> method, ClientStreamingServerMethod<TRequest, TResponse> invoker)
    : MethodHandler(method.FullName)
    where TRequest : class
    where TResponse : class
{
    protected override async ValueTask InvokeAsync(GrpcCall call)
    {
        TResponse response = await invoker(new RequestStream<TRequest>(call, method.RequestMarshaller), call);
        call.WriteMessage(response, method.ResponseMarshaller);
    }
}

internal sealed class ServerStreamingHandler<TRequest, TResponse>(Method<TRequest, TResponse> method, ServerStreamingServerMethod<TRequest, TResponse> invoker)
    : MethodHandler(method.FullName)
    where TRequest : class
    where TResponse : class
{
    protected override async ValueTask InvokeAsync(GrpcCall call)
    {
        TRequest request = await call.ReadSingleMessageAsync(method.RequestMarshaller);
        await invoker(request, new ResponseStream<TResponse>(call, method.ResponseMarshaller), call);
    }
}

internal sealed class DuplexStreamingHandler<TRequest, TResponse>(Method<TRequest, TResponse> method, DuplexStreamingServerMethod<TRequest, TResponse> invoker)
    : MethodHandler(method.FullName)
    where TRequest : class
    where TResponse : class
{
    protected override ValueTask InvokeAsync(GrpcCall call)
        => new(invoker(new RequestStream<TRequest>(call, method.RequestMarshaller),
                       new ResponseStream<TResponse>(call, method.ResponseMarshaller), call));
}
