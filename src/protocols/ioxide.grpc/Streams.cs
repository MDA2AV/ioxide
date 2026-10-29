using System.IO.Pipelines;
using Grpc.Core;

namespace ioxide.grpc;

/// <summary>The request messages of a client- or bidirectional-streaming call, as the client sends them.</summary>
internal sealed class RequestStream<T>(GrpcCall call, Marshaller<T> marshaller) : IAsyncStreamReader<T>
    where T : class
{
    private static readonly Task<bool> True = Task.FromResult(true);
    private static readonly Task<bool> False = Task.FromResult(false);

    private T? _current;
    private bool _reading;

    public T Current => _current ?? throw new InvalidOperationException("No current message: call MoveNext first.");

    // The token is checked on entry only: a read that has to wait wakes when the client sends more,
    // half-closes or resets, and a reset is the cancellation the call itself carries.
    public Task<bool> MoveNext(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<bool>(cancellationToken);
        }
        if (_reading)
        {
            throw new InvalidOperationException("Can't read the next message because the previous read is still in progress.");
        }

        ValueTask<(bool Read, T Message)> next = call.ReadMessageAsync(marshaller);
        if (next.IsCompletedSuccessfully)
        {
            return Take(next.Result);
        }
        return AwaitAsync(next);
    }

    private async Task<bool> AwaitAsync(ValueTask<(bool Read, T Message)> next)
    {
        _reading = true;
        try
        {
            return await Take(await next);
        }
        finally
        {
            _reading = false;
        }
    }

    private Task<bool> Take((bool Read, T Message) next)
    {
        _current = next.Read ? next.Message : null;
        return next.Read ? True : False;
    }
}

/// <summary>The response messages of a server- or bidirectional-streaming call. Each write is flushed unless it asks to be buffered.</summary>
internal sealed class ResponseStream<T>(GrpcCall call, Marshaller<T> marshaller) : IServerStreamWriter<T>
    where T : class
{
    private bool _writing;

    public WriteOptions? WriteOptions
    {
        get => call.WriteOptions;
        set => call.WriteOptions = value;
    }

    public Task WriteAsync(T message) => WriteAsync(message, CancellationToken.None);

    public Task WriteAsync(T message, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled(cancellationToken);
        }
        if (_writing)
        {
            throw new InvalidOperationException("Can't write the message because the previous write is in progress.");
        }

        call.WriteMessage(message, marshaller);
        if (WriteOptions is { } options && (options.Flags & WriteFlags.BufferHint) != 0)
        {
            return Task.CompletedTask;   // rides the next flush, or the trailers
        }

        ValueTask<FlushResult> flush = call.FlushAsync();
        if (flush.IsCompletedSuccessfully)
        {
            return flush.Result.IsCompleted ? Gone() : Task.CompletedTask;
        }
        return AwaitAsync(flush);
    }

    private async Task AwaitAsync(ValueTask<FlushResult> flush)
    {
        _writing = true;
        try
        {
            if ((await flush).IsCompleted)
            {
                await Gone();
            }
        }
        finally
        {
            _writing = false;
        }
    }

    // The peer reset the stream or left: a service writing in a loop has to hear it, or it writes forever.
    private static Task Gone() => Task.FromException(new OperationCanceledException("The client cancelled the call."));
}
