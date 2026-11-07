using System.Buffers.Binary;
using System.IO.Pipelines;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// One HTTP/2 frame off the wire, payload included. The payload is what makes a truncated body
/// visible: a response that loses its bytes still produces correctly shaped HEADERS and END_STREAM
/// frames, so a test that only walks frame headers passes while the client receives nothing.
/// </summary>
internal readonly record struct Frame(int Length, byte Type, byte Flags, int StreamId, byte[] Payload)
{
    public const byte Data = 0x0;
    public const byte Headers = 0x1;
    public const byte Settings = 0x4;
    public const byte WindowUpdate = 0x8;

    public bool EndStream => (Flags & 0x1) != 0;

    public static List<Frame> Walk(ReadOnlySpan<byte> wire)
    {
        var frames = new List<Frame>();
        int at = 0;
        while (at + 9 <= wire.Length)
        {
            int length = (wire[at] << 16) | (wire[at + 1] << 8) | wire[at + 2];
            byte type = wire[at + 3];
            byte flags = wire[at + 4];
            int stream = (int)(BinaryPrimitives.ReadUInt32BigEndian(wire[(at + 5)..]) & 0x7FFFFFFF);
            frames.Add(new Frame(length, type, flags, stream, wire.Slice(at + 9, length).ToArray()));
            at += 9 + length;
        }
        Assert.Equal(wire.Length, at);   // no torn frame: every byte accounted for
        return frames;
    }

    /// <summary>The DATA payloads for one stream, in wire order, concatenated.</summary>
    public static byte[] Body(IEnumerable<Frame> frames, int streamId)
    {
        var body = new List<byte>();
        foreach (Frame frame in frames)
        {
            if (frame is { Type: Data } && frame.StreamId == streamId)
            {
                body.AddRange(frame.Payload);
            }
        }
        return body.ToArray();
    }
}

/// <summary>
/// An HTTP/2 client the test steps by hand: an inline input pipe to feed frames, and a strict
/// output writer whose flushes complete only when the test releases them.
/// </summary>
internal sealed class StrictClient : IDuplexPipe, IDisposable
{
    private readonly Pipe _input = new(new PipeOptions(
        readerScheduler: PipeScheduler.Inline,
        writerScheduler: PipeScheduler.Inline,
        useSynchronizationContext: false));

    private readonly StrictWriter _writer = new();

    public StrictClient(Http2Options? options = null)
        => Connection = options is null ? new Http2Connection(this) : new Http2Connection(this, options);

    public Http2Connection Connection { get; }

    public PipeReader Input => _input.Reader;
    public PipeWriter Output => _writer;

    public int PendingFlushes => _writer.PendingFlushes;
    public byte[] ReleaseFlush() => _writer.ReleaseFlush();
    public void FaultFlush() => _writer.FaultFlush();
    public void ReportPeerClosed() => _writer.ReportPeerClosed();

    /// <summary>Release every flush the server has in flight, returning all frames they carried.</summary>
    public List<Frame> Drain(int maxFlushes = 512)
    {
        var frames = new List<Frame>();
        for (int i = 0; i < maxFlushes && PendingFlushes > 0; i++)
        {
            frames.AddRange(Frame.Walk(ReleaseFlush()));
        }
        return frames;
    }

    /// <summary>Preface, an empty SETTINGS, then one indexed-HPACK GET per stream id.</summary>
    public void SendRequests(params int[] streamIds)
    {
        var bytes = new List<byte>("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray());
        bytes.AddRange(FrameHeaderBytes(0, 0x4, 0, 0));
        foreach (int streamId in streamIds)
        {
            // 0x82 :method GET, 0x86 :scheme http, 0x84 :path / - static table only, so the
            // request needs no HPACK encoder of its own.
            bytes.AddRange(FrameHeaderBytes(3, 0x1, 0x5, streamId));
            bytes.AddRange([0x82, 0x86, 0x84]);
        }
        Feed(bytes.ToArray());
    }

    /// <summary>Credit a stream (or the connection, on stream 0) so a parked writer can continue.</summary>
    public void SendWindowUpdate(int streamId, int increment)
    {
        var bytes = new List<byte>(FrameHeaderBytes(4, 0x8, 0, streamId));
        Span<byte> value = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(value, (uint)increment);
        bytes.AddRange(value.ToArray());
        Feed(bytes.ToArray());
    }

    public void Feed(byte[] bytes)
        => _input.Writer.WriteAsync(bytes).GetAwaiter().GetResult();

    /// <summary>End the input and wait out the connection's run task.</summary>
    public void Close(Task run)
    {
        _input.Writer.Complete();
        Assert.True(run.Wait(5_000), "connection wound down");
    }

    public void Dispose() => Connection.Dispose();

    private static byte[] FrameHeaderBytes(int length, byte type, byte flags, int streamId) =>
    [
        (byte)(length >> 16), (byte)(length >> 8), (byte)length,
        type, flags,
        (byte)(streamId >> 24), (byte)(streamId >> 16), (byte)(streamId >> 8), (byte)streamId,
    ];
}

/// <summary>
/// The real transport's write contract, distilled: writes throw while a flush is in flight, a
/// second flush throws, and a flush completes only when the reactor - here, the test - says so.
/// </summary>
internal sealed class StrictWriter : PipeWriter
{
    private readonly List<byte> _staged = [];
    private readonly Queue<(TaskCompletionSource<FlushResult> Signal, byte[] Payload)> _inFlight = new();
    private byte[] _scratch = new byte[4096];
    private bool _flushing;

    public int PendingFlushes => _inFlight.Count;

    public override Memory<byte> GetMemory(int sizeHint = 0)
    {
        ThrowIfFlushing();
        EnsureScratch(sizeHint);
        return _scratch;
    }

    public override Span<byte> GetSpan(int sizeHint = 0)
    {
        ThrowIfFlushing();
        EnsureScratch(sizeHint);
        return _scratch;
    }

    public override void Advance(int bytes)
    {
        ThrowIfFlushing();
        _staged.AddRange(_scratch.AsSpan(0, bytes));
    }

    public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
    {
        if (_flushing)
        {
            throw new InvalidOperationException("FlushAsync already in progress.");
        }
        if (_staged.Count == 0)
        {
            return new ValueTask<FlushResult>(new FlushResult(isCanceled: false, isCompleted: false));
        }

        _flushing = true;
        var signal = new TaskCompletionSource<FlushResult>();
        _inFlight.Enqueue((signal, _staged.ToArray()));
        _staged.Clear();
        return new ValueTask<FlushResult>(signal.Task);
    }

    /// <summary>Complete the oldest in-flight flush and hand back the bytes it carried.</summary>
    public byte[] ReleaseFlush()
    {
        Assert.True(_inFlight.Count > 0, "a flush was expected to be in flight");
        (TaskCompletionSource<FlushResult> signal, byte[] payload) = _inFlight.Dequeue();

        // Writable again BEFORE the signal: the queue drain runs inline on SetResult and its
        // first act is to write.
        _flushing = false;
        signal.SetResult(new FlushResult(isCanceled: false, isCompleted: false));
        return payload;
    }

    /// <summary>Fail the oldest in-flight flush, as a torn-down transport would.</summary>
    public void FaultFlush()
    {
        Assert.True(_inFlight.Count > 0, "a flush was expected to be in flight");
        (TaskCompletionSource<FlushResult> signal, _) = _inFlight.Dequeue();
        _flushing = false;
        signal.SetException(new IOException("transport torn down"));
    }

    /// <summary>Complete the oldest in-flight flush as a closed peer does over TCP: no throw, its bytes dropped, IsCompleted.</summary>
    public void ReportPeerClosed()
    {
        Assert.True(_inFlight.Count > 0, "a flush was expected to be in flight");
        (TaskCompletionSource<FlushResult> signal, _) = _inFlight.Dequeue();
        _flushing = false;
        signal.SetResult(new FlushResult(isCanceled: false, isCompleted: true));
    }

    public override void Complete(Exception? exception = null)
    {
    }

    public override void CancelPendingFlush()
    {
    }

    private void ThrowIfFlushing()
    {
        if (_flushing)
        {
            throw new InvalidOperationException("Cannot write while flush is in progress.");
        }
    }

    private void EnsureScratch(int sizeHint)
    {
        if (_scratch.Length < sizeHint)
        {
            _scratch = new byte[sizeHint];
        }
    }
}
