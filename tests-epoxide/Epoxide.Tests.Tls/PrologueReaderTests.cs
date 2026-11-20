using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks.Sources;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// TlsProloguePipeReader, the kTLS-RX carry. Reachable without the kernel module by driving the
/// reader over an in-memory inner PipeReader, which is the only way most of it is testable at all.
/// </summary>
/// <remarks>
/// Everything here drives the reader directly over a <see cref="Pipe"/>: no reactor, no socket, no
/// certificate. That is the point of the file - end to end this class is only reachable with
/// KernelRx on, which needs the kernel module AND a session that negotiated a cipher the kernel
/// can take over, so the index arithmetic it is made of would otherwise only ever be exercised by
/// accident. Driving it directly pins each property on its own.
///
/// The one thing an in-memory inner reader is NOT is the real one: TcpConnectionPipeReader hands
/// out unmanaged recv memory and reports a closed connection rather than a completed writer. Where
/// that difference could matter the assertion says so.
/// </remarks>
internal static class PrologueReaderTests
{
    /// <summary>The reader's own bound on how far the carry may grow. Mirrored, not imported.</summary>
    private const int MaxCarryBytes = 1 << 20;

    public static void Register(Runner runner)
    {
        RegisterCarry(runner);
        RegisterCompletion(runner);
        RegisterTeardown(runner);
        RegisterBound(runner);
        RegisterPassThrough(runner);
    }

    // ---------------------------------------------------------------- serving the carry

    private static void RegisterCarry(Runner runner)
    {
        // The positions in a ReadResult built over carry[9..] report 9, not 0 - they are absolute
        // offsets into the backing array. AdvanceTo therefore ASSIGNS _consumed; adding would
        // double-count every partial consume after the first and skip the bytes in between, which
        // is silent: the caller just never sees them.
        runner.Test("prologue: a partial consume resumes where it left off, not past it", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("ABCDEFGHIJ"));
            var seen = new StringBuilder();

            ReadResult read = Await(reader.ReadAsync());
            Assert.Equal("ABCDEFGHIJ", Text(read.Buffer));
            seen.Append(Text(read.Buffer.Slice(0, 4)));
            reader.AdvanceTo(read.Buffer.GetPosition(4));

            read = Await(reader.ReadAsync());
            Assert.Equal("EFGHIJ", Text(read.Buffer));
            seen.Append(Text(read.Buffer.Slice(0, 3)));
            reader.AdvanceTo(read.Buffer.GetPosition(3));

            // Guard the shape of the failure as well as the content: a double-counting AdvanceTo
            // lands past the end and releases here, so this reader would already be a pass-through
            // with "HIJ" dropped on the floor.
            Assert.True(!reader.Drained, "three of ten bytes are still unconsumed, but the carry was already released");

            read = Await(reader.ReadAsync());
            Assert.Equal("HIJ", Text(read.Buffer));
            seen.Append(Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.End);

            Assert.Equal("ABCDEFGHIJ", seen.ToString());
            Assert.True(reader.Drained, "the carry was consumed to the end and should have been released");
        });

        // Examined to the end without consuming means "wake me when there is MORE" - the whole
        // reason PipeReader has a two-argument AdvanceTo. Handing the identical buffer straight
        // back satisfies the letter of ReadAsync and spins the caller at 100% of a reactor core.
        runner.Test("prologue: examining the whole carry without consuming waits for more bytes", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("ABCDE"));

            ReadResult read = Await(reader.ReadAsync());
            Assert.Equal("ABCDE", Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.Start, read.Buffer.End);

            // Nothing has been written to the pipe, so this can only complete by replaying bytes
            // the caller has already said are not enough.
            ValueTask<ReadResult> parked = reader.ReadAsync();
            Assert.True(!parked.IsCompleted, "the read returned the same examined bytes again instead of waiting: a hot spin");

            Await(pipe.Writer.WriteAsync(Ascii("FGH")));
            read = Await(parked);
            Assert.Equal("ABCDEFGH", Text(read.Buffer));

            // And a partial consume carried across the append: the unconsumed prefix survives
            // compaction and the new bytes land behind it, in order.
            reader.AdvanceTo(read.Buffer.GetPosition(2), read.Buffer.End);
            parked = reader.ReadAsync();
            Assert.True(!parked.IsCompleted, "the same replay, one compaction later");

            Await(pipe.Writer.WriteAsync(Ascii("IJ")));
            read = Await(parked);
            Assert.Equal("CDEFGHIJ", Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.End);
        });

        // It is a startup detour, not a pump: once the caller has consumed past the carry every
        // later read is the inner reader's own, uncopied.
        runner.Test("prologue: the carry drains exactly once and the reader turns into a pass-through", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("PRI * HTTP/2.0"));

            Assert.True(!reader.Drained, "nothing has consumed the carry yet");

            ReadResult read = Await(reader.ReadAsync());
            Assert.Equal("PRI * HTTP/2.0", Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.End);
            Assert.True(reader.Drained, "a fully consumed carry releases");

            Await(pipe.Writer.WriteAsync(Ascii("ring-bytes")));
            read = Await(reader.ReadAsync());
            Assert.Equal("ring-bytes", Text(read.Buffer));   // not the prologue a second time
            reader.AdvanceTo(read.Buffer.End);

            // Pass-through means the inner reader's completion is the one the caller sees.
            pipe.Writer.Complete();
            read = Await(reader.ReadAsync());
            Assert.True(read.IsCompleted, "the inner reader's completion did not reach the caller after the drain");
            Assert.Equal(0L, read.Buffer.Length);
            reader.AdvanceTo(read.Buffer.End);
        });
    }

    // ------------------------------------------------------------------- completion state

    private static void RegisterCompletion(Runner runner)
    {
        // Found by review, not by a failure in the field: the carry fast path in ReadAsync
        // hard-codes isCompleted:false, while the appending path propagates the inner reader's
        // flag. A partial consume after the peer is gone therefore takes the fast path and reports
        // the stream open again. IsCompleted is monotonic in System.IO.Pipelines - a completed
        // writer cannot un-complete - and a caller that latched on it to decide "this request is
        // truncated, stop waiting" is being told the opposite one read later.
        runner.Test("prologue: IsCompleted does not go back to false once the peer is gone", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("ABCDEFGHIJ"));

            ReadResult read = Await(reader.ReadAsync());
            reader.AdvanceTo(read.Buffer.Start, read.Buffer.End);   // examined it all, consumed none

            Await(pipe.Writer.WriteAsync(Ascii("KLMNO")));
            pipe.Writer.Complete();                                 // the peer is gone

            read = Await(reader.ReadAsync());
            Assert.Equal("ABCDEFGHIJKLMNO", Text(read.Buffer));
            Assert.True(read.IsCompleted, "the inner reader reported the writer gone");

            reader.AdvanceTo(read.Buffer.GetPosition(5));           // one message off the front

            read = Await(reader.ReadAsync());
            Assert.Equal("FGHIJKLMNO", Text(read.Buffer));
            Assert.True(read.IsCompleted,
                "IsCompleted flapped true then false: the reader un-completed a stream whose peer is already gone");
            reader.AdvanceTo(read.Buffer.End);
        });

        // The control for the Pending above, and the reason it is a defect rather than a taste:
        // the very reader being wrapped, driven through the identical sequence, keeps the flag.
        // Without this the Pending could be nothing but an unfair drive sequence.
        runner.Test("prologue: control: the Pipe being wrapped keeps IsCompleted true across the same reads", () =>
        {
            Pipe pipe = NewPipe();
            PipeReader reader = pipe.Reader;

            Await(pipe.Writer.WriteAsync(Ascii("ABCDEFGHIJ")));
            ReadResult read = Await(reader.ReadAsync());
            Assert.Equal("ABCDEFGHIJ", Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.Start, read.Buffer.End);

            Await(pipe.Writer.WriteAsync(Ascii("KLMNO")));
            pipe.Writer.Complete();

            read = Await(reader.ReadAsync());
            Assert.Equal("ABCDEFGHIJKLMNO", Text(read.Buffer));
            Assert.True(read.IsCompleted, "the Pipe should report the completed writer");

            reader.AdvanceTo(read.Buffer.GetPosition(5));

            read = Await(reader.ReadAsync());
            Assert.Equal("FGHIJKLMNO", Text(read.Buffer));
            Assert.True(read.IsCompleted, "a plain Pipe latches IsCompleted; that is the bar the wrapper misses");
            reader.AdvanceTo(read.Buffer.End);
        });
    }

    // ---------------------------------------------------------------- cancel and teardown

    private static void RegisterTeardown(Runner runner)
    {
        // A cancel raised while the carry is live is served HERE. Latching it into the inner
        // reader instead would hold it until the carry drains and then pop it out as a wake-up
        // nobody asked for, on a read that had nothing to do with it.
        runner.Test("prologue: a cancel raised while the carry is live is served once, and by the carry", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("ABCDE"));

            reader.CancelPendingRead();

            ReadResult read = Await(reader.ReadAsync());
            Assert.True(read.IsCanceled, "the cancel was not served by the carry");
            Assert.Equal("ABCDE", Text(read.Buffer));   // and it did not eat the bytes
            reader.AdvanceTo(read.Buffer.Start, read.Buffer.Start);

            read = Await(reader.ReadAsync());
            Assert.True(!read.IsCanceled, "the cancel was served twice");
            Assert.Equal("ABCDE", Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.End);
            Assert.True(reader.Drained, "the carry was consumed to the end");

            Await(pipe.Writer.WriteAsync(Ascii("Z")));
            read = Await(reader.ReadAsync());
            Assert.True(!read.IsCanceled, "the cancel resurfaced from the inner reader after the drain");
            Assert.Equal("Z", Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.End);
        });

        // The other half of that: a cancel that was never served has to travel with the drain,
        // because from there on reads go straight to the inner reader and would never see it.
        runner.Test("prologue: a cancel raised while the carry is live survives the drain", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("ABCDE"));

            ReadResult read = Await(reader.ReadAsync());
            reader.CancelPendingRead();        // nobody is parked; the carry would serve it
            reader.AdvanceTo(read.Buffer.End); // but the caller drains it first
            Assert.True(reader.Drained, "the carry was consumed to the end");

            // The pipe is empty and its writer is open, so this can only complete if the cancel
            // travelled. Checked synchronously: nothing else can write.
            ValueTask<ReadResult> next = reader.ReadAsync();
            Assert.True(next.IsCompleted, "the cancel was dropped by the drain: the caller is parked on a read it already cancelled");

            read = Await(next);
            Assert.True(read.IsCanceled, "the read completed, but not as a cancellation");
            reader.AdvanceTo(read.Buffer.Start, read.Buffer.Start);
        });

        // Complete arrives with bytes still in the carry on every abrupt teardown: a handler that
        // answers from the request head and returns, a decrypt fault, a reset. The pooled array has
        // to go back and the inner reader has to learn the read side is gone.
        runner.Test("prologue: Complete with the carry still live releases it and completes the inner reader", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("ABCDE"));

            ReadResult read = Await(reader.ReadAsync());
            reader.AdvanceTo(read.Buffer.Start, read.Buffer.Start);   // consumed nothing: still live
            Assert.True(!reader.Drained, "the carry is still live");

            reader.Complete();
            Assert.True(reader.Drained, "Complete left the carry held");
            reader.Complete();   // idempotent, and must not hand the array back a second time

            FlushResult flush = Await(pipe.Writer.WriteAsync(Ascii("x")));
            Assert.True(flush.IsCompleted, "Complete did not reach the inner reader: a writer flushing into it never learns the read side is gone");
        });

        // A double return puts one array in the pool twice and the next two rents of that size
        // class hand out the SAME instance. Large size class on purpose: the runner gives each
        // test its own thread, so the shared pool's per-thread cache for that bucket starts empty
        // and nothing else in the process is trading 256 KiB arrays inside this window.
        //
        // This can under-detect - the pool is free to serve the second rent from somewhere else -
        // but it cannot report a double return that did not happen.
        runner.Test("prologue: the pooled carry goes back to the pool exactly once", () =>
        {
            const int size = 200_000;
            byte[] prologue = new byte[size];
            prologue[0] = 0xAB;
            prologue[size - 1] = 0xCD;

            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, prologue);

            ReadResult read = Await(reader.ReadAsync());
            Assert.Equal((long)size, read.Buffer.Length);
            reader.AdvanceTo(read.Buffer.End);   // release
            Assert.True(reader.Drained, "the carry was consumed to the end");
            reader.Complete();                   // would release a second time if it still held one

            byte[] first = ArrayPool<byte>.Shared.Rent(size);
            byte[] second = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                // Return does not clear, so the carry comes back still carrying the prologue. If
                // this is some other array the carry was never returned at all and every kTLS-RX
                // connection leaks one.
                Assert.True(first[0] == 0xAB && first[size - 1] == 0xCD,
                    "the carry array never came back to the pool");
                Assert.True(!ReferenceEquals(first, second),
                    "the carry array went back to the pool twice: two rents handed out one array");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(first);
                ArrayPool<byte>.Shared.Return(second);
            }
        });
    }

    // -------------------------------------------------------------------- the carry bound

    private static void RegisterBound(Runner runner)
    {
        // While the carry is live this class copies received bytes in and hands the recv buffers
        // straight back, so there is nothing left to apply backpressure with. A peer that sends a
        // partial head and then dribbles forever keeps the caller examining without consuming, and
        // the carry grew for the life of the connection. It is bounded now, and the bound is the
        // kind of thing a later refactor drops without noticing, because nothing legitimate hits it.
        runner.Test("prologue: a carry that never gets consumed faults instead of growing without bound", () =>
        {
            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, Ascii("GET / HTTP/1.1\r\n"));
            byte[] chunk = new byte[64 * 1024];
            long fed = 0;

            Assert.Throws<IOException>(() =>
            {
                // Four times the bound. Reached without a fault, this loop is the unbounded growth
                // itself rather than a test of it.
                for (int i = 0; i < 64; i++)
                {
                    ReadResult read = Await(reader.ReadAsync());
                    reader.AdvanceTo(read.Buffer.Start, read.Buffer.End);   // examined, never consumed
                    Await(pipe.Writer.WriteAsync(chunk));
                    fed += chunk.Length;
                }
            }, "refusing to buffer more");

            Assert.True(fed <= MaxCarryBytes + chunk.Length,
                $"the carry took {fed} bytes before it faulted, well past the {MaxCarryBytes}-byte bound");
        });

        // The control, and the reason the bound is generous rather than tight: examining a whole
        // request head without consuming it is exactly what a legitimate caller does, and here it
        // does it one byte at a time - the append and compaction paths in their worst shape.
        // Faulting this caller would break the case the class exists for.
        runner.Test("prologue: control: an ordinary head examined byte by byte never reaches the bound", () =>
        {
            byte[] preface = Ascii("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            byte[] head = Ascii("GET / HTTP/1.1\r\nHost: ioxide\r\nAccept: */*\r\n\r\n");

            Pipe pipe = NewPipe();
            var reader = new TlsProloguePipeReader(pipe.Reader, preface);

            for (int i = 0; i < head.Length; i++)
            {
                ReadResult examined = Await(reader.ReadAsync());
                reader.AdvanceTo(examined.Buffer.Start, examined.Buffer.End);
                Await(pipe.Writer.WriteAsync(head.AsMemory(i, 1)));
            }

            ReadResult read = Await(reader.ReadAsync());
            Assert.Equal(Text(preface) + Text(head), Text(read.Buffer));
            reader.AdvanceTo(read.Buffer.End);
            Assert.True(reader.Drained, "the whole head was consumed, so the carry should be gone");
        });
    }

    // ------------------------------------------------------------------ the pass-through

    private static void RegisterPassThrough(Runner runner)
    {
        // Every keep-alive request on a kTLS-RX pipe connection is a read that waits, through here.
        runner.Test("prologue: once drained, a read that has to wait allocates nothing", () =>
        {
            var inner = new ParkedReader();
            var reader = new TlsProloguePipeReader(inner, Ascii("GET / HTTP/1.1\r\n\r\n"));
            ReadResult read = Await(reader.ReadAsync());
            reader.AdvanceTo(read.Buffer.End);
            Assert.True(reader.Drained, "the carry was consumed to the end and should have been released");

            const int warmup = 1_000, reads = 10_000;
            long before = 0;
            for (int i = 0; i < warmup + reads; i++)
            {
                if (i == warmup)
                {
                    before = GC.GetAllocatedBytesForCurrentThread();
                }
                ValueTask<ReadResult> parked = reader.ReadAsync();
                Assert.True(!parked.IsCompleted, "nothing was queued, so the read should have waited");
                inner.Deliver();
                read = Await(parked);
                reader.AdvanceTo(read.Buffer.End);
            }
            double perRead = (GC.GetAllocatedBytesForCurrentThread() - before) / (double)reads;

            Assert.True(perRead < 1, $"a drained read that had to wait allocated {perRead:F0} B");
        });
    }

    // ------------------------------------------------------------------------- plumbing

    /// <summary>Every read waits until <see cref="Deliver"/>, which resumes it inline; allocates nothing itself.</summary>
    private sealed class ParkedReader : PipeReader, IValueTaskSource<ReadResult>
    {
        private static readonly ReadOnlySequence<byte> Request = new(Ascii("GET / HTTP/1.1\r\n\r\n"));
        private ManualResetValueTaskSourceCore<ReadResult> _core;

        public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
        {
            _core.Reset();
            return new ValueTask<ReadResult>(this, _core.Version);
        }

        public void Deliver() => _core.SetResult(new ReadResult(Request, isCanceled: false, isCompleted: false));

        public ReadResult GetResult(short token) => _core.GetResult(token);

        public ValueTaskSourceStatus GetStatus(short token) => _core.GetStatus(token);

        public void OnCompleted(Action<object?> continuation, object? state, short token,
            ValueTaskSourceOnCompletedFlags flags) => _core.OnCompleted(continuation, state, token, flags);

        public override bool TryRead(out ReadResult result)
        {
            result = default;
            return false;
        }

        public override void AdvanceTo(SequencePosition consumed) { }

        public override void AdvanceTo(SequencePosition consumed, SequencePosition examined) { }

        public override void CancelPendingRead() { }

        public override void Complete(Exception? exception = null) { }
    }

    /// <summary>
    /// An inner reader with backpressure far out of the way: these tests drive the prologue
    /// reader, and a Pipe that paused its writer at 64 KB would be testing the Pipe instead.
    /// </summary>
    private static Pipe NewPipe() => new(new PipeOptions(
        pauseWriterThreshold: 8L * 1024 * 1024,
        resumeWriterThreshold: 4096,
        useSynchronizationContext: false));

    private static byte[] Ascii(string value) => Encoding.ASCII.GetBytes(value);

    private static string Text(ReadOnlySequence<byte> value) => Encoding.ASCII.GetString(value.ToArray());

    private static string Text(byte[] value) => Encoding.ASCII.GetString(value);

    /// <summary>
    /// Test bodies are synchronous, and blocking here is safe: the pipe has no synchronization
    /// context and every write that releases a parked read is made from this same thread.
    /// </summary>
    private static T Await<T>(ValueTask<T> task) => task.GetAwaiter().GetResult();
}
