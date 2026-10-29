using System.Diagnostics;
using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The ring on its own (#427): a submission goes in and its completion comes back, the SQ hands out
/// only the slots the kernel gave it, a bounded wait runs out, and the CQ's indices wrap.
/// </summary>
/// <remarks>
/// NOPs only, on this thread: a SINGLE_ISSUER ring is entered by the thread that created it.
/// </remarks>
internal static unsafe class RingTests
{
    // What a wait bounded by IORING_ENTER_EXT_ARG answers when its time runs out.
    private const int Etime = -62;

    // A power of two, so the kernel gives the SQ exactly this many entries.
    private const int SqEntries = 8;

    public static void Register(Runner runner)
    {
        runner.Test("ring: a NOP goes in and its completion comes back", () =>
        {
            using Ring ring = Ring.Create(16);
            Native.IoUringSqe* sqe = ring.GetSqe();
            Assert.True(sqe != null, "an empty SQ handed out no SQE");
            *sqe = default;   // opcode 0 is IORING_OP_NOP
            sqe->user_data = 0x1234_5678_9ABC;

            Assert.Equal(1, ring.SubmitAndWait(1));
            Assert.Equal(1u, ring.CqReady());
            Assert.True(ring.TryGetCqe(out Native.IoUringCqe cqe), "CqReady counted a completion TryGetCqe did not find");
            Assert.Equal(0x1234_5678_9ABCul, cqe.user_data);
            Assert.Equal(0, cqe.res);

            ring.CqeSeen();
            Assert.Equal(0u, ring.CqReady());
            Assert.True(!ring.TryGetCqe(out _), "a completion already seen was handed out again");
        }, timeoutMs: 10_000);

        runner.Test("ring: the SQ hands out no more SQEs than it has until an enter consumes them", () =>
        {
            using Ring ring = Ring.Create(SqEntries);

            Assert.Equal(SqEntries, FillSq(ring));
            Assert.True(ring.GetSqe() == null, "asked again, a full SQ handed out an SQE");

            Assert.Equal(SqEntries, ring.SubmitAndWait(SqEntries));
            ring.CqAdvance(ring.CqReady());

            // The enter consumed every one, so all of them are handed out again.
            Assert.Equal(SqEntries, FillSq(ring));
        }, timeoutMs: 10_000);

        runner.Test("ring: a timed wait with nothing in flight runs out with ETIME, and not before its time", () =>
        {
            const int timeoutMs = 20;
            using Ring ring = Ring.Create(8);

            long start = Stopwatch.GetTimestamp();
            int rc = ring.SubmitAndWait(1, timeoutMs);
            TimeSpan waited = Stopwatch.GetElapsedTime(start);

            Assert.Equal(Etime, rc);
            Assert.True(waited >= TimeSpan.FromMilliseconds(timeoutMs),
                $"a {timeoutMs} ms wait ran out after {waited.TotalMilliseconds:F3} ms");
        }, timeoutMs: 10_000);

        runner.Test("ring: the CQ wraps past its size", () =>
        {
            using Ring ring = Ring.Create(4);
            uint cqEntries = CqMaskOf(ring) + 1;   // the kernel's, twice the SQ

            // Three at a time, which shares no factor with the CQ's size, so the head meets every slot
            // as it comes round. Even batches are read the reactor's batched way, odd ones one by one.
            const uint batch = 3;
            ulong next = 0;
            for (int round = 0; round < cqEntries * 3; round++)
            {
                for (uint i = 0; i < batch; i++)
                {
                    Native.IoUringSqe* sqe = ring.GetSqe();
                    *sqe = default;
                    sqe->user_data = next + i;
                }

                Assert.Equal((int)batch, ring.SubmitAndWait(batch));
                Assert.Equal(batch, ring.CqReady());

                if (round % 2 == 0)
                {
                    for (uint i = 0; i < batch; i++)
                    {
                        Assert.Equal(next + i, ring.CqeAt(i).user_data);
                    }
                    ring.CqAdvance(batch);
                }
                else
                {
                    for (uint i = 0; i < batch; i++)
                    {
                        Assert.True(ring.TryGetCqe(out Native.IoUringCqe cqe), $"completion {next + i} was missing");
                        Assert.Equal(next + i, cqe.user_data);
                        ring.CqeSeen();
                    }
                }

                next += batch;
            }

            Assert.Equal(0u, ring.CqReady());
            Assert.True(next >= cqEntries * 3, $"{next} completions went round a CQ of {cqEntries} fewer than three times");
        }, timeoutMs: 10_000);
    }

    // NOPs into every SQE the ring hands out, until it hands out none; how many it handed out.
    private static int FillSq(Ring ring)
    {
        int handed = 0;
        for (Native.IoUringSqe* sqe = ring.GetSqe(); sqe != null && handed <= SqEntries; sqe = ring.GetSqe())
        {
            *sqe = default;
            sqe->user_data = (ulong)handed++;
        }
        return handed;
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_cqMask")]
    private static extern ref uint CqMaskOf(Ring ring);
}
