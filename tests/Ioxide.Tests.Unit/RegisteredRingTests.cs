using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// A ring registers its descriptor (IORING_REGISTER_RING_FDS) and every enter passes the slot it got,
/// so the kernel takes the ring from the thread's table instead of an fget/fput of the descriptor.
/// </summary>
/// <remarks>
/// Each test asks the kernel what the slot holds rather than trusting <see cref="Ring.EnterFd"/>: an
/// empty slot answers an enter by slot with EBADF, and a descriptor never notices the slot at all.
/// </remarks>
internal static unsafe class RegisteredRingTests
{
    // What io_uring_enter answers for a registered slot that holds no ring.
    private const int Ebadf = -9;

    // A thread's registered-ring table, IO_RINGFD_REG_MAX.
    private const int SlotsPerThread = 16;

    public static void Register(Runner runner)
    {
        runner.Test("ring: enters go through the registered slot, not the descriptor", () =>
        {
            using Ring ring = Ring.Create(16);

            Assert.Equal(1, Nop(ring));   // control: the ring as created

            // Emptied behind the ring's back: an enter by descriptor would not notice, one by slot must.
            Unregister(ring, ring.EnterFd);
            Assert.Equal(Ebadf, Nop(ring));
        });

        runner.Test("ring: disposing a ring frees its registered slot", () =>
        {
            Ring ring = Ring.Create(16);
            int slot = ring.EnterFd;
            Assert.Equal(1, Nop(ring));
            ring.Dispose();

            // A slot still holding the ring keeps it alive past its close, and would answer this.
            int rc = Native.io_uring_enter(slot, 0, 0, Native.IORING_ENTER_REGISTERED_RING | Native.IORING_ENTER_GETEVENTS);
            Assert.Equal(Ebadf, rc);
        });

        runner.Test("ring: a ring created with every slot taken still works, through its descriptor", () =>
        {
            var rings = new List<Ring>();
            try
            {
                for (int i = 0; i <= SlotsPerThread; i++)
                {
                    rings.Add(Ring.Create(16));
                }

                Assert.True(rings[0].EnterFd != rings[0].Fd, "the thread's first ring should have taken a slot");

                Ring last = rings[^1];
                Assert.Equal(last.Fd, last.EnterFd);
                Assert.Equal(1, Nop(last));
            }
            finally
            {
                foreach (Ring ring in rings)
                {
                    ring.Dispose();
                }
            }
        });
    }

    // One NOP submitted and waited for: 1, or the enter's negative errno.
    private static int Nop(Ring ring)
    {
        Native.IoUringSqe* sqe = ring.GetSqe();
        *sqe = default;   // opcode 0 is IORING_OP_NOP
        sqe->user_data = 1;

        int rc = ring.SubmitAndWait(1);
        if (rc == 1)
        {
            ring.CqAdvance(ring.CqReady());
        }

        return rc;
    }

    private static void Unregister(Ring ring, int slot)
    {
        var update = new Native.io_uring_rsrc_update { offset = (uint)slot };
        Native.io_uring_register(ring.Fd, Native.IORING_UNREGISTER_RING_FDS, &update, 1);
    }
}
