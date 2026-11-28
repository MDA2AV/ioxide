using System.Runtime.InteropServices;
using ioxide.utils;
// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// Incremental-mode per-connection buffer-ring state. The reactor drives setup/teardown and the
/// refcounted recycle; allocations persist across pool reuse and are freed in Dispose().
/// </summary>
public sealed unsafe partial class TcpConnection
{
    internal byte*   BufRing;          // kernel-shared ring control area
    internal byte*   BufSlab;
    internal ushort  Bgid;
    internal uint    BufRingMask;
    internal bool    IncrementalMode;

    internal int[]?  CumOffset;        // per-bid: offset where the next slice begins
    internal int[]?  RefCount;         // per-bid: outstanding handler refs
    internal bool[]? KernelDone;       // per-bid: kernel finished appending

    internal int Generation => Volatile.Read(ref _generation);

    /// <summary>Hand a consumed recv buffer back, routed by mode.</summary>
    public void ReturnBuffer(in SpscRecvRing.Item item)
    {
        if (Movable)
        {
            HandBackMoving(item.Gen, item.Bid, item.Ptr);
            return;
        }

        // As before connections moved: the buffer is this reactor's, which drops it if its tag (Gen) is another life's.
        if (IncrementalMode)
        {
            _reactor.EnqueueReturnQIncremental(Slot, item.Gen, item.Bid);
        }
        else
        {
            _reactor.EnqueueReturnQ(item.Bid);
        }
    }

    // The connection can change reactors (TcpOptions.Rebalance): by now the buffer's life may be over, and the next one on
    // another reactor, and a move waits until all it took is back.
    private void HandBackMoving(ushort gen, ushort bid, byte* ptr)
    {
        // Read before the generation: while it is still that of the buffer's life, so are these.
        Reactor reactor = Volatile.Read(ref _reactor);
        int slot = Volatile.Read(ref Slot);
        int tagGen = Volatile.Read(ref TagGen);

        if (gen != (ushort)Volatile.Read(ref _generation))
        {
            // Late, in another life, which can be on another reactor. A ring of its own went with the life it was of.
            if (!IncrementalMode)
            {
                reactor.ReturnLate(ptr, bid);
            }
            return;
        }

        if (IncrementalMode)
        {
            reactor.EnqueueReturnQIncremental(slot, (ushort)tagGen, bid);
        }
        else
        {
            reactor.EnqueueReturnQ(bid);
        }
        CountReturned();
    }

    private void DisposeIncremental()
    {
        if (BufRing != null)
        {
            NativeMemory.AlignedFree(BufRing);
            BufRing = null;
        }
        if (BufSlab != null)
        {
            NativeMemory.AlignedFree(BufSlab);
            BufSlab = null;
        }
    }
}
