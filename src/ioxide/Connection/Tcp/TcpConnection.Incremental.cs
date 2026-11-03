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
        if (IncrementalMode)
        {
            _reactor.EnqueueReturnQIncremental(ClientFd, item.Gen, item.Bid);
        }
        else
        {
            _reactor.EnqueueReturnQ(item.Bid);
        }
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
