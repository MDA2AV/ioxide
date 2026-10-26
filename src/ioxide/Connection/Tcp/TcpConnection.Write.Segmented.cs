using System.Runtime.InteropServices;
using static ioxide.Native;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// Segmented write overflow (<see cref="WriteOverflowStrategy.Segmented"/>). When a response outgrows
/// the primary write slab (see TcpConnection.Write.cs) the extra bytes spill into pooled fixed-size slabs
/// chained here, then flushed with a single vectored SENDMSG instead of growing one contiguous buffer.
/// </summary>
public sealed unsafe partial class TcpConnection
{
    // Once the primary slab (WriteBuffer/WriteTail) fills, further bytes spill into base-size slabs from
    // this connection's spares, or a one-off oversized alloc. All empty on the fast path / in Grow mode.
    private struct OvSeg { public nint Ptr; public int Used; public int Cap; public bool Pooled; }
    private OvSeg[]? _ov;
    private int  _ovCount;
    private bool _inOverflow;
    private bool _flushVectored;       // pending flush spans segments -> SENDMSG instead of a plain SEND

    // Slabs a sent response gave back, for this connection's next one; freed on recycle. Per connection, not
    // per reactor: the flush orders its rent and return, which a pool shared between connections lacked (#402).
    private Stack<nint>? _spareSlabs;

    // Stable scatter-gather descriptors for SENDMSG; the kernel reads them until the send completes.
    private iovec*  _iov;
    private msghdr* _msg;
    private int     _iovCap;
    private int     _sendIovIndex;     // first iovec not yet fully sent (partial-send re-slice)

    internal msghdr* MsgHdr => _msg;
    internal bool FlushVectored => _flushVectored;

    // Chains a new overflow segment big enough for `need`: a base-size slab, a spare when there is one, or a
    // one-off oversized allocation when a single write/span exceeds a slab.
    private void RentOverflow(int need)
    {
        nint ptr;
        int  cap;
        bool pooled;
        if (need <= _baseSlabSize)
        {
            _spareSlabs ??= new Stack<nint>();
            ptr = _spareSlabs.TryPop(out nint spare) ? spare : (nint)NativeMemory.AlignedAlloc((nuint)_baseSlabSize, 64);
            cap = _baseSlabSize;
            pooled = true;
        }
        else
        {
            ptr = (nint)NativeMemory.AlignedAlloc((nuint)need, 64);
            cap = need;
            pooled = false;
        }

        _ov ??= new OvSeg[8];
        if (_ovCount == _ov.Length)
        {
            Array.Resize(ref _ov, _ov.Length * 2);
        }
        _ov[_ovCount++] = new OvSeg { Ptr = ptr, Used = 0, Cap = cap, Pooled = pooled };
        _inOverflow = true;
    }

    // Builds the stable iovec/msghdr describing [primary, overflow...] for a SENDMSG. Lazily allocates
    // and grows the iovec storage; the msghdr is allocated once and reused.
    private void BuildIovec()
    {
        int n = 1 + _ovCount;
        if (_iovCap < n)
        {
            if (_iov != null) NativeMemory.AlignedFree(_iov);
            _iov = (iovec*)NativeMemory.AlignedAlloc((nuint)(sizeof(iovec) * n), 16);
            _iovCap = n;
        }
        if (_msg == null)
        {
            _msg = (msghdr*)NativeMemory.AlignedAlloc((nuint)sizeof(msghdr), 16);
            NativeMemory.Clear(_msg, (nuint)sizeof(msghdr));
        }

        _iov[0].iov_base = WriteBuffer;
        _iov[0].iov_len  = (nuint)WriteTail;
        for (int i = 0; i < _ovCount; i++)
        {
            _iov[i + 1].iov_base = (void*)_ov![i].Ptr;
            _iov[i + 1].iov_len  = (nuint)_ov[i].Used;
        }

        _sendIovIndex = 0;
        _msg->msg_iov    = _iov;
        _msg->msg_iovlen = (nuint)n;
    }

    // Advances the iovec past `sent` bytes after a partial SENDMSG, so a resubmit covers the remainder.
    internal void AdvanceIov(int sent)
    {
        int n = 1 + _ovCount;
        while (sent > 0 && _sendIovIndex < n)
        {
            int len = (int)_iov[_sendIovIndex].iov_len;
            if (sent >= len)
            {
                sent -= len;
                _sendIovIndex++;
            }
            else
            {
                _iov[_sendIovIndex].iov_base = (byte*)_iov[_sendIovIndex].iov_base + sent;
                _iov[_sendIovIndex].iov_len  = (nuint)(len - sent);
                sent = 0;
            }
        }
        _msg->msg_iov    = _iov + _sendIovIndex;
        _msg->msg_iovlen = (nuint)(n - _sendIovIndex);
    }

    // Keeps base-size segments as spares (frees one-offs) and clears the overflow state.
    private void ReleaseOverflow()
    {
        for (int i = 0; i < _ovCount; i++)
        {
            if (_ov![i].Pooled)
            {
                _spareSlabs!.Push(_ov[i].Ptr);
            }
            else
            {
                NativeMemory.AlignedFree((void*)_ov[i].Ptr);
            }
        }
        _ovCount = 0;
        _inOverflow = false;
        _flushVectored = false;
    }

    private void FreeSpareSlabs()
    {
        if (_spareSlabs == null)
        {
            return;
        }

        while (_spareSlabs.TryPop(out nint slab))
        {
            NativeMemory.AlignedFree((void*)slab);
        }
    }
}
