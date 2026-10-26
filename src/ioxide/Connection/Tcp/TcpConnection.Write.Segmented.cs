using System.Runtime.InteropServices;
using static ioxide.Native;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// Segmented write overflow (<see cref="WriteOverflowStrategy.Segmented"/>). When a response outgrows
/// the primary write slab (see TcpConnection.Write.cs) the extra bytes spill into segments chained here,
/// each twice the last, then flushed with a single vectored SENDMSG instead of growing one contiguous buffer.
/// </summary>
public sealed unsafe partial class TcpConnection
{
    // Once the primary slab (WriteBuffer/WriteTail) fills, further bytes spill into these segments. All empty
    // on the fast path / in Grow mode.
    private struct OvSeg { public nint Ptr; public int Used; public int Cap; }
    private OvSeg[]? _ov;
    private int  _ovCount;
    private bool _inOverflow;
    private bool _flushVectored;       // pending flush spans segments -> SENDMSG instead of a plain SEND

    // Segments stay in _ov after their response, for this connection's next one, until recycle. Per connection,
    // not per reactor: the flush orders their rent and return, which a pool shared between connections lacked (#402).
    private int _ovKept;

    // Stable scatter-gather descriptors for SENDMSG; the kernel reads them until the send completes.
    private iovec*  _iov;
    private msghdr* _msg;
    private int     _iovCap;
    private int     _sendIovIndex;     // first iovec not yet fully sent (partial-send re-slice)

    internal msghdr* MsgHdr => _msg;
    internal bool FlushVectored => _flushVectored;

    // Chains the next segment, big enough for `need`: the one kept at this position if it is, else a new one
    // twice the size of the last (from twice the slab, up to 64 slabs), so a response that spills a lot
    // spills into few segments.
    private void RentOverflow(int need)
    {
        _ov ??= new OvSeg[8];
        int k = _ovCount;
        if (k == _ov.Length)
        {
            Array.Resize(ref _ov, _ov.Length * 2);
        }

        if (k >= _ovKept || _ov[k].Cap < need)
        {
            if (k < _ovKept)
            {
                NativeMemory.AlignedFree((void*)_ov[k].Ptr);   // kept, but too small for this write
            }

            int cap = (int)Math.Min(Math.Max((long)_baseSlabSize << Math.Min(k + 1, 6), need), int.MaxValue);
            _ov[k] = new OvSeg { Ptr = (nint)NativeMemory.AlignedAlloc((nuint)cap, 64), Used = 0, Cap = cap };
            _ovKept = Math.Max(_ovKept, k + 1);
        }

        _ovCount = k + 1;
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

    // Keeps the segments for the next response and clears the overflow state.
    private void ReleaseOverflow()
    {
        for (int i = 0; i < _ovCount; i++)
        {
            _ov![i].Used = 0;
        }
        _ovCount = 0;
        _inOverflow = false;
        _flushVectored = false;
    }

    private void FreeKeptSegments()
    {
        for (int i = 0; i < _ovKept; i++)
        {
            NativeMemory.AlignedFree((void*)_ov![i].Ptr);
            _ov[i] = default;
        }
        _ovKept = 0;
    }
}
