using System.Runtime.InteropServices;
using static epoxide.Native;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace epoxide;

/// <summary>
/// Segmented write overflow (<see cref="WriteOverflowStrategy.Segmented"/>). When a response outgrows
/// the primary write slab (see TcpConnection.Write.cs) the extra bytes spill into pooled fixed-size slabs
/// chained here, then flushed with a single vectored sendmsg instead of growing one contiguous buffer.
/// </summary>
public sealed unsafe partial class TcpConnection
{
    // Once the primary slab (WriteBuffer/WriteTail) fills, further bytes spill into slabs rented from
    // the reactor's slab pool (base size) or a one-off oversized alloc (PoolId -1).
    private struct OvSeg { public nint Ptr; public int Used; public int Cap; public int PoolId; }
    private OvSeg[]? _ov;
    private int  _ovCount;
    private bool _inOverflow;
    private bool _flushVectored;       // pending flush spans segments -> sendmsg instead of a plain send

    // Scatter-gather descriptors for sendmsg, kept across the partial sends of one flush.
    private iovec*  _iov;
    private msghdr* _msg;
    private int     _iovCap;
    private int     _sendIovIndex;     // first iovec not yet fully sent (partial-send re-slice)

    // Chains a new overflow segment big enough for `need`: a base-size slab from the reactor's pool, or
    // a one-off allocation when a single write/span exceeds a slab.
    private void RentOverflow(int need)
    {
        nint ptr;
        int  cap;
        int  poolId;
        if (need <= _baseSlabSize)
        {
            ptr = (nint)_reactor.WriteSlabPool.Rent(out poolId);
            cap = _baseSlabSize;
        }
        else
        {
            ptr = (nint)NativeMemory.AlignedAlloc((nuint)need, 64);
            cap = need;
            poolId = -1;
        }

        _ov ??= new OvSeg[8];
        if (_ovCount == _ov.Length)
        {
            Array.Resize(ref _ov, _ov.Length * 2);
        }
        _ov[_ovCount++] = new OvSeg { Ptr = ptr, Used = 0, Cap = cap, PoolId = poolId };
        _inOverflow = true;
    }

    // Builds the iovec/msghdr describing [primary, overflow...] for a sendmsg. Lazily allocates and
    // grows the iovec storage; the msghdr is allocated once and reused.
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

    // Advances the iovec past `sent` bytes after a partial sendmsg, so the next one covers the remainder.
    private void AdvanceIov(int sent)
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

    // Returns overflow segments to the reactor's pool (or frees one-offs) and clears the overflow state.
    private void ReleaseOverflow()
    {
        for (int i = 0; i < _ovCount; i++)
        {
            if (_ov![i].PoolId >= 0)
            {
                _reactor.WriteSlabPool.Return(_ov[i].PoolId);
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
}
