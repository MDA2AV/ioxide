using System.Runtime.CompilerServices;
using static ioxide.Native;

// ReSharper disable SuggestVarOrType_BuiltInTypes
// ReSharper disable SuggestVarOrType_Elsewhere
#pragma warning disable CA1806

namespace ioxide;

public sealed unsafe class Ring : IDisposable
{
    private int _fd;

    public int Fd => _fd;

    private uint*       _sqHead;
    private uint*       _sqTail;
    private uint*       _sqArray;
    private uint        _sqMask;
    private uint        _sqEntries;
    private IoUringSqe* _sqes;

    private uint*       _cqHead;
    private uint*       _cqTail;
    private IoUringCqe* _cqes;
    private uint        _cqMask;

    private uint _sqeTail;

    private byte* _ringPtr;
    private nuint _ringSize;
    private byte* _sqePtr;
    private nuint _sqeSize;

    private bool _hasSqArray;

    /// <summary>ENOMEM here is transient, so it is worth a few milliseconds before giving up.</summary>
    /// <remarks>
    /// A ring's memory is charged against RLIMIT_MEMLOCK and released ASYNCHRONOUSLY after close,
    /// so a host that creates and drops reactors faster than the kernel reclaims them - a test
    /// suite standing servers up and tearing them down is the usual shape - gets ENOMEM while
    /// nothing is actually leaking. Measured: creating and immediately closing 30,000 rings failed
    /// 14,788 times, and every failure cleared on a retry 5 ms later.
    ///
    /// Only ENOMEM is retried. Every other errno is a decision the kernel has already made.
    ///
    /// This buys time against a reclaim backlog, not against a limit that is simply too small: with
    /// an 8 MB RLIMIT_MEMLOCK and the default ring size, measured, a third of attempts still fail
    /// first time and a few per thousand exhaust all six. There the answer is a bigger limit or a
    /// smaller ring, and the message below says so.
    /// </remarks>
    private static int SetupWithMemlockRetry(uint entries, IoUringParams* parameters)
    {
        // 5, 10, 20, 40, 80ms - about 155ms in total. Sized from the measured reclaim latency of a
        // SINGLE ring, whose median is ~20ms and whose tail reaches 47ms under load. A shorter
        // schedule looked sufficient against a BURST, where many rings are in flight and one is
        // always coming back within a few ms, but the one-at-a-time case a restarting server
        // produces is far slower and a 30ms budget still failed a fifth of the time.
        const int attempts = 6;

        int fd = io_uring_setup(entries, parameters);

        for (int attempt = 0, delay = 5; fd == -ENOMEM && attempt < attempts - 1; attempt++, delay *= 2)
        {
            Thread.Sleep(delay);
            fd = io_uring_setup(entries, parameters);
        }

        return fd;
    }

    /// <summary>Roughly what one ring costs against RLIMIT_MEMLOCK, for the diagnostic above.</summary>
    private static int EstimateRingKib(uint entries)
        => (int)((entries * (64 + 4) + entries * 2 * 16 + 4096) / 1024);

    public static Ring Create(uint entries)
    {
        // Prefer NO_SQARRAY (6.6+): the SQ slot index is implicit, dropping one
        // store + cache line per SQE. Fall back for older kernels (EINVAL).
        IoUringParams ioUringParams = default;
        ioUringParams.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_NO_SQARRAY;
        int fd = SetupWithMemlockRetry(entries, &ioUringParams);
        bool hasSqArray = false;

        if (fd == -EINVAL)
        {
            ioUringParams = default;
            ioUringParams.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
            fd = SetupWithMemlockRetry(entries, &ioUringParams);
            hasSqArray = true;
        }

        if (fd < 0)
        {
            throw new InvalidOperationException(
                $"io_uring_setup failed with errno {-fd}"
                + (fd == -ENOMEM
                    ? $". A ring of {entries} entries costs roughly {EstimateRingKib(entries)} KiB of "
                      + "RLIMIT_MEMLOCK, and the kernel reclaims a closed ring's memory "
                      + "asynchronously - raise `ulimit -l`, lower ServerConfig.RingEntries, or "
                      + "create reactors less abruptly."
                    : string.Empty));
        }

        var ring = new Ring
        {
            _fd = fd,
            _sqEntries = ioUringParams.sq_entries,
            _hasSqArray = hasSqArray
        };

        nuint sqRingBytes = ioUringParams.sq_off.array + ioUringParams.sq_entries * sizeof(uint);
        nuint cqRingBytes = ioUringParams.cq_off.cqes  + ioUringParams.cq_entries * (nuint)sizeof(IoUringCqe);
        nuint ringBytes   = sqRingBytes > cqRingBytes ? sqRingBytes : cqRingBytes;

        void* ringMem = mmap(null, ringBytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
        if (ringMem == (void*)-1)
        {
            close(fd);

            throw new InvalidOperationException("mmap(SQ_RING) failed");
        }
        ring._ringPtr  = (byte*)ringMem;
        ring._ringSize = ringBytes;

        nuint sqeBytes = ioUringParams.sq_entries * (nuint)sizeof(IoUringSqe);
        void* sqeMem = mmap(null, sqeBytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
        if (sqeMem == (void*)-1)
        {
            munmap(ringMem, ringBytes);
            close(fd);

            throw new InvalidOperationException("mmap(SQES) failed");
        }
        ring._sqes    = (IoUringSqe*)sqeMem;
        ring._sqePtr  = (byte*)sqeMem;
        ring._sqeSize = sqeBytes;

        byte* ringPointer = (byte*)ringMem;
        ring._sqHead  = (uint*)(ringPointer + ioUringParams.sq_off.head);
        ring._sqTail  = (uint*)(ringPointer + ioUringParams.sq_off.tail);
        ring._sqArray = (uint*)(ringPointer + ioUringParams.sq_off.array);
        ring._sqMask  = *(uint*)(ringPointer + ioUringParams.sq_off.ring_mask);

        ring._cqHead = (uint*)(ringPointer + ioUringParams.cq_off.head);
        ring._cqTail = (uint*)(ringPointer + ioUringParams.cq_off.tail);
        ring._cqes   = (IoUringCqe*)(ringPointer + ioUringParams.cq_off.cqes);
        ring._cqMask = *(uint*)(ringPointer + ioUringParams.cq_off.ring_mask);

        return ring;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IoUringSqe* GetSqe()
    {
        uint head = Volatile.Read(ref *_sqHead);

        if (_sqeTail - head >= _sqEntries)
        {
            return null;
        }

        uint slot = _sqeTail & _sqMask;
        if (_hasSqArray)
        {
            _sqArray[slot] = slot;
        }
        _sqeTail++;

        return &_sqes[slot];
    }

    public int SubmitAndWait(uint waitFor)
    {
        // liburing-style accounting: derive the submit count from the kernel-consumed head, so
        // SQEs published by an enter that consumed nothing (-EBUSY under CQ-overflow pressure)
        // are re-counted by the next call instead of stranding until later submits push them out.
        uint khead    = Volatile.Read(ref *_sqHead);
        uint toSubmit = _sqeTail - khead;

        if (_sqeTail != *_sqTail)
        {
            Volatile.Write(ref *_sqTail, _sqeTail);
        }

        if (toSubmit == 0 && waitFor == 0) return 0;

        uint flags = waitFor > 0 ? IORING_ENTER_GETEVENTS : 0;

        return io_uring_enter(_fd, toSubmit, waitFor, flags);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryGetCqe(out IoUringCqe cqe)
    {
        uint head = *_cqHead;
        uint tail = Volatile.Read(ref *_cqTail);

        if (head == tail)
        {
            cqe = default;

            return false;
        }

        cqe = _cqes[head & _cqMask];

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CqeSeen() => Volatile.Write(ref *_cqHead, *_cqHead + 1);

    // Batched CQ drain (liburing io_uring_for_each_cqe + io_uring_cq_advance):
    // read the kernel-written tail once (acquire), process the whole batch,
    // then publish the consumed head once (release) instead of once per CQE.

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint CqReady() => Volatile.Read(ref *_cqTail) - *_cqHead;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ref readonly IoUringCqe CqeAt(uint i) => ref _cqes[(*_cqHead + i) & _cqMask];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CqAdvance(uint n) => Volatile.Write(ref *_cqHead, *_cqHead + n);

    // BISECT PROBE 4 (temporary): closeFd == false does the munmaps and leaks only the ring fd.
    public void Dispose(bool closeFd)
    {
        _probeCloseFd = closeFd;
        Dispose();
    }

    private bool _probeCloseFd = true;

    public void Dispose()
    {
        if (_ringPtr != null)
        {
            munmap(_ringPtr, _ringSize); _ringPtr = null;
        }

        if (_sqePtr != null)
        {
            munmap(_sqePtr,  _sqeSize);  _sqePtr  = null;
        }

        if (_fd > 0 && _probeCloseFd)
        {
            close(_fd); _fd = 0;
        }
    }
}

#pragma warning restore CA1806
