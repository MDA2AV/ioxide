using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The process's RLIMIT_MEMLOCK, which the kernel charges a connection's buffer ring to (incremental mode): taken to nothing
/// and put back.
/// </summary>
public static class LockedMemory
{
    /// <summary>Whether a ring registered with none left is refused here.</summary>
    public static bool CanRunOut => !HoldsIpcLock() && !RegistersRingAtZero();

    /// <summary>No locked memory to be had until disposed. The soft limit only, so it can be put back; what is charged stays.</summary>
    public static IDisposable None()
    {
        Assert.Equal(0, getrlimit(Memlock, out RLimit original));
        var none = new RLimit { Cur = 0, Max = original.Max };
        Assert.Equal(0, setrlimit(Memlock, in none));
        return new Restore(original);
    }

    private sealed class Restore(RLimit original) : IDisposable
    {
        public void Dispose() => setrlimit(Memlock, in original);
    }

    // io_uring charges nothing to RLIMIT_MEMLOCK for a process with CAP_IPC_LOCK, so it cannot run out.
    private static bool HoldsIpcLock()
    {
        string? caps = File.ReadLines("/proc/self/status").FirstOrDefault(l => l.StartsWith("CapEff:", StringComparison.Ordinal));
        return caps is not null && (Convert.ToUInt64(caps["CapEff:".Length..].Trim(), 16) & (1UL << 14)) != 0;
    }

    // A kernel that registers the ring at a zero limit leaves nothing to refuse (GitHub's ubuntu-26.04 on
    // 7.0.0-1020-azure). Asked as the incremental accept asks: a 4-entry ring on its own page.
    private static unsafe bool RegistersRingAtZero()
    {
        if (getrlimit(Memlock, out RLimit _) != 0)
        {
            return false;   // the test asks again, and fails on it
        }

        int page = Environment.SystemPageSize;
        using Ring ring = Ring.Create(8);
        byte* memory = (byte*)NativeMemory.AlignedAlloc((nuint)page, (nuint)page);
        NativeMemory.Clear(memory, (nuint)page);
        int ret = -1;
        try
        {
            using (None())
            {
                var reg = new Native.io_uring_buf_reg
                {
                    ring_addr = (ulong)memory, ring_entries = 4, bgid = 1, flags = Native.IOU_PBUF_RING_INC,
                };
                ret = Native.io_uring_register(ring.Fd, Native.IORING_REGISTER_PBUF_RING, &reg, 1);
            }
        }
        finally
        {
            if (ret == 0)
            {
                var reg = new Native.io_uring_buf_reg { bgid = 1 };
                Native.io_uring_register(ring.Fd, Native.IORING_UNREGISTER_PBUF_RING, &reg, 1);
            }
            NativeMemory.AlignedFree(memory);
        }
        return ret == 0;
    }

    private const int Memlock = 8;   // RLIMIT_MEMLOCK

    [StructLayout(LayoutKind.Sequential)]
    private struct RLimit
    {
        public ulong Cur;
        public ulong Max;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getrlimit(int resource, out RLimit limit);

    [DllImport("libc", SetLastError = true)]
    private static extern int setrlimit(int resource, in RLimit limit);
}
