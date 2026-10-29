using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// io_uring disabled for real (#427): a seccomp filter fails io_uring_setup with EPERM, as a container
/// runtime's default profile does, and Ring.Create must say what RingSetupMessageTests says it says.
/// </summary>
/// <remarks>
/// The filter is one thread's, and every thread that thread creates inherits it, so the filtered thread
/// starts nothing - no thread, no task, no thread-pool work - and simply ends, taking the filter with it.
/// </remarks>
internal static unsafe class RingSetupSeccompTests
{
    // linux/prctl.h and linux/seccomp.h.
    private const int PrSetNoNewPrivs = 38;
    private const int PrSetSeccomp = 22;
    private const nuint SeccompModeFilter = 2;
    private const uint SeccompRetErrno = 0x0005_0000;
    private const uint SeccompRetAllow = 0x7fff_0000;

    // linux/filter.h: load a word of seccomp_data, compare it, return.
    private const ushort BpfLdWAbs = 0x20;
    private const ushort BpfJeqK = 0x15;
    private const ushort BpfRetK = 0x06;
    private const uint SeccompDataNr = 0;     // offsetof(struct seccomp_data, nr)
    private const uint SeccompDataArch = 4;   // offsetof(struct seccomp_data, arch)

    // linux/audit.h. io_uring_setup is 425 on both: it is in the generic syscall table.
    private const uint AuditArchX86_64 = 0xC000_003E;
    private const uint AuditArchAarch64 = 0xC000_00B7;
    private const uint IoUringSetup = 425;
    private const uint Eperm = 1;

    public static void Register(Runner runner)
    {
        runner.Test("ring setup: a ring a seccomp filter refuses says io_uring is disabled", () =>
        {
            string filtered = OnOwnThread(refuseIoUringSetup: true);

            Assert.True(filtered.Contains("errno 1 "), $"the filter's EPERM was not what failed: {filtered}");
            Assert.True(filtered.Contains("disabled"), $"EPERM was not explained: {filtered}");

            // Control: the refusal was the filter's - a thread without one still gets its ring.
            Assert.Equal("created", OnOwnThread(refuseIoUringSetup: false));
        }, skip: RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64)
                 || !File.ReadAllText("/proc/self/status").Contains("Seccomp:"));
    }

    // Ring.Create on a thread of its own: "created", or what it threw.
    private static string OnOwnThread(bool refuseIoUringSetup)
    {
        string outcome = "the thread never ran";
        var thread = new Thread(() =>
        {
            if (refuseIoUringSetup && !RefuseIoUringSetupOnThisThread(out int errno))
            {
                outcome = $"no filter: prctl failed with errno {errno}";
                return;
            }

            try
            {
                Ring.Create(16).Dispose();
                outcome = "created";
            }
            catch (InvalidOperationException e)
            {
                outcome = e.Message;
            }
        }) { IsBackground = true, Name = refuseIoUringSetup ? "seccomp-filtered" : "seccomp-control" };

        thread.Start();
        Assert.True(thread.Join(10_000), $"{thread.Name} did not finish");
        return outcome;
    }

    // EPERM for io_uring_setup, everything else allowed, on x86-64 and arm64; any other arch passes
    // untouched. No privilege is needed once no_new_privs is set.
    private static bool RefuseIoUringSetupOnThisThread(out int errno)
    {
        SockFilter* program = stackalloc SockFilter[]
        {
            new() { Code = BpfLdWAbs, K = SeccompDataArch },
            new() { Code = BpfJeqK, Jt = 1, Jf = 0, K = AuditArchX86_64 },
            new() { Code = BpfJeqK, Jt = 0, Jf = 3, K = AuditArchAarch64 },
            new() { Code = BpfLdWAbs, K = SeccompDataNr },
            new() { Code = BpfJeqK, Jt = 0, Jf = 1, K = IoUringSetup },
            new() { Code = BpfRetK, K = SeccompRetErrno | Eperm },
            new() { Code = BpfRetK, K = SeccompRetAllow },
        };
        var fprog = new SockFprog { Len = 7, Filter = program };

        if (prctl(PrSetNoNewPrivs, 1, 0, 0, 0) != 0 || prctl(PrSetSeccomp, SeccompModeFilter, (nuint)(&fprog), 0, 0) != 0)
        {
            errno = Marshal.GetLastPInvokeError();
            return false;
        }

        errno = 0;
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SockFilter
    {
        public ushort Code;
        public byte Jt;
        public byte Jf;
        public uint K;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SockFprog
    {
        public ushort Len;
        public SockFilter* Filter;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int prctl(int option, nuint arg2, nuint arg3, nuint arg4, nuint arg5);
}
