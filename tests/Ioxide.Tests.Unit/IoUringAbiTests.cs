using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The io_uring ABI ioxide declares by hand - syscall numbers, opcodes, flags, struct sizes and field
/// offsets - against the kernel's own header, asked through a probe compiled with cc (#427).
/// </summary>
/// <remarks>
/// The header is linux-libc-dev's, which trails the kernel. Values newer than the 6.8 one the CI runners
/// have are guarded, and reported as unchecked where the header lacks them; an older header fails to
/// build the probe rather than passing quietly.
/// </remarks>
internal static unsafe class IoUringAbiTests
{
    private const string Header = "/usr/include/linux/io_uring.h";

    /// <summary>
    /// One value: <paramref name="Ioxide"/> as ioxide declares it, <paramref name="Expression"/> as C
    /// asks the header for it. A <paramref name="Guard"/> macro the header lacks reads
    /// <paramref name="Fallback"/> instead, or leaves the value unchecked.
    /// </summary>
    private readonly record struct Entry(string Name, long Ioxide, string Expression, string? Guard = null, string? Fallback = null);

    public static void Register(Runner runner)
    {
        bool missing = !File.Exists(Header) || !OnPath("cc");

        runner.Test("abi: io_uring's syscall numbers, opcodes and flags match the kernel's header",
            () => AssertMatches(Constants()), skip: missing);

        runner.Test("abi: io_uring's struct sizes and field offsets match the kernel's header",
            () => AssertMatches(Layouts()), skip: missing);
    }

    private static Entry[] Constants() =>
    [
        new("__NR_io_uring_setup", Syscall("SYS_IO_URING_SETUP"), "__NR_io_uring_setup"),
        new("__NR_io_uring_enter", Syscall("SYS_IO_URING_ENTER"), "__NR_io_uring_enter"),
        new("__NR_io_uring_register", Syscall("SYS_IO_URING_REGISTER"), "__NR_io_uring_register"),

        new("IORING_OP_POLL_ADD", Native.IORING_OP_POLL_ADD, "IORING_OP_POLL_ADD"),
        new("IORING_OP_SENDMSG", Native.IORING_OP_SENDMSG, "IORING_OP_SENDMSG"),
        new("IORING_OP_RECVMSG", Native.IORING_OP_RECVMSG, "IORING_OP_RECVMSG"),
        new("IORING_OP_TIMEOUT", Native.IORING_OP_TIMEOUT, "IORING_OP_TIMEOUT"),
        new("IORING_OP_ACCEPT", Native.IORING_OP_ACCEPT, "IORING_OP_ACCEPT"),
        new("IORING_OP_ASYNC_CANCEL", Native.IORING_OP_ASYNC_CANCEL, "IORING_OP_ASYNC_CANCEL"),
        new("IORING_OP_CONNECT", Native.IORING_OP_CONNECT, "IORING_OP_CONNECT"),
        new("IORING_OP_READ", Native.IORING_OP_READ, "IORING_OP_READ"),
        new("IORING_OP_WRITE", Native.IORING_OP_WRITE, "IORING_OP_WRITE"),
        new("IORING_OP_SEND", Native.IORING_OP_SEND, "IORING_OP_SEND"),
        new("IORING_OP_RECV", Native.IORING_OP_RECV, "IORING_OP_RECV"),
        new("IORING_OP_SEND_ZC", Native.IORING_OP_SEND_ZC, "IORING_OP_SEND_ZC"),

        new("IORING_ENTER_GETEVENTS", Native.IORING_ENTER_GETEVENTS, "IORING_ENTER_GETEVENTS"),
        new("IORING_ENTER_EXT_ARG", Native.IORING_ENTER_EXT_ARG, "IORING_ENTER_EXT_ARG"),
        new("IORING_ENTER_REGISTERED_RING", Native.IORING_ENTER_REGISTERED_RING, "IORING_ENTER_REGISTERED_RING"),
        new("IORING_SQ_CQ_OVERFLOW", Native.IORING_SQ_CQ_OVERFLOW, "IORING_SQ_CQ_OVERFLOW"),
        new("IORING_OFF_SQ_RING", Native.IORING_OFF_SQ_RING, "IORING_OFF_SQ_RING"),
        new("IORING_OFF_SQES", Native.IORING_OFF_SQES, "IORING_OFF_SQES"),
        new("IORING_SETUP_SINGLE_ISSUER", Native.IORING_SETUP_SINGLE_ISSUER, "IORING_SETUP_SINGLE_ISSUER"),
        new("IORING_SETUP_DEFER_TASKRUN", Native.IORING_SETUP_DEFER_TASKRUN, "IORING_SETUP_DEFER_TASKRUN"),
        new("IORING_SETUP_NO_SQARRAY", Native.IORING_SETUP_NO_SQARRAY, "IORING_SETUP_NO_SQARRAY"),

        new("IORING_ACCEPT_MULTISHOT", Native.IORING_ACCEPT_MULTISHOT, "IORING_ACCEPT_MULTISHOT"),
        new("IORING_RECV_MULTISHOT", Native.IORING_RECV_MULTISHOT, "IORING_RECV_MULTISHOT"),
        new("IORING_POLL_ADD_MULTI", Native.IORING_POLL_ADD_MULTI, "IORING_POLL_ADD_MULTI"),
        new("IOSQE_BUFFER_SELECT", Native.IOSQE_BUFFER_SELECT, "IOSQE_BUFFER_SELECT"),
        new("IORING_CQE_F_BUFFER", Native.IORING_CQE_F_BUFFER, "IORING_CQE_F_BUFFER"),
        new("IORING_CQE_F_MORE", Native.IORING_CQE_F_MORE, "IORING_CQE_F_MORE"),
        new("IORING_CQE_F_NOTIF", Native.IORING_CQE_F_NOTIF, "IORING_CQE_F_NOTIF"),
        new("IORING_CQE_BUFFER_SHIFT", Native.IORING_CQE_BUFFER_SHIFT, "IORING_CQE_BUFFER_SHIFT"),
        new("IORING_REGISTER_RING_FDS", Native.IORING_REGISTER_RING_FDS, "IORING_REGISTER_RING_FDS"),
        new("IORING_UNREGISTER_RING_FDS", Native.IORING_UNREGISTER_RING_FDS, "IORING_UNREGISTER_RING_FDS"),
        new("IORING_REGISTER_PBUF_RING", Native.IORING_REGISTER_PBUF_RING, "IORING_REGISTER_PBUF_RING"),
        new("IORING_UNREGISTER_PBUF_RING", Native.IORING_UNREGISTER_PBUF_RING, "IORING_UNREGISTER_PBUF_RING"),

        // Linux 6.12, in one commit. IOU_PBUF_RING_INC is an enum value, so the macro guards both.
        new("IORING_CQE_F_BUF_MORE", Native.IORING_CQE_F_BUF_MORE, "IORING_CQE_F_BUF_MORE", Guard: "IORING_CQE_F_BUF_MORE"),
        new("IOU_PBUF_RING_INC", Native.IOU_PBUF_RING_INC, "IOU_PBUF_RING_INC", Guard: "IORING_CQE_F_BUF_MORE"),

        // The rest of Native.IoUring.cs: the ring's mappings, the wake eventfd, and the errnos Ring.Create reads.
        new("PROT_READ", Native.PROT_READ, "PROT_READ"),
        new("PROT_WRITE", Native.PROT_WRITE, "PROT_WRITE"),
        new("MAP_SHARED", Native.MAP_SHARED, "MAP_SHARED"),
        new("MAP_POPULATE", Native.MAP_POPULATE, "MAP_POPULATE"),
        new("EFD_CLOEXEC", Native.EFD_CLOEXEC, "EFD_CLOEXEC"),
        new("EFD_NONBLOCK", Native.EFD_NONBLOCK, "EFD_NONBLOCK"),
        new("POLLIN", Native.POLLIN, "POLLIN"),
        new("EPERM", Native.EPERM, "EPERM"),
        new("ENOMEM", Native.ENOMEM, "ENOMEM"),
        new("EINVAL", Native.EINVAL, "EINVAL"),
        new("ENOSYS", Native.ENOSYS, "ENOSYS"),
    ];

    private static Entry[] Layouts()
    {
        Native.IoUringSqe sqe = default;
        Native.IoUringCqe cqe = default;
        Native.IoUringParams p = default;
        Native.io_uring_buf_reg reg = default;
        Native.io_uring_rsrc_update update = default;
        Native.io_uring_getevents_arg arg = default;
        Native.__kernel_timespec ts = default;
        Native.io_uring_recvmsg_out msg = default;

        // Reserved space is left out: the kernel carves new fields from it - sq_off.user_addr in 6.5,
        // io_uring_buf_reg.min_left in 7.0 - with zero meaning what it meant before, and ioxide zeroes it.
        // Each struct's size and the fields either side pin where it is.
        return
        [
            Size("io_uring_sqe", sizeof(Native.IoUringSqe)),
            Field("io_uring_sqe", "opcode", Offset(ref sqe, ref sqe.opcode)),
            Field("io_uring_sqe", "flags", Offset(ref sqe, ref sqe.flags)),
            Field("io_uring_sqe", "ioprio", Offset(ref sqe, ref sqe.ioprio)),
            Field("io_uring_sqe", "fd", Offset(ref sqe, ref sqe.fd)),
            Field("io_uring_sqe", "off", Offset(ref sqe, ref sqe.off)),
            Field("io_uring_sqe", "addr", Offset(ref sqe, ref sqe.addr)),
            Field("io_uring_sqe", "len", Offset(ref sqe, ref sqe.len)),
            Field("io_uring_sqe", "op_flags", Offset(ref sqe, ref sqe.op_flags), "rw_flags"),   // one union: msg_flags, accept_flags, ...
            Field("io_uring_sqe", "user_data", Offset(ref sqe, ref sqe.user_data)),
            Field("io_uring_sqe", "buf_index", Offset(ref sqe, ref sqe.buf_index)),
            Field("io_uring_sqe", "personality", Offset(ref sqe, ref sqe.personality)),
            Field("io_uring_sqe", "splice_fd_in", Offset(ref sqe, ref sqe.splice_fd_in)),
            Field("io_uring_sqe", "addr3", Offset(ref sqe, ref sqe.addr3)),

            Size("io_uring_cqe", sizeof(Native.IoUringCqe)),
            Field("io_uring_cqe", "user_data", Offset(ref cqe, ref cqe.user_data)),
            Field("io_uring_cqe", "res", Offset(ref cqe, ref cqe.res)),
            Field("io_uring_cqe", "flags", Offset(ref cqe, ref cqe.flags)),

            Size("io_uring_params", sizeof(Native.IoUringParams)),
            Field("io_uring_params", "sq_entries", Offset(ref p, ref p.sq_entries)),
            Field("io_uring_params", "cq_entries", Offset(ref p, ref p.cq_entries)),
            Field("io_uring_params", "flags", Offset(ref p, ref p.flags)),
            Field("io_uring_params", "sq_thread_cpu", Offset(ref p, ref p.sq_thread_cpu)),
            Field("io_uring_params", "sq_thread_idle", Offset(ref p, ref p.sq_thread_idle)),
            Field("io_uring_params", "features", Offset(ref p, ref p.features)),
            Field("io_uring_params", "wq_fd", Offset(ref p, ref p.wq_fd)),
            Field("io_uring_params", "sq_off", Offset(ref p, ref p.sq_off)),
            Field("io_uring_params", "cq_off", Offset(ref p, ref p.cq_off)),

            Size("io_sqring_offsets", sizeof(Native.SqRingOffsets)),
            Field("io_sqring_offsets", "head", Offset(ref p.sq_off, ref p.sq_off.head)),
            Field("io_sqring_offsets", "tail", Offset(ref p.sq_off, ref p.sq_off.tail)),
            Field("io_sqring_offsets", "ring_mask", Offset(ref p.sq_off, ref p.sq_off.ring_mask)),
            Field("io_sqring_offsets", "ring_entries", Offset(ref p.sq_off, ref p.sq_off.ring_entries)),
            Field("io_sqring_offsets", "flags", Offset(ref p.sq_off, ref p.sq_off.flags)),
            Field("io_sqring_offsets", "dropped", Offset(ref p.sq_off, ref p.sq_off.dropped)),
            Field("io_sqring_offsets", "array", Offset(ref p.sq_off, ref p.sq_off.array)),

            Size("io_cqring_offsets", sizeof(Native.CqRingOffsets)),
            Field("io_cqring_offsets", "head", Offset(ref p.cq_off, ref p.cq_off.head)),
            Field("io_cqring_offsets", "tail", Offset(ref p.cq_off, ref p.cq_off.tail)),
            Field("io_cqring_offsets", "ring_mask", Offset(ref p.cq_off, ref p.cq_off.ring_mask)),
            Field("io_cqring_offsets", "ring_entries", Offset(ref p.cq_off, ref p.cq_off.ring_entries)),
            Field("io_cqring_offsets", "overflow", Offset(ref p.cq_off, ref p.cq_off.overflow)),
            Field("io_cqring_offsets", "cqes", Offset(ref p.cq_off, ref p.cq_off.cqes)),
            Field("io_cqring_offsets", "flags", Offset(ref p.cq_off, ref p.cq_off.flags)),

            Size("io_uring_buf_reg", sizeof(Native.io_uring_buf_reg)),
            Field("io_uring_buf_reg", "ring_addr", Offset(ref reg, ref reg.ring_addr)),
            Field("io_uring_buf_reg", "ring_entries", Offset(ref reg, ref reg.ring_entries)),
            Field("io_uring_buf_reg", "bgid", Offset(ref reg, ref reg.bgid)),
            Field("io_uring_buf_reg", "flags", Offset(ref reg, ref reg.flags)),

            Size("io_uring_rsrc_update", sizeof(Native.io_uring_rsrc_update)),
            Field("io_uring_rsrc_update", "offset", Offset(ref update, ref update.offset)),
            Field("io_uring_rsrc_update", "data", Offset(ref update, ref update.data)),

            Size("io_uring_getevents_arg", sizeof(Native.io_uring_getevents_arg)),
            Field("io_uring_getevents_arg", "sigmask", Offset(ref arg, ref arg.sigmask)),
            Field("io_uring_getevents_arg", "sigmask_sz", Offset(ref arg, ref arg.sigmask_sz)),
            // Named in 6.12, with IORING_FEAT_MIN_TIMEOUT; the same four bytes were pad before.
            Field("io_uring_getevents_arg", "min_wait_usec", Offset(ref arg, ref arg.min_wait_usec))
                with { Guard = "IORING_FEAT_MIN_TIMEOUT", Fallback = "offsetof(struct io_uring_getevents_arg, pad)" },
            Field("io_uring_getevents_arg", "ts", Offset(ref arg, ref arg.ts)),

            Size("__kernel_timespec", sizeof(Native.__kernel_timespec)),
            Field("__kernel_timespec", "tv_sec", Offset(ref ts, ref ts.tv_sec)),
            Field("__kernel_timespec", "tv_nsec", Offset(ref ts, ref ts.tv_nsec)),

            Size("io_uring_recvmsg_out", sizeof(Native.io_uring_recvmsg_out)),
            Field("io_uring_recvmsg_out", "namelen", Offset(ref msg, ref msg.namelen)),
            Field("io_uring_recvmsg_out", "controllen", Offset(ref msg, ref msg.controllen)),
            Field("io_uring_recvmsg_out", "payloadlen", Offset(ref msg, ref msg.payloadlen)),
            Field("io_uring_recvmsg_out", "flags", Offset(ref msg, ref msg.flags)),

            // The provided-buffer rings have no struct here: the reactor writes each entry by offset - addr,
            // len and bid at 0, 8 and 12 of a 16-byte entry - and the ring's tail at 14.
            Size("io_uring_buf", 16),
            Field("io_uring_buf", "addr", 0),
            Field("io_uring_buf", "len", 8),
            Field("io_uring_buf", "bid", 12),
            Field("io_uring_buf_ring", "tail", 14),
        ];
    }

    private static Entry Size(string type, int size) => new($"sizeof({type})", size, $"sizeof(struct {type})");

    private static Entry Field(string type, string field, long offset, string? headerField = null)
        => new($"{type}.{field}", offset, $"offsetof(struct {type}, {headerField ?? field})");

    private static long Offset<TStruct, TField>(ref TStruct value, ref TField field)
        => (long)Unsafe.ByteOffset(ref Unsafe.As<TStruct, byte>(ref value), ref Unsafe.As<TField, byte>(ref field));

    // The syscall numbers are private to Native.
    private static long Syscall(string name)
        => Convert.ToInt64(typeof(Native).GetField(name, BindingFlags.NonPublic | BindingFlags.Static)?.GetRawConstantValue()
                           ?? throw new Exception($"Native.{name} not found - the declaration moved; move this test with it"));

    private static void AssertMatches(Entry[] entries)
    {
        Dictionary<string, string> header = AskHeader(entries);

        var wrong = new List<string>();
        var tooNew = new List<string>();
        foreach (Entry entry in entries)
        {
            if (!header.TryGetValue(entry.Name, out string? value))
            {
                wrong.Add($"{entry.Name}: the probe printed nothing");
            }
            else if (value == "unchecked")
            {
                tooNew.Add(entry.Name);
            }
            else if (value != entry.Ioxide.ToString())
            {
                wrong.Add($"{entry.Name}: ioxide {entry.Ioxide}, the header {value}");
            }
        }

        if (tooNew.Count > 0)
        {
            Console.WriteLine($"      unchecked, this header is older than them: {string.Join(", ", tooNew)}");
        }

        Assert.True(wrong.Count == 0, $"{wrong.Count} of {entries.Length} differ from {Header}: {string.Join("; ", wrong)}");
    }

    // Compiles a probe printing "name value" per entry, or "name unchecked", and reads what it prints.
    private static Dictionary<string, string> AskHeader(Entry[] entries)
    {
        var source = new StringBuilder("""
            #include <errno.h>
            #include <poll.h>
            #include <stddef.h>
            #include <stdio.h>
            #include <sys/eventfd.h>
            #include <sys/mman.h>
            #include <sys/syscall.h>
            #include <linux/io_uring.h>
            #include <linux/time_types.h>

            int main(void)
            {

            """);
        foreach (Entry entry in entries)
        {
            string print = $"    printf(\"{entry.Name} %lld\\n\", (long long)({entry.Expression}));\n";
            if (entry.Guard is null)
            {
                source.Append(print);
                continue;
            }

            source.Append($"#ifdef {entry.Guard}\n").Append(print).Append("#else\n")
                .Append(entry.Fallback is null
                    ? $"    puts(\"{entry.Name} unchecked\");\n"
                    : $"    printf(\"{entry.Name} %lld\\n\", (long long)({entry.Fallback}));\n")
                .Append("#endif\n");
        }
        source.Append("    return 0;\n}\n");

        DirectoryInfo dir = Directory.CreateTempSubdirectory("ioxide-abi-");
        try
        {
            string c = Path.Combine(dir.FullName, "probe.c");
            string probe = Path.Combine(dir.FullName, "probe");
            File.WriteAllText(c, source.ToString());

            (int exit, string errors) = Run("cc", ["-std=gnu11", "-o", probe, c], stdout: false);
            Assert.True(exit == 0, $"cc could not build the probe against {Header}: {errors}");

            (exit, string printed) = Run(probe, [], stdout: true);
            Assert.True(exit == 0, $"the probe exited with {exit}");

            var values = new Dictionary<string, string>();
            foreach (string line in printed.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                int space = line.LastIndexOf(' ');
                values[line[..space]] = line[(space + 1)..];
            }
            return values;
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    // One pipe read, so the child can never block on the other: cc's errors, or the probe's output.
    private static (int Exit, string Text) Run(string file, string[] args, bool stdout)
    {
        var info = new ProcessStartInfo(file) { RedirectStandardOutput = stdout, RedirectStandardError = !stdout };
        foreach (string a in args)
        {
            info.ArgumentList.Add(a);
        }

        using Process process = Process.Start(info) ?? throw new IOException($"could not start {file}");
        string text = (stdout ? process.StandardOutput : process.StandardError).ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill();
            throw new TimeoutException($"{file} did not exit within 30 s");
        }
        return (process.ExitCode, text);
    }

    private static bool OnPath(string command)
        => (Environment.GetEnvironmentVariable("PATH") ?? "").Split(':')
            .Any(dir => dir.Length > 0 && File.Exists(Path.Combine(dir, command)));
}
