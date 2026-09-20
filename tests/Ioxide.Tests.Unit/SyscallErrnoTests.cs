using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The io_uring syscall wrappers must report failures the way the rest of the code reads them:
/// as a negative errno, liburing's convention (#220).
/// </summary>
/// <remarks>
/// glibc's <c>syscall()</c> returns -1 and puts the code in errno; it never returns -errno. An
/// import declared without <c>SetLastError</c> therefore loses the code entirely, and every
/// comparison against a specific errno becomes dead:
///
/// <code>
/// Ring.cs:46                      if (fd == -EINVAL)                        // the pre-6.6 fallback
/// Reactor.Loop.SharedRing.cs:60   rc != -EINTR &amp;&amp; rc != -EAGAIN &amp;&amp; rc != -EBUSY
/// Reactor.Loop.Incremental.cs:181 rc != -EINTR &amp;&amp; rc != -EAGAIN &amp;&amp; rc != -EBUSY
/// </code>
///
/// So NO_SQARRAY never falls back on 6.1-6.5, and one interrupted io_uring_enter - a SIGHUP
/// handler, a profiler's SIGPROF, anything the kernel routes to a reactor thread - ends that
/// reactor, while the process carries on reporting healthy at reduced capacity.
///
/// The three declarations sat next to each other in Native.IoUring.cs and only one of them,
/// syscall4 for io_uring_register, was declared SetLastError = true - which is how the omission
/// went unnoticed. All three now normalise to a negative errno.
///
/// No sockets, no signals, no timing here: ask the kernel for something it must refuse and read
/// what comes back.
/// </remarks>
internal static class SyscallErrnoTests
{
    /// <summary>EINVAL, which io_uring_setup must return for a zero-entry ring.</summary>
    private const int ExpectedSetupErrno = -22;

    /// <summary>EBADF, which io_uring_enter must return for a descriptor that is not a ring.</summary>
    private const int ExpectedEnterErrno = -9;

    public static void Register(Runner runner)
    {
        runner.Test("syscall: io_uring_setup reports a negative errno, not -1", () =>
        {
            // entries == 0 is refused by every kernel, so this needs no feature detection and
            // cannot pass by accident on a machine that happens to support something.
            int rc = SetupZeroEntries();

            Assert.True(rc < 0, $"io_uring_setup(0) was expected to fail, got {rc}");
            Assert.Equal(ExpectedSetupErrno, rc);
        });

        runner.Test("syscall: io_uring_enter reports a negative errno, not -1", () =>
        {
            // -1 is not a ring descriptor, so the kernel answers EBADF. This is the value the two
            // loops compare against -EINTR/-EAGAIN/-EBUSY to decide whether to keep going.
            int rc = Native.io_uring_enter(-1, 0, 0, 0);

            Assert.True(rc < 0, $"io_uring_enter(-1) was expected to fail, got {rc}");
            Assert.Equal(ExpectedEnterErrno, rc);
        });
    }

    private static unsafe int SetupZeroEntries()
    {
        Native.IoUringParams parameters = default;
        return Native.io_uring_setup(0, &parameters);
    }
}
