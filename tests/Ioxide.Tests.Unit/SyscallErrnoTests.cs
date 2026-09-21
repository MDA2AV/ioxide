using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The io_uring syscall wrappers must report failures the way the rest of the code reads them:
/// as a negative errno, liburing's convention (#220).
/// </summary>
/// <remarks>
/// glibc's <c>syscall()</c> returns -1 and puts the code in errno; it never returns -errno, so an
/// import without <c>SetLastError</c> loses it and every comparison against a specific errno goes
/// dead - NO_SQARRAY never falls back on 6.1-6.5, and one interrupted io_uring_enter ends that
/// reactor while the process reports healthy at reduced capacity.
///
/// The three declarations sat together and only syscall4 had it, which is how it went unnoticed.
/// No sockets, no signals, no timing here: ask the kernel for something it must refuse.
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
            // Refused by every kernel, so no feature detection and no accidental pass.
            int rc = SetupZeroEntries();

            Assert.True(rc < 0, $"io_uring_setup(0) was expected to fail, got {rc}");
            Assert.Equal(ExpectedSetupErrno, rc);
        });

        runner.Test("syscall: io_uring_enter reports a negative errno, not -1", () =>
        {
            // Not a ring descriptor, so the kernel answers EBADF - the value the two loops test
            // against -EINTR/-EAGAIN/-EBUSY to decide whether to keep going.
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
