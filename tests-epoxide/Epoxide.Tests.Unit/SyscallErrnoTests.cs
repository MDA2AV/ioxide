using System.Runtime.InteropServices;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// The syscall wrappers must report failures the way the rest of the code reads them: -1, with the
/// errno kept as the last P/Invoke error and read through <see cref="Native.Errno"/> straight after.
/// </summary>
/// <remarks>
/// ioxide's version of this (#220) caught an import without <c>SetLastError</c>: the call still
/// returned -1, but the code was gone, so every comparison against a specific errno went dead and
/// one interrupted wait ended the reactor. epoxide's loop decides the same way - EINTR to go on, a
/// read's EAGAIN to park, a send's to wait for the edge, EMFILE to pause the listener, EINPROGRESS
/// for a connect - so each wrapper those decisions read is asked for something the kernel must
/// refuse, and the errno it reports must be the one the kernel gave. No traffic, no timing.
/// </remarks>
internal static unsafe class SyscallErrnoTests
{
    private const int EBADF = 9;
    private const int EINVAL = 22;
    private const int EAFNOSUPPORT = 97;

    // The same call as Native.epoll_wait, declared WITHOUT SetLastError: the shape of ioxide's #220.
    [DllImport("libc", EntryPoint = "epoll_wait")]
    private static extern int EpollWaitLosingErrno(int epfd, void* events, int maxevents, int timeout);

    public static void Register(Runner runner)
    {
        runner.Test("syscall: epoll_wait reports its errno, not just -1", () =>
        {
            // Not an epoll descriptor, so the kernel answers EBADF - the value the loop tests against
            // EINTR to decide whether to keep going.
            byte* events = stackalloc byte[16];
            Marshal.SetLastPInvokeError(0);
            int rc = Native.epoll_wait(-1, events, 1, 0);
            int errno = Native.Errno;

            Assert.Equal(-1, rc);
            Assert.Equal(EBADF, errno);
        });

        runner.Test("syscall: control: an import without SetLastError loses the errno, so the check above can fail", () =>
        {
            byte* events = stackalloc byte[16];
            Marshal.SetLastPInvokeError(0);
            int rc = EpollWaitLosingErrno(-1, events, 1, 0);

            Assert.Equal(-1, rc);
            Assert.True(Native.Errno != EBADF, "an import without SetLastError still reported EBADF, so the test above cannot tell");
        });

        runner.Test("syscall: the socket and epoll calls the loops branch on report their errno", () =>
        {
            byte* buffer = stackalloc byte[64];
            Native.msghdr message = default;
            Native.sockaddr_in address = default;
            int option = 0;
            uint length = sizeof(int);
            uint addressLength = (uint)sizeof(Native.sockaddr_in);
            var wrong = new List<string>();

            // Each call is made straight before its check, which reads the errno before anything else
            // can make a P/Invoke on this thread.
            void Check(string call, long rc, int expected)
            {
                int errno = Native.Errno;
                if (rc != -1 || errno != expected)
                {
                    wrong.Add($"{call} returned {rc} with errno {errno}, expected -1 with {expected}");
                }
                if (rc >= 0 && call is "epoll_create1" or "eventfd" or "socket")
                {
                    Native.close((int)rc);   // it should have been refused, but it made a descriptor
                }
                Marshal.SetLastPInvokeError(0);
            }

            Marshal.SetLastPInvokeError(0);
            Check("epoll_ctl", Native.EpollCtl(-1, Native.EPOLL_CTL_ADD, -1, Native.EPOLLIN, 0), EBADF);
            Check("epoll_create1", Native.epoll_create1(0x1), EINVAL);
            Check("eventfd", Native.eventfd(0, 0x2), EINVAL);   // 0x1 is EFD_SEMAPHORE; 0x2 is no flag
            Check("socket", Native.socket(9_999, Native.SOCK_STREAM, 0), EAFNOSUPPORT);
            Check("accept4", Native.accept4(-1, null, null, Native.SOCK_NONBLOCK), EBADF);
            Check("connect", Native.connect(-1, &address, addressLength), EBADF);
            Check("bind", Native.bind(-1, &address, addressLength), EBADF);
            Check("listen", Native.listen(-1, 1), EBADF);
            Check("recv", Native.recv(-1, buffer, 64, 0), EBADF);
            Check("send", Native.send(-1, buffer, 64, Native.MSG_NOSIGNAL), EBADF);
            Check("sendmsg", Native.sendmsg(-1, &message, Native.MSG_NOSIGNAL), EBADF);
            Check("getsockopt", Native.getsockopt(-1, Native.SOL_SOCKET, Native.SO_ERROR, &option, &length), EBADF);
            Check("shutdown", Native.shutdown(-1, Native.SHUT_WR), EBADF);

            Assert.True(wrong.Count == 0, string.Join("; ", wrong));
        });
    }
}
