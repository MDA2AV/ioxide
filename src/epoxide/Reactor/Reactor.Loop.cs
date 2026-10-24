using static epoxide.Native;

namespace epoxide;

// Loop
public sealed unsafe partial class Reactor
{
    private void Loop()
    {
        int maxEvents = _config.MaxEvents;

        while (!_stopRequested)
        {
            DrainPostQ();
            DrainRegisterQ();
            DrainCloseQ();
            DrainRecycleQ();

            int n = Wait(maxEvents);
            if (n < 0)
            {
                // A signal is the one transient failure; anything else is a lifecycle or programming
                // error, thrown rather than broken out of: a reactor that vanishes while the process
                // reports healthy is the worst of both, and whether the process then dies is the
                // host's call, via Reactor.OnFault.
                int errno = Errno;
                if (errno == EINTR)
                {
                    continue;
                }
                throw new InvalidOperationException($"[r{_id}] epoll_wait failed with errno {errno}; this reactor cannot continue");
            }

            NowMs = MonotonicMs;   // one read per batch; see Reactor.Tcp.Sweep.cs

            for (int i = 0; i < n; i++)
            {
                Dispatch(EpollData(_events, i), EpollEvents(_events, i));
            }

            RunDueTimers();
            RunDueTickers();
        }
    }

    // Set once epoll_pwait2 is missing from the kernel or libc: from then on, the millisecond wait.
    private static bool s_millisecondWait;

    // epoll_pwait2 takes the timeout in ns, so the loop wakes at a timer's deadline, not the
    // millisecond after it - which every timer due in one sleep would otherwise share.
    private int Wait(int maxEvents)
    {
        long ns = WaitTimeoutNs();
        if (!s_millisecondWait)
        {
            try
            {
                timespec timeout = new() { tv_sec = ns / 1_000_000_000, tv_nsec = ns % 1_000_000_000 };
                int n = epoll_pwait2(_epfd, _events, maxEvents, &timeout, null);
                if (n >= 0 || Errno != ENOSYS)
                {
                    return n;
                }
            }
            catch (EntryPointNotFoundException)
            {
            }

            s_millisecondWait = true;
        }

        // Rounded up, so a timer never fires early.
        return epoll_wait(_epfd, _events, maxEvents, (int)Math.Min((ns + 999_999) / 1_000_000, int.MaxValue));
    }

    private void Dispatch(ulong data, uint events)
    {
        byte   kind = (byte)(data >> KindShift);
        ushort gen  = (ushort)(data >> GenShift);
        int    fd   = (int)(uint)data;

        switch (kind)
        {
            case KindConn:
                OnConnectionEvent(fd, gen, events);
                return;

            case KindListen:
                OnListenerReadable(fd);
                return;

            case KindWake:
                OnWake();
                return;
        }
    }

    private void OnConnectionEvent(int fd, ushort gen, uint events)
    {
        TcpConnection? conn = ConnAt(fd, gen);
        if (conn == null)
        {
            return;   // queued for the fd's previous tenant
        }

        if ((events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) != 0)
        {
            // A recv takes the peer's FIN along with the bytes in front of it, and stops short at an
            // urgent mark, so a short one no longer means drained once this edge, now spent, has said
            // either. Set before OnReadable, whose state change the reader's next recv follows.
            if ((events & (EPOLLPRI | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) != 0)
            {
                conn.ReadUntilEmpty();
            }

            conn.OnReadable();

            // The read may have resumed the handler inline, and it may have let the connection go.
            if (ConnAt(fd, gen) == null)
            {
                return;
            }
        }

        if ((events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) != 0)
        {
            conn.OnWritable();
        }
    }
}
