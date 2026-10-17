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

            int n = epoll_wait(_epfd, _events, maxEvents, WaitTimeoutMs());
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
