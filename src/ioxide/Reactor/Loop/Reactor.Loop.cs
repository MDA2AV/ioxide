namespace ioxide;

// Loop
public sealed unsafe partial class Reactor
{
    private void Loop()
    {
        long stopDeadlineMs = 0;
        while (true)
        {
            ClearWakePending();
            if (_incremental) DrainReturnQIncremental();
            else DrainReturnQ();
            DrainFlushQ();
            DrainRecycleQ();
            DrainRemoteOps();
            DrainPostQ();
            RearmStarvedRecvs();
            if (_leaving.Count > 0) RunLeaving();
            QuicFireDueTimers();

            // After the drains, so a stop whose last connection one of them let go of ends without a wait.
            if (_stopRequested && Stopped(ref stopDeadlineMs))
            {
                return;
            }

            // The transient three, which the loop carries on from: a signal, the kernel short of
            // resources, and overflow entries it could not flush - the CQ drain below is what EBUSY
            // wants anyway. Until #220 this could never match (the wrapper returned -1 for every
            // failure), so the first signal delivered to a reactor thread ended it.
            //
            // Anything else is a lifecycle or programming error. Throwing rather than breaking,
            // because a reactor that vanishes while the process reports healthy is the worst of
            // both; whether the process then dies is the host's call, via Reactor.OnFault.
            //
            // ETIME is not an error at all: the wait's own bound ran out (WaitForCompletions).
            int rc = WaitForCompletions();
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN && rc != -EBUSY && rc != -ETIME)
            {
                throw new InvalidOperationException(
                    $"[r{_id}] io_uring_enter failed with errno {-rc}; this reactor cannot continue");
            }

            NowMs = Native.MonotonicMs;   // one read per batch; see Reactor.Tcp.Sweep.cs

            // Picked once a batch, not per CQE, so no completion pays for the mode test, nor for whether this reactor is in a
            // round of TcpOptions.Rebalance, which only a tick changes.
            uint ready = _ring.CqReady();
            if (_weighing)
            {
                for (uint i = 0; i < ready; i++)
                {
                    DispatchWeighed(in _ring.CqeAt(i));
                }
            }
            else if (_incremental)
            {
                for (uint i = 0; i < ready; i++)
                {
                    DispatchIncremental(in _ring.CqeAt(i));
                }
            }
            else
            {
                for (uint i = 0; i < ready; i++)
                {
                    DispatchSharedRing(in _ring.CqeAt(i));
                }
            }
            _ring.CqAdvance(ready);

            RunDueTickers();
        }
    }
}
