using static ioxide.Native;

namespace ioxide;

// Loop - Dispatch Completions
public sealed unsafe partial class Reactor
{

#region Send

    // Shared by both loops. Handles plain SEND (one CQE) and SEND_ZC (a data CQE carrying
    // IORING_CQE_F_MORE, then a separate IORING_CQE_F_NOTIF once the kernel releases the slab).
    private void OnSendCompletion(int fd, ushort gen, int res, uint cqeFlags)
    {
        TcpConnection? conn = ConnAt(fd, gen);
        if (conn == null)
        {
            return;   // stale CQE - never touch the fd's new tenant
        }

        // Zero-copy buffer-release notification: the kernel is done with the slab. Recycle once the
        // data is fully sent and no further notifs are outstanding.
        if ((cqeFlags & IORING_CQE_F_NOTIF) != 0)
        {
            if (--conn.ZcNotifPending == 0 && conn.WriteHead >= conn.WriteInFlight)
            {
                FinishSend(conn, fd);
            }
            return;
        }

        if (res <= 0)
        {
            // Failed: nothing more goes out. A zero-copy send still posts its notif, so the
            // teardown runs from FinishSend once the kernel has let go of the slab.
            SubmitCancel(Tag(KindTcpRecv, gen, fd));   // the multishot recv is still armed
            conn.CloseAfterSend = true;
            conn.SuppressFin();
            conn.MarkClosed();
            conn.WriteInFlight = conn.WriteHead;
            res = 0;
        }
        conn.WriteHead += res;

        // A zero-copy send posts its data CQE with F_MORE and a notif will follow; hold the slab until
        // that notif arrives. Plain SEND never sets F_MORE, so this is a no-op for it.
        if ((cqeFlags & IORING_CQE_F_MORE) != 0)
        {
            conn.ZcNotifPending++;
        }

        if (conn.WriteHead < conn.WriteInFlight)
        {
            // Partial send (rare with MSG_WAITALL): resubmit the remainder.
            if (conn.FlushVectored)
            {
                conn.AdvanceIov(res);   // trim the iovec past the bytes just sent
                SubmitSendMsg(conn, fd, gen);
            }
            else
            {
                SubmitSend(conn, fd, gen, conn.WriteBuffer + conn.WriteHead, (uint)(conn.WriteInFlight - conn.WriteHead), conn.SendOpFlags);
            }
            return;
        }

        // Data fully sent: a ZC send still waits for its outstanding notif(s).
        if (conn.ZcNotifPending == 0)
        {
            FinishSend(conn, fd);
        }
    }

    // The kernel is done with the slab: complete the flush, then any teardown that waited for it.
    private void FinishSend(TcpConnection conn, int fd)
    {
        conn.CompleteFlush();

        if (conn.CloseAfterSend)
        {
            _connections[fd] = null;
            conn.ReleaseReactorRef();
        }
    }

#endregion

#region Wake

    private void OnWakeCompletion(bool more)
    {
        // Drain the eventfd counter so the next write re-triggers POLLIN; queues
        // drain at the top of the next loop iteration.
        ulong drain;
        read(_wakeFd, &drain, 8);
        if (!more)
        {
            ArmWakePoll();
        }
    }

#endregion

#region Client

    private void OnClientCompletion(int slot, int result)
    {
        IRingCompletion? target = _opTargets[slot];
        _opTargets[slot] = null;
        _opFree[_opFreeTop++] = slot;

        // The slot is free before Complete - the inline continuation may submit its next op.
        target?.Complete(result);
    }

#endregion

}
