namespace ioxide.ngtcp2;

/// <summary>Engine deadlines: the next-timeout query and the expiry callback.</summary>
public unsafe partial class QuicEngineConnection
{
    public override long GetNextTimeout(long nowMs)
    {
        if (_closed)
        {
            return long.MaxValue;
        }
        ulong expiryNs = Ngtcp2.iq_conn_expiry(_conn);
        if (expiryNs == ulong.MaxValue)
        {
            return long.MaxValue;
        }

        // Already due (it expired between ticker sweeps): fire on this sweep. The subtraction below
        // would otherwise underflow the ulong and push the deadline ~584 years out, permanently
        // killing this connection's loss recovery.
        ulong now = NowNs();
        if (expiryNs <= now)
        {
            return nowMs;
        }

        // The sweep works in TickCount64 ms; convert the ns deadline to that clock's frame.
        return nowMs + (long)((expiryNs - now) / 1_000_000);
    }

    public override void OnTimer(long nowMs)
    {
        if (_closed)
        {
            return;
        }
        _inEngineCycle = true;
        try
        {
            int rv = Ngtcp2.iq_conn_handle_expiry(_conn, NowNs());
            if (rv != 0)
            {
                CloseFromEngine(rv);
                return;
            }
            SignalSendCapacity();
            FireRecv();
            FireHandshakeSignal();
        }
        finally
        {
            EndEngineCycle();
        }
    }
}
