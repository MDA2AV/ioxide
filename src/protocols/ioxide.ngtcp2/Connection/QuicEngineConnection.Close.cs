namespace ioxide.ngtcp2;

/// <summary>App-initiated close: the mirror of CloseFromEngine, but the error is ours - a
/// CONNECTION_CLOSE with the given application error code goes out as the connection's last
/// datagram, then the same teardown as every other death.</summary>
public unsafe partial class QuicEngineConnection
{
    public override void Close(ulong applicationErrorCode)
    {
        if (_closed)
        {
            return;
        }

        // What this cycle queued is packetized first: after CONNECTION_CLOSE nothing more can be.
        if (_inEngineCycle)
        {
            FlushEgress();
            if (_closed)
            {
                return;
            }
        }

        int farewell = 0;
        if (_conn != 0)
        {
            fixed (byte* dest = _sendBuf)
            {
                nint written = Ngtcp2.iq_conn_close(_conn, applicationErrorCode,
                    dest, (nuint)_sendBuf.Length, NowNs());
                farewell = (int)written > 0 ? (int)written : 0;
            }
        }

        Teardown(farewell);
    }
}
