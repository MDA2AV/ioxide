namespace ioxide.ngtcp2;

/// <summary>Ingress: datagrams routed by the transport are fed to ngtcp2 here.</summary>
public unsafe partial class QuicEngineConnection
{
    /// <summary>Kept for callers that have no address to give - feeds ngtcp2 the path it already has.</summary>
    public override void OnDatagram(ReadOnlySpan<byte> payload, byte tos)
        => OnDatagram(payload, tos, 0, 0);

    public override void OnDatagram(ReadOnlySpan<byte> payload, byte tos, nint peerAddr, int peerAddrLen)
    {
        if (_closed)
        {
            return;
        }
        _inEngineCycle = true;
        try
        {
            OnDatagramCore(payload, tos, peerAddr, peerAddrLen);
        }
        finally
        {
            EndEngineCycle();
        }
    }

    private void OnDatagramCore(ReadOnlySpan<byte> payload, byte tos, nint peerAddr, int peerAddrLen)
    {
        // One call = one wire datagram: the transport pre-splits GRO trains before demux.
        int rv;

        // TODO: can we get the byte* without a fixed
        fixed (byte* p = payload)
        {
            // The address this datagram really came from. ngtcp2 compares it against the path in
            // force and, when they differ, validates the new one with PATH_CHALLENGE before
            // adopting it - so passing it is not "trust the sender", it is giving the library the
            // input its own migration logic needs. Zero means the caller had none, and the path
            // it already holds is used.
            rv = Ngtcp2.iq_conn_read(_conn, (void*)peerAddr, (nuint)peerAddrLen,
                p, (nuint)payload.Length, tos, NowNs());
        }
        if (rv != 0)
        {
            CloseFromEngine(rv);
            return;
        }
        if (!_handshakeDone && Ngtcp2.iq_conn_is_established(_conn) != 0)
        {
            HandshakeCompletedOnce();
        }

        SignalSendCapacity();
        FireRecv();
        FireHandshakeSignal();
    }
}
