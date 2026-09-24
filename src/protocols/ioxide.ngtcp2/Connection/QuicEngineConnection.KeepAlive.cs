namespace ioxide.ngtcp2;

/// <summary>
/// Keep-alive while a response is owed: the engine's half of the QUIC read timeout.
/// </summary>
/// <remarks>
/// The transport reaps a connection whose peer has been silent for
/// <see cref="QuicOptions.ReadTimeoutMs"/>, and the peer may idle it out too. Both are right while
/// the connection waits on its peer and wrong while the peer waits on us: a request that takes
/// minutes to answer leaves both ends silent the whole time. So while any request has arrived whole
/// and its response is not finished, ngtcp2 pings the peer inside both bounds (see
/// iq_conn_set_keep_alive); its ACKs keep either clock from firing, and a peer that has gone stops
/// answering and is reaped as before.
///
/// "Owed" is judged on streams, which is what makes it protocol-agnostic: a bidirectional stream the
/// peer opened, whose FIN has arrived, and whose FIN this side has not sent. That is exactly a
/// request that is complete and unanswered in h3 or any request/response protocol over QUIC. A
/// request still arriving is not owed, so a peer that stalls halfway through one is still reaped.
/// </remarks>
public unsafe partial class QuicEngineConnection
{
    private readonly HashSet<long> _owedStreams = [];
    private bool _keepAliveOn;

    // The interval has to be derived again even though on/off has not changed - see
    // ReapplyKeepAliveAfterHandshake.
    private bool _keepAliveStale;

    // Bidirectional (bit 1 clear) and opened by the peer (bit 0 names the initiator: 0 = client).
    private bool IsPeerBidi(long streamId)
        => (streamId & 0x2) == 0 && (streamId & 0x1) == (_engine is not null ? 0 : 1);

    // The peer's FIN arrived. Inside an engine callback, so only recorded; ApplyKeepAlive acts on it.
    private void OweResponse(long streamId)
    {
        if (IsPeerBidi(streamId))
        {
            _owedStreams.Add(streamId);
        }
    }

    // Our FIN went out, or the stream ended some other way - closed, reset, refused.
    private void SettleResponse(long streamId) => _owedStreams.Remove(streamId);

    /// <summary>
    /// Brings ngtcp2's keep-alive in line with whether a response is owed. Runs outside ngtcp2's
    /// callbacks: at the end of every engine cycle, and after a SendStream made outside one.
    /// </summary>
    private void ApplyKeepAlive()
    {
        bool want = _owedStreams.Count > 0 && !_closed && _conn != 0;
        if (want == _keepAliveOn && !(want && _keepAliveStale))
        {
            return;
        }
        _keepAliveOn = want;
        _keepAliveStale = false;

        ulong boundNs = (ulong)Math.Max(0, _reactor.QuicReadTimeoutMs) * 1_000_000UL;
        Ngtcp2.iq_conn_set_keep_alive(_conn, want ? 1 : 0, boundNs);
    }

    // The interval is derived from the peer's idle timeout, which only becomes known with the
    // handshake. A response owed before that (0-RTT) re-derives it at the next cycle end.
    private void ReapplyKeepAliveAfterHandshake() => _keepAliveStale = true;
}
