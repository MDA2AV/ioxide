namespace ioxide.ngtcp2;

/// <summary>
/// While a request has arrived whole and is unanswered - a peer-opened bidi stream with the peer's
/// FIN and not ours - keep-alive PINGs keep the peer answering, so neither the transport's read
/// timeout nor the peer's own idle timer reaps a connection whose handler is just slow.
/// </summary>
public unsafe partial class QuicEngineConnection
{
    private readonly HashSet<long> _owedStreams = [];
    private bool _keepAliveOn;
    private bool _keepAliveStale;   // re-derive the interval once the peer's idle timeout is known

    // Bidirectional (bit 1 clear) and opened by the peer (bit 0: 0 = client).
    private bool IsPeerBidi(long streamId)
        => (streamId & 0x2) == 0 && (streamId & 0x1) == (_engine is not null ? 0 : 1);

    private void OweResponse(long streamId)
    {
        if (IsPeerBidi(streamId))
        {
            _owedStreams.Add(streamId);
        }
    }

    private void SettleResponse(long streamId) => _owedStreams.Remove(streamId);

    // Outside ngtcp2's callbacks: at every engine cycle's end, and after a SendStream made outside one.
    private void ApplyKeepAlive()
    {
        bool want = _owedStreams.Count > 0 && !_closed && _conn != 0;
        if (want == _keepAliveOn && !(want && _keepAliveStale))
        {
            return;
        }
        _keepAliveOn = want;
        _keepAliveStale = false;

        // The sweep reaps on a tick, and an idle reactor sends the ping - and the ACK before it,
        // which restarts ngtcp2's keep-alive clock - only on a tick. Keep two ticks clear.
        int readMs = Math.Max(0, _reactor.QuicReadTimeoutMs);
        int boundMs = readMs - Math.Min(2 * Reactor.TickMs, readMs / 2);
        Ngtcp2.iq_conn_set_keep_alive(_conn, want ? 1 : 0, (ulong)boundMs * 1_000_000UL);
    }

    private void ReapplyKeepAliveAfterHandshake() => _keepAliveStale = true;
}
