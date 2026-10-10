namespace ioxide.nghttp2;

/// <summary>
/// The STREAMED-REQUEST half: with <see cref="Nghttp2Options.StreamRequestBodies"/> on, a request is
/// dispatched at its headers and its body arrives through an <see cref="Nghttp2BodyReader"/>.
///
/// The session is created with nghttp2's automatic WINDOW_UPDATE off, so the only credit the peer
/// ever gets back is what this side consumes - and every DATA byte nghttp2 hands out has to be
/// consumed exactly once, or the connection window leaks shut. A byte is consumed when its reader
/// hands it to the handler, when a handler that returns leaves it unread, when its stream is reset,
/// or on arrival when nobody is reading it any more. nghttp2 consumes padding and the DATA it
/// discards itself.
/// </summary>
public sealed partial class Nghttp2Connection
{
    // Readers whose parked ReadAsync has something to hand over. Collected inside the native calls
    // and fired once they have unwound, so a resumed handler cannot re-enter the session.
    private readonly List<Nghttp2BodyReader> _bodyWakes = [];

    // From ih2_read to the end of dispatch: credit consumed meanwhile rides the pass's own drain.
    private bool _inPass;

    /// <summary>Return consumed body bytes' credit to the peer, on the stream and the connection.</summary>
    internal void CreditBody(int streamId, int length)
    {
        if (length <= 0 || _handle == 0)
        {
            return;
        }

        if (Nghttp2.ih2_consume(_handle, streamId, (nuint)length) != 0)
        {
            _failed = true;
        }

        // Outside a pass nothing else would drain this credit, and a peer out of window sends
        // nothing that would start one. A drain already running takes it on its next turn.
        if (!_inPass)
        {
            _ = FlushCreditAsync();
        }
    }

    private async Task FlushCreditAsync()
    {
        try
        {
            await FlushEgressAsync();
        }
        catch
        {
            _failed = true;   // nobody observes this task; the read loop sees the connection broken
        }
    }

    /// <summary>A reader has something for a parked ReadAsync; wake it once nghttp2 has unwound.</summary>
    internal void NoteBodyWake(Nghttp2BodyReader reader)
    {
        if (!_bodyWakes.Contains(reader))
        {
            _bodyWakes.Add(reader);
        }
    }

    private void FireBodyWakes()
    {
        if (_bodyWakes.Count == 0)
        {
            return;
        }

        // Snapshot-and-clear: a resumed handler can drain, and a stream closing in that drain lands
        // another wake here while the list is being walked.
        Nghttp2BodyReader[] wakes = _bodyWakes.ToArray();
        _bodyWakes.Clear();

        foreach (Nghttp2BodyReader reader in wakes)
        {
            reader.FireIfReady();
        }
    }
}
