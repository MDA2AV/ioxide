namespace ioxide.nghttp3;

/// <summary>
/// The STREAMED request body, for a handler that takes a body reader: dispatch at end-of-headers,
/// body pulled through its <see cref="Nghttp3BodyReader"/> under flow-control
/// pacing, plus all the machinery only this mode uses - the body-wake deferral and window crediting.
/// A buffered response dispatches in RunBuffered, a streamed one in Streamed.
/// Requests recycle when the handler's task has completed AND the stream has left the tables
/// (whichever happens last owns the release; the Pooled flag makes it race-free).
/// </summary>
public sealed partial class Nghttp3Connection
{
    // Credit consumed bytes of a paced request stream back to the peer's flow-control window.
    internal void CreditBody(long streamId, int bytes) => _quicConnection.ConsumeStreamData(streamId, bytes);

    internal Reactor Reactor => _quicConnection.Reactor;

    // No reactor owns a connection its driver runs itself, so its caller is the only thread.
    internal bool OffReactor => Reactor is { OnReactorThread: false };

    // The handler is done with the body: credit what it left unread and let the engine credit the rest.
    private void RetireBody(Nghttp3Request request)
    {
        if (request.BodyReader is null)
        {
            return;
        }
        request.BodyReader.Drop();
        if (_sinks.Remove(request.StreamId))
        {
            _quicConnection.SetStreamPaced(request.StreamId, false);
        }
    }

    // A sink with a parked reader became ready mid-PushToEngine; the wake is deferred to FireBodyWakes.
    internal void NoteBodyWake(Nghttp3BodyReader sink)
    {
        if (!_bodyWakes.Contains(sink))
        {
            _bodyWakes.Add(sink);
        }
    }

    private void FireBodyWakes()
    {
        for (int i = 0; i < _bodyWakes.Count; i++)
        {
            _bodyWakes[i].FireIfReady();
        }
        _bodyWakes.Clear();
    }
}
