using ioxide.http2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// The connection's receive window, which every upload on a connection shares. SETTINGS size the
/// streams' windows only and the connection's moves by WINDOW_UPDATE alone (RFC 9113 6.9.2), so
/// InitialConnectionWindowSize is opened in one, and without it a connection has 65535 bytes in
/// flight whatever InitialWindowSize says. Http2FlowControlTests has the credit that keeps both open.
/// </summary>
internal static class Http2ConnectionWindowTests
{
    private const int StreamWindow = 1 << 20;        // InitialWindowSize's default
    private const int Opened = 2 * StreamWindow;     // a window one stalled stream cannot take whole

    public static void Register(Runner runner)
    {
        runner.Test("h2 flow: InitialConnectionWindowSize opens the connection window right behind the server's SETTINGS, which by default leave it at 65535", () =>
        {
            foreach ((string name, Http2Options options, int expected) in new (string, Http2Options, int)[]
            {
                ("set", new Http2Options { InitialConnectionWindowSize = Opened }, Opened),
                ("by default", new Http2Options(), ConnectionWindow),
                ("set below the RFC's", new Http2Options { InitialConnectionWindowSize = 16384 }, ConnectionWindow),
                ("set negative", new Http2Options { InitialConnectionWindowSize = -1 }, ConnectionWindow),
            })
            {
                using var client = new StrictClient(options);
                Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200 });

                List<Frame> preface = Frame.Walk(client.ReleaseFlush());
                var peer = new PeerWindow();
                peer.Absorb(preface);

                Assert.True(preface[0].Type == Frame.Settings, $"{name}: the server's first frame was not its SETTINGS (RFC 9113 3.4)");
                Assert.True(peer.Connection == expected,
                    $"{name}: the server's preface gave the peer a {peer.Connection}-byte connection window, not {expected}");

                // At the RFC's own there is nothing to open, and a WINDOW_UPDATE of 0 is a PROTOCOL_ERROR.
                bool opened = expected > ConnectionWindow;
                Assert.True(preface.Count == (opened ? 2 : 1),
                    $"{name}: the preface was {preface.Count} frames, not SETTINGS {(opened ? "and one WINDOW_UPDATE" : "alone")}");

                client.Close(run);
            }
        });

        runner.Test("h2 flow: with the connection window opened, an upload its handler has not read yet has its whole stream window in flight", () =>
        {
            const int Size = 2 * StreamWindow;
            var ready = new TaskCompletionSource();
            var read = new Tally();

            using var client = new StrictClient(new Http2Options { InitialConnectionWindowSize = Opened });
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                await ready.Task;                                    // reads once something else is done: a database, a disk
                await ReadAll(body, read);
                await Answer(writer, 200);
            });

            var peer = new PeerWindow();
            var frames = new List<Frame>();
            Take(client, peer, frames);                              // the server's SETTINGS, and the window behind them
            client.Feed([.. Open(), .. Post(1)]);

            long sent = Send(client, peer, frames, streamId: 1, from: 0, Size);
            Assert.True(sent == StreamWindow,
                $"the peer could send {sent} bytes before the handler read any, not its {StreamWindow}-byte stream window");

            ready.SetResult();
            sent = Send(client, peer, frames, streamId: 1, from: sent, Size);
            Assert.True(sent == Size && read.Bytes == Size, $"the upload stopped at {sent} of {Size} bytes, {read.Bytes} of them read");
            Assert.True(frames.Any(f => f.Type == Frame.Headers && f.StreamId == 1), "the upload was never answered");

            client.Close(run);
        });

        runner.Test("h2 flow: a connection window of two stream windows keeps one handler that has stopped reading from holding back another upload", () =>
        {
            const int Size = 2 * StreamWindow;
            var release = new TaskCompletionSource();
            var held = new Tally();
            var other = new Tally();

            using var client = new StrictClient(new Http2Options { InitialConnectionWindowSize = Opened });
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                bool stalled = request.StreamId == 1;
                if (stalled)
                {
                    await release.Task;                              // stopped reading: a slow disk, a response its client is not taking
                }
                await ReadAll(body, stalled ? held : other);
                await Answer(writer, 200);
            });

            var peer = new PeerWindow();
            var frames = new List<Frame>();
            Take(client, peer, frames);
            client.Feed([.. Open(), .. Post(1)]);
            long holding = Send(client, peer, frames, streamId: 1, from: 0, Size);   // until stream 1's windows are spent

            client.Feed(Post(3));
            long sent = Send(client, peer, frames, streamId: 3, from: 0, Size);

            Assert.True(sent == Size && other.Bytes == Size,
                $"the upload on stream 3 stopped at {sent} of {Size} bytes behind {holding} unread on stream 1, "
                + $"with {peer.Connection} bytes of connection window left to it");
            Assert.True(holding == StreamWindow && held.Bytes == 0,
                $"stream 1 was to hold a whole stream window unread, and held {holding - held.Bytes} bytes");
            Assert.True(frames.Any(f => f.Type == Frame.Headers && f.StreamId == 3), "the upload on stream 3 was never answered");

            release.SetResult();
            holding = Send(client, peer, frames, streamId: 1, from: holding, Size);
            Assert.True(holding == Size && held.Bytes == Size,
                $"once its handler read again, stream 1's upload stopped at {holding} of {Size} bytes, {held.Bytes} of them read");

            client.Close(run);
        });
    }

    // A stream's body from `from` on, a frame at a time while the windows the server has granted have
    // room, taking in everything it flushes before each frame. Returns how far it got.
    private static long Send(StrictClient client, PeerWindow peer, List<Frame> frames, int streamId, long from, long size)
    {
        long sent = from;
        while (true)
        {
            Take(client, peer, frames);

            int room = (int)Math.Min(Math.Min(16384, peer.Room(streamId)), size - sent);
            if (room <= 0)
            {
                return sent;
            }

            client.Feed(Data(streamId, room, endStream: sent + room == size));
            peer.Spend(streamId, room);
            sent += room;
        }
    }

    // Every flush the server has in flight, taken in by the peer and kept for the test to look at.
    private static void Take(StrictClient client, PeerWindow peer, List<Frame> frames)
    {
        List<Frame> flushed = client.Drain();
        peer.Absorb(flushed);
        frames.AddRange(flushed);
    }
}
