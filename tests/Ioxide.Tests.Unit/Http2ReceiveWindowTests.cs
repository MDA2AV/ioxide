using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using ioxide.http2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// What the server enforces on what it receives (RFC 9113 6.9), and the frame loop that reads on behind a
/// stalled flush. Http2FlowControlTests has the credit the server gives back as bodies are read.
/// </summary>
internal static class Http2ReceiveWindowTests
{
    private const int MaxWindow = int.MaxValue;
    private const byte PingFrame = 0x6, GoAwayFrame = 0x7;
    private const uint FlowControlError = 0x3, RefusedStream = 0x7;

    private const string Whole = "ended whole", CutOff = "was cut off";

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_receiveWindow")]
    private static extern ref int ReceiveWindow(Http2Connection connection);

    public static void Register(Runner runner)
    {
        // ---------------------------------------------------------------- what the server advertises

        runner.Test("h2 flow: the server's preface is its SETTINGS, then a WINDOW_UPDATE that opens the connection's window to 2^31-1, in the same write", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200 });

            List<Frame> preface = Frame.Walk(client.ReleaseFlush());
            Assert.True(preface.Count == 2
                        && preface[0] is { Type: Frame.Settings, Flags: 0, StreamId: 0 }
                        && preface[1] is { Type: Frame.WindowUpdate, StreamId: 0 },
                $"the preface was [{string.Join(", ", preface.Select(f => $"type {f.Type} on {f.StreamId}"))}], not SETTINGS and then a WINDOW_UPDATE on stream 0");
            Assert.Equal(MaxWindow - ConnectionWindow, Increment(preface[1]));

            client.Close(run);
        });

        runner.Test("h2: by default the server advertises 100 concurrent streams, each with a 256 KiB window", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200 });

            Frame settings = Frame.Walk(client.ReleaseFlush())[0];
            Assert.Equal(100u, Setting(settings, 0x3));                      // MAX_CONCURRENT_STREAMS
            Assert.Equal((uint)StreamWindow, Setting(settings, InitialWindowSize));

            client.Close(run);
        });

        // ---------------------------------------------------------------- what it enforces

        runner.Test("h2 flow: a DATA frame past its stream's window resets that stream with FLOW_CONTROL_ERROR, and the connection serves on", () =>
        {
            var gate = new TaskCompletionSource();
            string end = "never read";

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                if (request.StreamId == 1)
                {
                    await gate.Task;                                  // not reading: its window is all the peer has
                    end = await EndOf(body, new Tally());
                }
                await Answer(writer, 200);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Fill(1, StreamWindow)]);
            Assert.True(!client.Drain().Any(f => f.Type == RstStreamFrame), "a stream was reset inside its window");

            client.Feed([.. Data(1, 1, endStream: false), .. Get(3)]);
            List<Frame> frames = client.Drain();
            Assert.True(frames.Any(f => f is { Type: RstStreamFrame, StreamId: 1 } && ErrorCode(f) == FlowControlError),
                "a byte past stream 1's window was taken without a reset");
            Assert.True(frames.Any(f => f is { Type: Frame.Headers, StreamId: 3 }) && !frames.Any(f => f.Type == GoAwayFrame),
                "the connection stopped serving over one stream's overrun");

            gate.SetResult();
            frames = client.Drain();
            Assert.Equal(CutOff, end);
            Assert.True(!frames.Any(f => f.StreamId == 1), "a frame went out on stream 1 after the server had reset it");

            client.Close(run);
        });

        runner.Test("h2 flow: a DATA frame past the connection's window is a GOAWAY with FLOW_CONTROL_ERROR", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200 });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1)]);
            client.Drain();

            // Topped up below a quarter, the window never runs this low from the wire, so it is set here.
            ReceiveWindow(client.Connection) = 1000;
            client.Feed(Data(1, 1000, endStream: false));            // fits exactly, and empties it
            List<Frame> frames = client.Drain();
            Assert.True(!frames.Any(f => f.Type == GoAwayFrame), "a frame that fit the connection's window ended the connection");
            Assert.Equal(MaxWindow, Credit(frames, 0));              // the whole window back, and no more

            ReceiveWindow(client.Connection) = 1000;
            client.Feed(Data(1, 1001, endStream: false));
            frames = client.Drain();
            Assert.True(frames.Any(f => f.Type == GoAwayFrame && GoAwayError(f) == FlowControlError),
                "a frame past the connection's window did not end the connection with FLOW_CONTROL_ERROR");

            client.Close(run);
        });

        runner.Test("h2 flow: a DATA frame's padding counts against its stream's window", () =>
        {
            // 100 bytes of window left: a frame with a 50-byte body fits it unpadded, and past 49 bytes of padding does not.
            foreach ((int padding, bool reset) in new[] { (49, false), (50, true) })
            {
                var gate = new TaskCompletionSource();

                using var client = new StrictClient();
                Task run = client.Connection.RunAsync(async (_, body, writer) =>
                {
                    await gate.Task;
                    await EndOf(body, new Tally());
                    await Answer(writer, 200);
                });

                client.ReleaseFlush();
                client.Feed([.. Open(), .. Post(1), .. Fill(1, StreamWindow - 100), .. Data(1, 50, endStream: false, padding: padding)]);
                bool wasReset = client.Drain().Any(f => f is { Type: RstStreamFrame, StreamId: 1 } && ErrorCode(f) == FlowControlError);
                Assert.True(wasReset == reset,
                    $"a 50-byte body with {padding} bytes of padding, {1 + 50 + padding} flow-controlled in all, against 100 left: "
                    + (reset ? "taken" : "reset"));

                gate.SetResult();
                client.Drain();
                client.Close(run);
            }
        });

        runner.Test("h2 flow: every byte comes back once, on the connection's top-up, whether it was read, dropped, reset or sent to a closed or refused stream", () =>
        {
            // The largest frame there is, so the 1.5 GiB it takes to bring the window below a quarter is 96 frames.
            const int Big = 16_777_215;
            const long Quarter = MaxWindow - (MaxWindow / 4);         // charged past this, the window is below a quarter
            var options = new Http2Options { MaxFrameSize = Big, InitialWindowSize = MaxWindow, MaxConcurrentStreams = 3 };
            var held = new Dictionary<int, TaskCompletionSource> { [3] = new(), [5] = new() };
            var read = new Tally();

            using var client = new StrictClient(options);
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                if (request.StreamId == 1)
                {
                    await ReadAll(body, read);                        // read as it comes
                }
                else
                {
                    await held[request.StreamId].Task;
                    if (request.StreamId == 5)
                    {
                        await EndOf(body, new Tally());               // reset under its handler; 3 answers unread
                    }
                }
                await Answer(writer, 200);
            });

            var frames = new List<Frame>(Frame.Walk(client.ReleaseFlush()));
            long sent = 0, toStream1 = 0;
            void Send(byte[] frame, int streamId)
            {
                int payload = (frame[0] << 16) | (frame[1] << 8) | frame[2];
                sent += payload;
                toStream1 += streamId == 1 ? payload : 0;
                client.Feed(frame);
                frames.AddRange(client.Drain());
            }

            client.Feed([.. Open(), .. Post(1), .. Post(3), .. Post(5), .. Post(7)]);
            frames.AddRange(client.Drain());
            Assert.True(frames.Any(f => f is { Type: RstStreamFrame, StreamId: 7 } && ErrorCode(f) == RefusedStream), "stream 7 was not refused");

            Send(Data(1, 10_000, endStream: false, padding: 200), 1);   // read, and its padding credited on arrival
            Send(Data(3, 10_000, endStream: false), 3);                 // queued, then dropped unread
            Send(Data(5, 10_000, endStream: false), 5);                 // queued, then dropped by the peer's reset
            Send(Data(7, 10_000, endStream: false, padding: 50), 7);    // to a refused stream
            client.Feed(RstStream(5, Cancel));
            held[3].SetResult();
            held[5].SetResult();
            frames.AddRange(client.Drain());
            Send(Data(3, 10_000, endStream: false, padding: 10), 3);    // after its answer, to a stream the server is done with

            byte[] big = Data(1, Big, endStream: false);
            while (sent + Big <= Quarter)
            {
                Send(big, 1);
            }
            Assert.True(frames.Count(f => f is { Type: Frame.WindowUpdate, StreamId: 0 }) == 1,
                $"the connection was credited before its window fell below a quarter, {sent} bytes in");

            Send(Data(1, (int)(Quarter - sent + 1), endStream: false), 1);   // the frame that takes it below

            List<int> connection = frames.Where(f => f is { Type: Frame.WindowUpdate, StreamId: 0 }).Skip(1).Select(Increment).ToList();
            Assert.True(connection.Count == 1 && connection[0] == sent,
                $"{sent} bytes were charged to the connection, and its top-ups came to [{string.Join(", ", connection)}]");
            Assert.True(Credit(frames, 1) == toStream1 && read.Bytes == toStream1 - 201,
                $"stream 1 was sent {toStream1} bytes, read {read.Bytes} of them, and was credited {Credit(frames, 1)}");
            Assert.True(Credit(frames, 3) == 0 && Credit(frames, 5) == 0 && Credit(frames, 7) == 0,
                $"credit went to streams the server was done with: {Credit(frames, 3)} to 3, {Credit(frames, 5)} to 5, {Credit(frames, 7)} to 7");

            client.Feed(Data(1, 0, endStream: true));
            client.Drain();
            client.Close(run);
        });

        runner.Test("h2 flow: concurrent uploads are each held to their own stream window", () =>
        {
            const int Size = 2 * StreamWindow;
            int[] streams = [1, 3, 5];
            var gates = streams.ToDictionary(id => id, _ => new TaskCompletionSource());
            var read = streams.ToDictionary(id => id, _ => new Tally());
            var ends = new Dictionary<int, string>();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                int id = request.StreamId;
                await gates[id].Task;                                 // none reads until let go
                ends[id] = await EndOf(body, read[id]);
                await Answer(writer, 200);
            });

            var peer = new PeerWindow();
            var frames = new List<Frame>();
            Take(client, peer, frames);                               // the SETTINGS, and the connection's window behind them
            client.Feed([.. Open(), .. Post(1), .. Post(3), .. Post(5)]);

            Dictionary<int, long> sent = streams.ToDictionary(id => id, id => Send(client, peer, frames, id, from: 0, Size));
            Assert.True(sent.Values.All(n => n == StreamWindow),
                $"unread, the uploads had [{string.Join(", ", sent.Values)}] bytes in flight, not a whole {StreamWindow}-byte window each");
            Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "an upload inside its window was reset");

            client.Feed(Data(3, 1, endStream: false));                // past what stream 3 was granted
            Take(client, peer, frames);
            Assert.True(frames.Any(f => f is { Type: RstStreamFrame, StreamId: 3 } && ErrorCode(f) == FlowControlError),
                "a byte past stream 3's window was taken without a reset");
            Assert.True(!frames.Any(f => f.Type == RstStreamFrame && f.StreamId != 3), "a stream inside its window was reset with the one past it");

            foreach (int id in new[] { 1, 5 })
            {
                gates[id].SetResult();
                sent[id] = Send(client, peer, frames, id, from: sent[id], Size);
                Assert.True(sent[id] == Size && read[id].Bytes == Size && ends[id] == Whole,
                    $"once read, the upload on stream {id} stopped at {sent[id]} of {Size} bytes, {read[id].Bytes} of them read");
            }
            gates[3].SetResult();
            Take(client, peer, frames);
            Assert.Equal(CutOff, ends[3]);

            client.Close(run);
        });

        // ---------------------------------------------------------------- the frame loop behind a stalled flush

        runner.Test("h2 flow: the frame loop goes on reading while a flush is stalled", () =>
        {
            var read = new Tally();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                if (request.StreamId == 1)
                {
                    await ReadAll(body, read);
                }
                await Answer(writer, 200);
            });

            client.ReleaseFlush();                                    // server SETTINGS
            client.Feed([.. Open(), .. Post(1), .. Get(3)]);          // stream 3's answer leaves on this pass's flush, which the peer does not take
            Assert.Equal(1, client.PendingFlushes);

            client.Feed([.. Data(1, 16384, endStream: false), .. Data(1, 16384, endStream: false), .. Ping()]);
            Assert.True(read.Bytes == 2 * 16384,
                $"behind the stalled flush the handler read {read.Bytes} of the {2 * 16384} bytes sent after it");
            Assert.Equal(1, client.PendingFlushes);                   // what the frames produced waits behind it

            List<Frame> frames = client.Drain();
            Assert.Equal(2 * 16384, Credit(frames, 1));
            Assert.True(frames.Any(f => f is { Type: PingFrame, Flags: 1 }), "the PING read behind the stalled flush was never answered");

            client.Feed(Data(1, 0, endStream: true));
            client.Drain();
            client.Close(run);
        });

        runner.Test("h2 flow: a download queued behind a stalled flush does not stop the frame loop reading", () =>
        {
            const int Download = 2 << 20;                             // all DATA, and past what else may queue
            var read = new Tally();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                if (request.StreamId == 5)
                {
                    await ReadAll(body, read);
                    await Answer(writer, 200);
                    return;
                }
                writer.WriteHeaders(new Http2Response { Status = 200 });
                writer.Write(new byte[Download]);
                await writer.CompleteAsync();
            });

            client.ReleaseFlush();                                    // server SETTINGS
            client.Feed([.. Open((InitialWindowSize, 1 << 30)), .. WindowUpdate(0, 1 << 30), .. Get(1)]);   // a download the peer does not take
            Assert.Equal(1, client.PendingFlushes);

            client.Feed(Get(3));                                      // a second one, queued whole behind it
            client.Feed([.. Post(5), .. Data(5, 16384, endStream: false)]);
            Assert.True(read.Bytes == 16384, $"behind {Download} bytes of queued download the handler read {read.Bytes} of 16384 bytes sent after it");

            client.Feed(Data(5, 0, endStream: true));
            List<Frame> frames = client.Drain();
            Assert.True(Frame.Body(frames, 1).Length == Download && Frame.Body(frames, 3).Length == Download,
                $"the downloads came to {Frame.Body(frames, 1).Length} and {Frame.Body(frames, 3).Length} bytes, not {Download} each");

            client.Close(run);
        });

        runner.Test("h2 flow: past 1 MiB of frames besides DATA queued behind a stalled flush, the frame loop stops reading until the flush that carries them is out", () =>
        {
            const int Bound = 1024 * 1024, Ack = 17, Pings = 62_000;
            const int Taken = (Bound / Ack) + 1;                      // the PING whose ACK takes the queue past the bound is the last one read

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200 });

            client.ReleaseFlush();                                    // server SETTINGS
            client.Feed([.. Open(), .. Ping()]);                      // this pass's flush the peer does not take
            for (int i = 0; i < Pings; i++)
            {
                client.Feed(Ping());                                  // a pass each, its ACK queued behind it
            }

            client.ReleaseFlush();                                    // the stalled flush
            int queued = Frame.Walk(client.ReleaseFlush()).Count(f => f.Type == PingFrame);
            int later = client.Drain().Count(f => f.Type == PingFrame);
            Assert.True(queued == Taken && later == Pings - Taken,
                $"{queued} PINGs were answered behind the stalled flush and {later} once it was out, not {Taken} and {Pings - Taken}");

            client.Close(run);
        });

        // ---------------------------------------------------------------- a window below the RFC's

        runner.Test("h2 flow: a stream window below 65,535 holds a stream once the peer has acknowledged the SETTINGS that set it", () =>
        {
            const int Small = 16384;
            int[] streams = [1, 5, 7];
            var gates = streams.ToDictionary(id => id, _ => new TaskCompletionSource());   // one each: a second awaiter resumes on the pool
            var ends = new Dictionary<int, string>();

            using var client = new StrictClient(new Http2Options { InitialWindowSize = Small });
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                await gates[request.StreamId].Task;
                ends[request.StreamId] = await EndOf(body, new Tally());
                await Answer(writer, 200);
            });

            client.ReleaseFlush();

            // Sent before the peer could see the SETTINGS, so sized at the RFC's 65,535 (RFC 9113 6.9.3).
            client.Feed([.. Open(), .. Post(1), .. Post(5), .. Fill(1, ConnectionWindow), .. Fill(5, ConnectionWindow)]);
            Assert.True(!client.Drain().Any(f => f.Type == RstStreamFrame), "a stream the peer opened before it saw the SETTINGS was held to them");

            // Acknowledged: open streams lose 65,535 - 16,384, new ones start at 16,384 (6.9.2), and an empty END_STREAM needs no window (6.9.1).
            client.Feed([.. SettingsAck(), .. Post(7), .. Fill(7, Small), .. Data(5, 0, endStream: true)]);
            Assert.True(!client.Drain().Any(f => f.Type == RstStreamFrame), "a stream was reset inside the window its peer had");

            client.Feed([.. Data(1, 1, endStream: false), .. Data(7, 1, endStream: false)]);
            List<Frame> frames = client.Drain();
            foreach (int id in new[] { 1, 7 })
            {
                Assert.True(frames.Any(f => f is { Type: RstStreamFrame } && f.StreamId == id && ErrorCode(f) == FlowControlError),
                    $"a byte past stream {id}'s window, once the SETTINGS were acknowledged, was taken without a reset");
            }

            foreach (int id in streams)
            {
                gates[id].SetResult();
            }
            client.Drain();
            Assert.True(ends[1] == CutOff && ends[7] == CutOff && ends[5] == Whole,
                $"the bodies ended: 1 {ends[1]}, 7 {ends[7]}, 5 {ends[5]}");

            client.Close(run);
        });
    }

    // A stream's body from `from` on, within what the server granted, taking in its flushes before each frame. Returns how far it got.
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

    // How a body read ends: whole at END_STREAM, or with the IOException of a reset stream.
    private static async ValueTask<string> EndOf(Http2BodyReader body, Tally read)
    {
        try
        {
            await ReadAll(body, read);
            return Whole;
        }
        catch (IOException)
        {
            return CutOff;
        }
    }

    private static int Increment(Frame windowUpdate) => (int)(BinaryPrimitives.ReadUInt32BigEndian(windowUpdate.Payload) & 0x7FFFFFFF);

    private static uint ErrorCode(Frame rstStream) => BinaryPrimitives.ReadUInt32BigEndian(rstStream.Payload);

    private static uint GoAwayError(Frame goAway) => BinaryPrimitives.ReadUInt32BigEndian(goAway.Payload.AsSpan(4));

    private static uint Setting(Frame settings, ushort id)
    {
        for (int at = 0; at + 6 <= settings.Payload.Length; at += 6)
        {
            if (BinaryPrimitives.ReadUInt16BigEndian(settings.Payload.AsSpan(at)) == id)
            {
                return BinaryPrimitives.ReadUInt32BigEndian(settings.Payload.AsSpan(at + 2));
            }
        }
        throw new Exception($"the SETTINGS carried no setting 0x{id:x}");
    }

    private static byte[] SettingsAck() => FrameBytes(0x4, 0x1, 0, []);
}
