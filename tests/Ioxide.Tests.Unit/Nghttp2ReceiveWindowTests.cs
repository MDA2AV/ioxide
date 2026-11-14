using System.Buffers.Binary;
using ioxide.nghttp2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// The nghttp2 server's receive windows (RFC 9113 6.9): the connection's opened behind the SETTINGS,
/// each stream's held to its own, the credit nghttp2 returns as bodies are consumed, and the frame
/// loop that reads on behind a stalled flush.
/// </summary>
internal static class Nghttp2ReceiveWindowTests
{
    private const int MaxWindow = int.MaxValue;
    private const byte PingFrame = 0x6, GoAwayFrame = 0x7;
    private const uint FlowControlError = 0x3;

    private const string Whole = "ended whole", CutOff = "was cut off";

    public static void Register(Runner runner)
    {
        // ---------------------------------------------------------------- what the server advertises

        runner.Test("nghttp2 flow: the server's preface is its SETTINGS, then a WINDOW_UPDATE that opens the connection's window to 2^31-1, in the same write", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(_ => new Nghttp2Response { Status = 200 });

            List<Frame> preface = Frame.Walk(client.ReleaseFlush());
            Assert.True(preface.Count == 2
                        && preface[0] is { Type: Frame.Settings, Flags: 0, StreamId: 0 }
                        && preface[1] is { Type: Frame.WindowUpdate, StreamId: 0 },
                $"the preface was [{string.Join(", ", preface.Select(f => $"type {f.Type} on {f.StreamId}"))}], not SETTINGS and then a WINDOW_UPDATE on stream 0");
            Assert.Equal(MaxWindow - ConnectionWindow, Increment(preface[1]));

            client.Close(run);
            connection.Dispose();
        });

        runner.Test("nghttp2: by default the server advertises 100 concurrent streams, each with a 256 KiB window, and Nghttp2Options sets both", () =>
        {
            foreach ((Nghttp2Options? options, uint streams, uint window) in new (Nghttp2Options?, uint, uint)[]
                     {
                         (null, 100, StreamWindow),
                         (new Nghttp2Options { MaxConcurrentStreams = 7, InitialWindowSize = 100_000 }, 7, 100_000),
                     })
            {
                using var client = new StrictClient();
                var connection = new Nghttp2Connection(client, options);
                Task run = connection.RunAsync(_ => new Nghttp2Response { Status = 200 });

                Frame settings = Frame.Walk(client.ReleaseFlush())[0];
                Assert.True(Setting(settings, 0x3) == streams && Setting(settings, InitialWindowSize) == window,
                    $"the SETTINGS advertised {Setting(settings, 0x3)} streams of {Setting(settings, InitialWindowSize)} bytes, not {streams} of {window}");

                client.Close(run);
                connection.Dispose();
            }
        });

        // ---------------------------------------------------------------- what holds an upload back

        runner.Test("nghttp2 flow: concurrent uploads are each held to their own stream window, and a byte past one ends the connection with FLOW_CONTROL_ERROR", () =>
        {
            const int Size = 2 * StreamWindow;
            int[] streams = [1, 3, 5];
            var gates = streams.ToDictionary(id => id, _ => new TaskCompletionSource());   // one each: a second awaiter resumes on the pool
            var read = streams.ToDictionary(id => id, _ => new Tally());
            var ends = new Dictionary<int, string>();

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (request, body) =>
            {
                int id = request.StreamId;
                await gates[id].Task;                                 // none reads until let go
                ends[id] = await EndOf(body, read[id]);
                return new Nghttp2Response { Status = 200 };
            });

            var peer = new PeerWindow();
            var frames = new List<Frame>();
            Take(client, peer, frames);                               // the SETTINGS, and the connection's window behind them
            client.Feed([.. Open(), .. SettingsAck(), .. Post(1), .. Post(3), .. Post(5)]);

            Dictionary<int, long> sent = streams.ToDictionary(id => id, id => Send(client, peer, frames, id, from: 0, Size));
            Assert.True(sent.Values.All(n => n == StreamWindow),
                $"unread, the uploads had [{string.Join(", ", sent.Values)}] bytes in flight, not a whole {StreamWindow}-byte window each");
            Assert.True(!frames.Any(f => f.Type is RstStreamFrame or GoAwayFrame), "an upload inside its window was refused");

            foreach (int id in new[] { 1, 5 })
            {
                gates[id].SetResult();
                sent[id] = Send(client, peer, frames, id, from: sent[id], Size);
                Assert.True(sent[id] == Size && read[id].Bytes == Size && ends.GetValueOrDefault(id) == Whole,
                    $"once read, the upload on stream {id} stopped at {sent[id]} of {Size} bytes, {read[id].Bytes} of them read");
            }

            // nghttp2 makes it a connection error, which RFC 9113 6.9 allows as well as a stream one.
            client.Feed(Data(3, 1, endStream: false));                // past what stream 3 was granted
            Take(client, peer, frames);
            Assert.True(frames.Any(f => f.Type == GoAwayFrame && GoAwayError(f) == FlowControlError),
                "a byte past stream 3's window was taken without a FLOW_CONTROL_ERROR");
            Assert.True(run.Wait(5_000), "the connection did not end after its GOAWAY");

            gates[3].SetResult();
            Assert.Equal(CutOff, ends[3]);

            client.Close(run);
            connection.Dispose();
        });

        runner.Test("nghttp2 flow: every byte comes back once, on nghttp2's top-up half way down the connection's window, whether it was read, dropped, reset or sent after its answer", () =>
        {
            // nghttp2 credits a window once half of it is consumed: 1,073,741,823 bytes of a 2^31-1 one.
            const int TopUp = MaxWindow / 2;
            var held = new Dictionary<int, TaskCompletionSource> { [3] = new(), [5] = new() };
            var read = new Tally();

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client, new Nghttp2Options { InitialWindowSize = MaxWindow });   // only the connection's window binds
            Task run = connection.RunAsync(async (request, body) =>
            {
                switch (request.StreamId)
                {
                    case 1:
                        await ReadAll(body, read);                    // read as it comes
                        break;
                    case 3:
                        await held[3].Task;                           // answers with its body unread
                        break;
                    case 5:
                        await held[5].Task;
                        await EndOf(body, new Tally());               // its body dropped by the peer's reset
                        break;
                }
                return new Nghttp2Response { Status = 200 };          // 7 answers at once, before its body
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

            client.Feed([.. Open(), .. SettingsAck(), .. Post(1), .. Post(3), .. Post(5), .. Post(7)]);
            frames.AddRange(client.Drain());

            Send(Data(1, 10_000, endStream: false, padding: 200), 1);   // read, and its padding taken by nghttp2
            Send(Data(3, 10_000, endStream: false), 3);                 // queued, then dropped unread
            Send(Data(5, 10_000, endStream: false), 5);                 // queued, then dropped by the peer's reset
            Send(Data(7, 10_000, endStream: false, padding: 50), 7);    // after its answer
            client.Feed(RstStream(5, Cancel));
            held[3].SetResult();
            held[5].SetResult();
            frames.AddRange(client.Drain());
            Send(Data(3, 10_000, endStream: false, padding: 10), 3);    // after its answer too

            // Stream 1 up to the top-up, in full frames 64 to a write, and one more frame that reaches it.
            const int Frame16K = 16384, PerWrite = 64;
            long rest = TopUp - sent;
            long full = (rest - 1) / Frame16K;
            byte[] batch = [.. Enumerable.Range(0, PerWrite).SelectMany(_ => Data(1, Frame16K, endStream: false))];
            for (long done = 0; done < full; done += PerWrite)
            {
                int count = (int)Math.Min(PerWrite, full - done);
                client.Feed(count == PerWrite ? batch : batch[..(count * (9 + Frame16K))]);
                sent += (long)count * Frame16K;
                toStream1 += (long)count * Frame16K;
                List<Frame> drained = client.Drain();
                Assert.True(!drained.Any(f => f.Type == GoAwayFrame), $"the connection ended with a GOAWAY {sent} bytes in");
                frames.AddRange(drained);
            }
            Assert.True(frames.Count(f => f is { Type: Frame.WindowUpdate, StreamId: 0 }) == 1,
                $"the connection was credited before half its window was consumed, {sent} bytes in");

            Send(Data(1, (int)(TopUp - sent), endStream: false), 1);   // the frame whose last byte reaches it

            List<int> topUps = frames.Where(f => f is { Type: Frame.WindowUpdate, StreamId: 0 }).Skip(1).Select(Increment).ToList();
            Assert.True(topUps.Count == 1 && topUps[0] == sent,
                $"{sent} bytes were charged to the connection, and its top-ups came to [{string.Join(", ", topUps)}]");
            Assert.True(read.Bytes == toStream1 - 201, $"stream 1 was sent {toStream1} bytes and read {read.Bytes} of them");

            client.Feed(Data(1, 0, endStream: true));
            client.Drain();
            client.Close(run);
            connection.Dispose();
        });

        // ---------------------------------------------------------------- the frame loop behind a stalled flush

        runner.Test("nghttp2 flow: the frame loop goes on reading while a flush is stalled", () =>
        {
            var read = new Tally();

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (request, body) =>
            {
                if (request.StreamId == 3)
                {
                    await ReadAll(body, read);
                }
                return new Nghttp2Response { Status = 200 };
            });

            client.ReleaseFlush();                                    // server SETTINGS
            client.Feed([.. Open(), .. Get(1)]);                      // stream 1's answer leaves on this pass's flush, which the peer does not take
            Assert.Equal(1, client.PendingFlushes);

            client.Feed([.. Post(3), .. Data(3, 16384, endStream: false), .. Data(3, 16384, endStream: false), .. Ping()]);
            Assert.True(read.Bytes == 2 * 16384,
                $"behind the stalled flush the handler read {read.Bytes} of the {2 * 16384} bytes sent after it");
            Assert.Equal(1, client.PendingFlushes);                   // what the frames produced waits behind it

            List<Frame> frames = client.Drain();
            Assert.True(frames.Any(f => f is { Type: PingFrame, Flags: 1 }), "the PING read behind the stalled flush was never answered");

            client.Feed(Data(3, 0, endStream: true));
            client.Drain();
            client.Close(run);
            connection.Dispose();
        });

        runner.Test("nghttp2 flow: a stream nghttp2 resets behind a stalled flush ends its handler's read once that flush's drain sends the reset", () =>
        {
            string end = "still reading";

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (request, body) =>
            {
                if (request.StreamId == 3)
                {
                    end = await EndOf(body, new Tally());
                }
                return new Nghttp2Response { Status = 200 };
            });

            client.ReleaseFlush();                                    // server SETTINGS
            client.Feed([.. Open(), .. Get(1)]);                      // this pass's flush the peer does not take yet
            Assert.Equal(1, client.PendingFlushes);

            // A body past its content-length: nghttp2 resets the stream itself, and closes it as the reset goes out.
            client.Feed([.. PostWithLength(3, 5), .. Data(3, 20, endStream: false)]);
            Assert.Equal("still reading", end);

            List<Frame> frames = client.Drain();                      // the peer sends nothing more, so no later pass can end the read
            Assert.True(frames.Any(f => f is { Type: RstStreamFrame, StreamId: 3 }), "nghttp2 did not reset a body longer than its content-length");
            Assert.Equal(CutOff, end);

            client.Close(run);
            connection.Dispose();
        });

        runner.Test("nghttp2 flow: a request read behind a stalled flush as the input ends is answered before the connection is torn down", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(_ => Nghttp2Response.Text("ok"));

            client.ReleaseFlush();                                    // server SETTINGS
            client.Feed([.. Open(), .. Get(1)]);                      // this pass's flush the peer does not take yet
            Assert.Equal(1, client.PendingFlushes);

            client.Feed(Get(3));                                      // read behind it, answered behind it
            client.EndInput();
            Assert.True(!run.IsCompleted, "the connection was torn down with an answer still queued behind its flush");

            List<Frame> frames = client.Drain();
            Assert.True(run.Wait(5_000), "the connection did not wind down once its flushes were out");
            Assert.True(frames.Any(f => f is { Type: Frame.Data, StreamId: 3, EndStream: true }),
                $"stream 3's answer never went out: [{string.Join(", ", frames.Select(f => $"type {f.Type} on {f.StreamId}"))}]");

            connection.Dispose();
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

    private static async ValueTask ReadAll(Nghttp2BodyReader body, Tally read)
    {
        while (true)
        {
            ReadOnlyMemory<byte> chunk = await body.ReadAsync();
            if (chunk.IsEmpty)
            {
                return;
            }
            read.Bytes += chunk.Length;
        }
    }

    // How a body read ends: whole at END_STREAM, or with the IOException of a reset stream.
    private static async ValueTask<string> EndOf(Nghttp2BodyReader body, Tally read)
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

    // :method, :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static byte[] Post(int streamId) => FrameBytes(0x1, 0x4, streamId, [0x83, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()]);

    private static byte[] Get(int streamId) => FrameBytes(0x1, 0x5, streamId, [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()]);

    // A POST with a one-digit content-length: static entry 28, its value a literal.
    private static byte[] PostWithLength(int streamId, int length)
        => FrameBytes(0x1, 0x4, streamId, [0x83, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray(), 0x0F, 0x0D, 0x01, (byte)('0' + length)]);

    private static byte[] SettingsAck() => FrameBytes(0x4, 0x1, 0, []);

    private static int Increment(Frame windowUpdate) => (int)(BinaryPrimitives.ReadUInt32BigEndian(windowUpdate.Payload) & 0x7FFFFFFF);

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
}
