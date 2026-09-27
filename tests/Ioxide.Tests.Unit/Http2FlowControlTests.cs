using System.Buffers;
using System.Buffers.Binary;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// HTTP/2 flow-control credit, from the GenHTTP upload report against 0.14.239.
/// </summary>
internal static class Http2FlowControlTests
{
    // RFC 9113 6.9.2 default; ioxide never sends a stream-0 WINDOW_UPDATE to raise it.
    private const int ConnectionWindow = 65535;

    private const ushort InitialWindowSize = 0x4;
    private const uint Cancel = 0x8;
    private const byte RstStreamFrame = 0x3;

    private static readonly Http2Options Streamed = new() { StreamRequestBodies = true };

    public static void Register(Runner runner)
    {
        // ---------------------------------------------------------------- reads outside the pass

        runner.Test("h2 flow: credit from a read outside the pass is written to the peer", () =>
        {
            var busy = new TaskCompletionSource();
            var read = new Tally();

            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                await busy.Task;
                await ReadAll(request, read);
                await Answer(writer, 200);
            });

            client.ReleaseFlush();                                   // server SETTINGS
            client.Feed([.. Open(), .. Post(1), .. FillConnectionWindow(1)]);
            Assert.Equal(0, Credit(client.Drain(), 0));

            busy.SetResult();                                        // resumes outside the pass, as off-ring completions do
            Assert.Equal(ConnectionWindow, (int)read.Bytes);

            int credited = Credit(client.Drain(), 0);
            Assert.True(credited == ConnectionWindow,
                $"the handler consumed {read.Bytes} bytes but {credited} bytes of credit reached a peer that is out of window");

            client.Feed(Data(1, 0, endStream: true));
            client.Drain();
            client.Close(run);
        });

        runner.Test("h2 flow: a 1.2 MB upload through a handler that awaits between reads completes", () =>
        {
            const int Size = 1_200_000;
            var disk = new Queue<TaskCompletionSource>();
            var read = new Tally();

            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                await ReadAll(request, read, between: () =>
                {
                    var write = new TaskCompletionSource();          // a file write, completing off the ring
                    disk.Enqueue(write);
                    return write.Task;
                });
                await Answer(writer, 200);
            });

            var peer = new PeerWindow();
            long sent = Upload(client, peer, streamId: 1, Size, disk);

            Assert.True(read.Bytes == Size,
                $"the upload stalled at {read.Bytes} of {Size} bytes; the peer sent {sent} and has "
                + $"{peer.Connection} bytes of connection window");

            client.Close(run);
        });

        runner.Test("h2 flow: a 1.2 MB upload read without awaiting between chunks completes", () =>
        {
            const int Size = 1_200_000;
            var read = new Tally();

            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                await ReadAll(request, read);
                await Answer(writer, 200);
            });

            Upload(client, new PeerWindow(), streamId: 1, Size, new Queue<TaskCompletionSource>());
            Assert.Equal((long)Size, read.Bytes);

            client.Close(run);
        });

        // ---------------------------------------------------------------- unread bodies

        runner.Test("h2 flow: a body answered without being read gives its credit back", () =>
        {
            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync((_, writer) => Answer(writer, 404));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 10_000, endStream: true)]);   // one read, like a small POST
            List<Frame> frames = client.Drain();

            Assert.True(frames.Any(f => f.Type == Frame.Headers && f.StreamId == 1), "the 404 went out");
            int credited = Credit(frames, 0);
            Assert.True(credited == 10_000,
                $"10000 bytes were dropped unread and {credited} came back; the connection window is that much smaller for good");

            client.Close(run);
        });

        runner.Test("h2 flow: a body arriving after the answer is credited", () =>
        {
            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync((_, writer) => Answer(writer, 404));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1)]);
            client.Drain();                                          // answered and retired before the body
            client.Feed(Data(1, 10_000, endStream: true));
            Assert.Equal(10_000, Credit(client.Drain(), 0));

            client.Close(run);
        });

        runner.Test("h2 flow: a body the peer resets gives back the credit it had queued", () =>
        {
            var busy = new TaskCompletionSource();

            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                await busy.Task;
                await ReadAll(request, new Tally());
                await Answer(writer, 200);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 10_000, endStream: false)]);
            client.Drain();

            client.Feed(RstStream(1, Cancel));                       // an aborted fetch
            int credited = Credit(client.Drain(), 0);
            Assert.True(credited == 10_000,
                $"the reset dropped 10000 queued bytes and {credited} came back");

            busy.SetResult();
            client.Drain();
            client.Close(run);
        });

        runner.Test("h2 flow: bodies answered unread do not starve later uploads on the connection", () =>
        {
            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                if (request.StreamId <= 13)
                {
                    await Answer(writer, 404);                       // seven bodies answered unread
                    return;
                }
                await ReadAll(request, new Tally());
                await Answer(writer, 200);
            });

            var peer = new PeerWindow();
            HashSet<int> answered = Session(client, peer);

            Assert.True(answered.Contains(17), "a GET on the same connection is still answered");
            Assert.True(answered.Contains(15),
                $"the upload on stream 15 never started: {peer.Connection} bytes of connection window are left");

            client.Close(run);
        });

        runner.Test("h2 flow: padding on a streamed body is credited", () =>
        {
            var read = new Tally();

            using var client = new StrictClient(Streamed);
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                await ReadAll(request, read);
                await Answer(writer, 200);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. PaddedBody(1)]);
            List<Frame> frames = client.Drain();

            Assert.Equal(1000L, read.Bytes);
            int credited = Credit(frames, 0);
            Assert.True(credited == PaddedBodyPayload,
                $"{PaddedBodyPayload} flow-controlled bytes arrived and {credited} were credited");

            client.Close(run);
        });

        runner.Test("h2 flow: padding on the buffered path is credited in full", () =>
        {
            using var client = new StrictClient(new Http2Options());
            Task run = client.Connection.RunBufferedAsync(_ => new Http2Response { Status = 200 });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. PaddedBody(1)]);
            Assert.Equal(PaddedBodyPayload, Credit(client.Drain(), 0));

            client.Close(run);
        });

        runner.Test("h2 flow: a DATA frame past MaxRequestBytes is still credited", () =>
        {
            using var client = new StrictClient(new Http2Options { MaxRequestBytes = 20_000 });
            Task run = client.Connection.RunBufferedAsync(_ => new Http2Response { Status = 200 });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 16384, endStream: false), .. Data(1, 16384, endStream: true)]);
            List<Frame> frames = client.Drain();

            Assert.True(frames.Any(f => f.Type == RstStreamFrame && f.StreamId == 1), "the stream was reset for its size");
            int credited = Credit(frames, 0);
            Assert.True(credited == 2 * 16384, $"{2 * 16384} bytes arrived and {credited} were credited");

            client.Close(run);
        });

        // ---------------------------------------------------------------- send side

        runner.Test("h2 flow: a SETTINGS raise of the stream window resumes a parked writer", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, writer) => AnswerWith(writer, new byte[64 * 1024]));

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Get(1)]);
            List<Frame> frames = client.Drain();
            Assert.Equal(16384, Frame.Body(frames, 1).Length);       // one stream window, then parked

            client.Feed(Settings((InitialWindowSize, 1 << 20)));     // RFC 9113 6.9.2: grows open streams too
            frames.AddRange(client.Drain());

            int received = Frame.Body(frames, 1).Length;
            Assert.True(received == 64 * 1024,
                $"{received} of {64 * 1024} bytes: the window grew under the parked writer and nothing woke it");

            client.Close(run);
        });

        runner.Pending("h2 flow: a buffered response waits on the peer's stream window instead of overrunning it", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunBufferedAsync(_ => new Http2Response { Status = 200, Body = new byte[64 * 1024] });

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Get(1)]);
            List<Frame> frames = client.Drain();

            int sent = Frame.Body(frames, 1).Length;
            Assert.True(sent <= 16384,
                $"{sent} bytes of DATA against a 16384-byte stream window, which the peer may answer with FLOW_CONTROL_ERROR");

            client.Feed(WindowUpdate(1, 1 << 20));
            frames.AddRange(client.Drain());
            Assert.Equal(64 * 1024, Frame.Body(frames, 1).Length);   // the rest follows the credit, not a reset

            client.Close(run);
        }, "Http2Connection.WriteData bounds DATA by the connection window only; the peer's stream "
           + "window is never consulted on the buffered path");

        runner.Test("h2 flow: control: the streamed path stops at the same stream window", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, writer) => AnswerWith(writer, new byte[64 * 1024]));

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Get(1)]);
            Assert.Equal(16384, Frame.Body(client.Drain(), 1).Length);

            client.Feed(WindowUpdate(1, 1 << 20));
            client.Drain();
            client.Close(run);
        });
    }

    // Seven POSTs of 10000 bytes on streams 1-13, a POST the handler reads on 15, then a GET on 17;
    // bodies go out with their HEADERS in one read, and only as far as the peer's window allows.
    private static HashSet<int> Session(StrictClient client, PeerWindow peer)
    {
        const int Body = 10_000;
        var answered = new HashSet<int>();

        peer.Absorb(Frame.Walk(client.ReleaseFlush()));
        client.Feed(Open());
        Deliver(client, peer, answered);

        for (int stream = 1; stream <= 15; stream += 2)
        {
            int room = Math.Min(Body, peer.Room(stream));
            client.Feed([.. Post(stream), .. (room > 0 ? Data(stream, room, endStream: room == Body) : [])]);
            peer.Spend(stream, room);
            Deliver(client, peer, answered);
        }

        client.Feed(Get(17));
        Deliver(client, peer, answered);
        return answered;
    }

    // A browser uploading: send what the windows allow, take in what the server flushes, and let a
    // pending file write finish only when neither side can move - so the handler resumes outside the pass.
    private static long Upload(StrictClient client, PeerWindow peer, int streamId, int size,
        Queue<TaskCompletionSource> disk)
    {
        peer.Absorb(Frame.Walk(client.ReleaseFlush()));
        client.Feed([.. Open(), .. Post(streamId)]);

        long sent = 0;
        for (int turn = 0; turn < 1_000_000; turn++)
        {
            if (client.PendingFlushes > 0)
            {
                peer.Absorb(Frame.Walk(client.ReleaseFlush()));
                continue;
            }

            int room = (int)Math.Min(Math.Min(16384, peer.Room(streamId)), size - sent);
            if (room > 0)
            {
                client.Feed(Data(streamId, room, endStream: sent + room == size));
                peer.Spend(streamId, room);
                sent += room;
                continue;
            }

            if (disk.Count > 0)
            {
                disk.Dequeue().SetResult();
                continue;
            }

            break;
        }

        return sent;
    }

    private static void Deliver(StrictClient client, PeerWindow peer, HashSet<int> answered)
    {
        List<Frame> frames = client.Drain();
        peer.Absorb(frames);
        foreach (Frame frame in frames)
        {
            if (frame.Type == Frame.Headers)
            {
                answered.Add(frame.StreamId);
            }
        }
    }

    private sealed class Tally
    {
        public long Bytes;
    }

    private static async ValueTask ReadAll(Http2Request request, Tally read, Func<Task>? between = null)
    {
        while (true)
        {
            ReadOnlyMemory<byte> chunk = await request.BodyReader!.ReadAsync();
            if (chunk.IsEmpty)
            {
                return;
            }

            read.Bytes += chunk.Length;
            if (between is not null)
            {
                await between();
            }
        }
    }

    private static ValueTask Answer(Http2ResponseWriter writer, int status)
    {
        writer.WriteHeaders(new Http2Response { Status = status });
        return writer.CompleteAsync();
    }

    private static ValueTask AnswerWith(Http2ResponseWriter writer, byte[] body)
    {
        writer.WriteHeaders(new Http2Response { Status = 200 });
        writer.Write(body);
        return writer.CompleteAsync();
    }

    private static int Credit(IEnumerable<Frame> frames, int streamId)
    {
        int total = 0;
        foreach (Frame frame in frames)
        {
            if (frame.Type == Frame.WindowUpdate && frame.StreamId == streamId)
            {
                total += (int)(BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7FFFFFFF);
            }
        }
        return total;
    }

    /// <summary>Flow control as the client keeps it: only WINDOW_UPDATEs that reach it give credit back.</summary>
    private sealed class PeerWindow
    {
        private readonly Dictionary<int, long> _streams = new();
        private long _streamInitial = 65535;

        public long Connection { get; private set; } = ConnectionWindow;

        public int Room(int streamId) => (int)Math.Max(0, Math.Min(Connection, StreamWindow(streamId)));

        public void Spend(int streamId, int bytes)
        {
            Connection -= bytes;
            _streams[streamId] = StreamWindow(streamId) - bytes;
        }

        public void Absorb(IEnumerable<Frame> frames)
        {
            foreach (Frame frame in frames)
            {
                if (frame.Type == Frame.WindowUpdate)
                {
                    long increment = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7FFFFFFF;
                    if (frame.StreamId == 0)
                    {
                        Connection += increment;
                    }
                    else
                    {
                        _streams[frame.StreamId] = StreamWindow(frame.StreamId) + increment;
                    }
                }
                else if (frame.Type == Frame.Settings && (frame.Flags & 0x1) == 0)
                {
                    for (int at = 0; at + 6 <= frame.Payload.Length; at += 6)
                    {
                        if (BinaryPrimitives.ReadUInt16BigEndian(frame.Payload.AsSpan(at)) != InitialWindowSize)
                        {
                            continue;
                        }

                        long value = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload.AsSpan(at + 2));
                        foreach (int id in _streams.Keys.ToArray())
                        {
                            _streams[id] += value - _streamInitial;
                        }
                        _streamInitial = value;
                    }
                }
            }
        }

        private long StreamWindow(int streamId)
            => _streams.TryGetValue(streamId, out long window) ? window : _streamInitial;
    }

    // ---------------------------------------------------------------- frames

    private static readonly byte[] Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    // 1 pad-length octet + 1000 body + 200 padding, then a frame of nothing but padding (1 + 255).
    private const int PaddedBodyPayload = 1201 + 256;

    private static byte[] PaddedBody(int streamId)
        => [.. Data(streamId, 1000, endStream: false, padding: 200), .. Data(streamId, 0, endStream: true, padding: 255)];

    private static byte[] FillConnectionWindow(int streamId)
        =>
        [
            .. Data(streamId, 16384, endStream: false), .. Data(streamId, 16384, endStream: false),
            .. Data(streamId, 16384, endStream: false), .. Data(streamId, 16383, endStream: false),
        ];

    private static byte[] Open(params (ushort Id, uint Value)[] settings) => [.. Preface, .. Settings(settings)];

    private static byte[] Settings(params (ushort Id, uint Value)[] settings)
    {
        byte[] payload = new byte[settings.Length * 6];
        for (int i = 0; i < settings.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(i * 6), settings[i].Id);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan((i * 6) + 2), settings[i].Value);
        }
        return FrameBytes(0x4, 0, 0, payload);
    }

    // Static-table HPACK only: 0x83 POST / 0x82 GET, 0x86 :scheme http, 0x84 :path /.
    private static byte[] Post(int streamId) => FrameBytes(0x1, 0x4, streamId, [0x83, 0x86, 0x84]);

    private static byte[] Get(int streamId) => FrameBytes(0x1, 0x5, streamId, [0x82, 0x86, 0x84]);

    private static byte[] Data(int streamId, int length, bool endStream, int padding = -1)
    {
        byte flags = endStream ? (byte)0x1 : (byte)0x0;
        if (padding < 0)
        {
            byte[] body = new byte[length];
            body.AsSpan().Fill((byte)'z');
            return FrameBytes(0x0, flags, streamId, body);
        }

        byte[] payload = new byte[1 + length + padding];
        payload[0] = (byte)padding;
        payload.AsSpan(1, length).Fill((byte)'z');
        return FrameBytes(0x0, (byte)(flags | 0x8), streamId, payload);
    }

    private static byte[] RstStream(int streamId, uint error)
    {
        byte[] payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, error);
        return FrameBytes(0x3, 0, streamId, payload);
    }

    private static byte[] WindowUpdate(int streamId, int increment)
    {
        byte[] payload = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(payload, increment);
        return FrameBytes(0x8, 0, streamId, payload);
    }

    private static byte[] Ping() => FrameBytes(0x6, 0, 0, new byte[8]);

    private static byte[] FrameBytes(byte type, byte flags, int streamId, ReadOnlySpan<byte> payload)
    {
        byte[] frame = new byte[9 + payload.Length];
        frame[0] = (byte)(payload.Length >> 16);
        frame[1] = (byte)(payload.Length >> 8);
        frame[2] = (byte)payload.Length;
        frame[3] = type;
        frame[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(5), streamId);
        payload.CopyTo(frame.AsSpan(9));
        return frame;
    }
}
