using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using ioxide.http2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// A stream's receive window is credited a step at a time, a quarter of the window and at most 65,535 bytes,
/// rather than once per DATA frame (RFC 9113 6.9): fewer WINDOW_UPDATEs, a client that is never left out of
/// window while its handler reads, whatever window it counts, and no credit for a stream that has ended or
/// been reset.
/// </summary>
internal static class Http2CreditStepTests
{
    // The default window's step: a quarter of 256 KiB is 65,536, one byte past the window a client counts before it applies the SETTINGS.
    private const int Step = 65535;

    private const uint EnhanceYourCalm = 0xb;

    public static void Register(Runner runner)
    {
        RegisterSteps(runner);
        RegisterNoStall(runner);
        RegisterEnds(runner);
    }

    private static void RegisterSteps(Runner runner)
    {
        foreach (int frame in new[] { 16384, 1000 })
        {
            runner.Test($"h2 credit: an upload in {frame}-byte frames gets one WINDOW_UPDATE per step, each a whole step, and completes", () =>
            {
                const long Size = 4L << 20;
                var read = new Tally();

                using var client = new StrictClient();
                Task run = client.Connection.RunAsync(async (_, body, writer) =>
                {
                    await ReadAll(body, read);
                    await Answer(writer, 200);
                });

                Uploader up = Start(client, applied: true, frame);
                Assert.True(up.SendTo(Size, Size) && read.Bytes == Size,
                    $"the upload stopped at {up.Sent} of {Size} bytes, {read.Bytes} read");

                List<int> credit = Increments(up.Frames, 1);
                Assert.True(credit.Count > 0 && credit.Count * 4 <= up.DataFrames && credit.All(c => c >= Step),
                    $"{up.DataFrames} DATA frames were credited by {credit.Count} WINDOW_UPDATEs of [{Summary(credit)}], not by one per {Step}-byte step");

                client.Close(run);
            });
        }

        runner.Test("h2 credit: what a handler has not read is never credited, so its window still bounds what it holds", () =>
        {
            var first = new TaskCompletionSource();
            var rest = new TaskCompletionSource();
            var read = new Tally();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                await first.Task;
                read.Bytes += (await body.ReadAsync()).Length;      // one chunk; the rest stays queued
                await rest.Task;
                await ReadAll(body, read);
                await Answer(writer, 200);
            });

            client.ReleaseFlush();                                   // server SETTINGS
            client.Feed([.. Open(), .. Post(1), .. Fill(1, StreamWindow)]);
            client.Drain();

            first.SetResult();
            int credited = Credit(client.Drain(), 1);
            Assert.True(read.Bytes == 16384 && credited == 0,
                $"{read.Bytes} of the {StreamWindow} bytes in its window were read and {credited} were credited");

            rest.SetResult();
            credited += Credit(client.Drain(), 1);
            Assert.True(read.Bytes == StreamWindow && credited == StreamWindow,
                $"read to the end of its window, {read.Bytes} bytes, the stream was credited {credited}");

            client.Feed(Data(1, 0, endStream: true));
            client.Drain();
            client.Close(run);
        });

        runner.Test("h2 credit: reads short of a step flush nothing, outside the pass too, and the read that completes it is credited in one WINDOW_UPDATE", () =>
        {
            var gate = new TaskCompletionSource();
            var read = new Tally();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                await gate.Task;
                writer.WriteHeaders(new Http2Response { Status = 200 });   // staged for the writer's own flush, which a read has no reason to make
                await ReadAll(body, read);
                await writer.CompleteAsync();
            });

            client.ReleaseFlush();                                   // server SETTINGS
            client.Feed([.. Open(), .. Post(1), .. Fill(1, 3 * 16384)]);
            client.Drain();

            gate.SetResult();                                        // three reads outside the pass, 16,383 bytes short of a step
            Assert.True(read.Bytes == 3 * 16384 && client.PendingFlushes == 0,
                $"{read.Bytes} bytes were read short of a step and {client.PendingFlushes} flushes went out behind them");

            client.Feed(Data(1, 16384, endStream: false));
            var flushes = new List<List<Frame>>();
            while (client.PendingFlushes > 0)
            {
                flushes.Add(Frame.Walk(client.ReleaseFlush()));
            }
            List<int> credit = Increments(flushes.SelectMany(f => f), 1);
            Assert.True(flushes.Count == 1 && credit.Count == 1 && credit[0] == 4 * 16384,
                $"the read that made the step went out in {flushes.Count} flushes with [{Summary(credit)}] on its stream");

            client.Feed(Data(1, 0, endStream: true));
            client.Drain();
            client.Close(run);
        });

        runner.Test("h2 credit: a buffered body is credited in steps as it arrives, and MaxRequestBytes still bounds it", () =>
        {
            const int Cap = 1 << 20;

            using var client = new StrictClient(new Http2Options { MaxRequestBytes = Cap });
            Task run = client.Connection.RunAsync(request => Http2Response.Text(request.Body.Length.ToString(CultureInfo.InvariantCulture)));

            Uploader up = Start(client, applied: true, frame: 16384);
            Assert.True(up.SendTo(Cap, Cap), $"a body of exactly MaxRequestBytes stopped at {up.Sent} of {Cap} bytes");
            Assert.Equal(Cap.ToString(CultureInfo.InvariantCulture), Encoding.ASCII.GetString(Frame.Body(up.Frames, 1)));

            List<int> credit = Increments(up.Frames, 1);
            Assert.True(credit.Count > 0 && credit.Count * 4 <= up.DataFrames && credit.All(c => c >= Step),
                $"{up.DataFrames} DATA frames of a buffered body were credited by [{Summary(credit)}], not in whole steps");

            client.Feed(Post(3));
            var over = new Uploader(client, up.Peer, streamId: 3, frame: 16384);
            over.SendTo(Cap + 16384, Cap + (2 * 16384));             // the frame past the cap, its body not yet ended
            int reset = over.Frames.FindIndex(f => f is { Type: RstStreamFrame, StreamId: 3 });
            Assert.True(reset >= 0 && BinaryPrimitives.ReadUInt32BigEndian(over.Frames[reset].Payload) == EnhanceYourCalm,
                $"a body past MaxRequestBytes was not reset with ENHANCE_YOUR_CALM, {over.Sent} bytes in");

            client.Feed(Data(3, 16384, endStream: false));           // in flight when the reset went out
            over.Take();
            Assert.True(Increments(over.Frames.Skip(reset), 3).Count == 0, "stream 3 was credited after the server reset it");

            client.Close(run);
        });
    }

    private static void RegisterNoStall(Runner runner)
    {
        runner.Test("h2 credit: a reader that keeps up never leaves the client out of window, whatever InitialWindowSize, before and after the client applies and acknowledges the SETTINGS", () =>
        {
            var stalls = new List<string>();
            foreach (int window in new[] { StreamWindow, 1 << 20, 65536, 65535, 16384, 1000, 100, 3 })
            {
                foreach (SettingsState when in Enum.GetValues<SettingsState>())
                {
                    if (UploadWhileReading(window, when) is { } stall)
                    {
                        stalls.Add(stall);
                    }
                }
            }

            Assert.True(stalls.Count == 0, string.Join("; ", stalls));
        });
    }

    // How far the client has got with the server's SETTINGS when it uploads: not applied, applied but the ACK not yet
    // sent, acknowledged before the upload, or applied with one 65,535 window in flight and acknowledged after the next.
    private enum SettingsState { Unseen, Applied, Acknowledged, MidUpload }

    private static string? UploadWhileReading(int window, SettingsState when)
    {
        long size = (3L * Math.Max(window, 65535)) + 1001;
        var read = new Tally();

        using var client = new StrictClient(new Http2Options { InitialWindowSize = window });
        Task run = client.Connection.RunAsync(async (_, body, writer) =>
        {
            await ReadAll(body, read);
            await Answer(writer, 200);
        });

        bool applied = when is SettingsState.Applied or SettingsState.Acknowledged;
        Uploader up = Start(client, applied, frame: 16384, acknowledge: when == SettingsState.Acknowledged);

        bool done;
        if (when == SettingsState.MidUpload)
        {
            done = up.SendTo(65535, size);
            up.Peer.Absorb([up.ServerSettings]);                     // resizes the open stream by the difference (RFC 9113 6.9.2)
            done = done && up.SendTo(2 * 65535, size);
            client.Feed(SettingsAck());                              // and from here the server holds it to the new window (6.5.3)
            done = done && up.SendTo(size, size);
        }
        else
        {
            done = up.SendTo(size, size);
        }

        string? stall = done && read.Bytes == size ? null
            : $"InitialWindowSize {window}, SETTINGS {when}: the upload stopped at {up.Sent} of {size} bytes, {read.Bytes} of them read, the client out of window";
        client.Close(run);
        return stall;
    }

    private static void RegisterEnds(Runner runner)
    {
        runner.Test("h2 credit: a stream that ends or is reset a step short is credited none of it afterwards", () =>
        {
            var read = new Dictionary<int, Tally> { [1] = new(), [3] = new(), [5] = new() };

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                Tally tally = read[request.StreamId];
                if (request.StreamId == 5)
                {
                    tally.Bytes = await ReadAtLeast(body, 3 * 16384);
                    await writer.ResetStreamAsync(Http2ErrorCode.Cancel);
                    return;
                }

                try
                {
                    await ReadAll(body, tally);
                }
                catch (IOException)
                {
                    // stream 3, reset by the peer
                }
                await Answer(writer, 200);
            });

            // Three frames read on each: 16,383 bytes short of a step.
            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Fill(1, 3 * 16384), .. Post(3), .. Fill(3, 3 * 16384), .. Post(5), .. Fill(5, 3 * 16384)]);
            List<Frame> before = client.Drain();
            Assert.True(Increments(before, 1).Count + Increments(before, 3).Count + Increments(before, 5).Count == 0,
                "a stream was credited short of a step");

            // A frame each that would make the step: 1 ends with it, 3 is reset by the peer ahead of it, 5 was reset by its handler.
            client.Feed([.. Data(1, 16384, endStream: true), .. RstStream(3, Cancel), .. Data(3, 16384, endStream: false), .. Data(5, 16384, endStream: false)]);
            List<Frame> after = client.Drain();
            Assert.True(read[1].Bytes == 4 * 16384 && read[3].Bytes == 3 * 16384 && read[5].Bytes == 3 * 16384,
                $"the handlers read {read[1].Bytes}, {read[3].Bytes} and {read[5].Bytes} bytes, so stream 1 never read the step it was owed");
            Assert.True(Credit(after, 1) == 0 && Credit(after, 3) == 0 && Credit(after, 5) == 0,
                $"credit went out after the end: {Credit(after, 1)} to 1, which ended, {Credit(after, 3)} to 3, which the peer reset, "
                + $"{Credit(after, 5)} to 5, which its handler reset");

            client.Close(run);
        });
    }

    /// <summary>
    /// A client uploading on one stream: it sends what the windows it counts allow, in frames of at most
    /// <c>frame</c> bytes, and takes in everything the server flushes before each frame.
    /// </summary>
    private sealed class Uploader(StrictClient client, PeerWindow peer, int streamId, int frame)
    {
        public PeerWindow Peer => peer;
        public List<Frame> Frames { get; } = [];
        public Frame ServerSettings { get; init; }
        public long Sent { get; private set; }
        public int DataFrames { get; private set; }

        // Sends on until `until` of a `size`-byte body; false once the client is out of window with nothing more coming.
        public bool SendTo(long until, long size)
        {
            while (Sent < until)
            {
                Take();
                int room = (int)Math.Min(Math.Min(frame, peer.Room(streamId)), until - Sent);
                if (room <= 0)
                {
                    return false;
                }

                client.Feed(Data(streamId, room, endStream: Sent + room == size));
                peer.Spend(streamId, room);
                Sent += room;
                DataFrames++;
            }

            Take();
            return true;
        }

        public void Take()
        {
            List<Frame> flushed = client.Drain();
            peer.Absorb(flushed);
            Frames.AddRange(flushed);
        }
    }

    // The preface taken in, the server's SETTINGS applied by the client or not, then the client's own preface and a POST on stream 1.
    private static Uploader Start(StrictClient client, bool applied, int frame, bool acknowledge = false)
    {
        List<Frame> preface = Frame.Walk(client.ReleaseFlush());
        var peer = new PeerWindow();
        peer.Absorb(applied ? preface : preface.Where(f => f.Type != Frame.Settings));

        client.Feed([.. Open(), .. (acknowledge ? SettingsAck() : []), .. WindowUpdate(0, 1 << 20), .. Post(1)]);
        return new Uploader(client, peer, streamId: 1, frame) { ServerSettings = preface.First(f => f.Type == Frame.Settings) };
    }

    private static async ValueTask<long> ReadAtLeast(Http2BodyReader body, int bytes)
    {
        long read = 0;
        while (read < bytes)
        {
            read += (await body.ReadAsync()).Length;
        }
        return read;
    }

    private static List<int> Increments(IEnumerable<Frame> frames, int streamId)
        => frames.Where(f => f.Type == Frame.WindowUpdate && f.StreamId == streamId)
                 .Select(f => (int)(BinaryPrimitives.ReadUInt32BigEndian(f.Payload) & 0x7FFFFFFF)).ToList();

    private static string Summary(List<int> credit)
        => credit.Count <= 8 ? string.Join(", ", credit) : $"{string.Join(", ", credit.Take(8))}, ... {credit.Count} in all";

    private static byte[] SettingsAck() => FrameBytes(0x4, 0x1, 0, []);
}
