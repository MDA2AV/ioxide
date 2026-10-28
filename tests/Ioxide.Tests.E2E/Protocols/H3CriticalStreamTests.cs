using ioxide;
using ioxide.nghttp3;
using static Ioxide.Tests.H3ErrorCodeTests;

namespace Ioxide.Tests;

/// <summary>
/// The peer's critical streams: its control stream (RFC 9114 section 6.2.1) and its QPACK encoder
/// and decoder streams (RFC 9204 section 4.2). None of them may ever close, and closing or resetting
/// one is a connection error of type H3_CLOSED_CRITICAL_STREAM.
/// </summary>
/// <remarks>
/// Driven through <see cref="H3ErrorCodeTests"/>'s recording transport, so each test pins the code
/// the connection closes with rather than only that it closed.
/// </remarks>
internal static class H3CriticalStreamTests
{
    // Stream type 0x00 (control), then SETTINGS(len 0).
    private static readonly byte[] ControlPreface = [0x00, 0x04, 0x00];

    private const ulong H3RequestCancelled = 0x010c;

    public static void Register(Runner runner)
    {
        RegisterControlStream(runner);
        RegisterOtherUniStreams(runner);
        RegisterNghttp3(runner);
    }

    // --- RFC 9114 section 6.2.1: the control stream ----------------------------------------------

    private static void RegisterControlStream(Runner runner)
    {
        runner.Test("http3/codes: control - a client control stream is parsed and requests still serve", () =>
        {
            // The premise for the tests below: the uni-stream feed path genuinely runs (type
            // varint, SETTINGS walk) and an OPEN control stream is not an error. The next test
            // differs from this rig by exactly one bit - the fin.
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: true,
                (2, ControlPreface, false),
                (0, WellFormedGet, true));

            Assert.True(run.IsCompleted, "the run loop should complete inline once the transport closes");
            Assert.Equal(1, served.Count);
            Assert.True(quic.ClosedWith is null, "an open control stream is not an error");
        });

        runner.Test("http3/codes: closing the peer's control stream is a connection error H3_CLOSED_CRITICAL_STREAM", () =>
        {
            // RFC 9114 section 6.2.1: "If either control stream is closed at any point, this MUST
            // be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM."
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out _, closeTransport: true,
                (2, ControlPreface, false),          // the same control stream as above...
                (2, Array.Empty<byte>(), true));     // ...now fin'd - a critical stream closed

            Assert.True(run.IsCompleted, "the run loop should have ended");
            AssertClosedWith(quic, H3ClosedCriticalStream, "H3_CLOSED_CRITICAL_STREAM");
        });

        runner.Test("http3/codes: resetting the peer's control stream is a connection error H3_CLOSED_CRITICAL_STREAM", () =>
        {
            // The other way a stream closes. A RESET_STREAM reaches the h3 layer as a lifecycle
            // item, not as a fin, so it is a separate path to the same error.
            var quic = new RecordingQuic();
            Assert.True(quic.EnqueueStreamData(2, ControlPreface, false), "the recv ring rejected the item");
            Assert.True(quic.EnqueueStreamEvent(2, QuicStreamEvent.Reset, H3RequestCancelled), "the recv ring rejected the item");
            Task run = StartPure(quic, out _, closeTransport: true);

            Assert.True(run.IsCompleted, "the run loop should have ended");
            AssertClosedWith(quic, H3ClosedCriticalStream, "H3_CLOSED_CRITICAL_STREAM");
        });
    }

    // --- RFC 9204 section 4.2, and the uni streams the rule does not cover -----------------------

    private static void RegisterOtherUniStreams(Runner runner)
    {
        runner.Test("http3/codes: closing or resetting a QPACK encoder or decoder stream is a connection error H3_CLOSED_CRITICAL_STREAM", () =>
        {
            // The server advertises a QPACK capacity of 0, so these streams carry nothing it reads.
            // Their closure is still an error.
            foreach ((byte type, string name) in new[] { ((byte)0x02, "encoder"), ((byte)0x03, "decoder") })
            {
                foreach (bool reset in new[] { false, true })
                {
                    var quic = new RecordingQuic();
                    Assert.True(quic.EnqueueStreamData(6, [type], false), "the recv ring rejected the item");
                    Assert.True(reset
                            ? quic.EnqueueStreamEvent(6, QuicStreamEvent.Reset, H3RequestCancelled)
                            : quic.EnqueueStreamData(6, Array.Empty<byte>(), true),
                        "the recv ring rejected the item");
                    Task run = StartPure(quic, out _, closeTransport: true);

                    Assert.True(run.IsCompleted, "the run loop should have ended");
                    AssertClosedWith(quic, H3ClosedCriticalStream,
                        $"H3_CLOSED_CRITICAL_STREAM for a {(reset ? "reset" : "closed")} QPACK {name} stream");
                }
            }
        });

        runner.Test("http3/codes: control - a uni stream of another type may close or reset, and requests still serve", () =>
        {
            // A reserved type (0x1f * N + 0x21) is not critical. RFC 9114 section 6.2 also requires
            // tolerating a stream that ends before its type has arrived.
            var quic = new RecordingQuic();
            Assert.True(quic.EnqueueStreamData(2, ControlPreface, false), "the recv ring rejected the item");
            Assert.True(quic.EnqueueStreamData(6, [0x21, 0xAA], true), "the recv ring rejected the item");    // reserved type, fin'd
            Assert.True(quic.EnqueueStreamData(10, [0x21], false), "the recv ring rejected the item");
            Assert.True(quic.EnqueueStreamEvent(10, QuicStreamEvent.Reset, H3RequestCancelled),
                "the recv ring rejected the item");                                                                // reserved type, reset
            Assert.True(quic.EnqueueStreamData(14, [0x40], true), "the recv ring rejected the item");          // fin'd inside its type varint
            Task run = StartPure(quic, out Served served, closeTransport: true, (0, WellFormedGet, true));

            Assert.True(run.IsCompleted, "the run loop should complete inline once the transport closes");
            Assert.Equal(1, served.Count);
            Assert.True(quic.ClosedWith is null,
                $"only a critical stream's closure is an error, got 0x{quic.ClosedWith:x}");
        });
    }

    // --- the other stack: ioxide.nghttp3 ---------------------------------------------------------

    private static void RegisterNghttp3(Runner runner)
    {
        runner.Test("h3/codes: nghttp3 - closing or resetting the peer's control stream ends the connection with H3_CLOSED_CRITICAL_STREAM", () =>
        {
            // Pinned so the two stacks keep agreeing. nghttp3 learns of a reset through the close
            // that follows it, so both items are fed, in the order the engine delivers them.
            foreach (bool reset in new[] { false, true })
            {
                var quic = new RecordingQuic();
                Assert.True(quic.EnqueueStreamData(2, ControlPreface, false), "the recv ring rejected the item");
                if (reset)
                {
                    Assert.True(quic.EnqueueStreamEvent(2, QuicStreamEvent.Reset, H3RequestCancelled), "the recv ring rejected the item");
                    Assert.True(quic.EnqueueStreamEvent(2, QuicStreamEvent.Closed, H3RequestCancelled), "the recv ring rejected the item");
                }
                else
                {
                    Assert.True(quic.EnqueueStreamData(2, Array.Empty<byte>(), true), "the recv ring rejected the item");
                }

                Task run = new Nghttp3Connection(quic).RunAsync(static _ => Nghttp3Response.Text("ok"));

                Assert.True(run.IsCompleted,
                    $"nghttp3 kept serving after its peer's control stream was {(reset ? "reset" : "closed")}");
                AssertClosedWith(quic, H3ClosedCriticalStream, "H3_CLOSED_CRITICAL_STREAM");
            }
        });
    }
}
