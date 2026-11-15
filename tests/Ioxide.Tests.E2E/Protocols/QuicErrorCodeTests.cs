using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The application error code a QUIC connection gives its peer in STOP_SENDING, RESET_STREAM and
/// CONNECTION_CLOSE. RFC 9000 section 16 sends it as a variable-length integer, which holds 62
/// bits, so 2^62 - 1 is the largest there is.
/// </summary>
/// <remarks>
/// ngtcp2 checks that bound with an assertion its build keeps in release, so a larger code reaching
/// its encoder aborts the process, and every reactor and connection in it. The calls refuse one
/// instead, before they change anything. Without that, the first test here ends the suite with
/// ngtcp2_put_uvarintlen's assertion failure.
/// </remarks>
internal static class QuicErrorCodeTests
{
    private const int ExchangeMs = 10_000;

    // How long the farewell is waited for once the handler has closed: it is sent inside the close.
    private const int FarewellMs = 5_000;

    private const ulong Largest = (1UL << 62) - 1;
    private const ulong PastLargest = 1UL << 62;

    public static void Register(Runner runner)
    {
        runner.Test("quic: an error code past 2^62 - 1 is refused by StopReading, ResetStream and Close, and the stream and the connection carry on", () =>
        {
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = Start(report, static (conn, stream) =>
            {
                // Send state first, so a refused call that touched the stream would show on the wire.
                conn.SendStream(stream, "open"u8, fin: false);

                string wrong = "";
                foreach (ulong past in (ulong[])[PastLargest, ulong.MaxValue])
                {
                    wrong += Refused("StopReading", past, () => conn.StopReading(stream, past));
                    wrong += Refused("ResetStream", past, () => conn.ResetStream(stream, past));
                    wrong += Refused("Close", past, () => conn.Close(past));
                }

                conn.SendStream(stream, " still"u8, fin: true);
                return wrong;
            });

            using var client = new TeardownWireClient(port);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            // No fin, so the stream's reading side is still open for StopReading to act on.
            long sid = client.SendRequest("hello"u8.ToArray(), fin: false);
            Assert.True(client.ConverseUntil(() => report.Task.IsCompleted, ExchangeMs), "the handler never got the request");
            Assert.True(report.Task.Result.Length == 0, report.Task.Result);

            string answer = client.WaitForEcho(ExchangeMs);
            bool reset = client.SawReset(sid, out ulong code);
            Assert.True(answer == "open still" && client.SawFin(sid) && !reset,
                $"a refused call changed the stream: the peer got \"{answer}\"{(client.SawFin(sid) ? "" : " and no fin")}"
                + (reset ? $", and RESET_STREAM 0x{code:x}" : ""));
            Assert.True(!client.SawConnectionClose, "a refused Close closed the connection");
        });

        runner.Test("quic: StopReading, ResetStream and Close take 2^62 - 1, the largest error code QUIC carries, and once closed still refuse a larger one", () =>
        {
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = Start(report, static (conn, stream) =>
            {
                string wrong = Taken("StopReading", () => conn.StopReading(stream, Largest))
                             + Taken("ResetStream", () => conn.ResetStream(stream, Largest))
                             + Taken("Close", () => conn.Close(Largest));

                // Closed now, so the calls do nothing, but a code QUIC cannot carry is still the caller's mistake.
                wrong += Refused("StopReading", PastLargest, () => conn.StopReading(stream, PastLargest));
                wrong += Refused("ResetStream", PastLargest, () => conn.ResetStream(stream, PastLargest));
                wrong += Refused("Close", PastLargest, () => conn.Close(PastLargest));
                return wrong;
            });

            using var client = new TeardownWireClient(port);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            long sid = client.SendRequest("hello"u8.ToArray(), fin: false);
            Assert.True(client.ConverseUntil(() => report.Task.IsCompleted, ExchangeMs), "the handler never got the request");
            Assert.True(report.Task.Result.Length == 0, report.Task.Result);

            Assert.True(client.WaitForConnectionClose(FarewellMs),
                $"the Close never reached the peer: {client.DatagramsReceived} datagrams arrived and none was a CONNECTION_CLOSE");
            bool reset = client.SawReset(sid, out ulong code);
            Assert.True(reset && code == Largest,
                $"expected RESET_STREAM 0x{Largest:x}, got {(reset ? $"0x{code:x}" : "none")}");
        });
    }

    /// <summary>
    /// A QUIC server whose handler runs <paramref name="act"/> on the reactor for the first stream
    /// that brings data, reports what it returns, and reads on until the connection ends.
    /// </summary>
    private static int Start(TaskCompletionSource<string> report, Func<QuicConnection, long, string> act)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: async (_, conn) =>
            {
                try
                {
                    bool acted = false;
                    while (true)
                    {
                        QuicRecvSnapshot snap = await conn.ReadAsync();

                        long sid = -1;
                        while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                        {
                            if (item.Kind == QuicStreamEvent.Data && sid < 0)
                            {
                                sid = item.StreamId;
                            }
                            conn.ReturnBuffer(in item);
                        }

                        if (sid >= 0 && !acted)
                        {
                            acted = true;
                            try
                            {
                                report.TrySetResult(act(conn, sid));
                            }
                            catch (Exception e)
                            {
                                report.TrySetResult($"the handler threw {e.GetType().Name}: {e.Message}");
                            }
                        }

                        if (snap.IsClosed)
                        {
                            break;
                        }
                        conn.ResetRead();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });
        return udpPort;
    }

    // What went wrong when a call was given a code QUIC cannot carry: nothing, if it refused that code by name.
    private static string Refused(string call, ulong code, Action action)
    {
        try
        {
            action();
            return $"{call} took 0x{code:x}; ";
        }
        catch (ArgumentOutOfRangeException e) when (e.ParamName == "applicationErrorCode")
        {
            return "";
        }
        catch (Exception e)
        {
            return $"{call} threw {e.GetType().Name} for 0x{code:x}, not a refusal of applicationErrorCode: {e.Message}; ";
        }
    }

    private static string Taken(string call, Action action)
    {
        try
        {
            action();
            return "";
        }
        catch (Exception e)
        {
            return $"{call} refused 0x{Largest:x}: {e.Message}; ";
        }
    }
}
