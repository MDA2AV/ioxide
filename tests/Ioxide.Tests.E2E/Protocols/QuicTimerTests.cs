using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// Engine timers: expiry arithmetic, and loss recovery when datagrams actually go missing.
/// </summary>
/// <remarks>
/// Loopback does not drop packets, so every other QUIC test in the suite runs a connection that
/// never needs a timer: the one test that fires one drives a stub connection, and the real
/// <see cref="QuicEngineConnection.GetNextTimeout"/> / <see cref="QuicEngineConnection.OnTimer"/>
/// pair was only ever reached incidentally. The client here owns its socket, so a "loss" is a
/// datagram it receives and does not feed to ngtcp2 - and it never calls handle_expiry, so it has
/// no retransmit of its own. What it cannot get back, only the SERVER's timer can resend.
/// </remarks>
internal static class QuicTimerTests
{
    public static void Register(Runner runner)
    {
        RegisterExpiryArithmetic(runner);
        RegisterLossRecovery(runner);
        RegisterTimerFaults(runner);
        RegisterOutboundTimers(runner);
        RegisterIdleReactor(runner);
    }

    // --- the expiry arithmetic itself -------------------------------------------------------

    private static void RegisterExpiryArithmetic(Runner runner)
    {
        runner.Test("quic/timer: a deadline that is already due is reported as due, not centuries out", () =>
        {
            // GetNextTimeout converts ngtcp2's ns expiry into the sweep's TickCount64 ms frame by
            // subtracting the current ns clock. Both are UNSIGNED, and by the time the loop looks,
            // the expiry has normally already passed - the loop wakes for it at millisecond
            // granularity, or for some other completion, so it reads the clock after it. Unguarded,
            // that subtraction underflows and the connection's next deadline comes back roughly 584
            // years out. It does not look like a crash: the connection works perfectly until the
            // first packet is lost, and then never recovers, for the rest of its life.
            //
            // The probe reads the SAME two values the guard branches on - the engine's expiry and
            // the ns clock - immediately before each call, so what is asserted is the guard's own
            // contract on real engine state: an expiry that has already passed must come back as
            // "due now", never as a future deadline.
            TimerProbeConnection.Reset();

            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(r => new TimerProbeConnection(engine)),
                quicHandle: EchoHandler);

            using var client = new LossyQuicClient(udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(5_000), "handshake did not complete");

            // Three exchanges with a gap between them: each gap parks the reactor loop, so the
            // ack/loss deadlines it armed are noticed late - which is the state the guard is for.
            for (int i = 0; i < 3; i++)
            {
                Assert.Equal($"probe-{i}", client.RequestEcho(Encoding.ASCII.GetBytes($"probe-{i}"), 5_000));
                client.Pump(400);
            }

            // Keep it turning over until the transport has actually been asked for a deadline that
            // had already passed - the state the guard exists for, and the only state in which this
            // test means anything. It happens within a second; the budget is generous only so a
            // loaded machine cannot make it flaky. Any amount past counts: the clock only moves
            // forward, so an expiry the probe saw pass has passed for GetNextTimeout's re-read too.
            TimerProbeConnection.Observation[] alreadyDue;
            long deadline = Environment.TickCount64 + 20_000;
            do
            {
                client.Pump(100);
                alreadyDue = TimerProbeConnection.Snapshot()
                    .Where(o => o.ExpiryNs != ulong.MaxValue && o.ExpiryNs < o.NowNs)
                    .ToArray();
            }
            while (alreadyDue.Length == 0 && Environment.TickCount64 < deadline);

            int calls = TimerProbeConnection.Snapshot().Length;

            // Vacuity guards: neither the branch nor the firing path can be assumed.
            Assert.True(alreadyDue.Length > 0,
                $"in {calls} calls the engine never once reported a deadline that had already passed, "
                + "so this run never reached the branch this test is about");
            Assert.True(Volatile.Read(ref TimerProbeConnection.TimersFired) >= 1,
                $"no engine deadline was ever dispatched ({calls} were computed), so the firing path "
                + "this is about never ran");

            const long yearMs = 365L * 24 * 60 * 60 * 1000;
            foreach (TimerProbeConnection.Observation o in alreadyDue)
            {
                Assert.True(o.Deadline <= o.NowMs,
                    $"an expiry that passed {(o.NowNs - o.ExpiryNs) / 1_000_000} ms ago came back as a "
                    + $"deadline {o.Deadline - o.NowMs} ms ({(o.Deadline - o.NowMs) / yearMs} years) in "
                    + "the future: the unsigned ns subtraction underflowed, and this connection will "
                    + "never run loss recovery again");
            }
        });
    }

    // --- loss recovery ----------------------------------------------------------------------

    private static void RegisterLossRecovery(Runner runner)
    {
        runner.Test("quic/timer: an answer the peer never acknowledged is sent again", () =>
        {
            // The blackout is the whole test: for its duration the client feeds ngtcp2 nothing and
            // sends nothing, so the server's answer is lost AND the server hears silence. Nothing
            // the client does can ask for the answer again - it has no timer of its own - so an
            // answer that arrives afterwards was framed by OnTimer/handle_expiry out of the send
            // retention. That is the only thing in ioxide that can produce it.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoHandler);

            using var client = new LossyQuicClient(udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(5_000), "handshake did not complete");

            client.SendRequest(Encoding.ASCII.GetBytes("retransmit-me"));
            client.Blackout(700);

            // Vacuity guards. Without the first, a server that answered nothing at all would look
            // exactly like a server whose answer was lost; without the second, an answer delivered
            // before the blackout opened would make the recovery below meaningless.
            Assert.True(client.DroppedInbound > 0,
                "nothing arrived during the blackout, so no answer was ever thrown away and there is no loss to recover from");
            Assert.True(!client.EchoComplete,
                $"the answer was already complete before the blackout ended: [{client.EchoSoFar}]");

            string echoed = client.CollectEcho(30_000);
            Assert.Equal("retransmit-me", echoed);
        });

        runner.Test("quic/timer: an answer sent after a ring wait, not while a datagram is handled, is sent again", () =>
        {
            // The shape of a handler that waited on a query: its answer goes out from a RingTimer
            // completion, not while the reactor handles one of the peer's datagrams. The reactor only
            // learned of the retransmit deadline that answer set at the peer's NEXT datagram - so with
            // the answer lost and the peer silent, it was resent at the next deadline the reactor did
            // know of: the keep-alive, half the 60 s read timeout away.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: RingDelayedEchoHandler(600, answered));

            using var client = new LossyQuicClient(udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(5_000), "handshake did not complete");

            // Only the answer may be lost. Anything else of the server's left unacknowledged - the
            // handshake's tail, what it sends on taking the request - keeps a deadline the reactor does
            // know of, and that firing would rescan this connection and resend the answer by accident.
            client.Pump(500);
            client.SendRequest(Encoding.ASCII.GetBytes("retransmit-me"));
            client.Pump(400);
            client.Blackout(1_000);

            // The answer went out inside the blackout, so it was lost; without this, an answer still
            // to come would make the recovery below meaningless.
            Assert.True(answered.Task.IsCompleted, "the handler had not answered by the end of the blackout");
            Assert.True(!client.EchoComplete,
                $"the answer was already complete before the blackout ended: [{client.EchoSoFar}]");

            string echoed = client.CollectEcho(5_000);
            Assert.True(echoed == "retransmit-me",
                $"the lost answer was not sent again within 5 s (got [{echoed}]): its retransmit deadline "
                + "was never handed to the reactor");
        });

        runner.Test("control: with the engine timer suppressed the same lost answer never comes back", () =>
        {
            // What makes the test above about the TIMER rather than about QUIC being resilient in
            // general. Same client, same blackout, same handler - the only difference is a server
            // connection whose OnTimer does nothing, so handle_expiry never runs. If the answer
            // still found its way back here, the recovery above would be coming from somewhere
            // else and would say nothing about the code this file is for.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(r => new SuppressedTimerConnection(engine)),
                quicHandle: EchoHandler);

            using var client = new LossyQuicClient(udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(5_000), "handshake did not complete");

            client.SendRequest(Encoding.ASCII.GetBytes("retransmit-me"));
            client.Blackout(700);

            Assert.True(client.DroppedInbound > 0,
                "nothing arrived during the blackout, so the control staged no loss either");

            string echoed = client.CollectEcho(8_000);
            Assert.Equal("", echoed);
        });

        runner.Test("quic/timer: a handshake whose server flight is lost still completes", () =>
        {
            // The handshake bound (10 s by default) and retransmission share this timer, and the
            // bound is the newer of the two: it fires from the same handle_expiry that resends the
            // lost CRYPTO. A bound that killed a handshake the timer was still recovering would
            // look exactly like a slow network, and only under loss - which loopback never has.
            //
            // The client cannot resend its own Initial (no handle_expiry), so the server's flight
            // comes back only if the server's timer resends it.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoHandler);

            using var client = new LossyQuicClient(udpPort);
            client.Connect();
            client.SendFirstFlight();
            client.Blackout(600);

            Assert.True(client.DroppedInbound > 0,
                "the server sent nothing during the blackout, so its flight was never lost and nothing was recovered");
            Assert.True(!client.IsEstablished,
                "the handshake completed during the blackout, so the flight it needed was not the one dropped");

            Assert.True(client.CompleteHandshake(30_000),
                $"the handshake never completed after its server flight was lost "
                + $"({client.DroppedInbound} datagrams dropped)");

            // And the connection that survived the loss is a working one, not just an established
            // handshake: the same timer had to keep the stream data safe across it.
            Assert.Equal("after-loss", client.RequestEcho(Encoding.ASCII.GetBytes("after-loss"), 10_000));
        });
    }

    // --- a timer that faults ----------------------------------------------------------------

    private static void RegisterTimerFaults(Runner runner)
    {
        runner.Test("quic/timer: a connection whose timer throws fires once and the reactor keeps serving", () =>
        {
            // QuicFireDueTimers runs bare in the loop body with nothing above it that catches, so
            // an exception out of a protocol engine used to end the reactor thread and every
            // connection on it. The connection is dropped rather than skipped because its deadline
            // stays in the past: a skipped one would re-fire on every pass forever.
            TimerFaultConnection.Reset();

            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            // Only the FIRST connection faults, so the second one measures a reactor that has
            // already survived a fault rather than one that is about to have another.
            int accepted = 0;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(r => Interlocked.Increment(ref accepted) == 1
                    ? new TimerFaultConnection(engine)
                    : new QuicEngineConnection(engine)),
                quicHandle: EchoHandler);

            using (var doomed = new LossyQuicClient(udpPort))
            {
                doomed.Connect();
                doomed.CompleteHandshake(5_000);   // may or may not finish before the timer faults

                long deadline = Environment.TickCount64 + 20_000;
                while (Environment.TickCount64 < deadline && Volatile.Read(ref TimerFaultConnection.Fired) == 0)
                {
                    doomed.Pump(100);
                }

                Assert.True(Volatile.Read(ref TimerFaultConnection.Fired) >= 1,
                    "the engine deadline was never dispatched, so nothing faulted and this test proves nothing");
            }

            // The faulted connection is out of the transport's set, so its deadline - still in the
            // past - must never be looked at again. Anything above one fire is the busy loop the
            // drop exists to prevent.
            Thread.Sleep(1_000);
            Assert.True(Volatile.Read(ref TimerFaultConnection.Fired) == 1,
                $"the faulting timer fired {Volatile.Read(ref TimerFaultConnection.Fired)} times: its "
                + "deadline is in the past, so a connection left in the set re-fires every loop pass");

            // The reactor thread is what the fault could have taken with it, so the proof is a
            // whole second connection: handshake, request, answer.
            using var after = new LossyQuicClient(udpPort);
            after.Connect();
            Assert.True(after.CompleteHandshake(5_000),
                "the reactor stopped accepting after a connection's timer threw");
            Assert.Equal("still-serving", after.RequestEcho(Encoding.ASCII.GetBytes("still-serving"), 10_000));
        });

        runner.Test("quic/timer: a connection dropped for a faulting timer is told it was evicted", () =>
        {
            // OnEvicted is how a QuicConnection learns the transport let go of it, and for the
            // engine binding it is the ONLY call that runs Destroy: ngtcp2_conn_del, the picotls
            // session, the GCHandle rooting the managed object, and every retained send chunk (up
            // to MaxSendRetentionBytes, 16 MiB by default). The idle sweep and the shutdown path
            // both call it after QuicRemoveConnection, and so does the timer-fault path - it did
            // not, which is what this test was written to catch. Removal is what made that leak
            // permanent: once out of _quicConnSet and every CID route, the connection could never
            // be reached by the idle sweep or by teardown again.
            TimerFaultConnection.Reset();

            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(r => new TimerFaultConnection(engine)),
                quicHandle: EchoHandler);

            using var client = new LossyQuicClient(udpPort);
            client.Connect();
            client.CompleteHandshake(5_000);

            long deadline = Environment.TickCount64 + 20_000;
            while (Environment.TickCount64 < deadline && Volatile.Read(ref TimerFaultConnection.Fired) == 0)
            {
                client.Pump(100);
            }

            Assert.True(Volatile.Read(ref TimerFaultConnection.Fired) >= 1,
                "the engine deadline was never dispatched, so the connection was never dropped for a fault");

            // Generous: eviction would be synchronous inside the same catch that drops it.
            Thread.Sleep(1_000);

            Assert.True(Volatile.Read(ref TimerFaultConnection.Evicted) >= 1,
                "the transport dropped the connection without telling it: nothing ran Destroy, so its "
                + $"ngtcp2 conn, picotls session and retained send buffers are still allocated "
                + $"(the object still reports CanQueueSend={TimerFaultConnection.Latest?.CanQueueSend}, "
                + "i.e. an open engine)");
        });
    }

    // --- outbound (client) connections ------------------------------------------------------

    private static void RegisterOutboundTimers(Runner runner)
    {
        runner.Test("quic/timer: an outbound connection resends an Initial nobody answered", () =>
        {
            // A reactor that OPENS QUIC connections runs the same firing loop, and its very first
            // datagram is the one with no fallback: nothing else is in flight, and a client that
            // never resends its Initial just waits out the idle sweep and reports a dead server.
            //
            // The peer here is a bare UDP socket that never answers, so every datagram arriving
            // after the first is a retransmission that only a timer could have produced.
            int holePort = TestServer.NextPort();
            using var blackHole = new UdpClient(new IPEndPoint(IPAddress.Loopback, holePort));
            blackHole.Client.ReceiveTimeout = 250;

            // The same shim entry points the reactor's client path uses, driven by hand, to show
            // WHEN a fresh connection first has a deadline at all. A second quiet socket keeps its
            // Initial off the black hole's count.
            int quietPort = TestServer.NextPort();
            using var quietPeer = new UdpClient(new IPEndPoint(IPAddress.Loopback, quietPort));
            using var probe = new LossyQuicClient(quietPort);
            probe.Connect();
            ulong expiryBeforeFlight = probe.ExpiryNs;
            probe.SendFirstFlight();
            ulong expiryAfterFlight = probe.ExpiryNs;

            // Never disposed on purpose: the connection it mints outlives this test body (the
            // harness stops reactors afterwards), and freeing the engine under a live conn is a
            // native use-after-free.
            var clientEngine = new QuicClientEngine("echo");

            Exception? connectFailure = null;
            TestServer.StartQuicClientHost(
                tcpHandle: (_, _) => Task.CompletedTask,
                onStart: reactor =>
                {
                    try
                    {
                        clientEngine.Connect(reactor, "127.0.0.1", (ushort)holePort, "localhost");
                    }
                    catch (Exception e)
                    {
                        connectFailure = e;   // rethrowing here would kill the reactor instead
                    }
                });

            int arrived = 0;
            long deadline = Environment.TickCount64 + 15_000;
            while (Environment.TickCount64 < deadline && arrived < 2)
            {
                try
                {
                    IPEndPoint? from = null;
                    blackHole.Receive(ref from);
                    arrived++;
                }
                catch (SocketException)
                {
                    // receive timeout - keep waiting for the retransmit
                }
            }

            Assert.True(connectFailure is null, $"the outbound connect failed: {connectFailure?.Message}");
            Assert.True(arrived >= 1, "the client never sent its Initial at all");
            Assert.True(arrived >= 2,
                "the Initial was sent once and never again, so a lost first flight is unrecoverable. "
                + $"A fresh connection reports expiry={expiryBeforeFlight} before its first flight "
                + $"(ulong.MaxValue = no deadline) and {expiryAfterFlight} after it - the reactor has to "
                + "learn of it when the flight is sent (QuicConnection.Send), not from QuicAdoptClient, "
                + "which runs before Connect pumps the flight out");
        });
    }

    // --- an idle reactor ---------------------------------------------------------------------

    private static void RegisterIdleReactor(Runner runner)
    {
        runner.Test("quic/timer: an idle reactor fires an engine deadline when it is due, not at the next tick", () =>
        {
            // Nothing wakes an idle reactor but a completion, and the only one it can count on is the
            // 250 ms ticker - so a retransmit due ~25 ms after a loss went out at the next tick. Here
            // the answer is lost and the peer stays silent, so the retransmit timer fires again and
            // again with backoff, each firing timed against the engine's own deadline.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(r => new TimerLatenessConnection(engine)),
                quicHandle: RingDelayedEchoHandler(300, answered));

            using var client = new LossyQuicClient(udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(5_000), "handshake did not complete");

            client.Pump(500);
            client.SendRequest(Encoding.ASCII.GetBytes("on-time"));
            client.Pump(100);

            // From here the reactor has nothing to do but the answer, then its retransmits.
            TimerLatenessConnection.Reset();
            client.Blackout(3_000);

            Assert.True(answered.Task.IsCompleted, "the handler had not answered by the end of the blackout");
            double[] lateMs = TimerLatenessConnection.Snapshot();
            Assert.True(lateMs.Length >= 3,
                $"the engine timer fired {lateMs.Length} times in the blackout, too few to judge its timing");
            Assert.True(lateMs.Max() < 50,
                $"engine deadlines fired up to {lateMs.Max():F0} ms late "
                + $"([{string.Join(", ", lateMs.Select(l => l.ToString("F0")))}] ms): the reactor slept past "
                + "them until the next tick");
        });

        runner.Test("quic/timer: a reactor whose last connection is gone does not keep waking for it", () =>
        {
            // The reactor tracks only the earliest engine deadline, and nothing resets it when the last
            // connection leaves: the loop stops looking once there are none. A wait bounded by that
            // leftover would wake an empty reactor every millisecond, for good.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: 1_000,
                quicHandle: EchoHandler);

            using (var client = new LossyQuicClient(udpPort))
            {
                client.Connect();
                Assert.True(client.CompleteHandshake(5_000), "handshake did not complete");

                // The answer is lost and the peer goes silent, so the connection is evicted for its read
                // timeout with a retransmit still scheduled - a deadline that then passes.
                client.SendRequest(Encoding.ASCII.GetBytes("leave-a-deadline"));
                client.Blackout(3_000);
                Assert.True(client.DroppedInbound > 0, "the server never answered, so it scheduled no retransmit");
            }

            string reactorThread = $"test-reactor-udp-{udpPort}";
            long before = VoluntarySwitches(reactorThread);
            Thread.Sleep(1_000);
            long wakes = VoluntarySwitches(reactorThread) - before;

            Assert.True(wakes < 50,
                $"a reactor with no connections woke {wakes} times in a second; its ticker accounts for 4");
        });
    }

    // How often a thread has parked: each io_uring wait that sleeps is one voluntary switch.
    private static long VoluntarySwitches(string threadName)
    {
        string comm = threadName.Length > 15 ? threadName[..15] : threadName;   // the kernel keeps 15 bytes
        foreach (string task in Directory.GetDirectories("/proc/self/task"))
        {
            if (File.ReadAllText(Path.Combine(task, "comm")).TrimEnd('\n') != comm)
            {
                continue;
            }
            string line = File.ReadLines(Path.Combine(task, "status")).First(l => l.StartsWith("voluntary_ctxt_switches:"));
            return long.Parse(line["voluntary_ctxt_switches:".Length..].Trim());
        }
        throw new InvalidOperationException($"no thread named {comm}");
    }

    // --- handler -----------------------------------------------------------------------------

    private static async Task EchoHandler(Reactor reactor, QuicConnection conn)
    {
        try
        {
            while (true)
            {
                QuicRecvSnapshot snap = await conn.ReadAsync();

                while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                {
                    conn.SendStream(item.StreamId, item.AsSpan(), item.Fin);
                    conn.ReturnBuffer(in item);
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
    }

    // Echoes each finished request after a ring wait - answering from a RingTimer completion, not
    // from the handling of a datagram.
    private static Func<Reactor, QuicConnection, Task> RingDelayedEchoHandler(int delayMs, TaskCompletionSource answered)
        => async (reactor, conn) =>
        {
            var timer = new RingTimer(reactor);
            var requests = new Dictionary<long, List<byte>>();
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();

                    var finished = new List<(long StreamId, byte[] Body)>();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        if (item.Kind == QuicStreamEvent.Data)
                        {
                            if (!requests.TryGetValue(item.StreamId, out List<byte>? body))
                            {
                                requests[item.StreamId] = body = [];
                            }
                            body.AddRange(item.AsSpan());
                            if (item.Fin)
                            {
                                finished.Add((item.StreamId, [.. body]));
                                requests.Remove(item.StreamId);
                            }
                        }
                        conn.ReturnBuffer(in item);
                    }

                    if (snap.IsClosed)
                    {
                        break;
                    }
                    conn.ResetRead();

                    foreach ((long streamId, byte[] body) in finished)
                    {
                        await timer.DelayAsync(delayMs);
                        conn.SendStream(streamId, body, fin: true);
                        answered.TrySetResult();
                    }
                }
            }
            finally
            {
                conn.DecRef();
            }
        };

    /// <summary>
    /// Records what the transport was handed, alongside the two values the conversion is made from:
    /// the engine's own expiry and the ns clock, read through the same shim entry point the
    /// connection uses. Reflection reaches the iq_conn* because it is the connection's private
    /// handle - there is no public way to ask an engine connection what its raw deadline is, and
    /// this is a test, not a reason to widen the surface.
    /// </summary>
    private sealed class TimerProbeConnection(QuicEngine engine) : QuicEngineConnection(engine)
    {
        internal readonly record struct Observation(ulong ExpiryNs, ulong NowNs, long NowMs, long Deadline);

        internal static readonly System.Reflection.FieldInfo ConnHandle =
            typeof(QuicEngineConnection).GetField("_conn",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new Exception("could not reflect QuicEngineConnection._conn");

        private static readonly List<Observation> Observed = [];
        public static int TimersFired;

        public static void Reset()
        {
            lock (Observed)
            {
                Observed.Clear();
            }
            Volatile.Write(ref TimersFired, 0);
        }

        public static Observation[] Snapshot()
        {
            lock (Observed)
            {
                return Observed.ToArray();
            }
        }

        // Same clock and the same call the engine makes; reactor thread, like everything else here.
        internal static ulong NowNs() => (ulong)(System.Diagnostics.Stopwatch.GetTimestamp() *
                                                (1_000_000_000.0 / System.Diagnostics.Stopwatch.Frequency));

        public override long GetNextTimeout(long nowMs)
        {
            nint conn = (nint)ConnHandle.GetValue(this)!;
            ulong expiry = conn == 0 ? ulong.MaxValue : LossyQuicClient.Expiry(conn);
            ulong now = NowNs();

            long deadline = base.GetNextTimeout(nowMs);

            lock (Observed)
            {
                Observed.Add(new Observation(expiry, now, nowMs, deadline));
            }
            return deadline;
        }

        public override void OnTimer(long nowMs)
        {
            Interlocked.Increment(ref TimersFired);
            base.OnTimer(nowMs);
        }
    }

    /// <summary>
    /// Records how late each firing was: the engine's own ns expiry against the ns clock, on entry to
    /// OnTimer. A firing whose expiry is still ahead (the ms deadline rounds down) is not a late one.
    /// </summary>
    private sealed class TimerLatenessConnection(QuicEngine engine) : QuicEngineConnection(engine)
    {
        private static readonly List<double> LateMs = [];

        public static void Reset()
        {
            lock (LateMs)
            {
                LateMs.Clear();
            }
        }

        public static double[] Snapshot()
        {
            lock (LateMs)
            {
                return LateMs.ToArray();
            }
        }

        public override void OnTimer(long nowMs)
        {
            nint conn = (nint)TimerProbeConnection.ConnHandle.GetValue(this)!;
            ulong expiry = conn == 0 ? ulong.MaxValue : LossyQuicClient.Expiry(conn);
            ulong now = TimerProbeConnection.NowNs();
            if (expiry <= now)
            {
                lock (LateMs)
                {
                    LateMs.Add((now - expiry) / 1_000_000.0);
                }
            }
            base.OnTimer(nowMs);
        }
    }

    /// <summary>An engine connection whose deadlines are still armed but never acted on.</summary>
    private sealed class SuppressedTimerConnection(QuicEngine engine) : QuicEngineConnection(engine)
    {
        public override void OnTimer(long nowMs)
        {
            // Deliberately nothing: the transport still dispatches, ngtcp2 never hears about it.
        }
    }

    /// <summary>A real engine connection whose timer throws, the way a protocol engine can.</summary>
    private sealed class TimerFaultConnection : QuicEngineConnection
    {
        public static int Fired;
        public static int Evicted;

        /// <summary>The last one built, for the failure message; written on the reactor thread.</summary>
        public static volatile TimerFaultConnection? Latest;

        public TimerFaultConnection(QuicEngine engine) : base(engine) => Latest = this;

        public static void Reset()
        {
            Volatile.Write(ref Fired, 0);
            Volatile.Write(ref Evicted, 0);
            Latest = null;
        }

        public override void OnTimer(long nowMs)
        {
            Interlocked.Increment(ref Fired);
            throw new InvalidOperationException("probe: OnTimer threw");
        }

        public override void OnEvicted(QuicEvictReason reason)
        {
            Interlocked.Increment(ref Evicted);
            base.OnEvicted(reason);
        }
    }
}

/// <summary>
/// A minimal ngtcp2 client that can lose datagrams on purpose: it owns its socket, so dropping one
/// is simply not feeding it to the engine. It never calls handle_expiry either, so it has no loss
/// recovery of its own - everything it gets back after a blackout came from the server's timer.
/// Not production code; it exists to drive the server engine (compare QuicTestClient, which cannot
/// drop anything).
/// </summary>
internal sealed unsafe class LossyQuicClient : IDisposable
{
    private readonly UdpClient _udp;
    private readonly IPEndPoint _server;
    private nint _engine;
    private nint _conn;
    private GCHandle _self;
    private readonly byte[] _scratch = new byte[1452];
    private readonly List<byte> _echo = [];
    private bool _echoFin;

    /// <summary>Datagrams received and deliberately not fed to the engine.</summary>
    public int DroppedInbound { get; private set; }

    public string EchoSoFar => Encoding.ASCII.GetString(_echo.ToArray());
    public bool EchoComplete => _echoFin;
    public bool IsEstablished => _conn != 0 && iq_conn_is_established(_conn) != 0;

    /// <summary>The engine's next deadline in ns, or ulong.MaxValue when it has none.</summary>
    public ulong ExpiryNs => _conn == 0 ? ulong.MaxValue : iq_conn_expiry(_conn);

    /// <summary>The same question for any iq_conn*, so the server-side probe can ask it too.</summary>
    public static ulong Expiry(nint conn) => iq_conn_expiry(conn);

    private static ulong NowNs() => (ulong)(System.Diagnostics.Stopwatch.GetTimestamp() *
                                            (1_000_000_000.0 / System.Diagnostics.Stopwatch.Frequency));

    public LossyQuicClient(int port)
    {
        _udp = new UdpClient();
        _udp.Client.ReceiveTimeout = 100;
        _server = new IPEndPoint(IPAddress.Loopback, port);
        _udp.Connect(_server);   // fixes the local port, so the server's replies come back here
    }

    public void Connect()
    {
        var cbs = new IqCallbacks { StructSize = (nuint)sizeof(IqCallbacks), OnStreamData = &OnClientStreamData };
        _engine = iq_client_engine_new_mtls("echo", null, null, cbs);
        Assert.True(_engine != 0, "client engine init failed");

        Span<byte> local = stackalloc byte[16];
        Span<byte> remote = stackalloc byte[16];
        FillSockaddrIn(local, (ushort)((IPEndPoint)_udp.Client.LocalEndPoint!).Port, IPAddress.Loopback);
        FillSockaddrIn(remote, (ushort)_server.Port, IPAddress.Loopback);

        _self = GCHandle.Alloc(this);
        fixed (byte* l = local)
        fixed (byte* r = remote)
        {
            _conn = iq_client_connect(_engine, l, 16, r, 16, "localhost", "echo",
                                      16, NowNs(), (void*)GCHandle.ToIntPtr(_self), null);
        }
        Assert.True(_conn != 0, "client connect failed");
    }

    /// <summary>Send the client's first flight and nothing else.</summary>
    public void SendFirstFlight() => FlushOut();

    public bool CompleteHandshake(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            FlushOut();
            if (IsEstablished)
            {
                return true;
            }
            PumpIn();
        }
        return false;
    }

    /// <summary>Keep the connection turning over for roughly <paramref name="ms"/> milliseconds.</summary>
    public void Pump(int ms)
    {
        long deadline = Environment.TickCount64 + ms;
        do
        {
            FlushOut();
            PumpIn();
        }
        while (Environment.TickCount64 < deadline);
    }

    /// <summary>Open a stream, send the payload with fin, and leave the answer to arrive later.</summary>
    public void SendRequest(byte[] payload)
    {
        // Each request is answered on its own stream, so the collected answer starts empty.
        _echo.Clear();
        _echoFin = false;

        long streamId = iq_client_open_bidi(_conn);
        Assert.True(streamId >= 0, "failed to open client stream");

        long consumed;
        fixed (byte* dest = _scratch)
        fixed (byte* src = payload)
        {
            int off = 0;
            long sid = streamId;
            while (true)
            {
                byte* dataPtr = sid >= 0 ? src + off : null;
                nuint dataLen = sid >= 0 ? (nuint)(payload.Length - off) : 0;
                nint n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, sid,
                                       dataPtr, dataLen, 1, &consumed, NowNs());
                if ((int)n < 0)
                {
                    sid = -1;   // stream done or blocked - keep flushing the connection's own packets
                    continue;
                }
                if (consumed > 0)
                {
                    off += (int)consumed;
                }
                if (n > 0)
                {
                    _udp.Send(_scratch, (int)n);
                }
                if (n == 0)
                {
                    if (sid >= 0 && off < payload.Length)
                    {
                        sid = -1;
                        continue;
                    }
                    break;
                }
            }
        }
    }

    /// <summary>
    /// For <paramref name="ms"/> milliseconds: receive datagrams and throw them away, and send
    /// nothing at all. The peer's view is a connection that went silent, and nothing this client
    /// does afterwards can ask for what was lost.
    /// </summary>
    public void Blackout(int ms)
    {
        long deadline = Environment.TickCount64 + ms;
        while (Environment.TickCount64 < deadline)
        {
            try
            {
                IPEndPoint? from = null;
                _udp.Receive(ref from);
                DroppedInbound++;
            }
            catch (SocketException)
            {
                // receive timeout - stay silent until the window closes
            }
        }
    }

    /// <summary>Pump until the echo's fin arrives, or the deadline passes.</summary>
    public string CollectEcho(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline && !_echoFin)
        {
            FlushOut();
            PumpIn();
        }
        return EchoSoFar;
    }

    /// <summary>Request and answer in one call, for the connections that are not losing anything.</summary>
    public string RequestEcho(byte[] payload, int timeoutMs)
    {
        SendRequest(payload);
        return CollectEcho(timeoutMs);
    }

    private void FlushOut()
    {
        long consumed;
        fixed (byte* dest = _scratch)
        {
            while (true)
            {
                nint n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, -1, null, 0, 0, &consumed, NowNs());
                if (n <= 0)
                {
                    break;
                }
                _udp.Send(_scratch, (int)n);
            }
        }
    }

    private void PumpIn()
    {
        try
        {
            IPEndPoint? from = null;
            byte[] packet = _udp.Receive(ref from);
            fixed (byte* p = packet)
            {
                iq_conn_read(_conn, null, 0, p, (nuint)packet.Length, 0, NowNs());
            }
        }
        catch (SocketException)
        {
            // receive timeout; the caller loops
        }
    }

    private static void FillSockaddrIn(Span<byte> sa, ushort port, IPAddress addr)
    {
        sa.Clear();
        sa[0] = 2;   // AF_INET (x86 little-endian: family low byte)
        sa[2] = (byte)(port >> 8);
        sa[3] = (byte)(port & 0xff);
        addr.GetAddressBytes().CopyTo(sa[4..]);
    }

    [UnmanagedCallersOnly]
    private static void OnClientStreamData(void* user, long streamId, byte* data, nuint len, int fin)
    {
        var self = (LossyQuicClient)GCHandle.FromIntPtr((nint)user).Target!;
        self._echo.AddRange(new ReadOnlySpan<byte>(data, (int)len).ToArray());
        if (fin != 0)
        {
            self._echoFin = true;
        }
    }

    public void Dispose()
    {
        if (_conn != 0)
        {
            iq_conn_free(_conn);
            _conn = 0;
        }
        if (_engine != 0)
        {
            iq_client_engine_free(_engine);
            _engine = 0;
        }
        if (_self.IsAllocated)
        {
            _self.Free();
        }
        _udp.Dispose();
    }

    // --- shim client entry points (test-only) ---

    [StructLayout(LayoutKind.Sequential)]
    private struct IqCallbacks
    {
        public nuint StructSize;
        public delegate* unmanaged<void*, long, byte*, nuint, int, void> OnStreamData;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamClose;
        public delegate* unmanaged<void*, void>                         OnHandshakeCompleted;
        public delegate* unmanaged<void*, byte*, nuint, void>           OnNewCid;
        public delegate* unmanaged<void*, byte*, nuint, void>           OnRetireCid;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamReset;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamStopSending;
        public delegate* unmanaged<void*, long, ulong, ulong, void>     OnAckedStreamData;
        public delegate* unmanaged<void*, void*, nuint, void>           OnPathChange;
    }

    private const string Lib = "ioxide_ngtcp2";
    [DllImport(Lib)] private static extern nint iq_client_engine_new_mtls(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? certPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, IqCallbacks cbs);
    [DllImport(Lib)] private static extern void iq_client_engine_free(nint e);
    [DllImport(Lib)] private static extern nint iq_client_connect(nint e, byte* localSa, nuint localLen, byte* remoteSa, nuint remoteLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string serverName, [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn, nuint scidLen, ulong ts, void* user, byte* scidOut);
    [DllImport(Lib)] private static extern long iq_client_open_bidi(nint conn);
    [DllImport(Lib)] private static extern nint iq_conn_write(nint conn, byte* dest, nuint destLen, long streamId, byte* data, nuint dataLen, int fin, long* pConsumed, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_read(nint conn, void* remoteSa, nuint remoteLen, byte* pkt, nuint pktLen, byte ecn, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_is_established(nint conn);
    [DllImport(Lib)] private static extern ulong iq_conn_expiry(nint conn);
    [DllImport(Lib)] private static extern void iq_conn_free(nint conn);
}
