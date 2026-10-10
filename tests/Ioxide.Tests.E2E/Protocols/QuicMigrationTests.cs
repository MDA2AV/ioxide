using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// A client whose address changes mid-connection - the thing QUIC's connection id exists for.
/// </summary>
/// <remarks>
/// The shape is h2o's <c>40http3-migration.t</c> and nginx's <c>quic_migration.t</c>: put a UDP
/// forwarder between client and server, then swap the forwarder's UPSTREAM socket part way
/// through. The server sees the same connection id arriving from a new source address, exactly as
/// it would when a NAT rebinds a mapping or a phone moves from Wi-Fi to cellular.
///
/// That trigger is more ordinary than "the user changed network": home and mobile NATs recycle UDP
/// mappings after fairly short idle periods, so a connection that goes quiet and speaks again can
/// come back from a different port without the client moving at all.
///
/// What must happen is ngtcp2's decision, not ours - it challenges the new path, waits for the
/// response, and only then adopts it. What ioxide has to get right is feeding it the address the
/// datagram actually arrived on, and then sending to the address it settled on.
/// </remarks>
internal static class QuicMigrationTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic/migration: a client whose address changes keeps being served", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int serverPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("migrated-ok")));

            using var forwarder = new UdpForwarder(serverPort);
            using var client = new H3TestClient("127.0.0.1", forwarder.Port);

            client.Connect();
            Assert.True(client.CompleteHandshake(10_000), "the handshake through the forwarder did not complete");

            // Before: proves the path under test is a working one, so a failure after the swap is
            // the swap and not the forwarder.
            (int firstStatus, string firstBody) = client.Request("GET", "/before", null, 10_000);
            Assert.Equal(200, firstStatus);
            Assert.Equal("migrated-ok", firstBody);

            // The client's address changes. Same connection id, new source port.
            forwarder.SwapUpstream();

            (int secondStatus, string secondBody) = client.Request("GET", "/after", null, 15_000);

            Assert.Equal(200, secondStatus);
            Assert.Equal("migrated-ok", secondBody);
            // The discriminating assertion, and the reason the two above are not enough. A server
            // that ignores the address change still answers requests it received BEFORE the swap,
            // so "the request succeeded" proves nothing on its own. What only a migrated server can
            // do is send to the new address - measured here as datagrams arriving back on the
            // socket the swap created. Without the path being passed through to ngtcp2 this is 0.
            Assert.True(forwarder.RelayedAfterSwap > 0,
                $"nothing was relayed after the swap, so the exchange never crossed the new path");
            Assert.True(forwarder.FromServerAfterSwap > 0,
                "the server never sent anything to the client's NEW address: it kept answering the "
                + "address the connection was accepted on, which is the connection blackholing");
        });

        runner.Test("quic/migration: a fleet serves a client whose packets moved to another reactor", () =>
        {
            // The multi-reactor case every other QUIC test is blind to - they pin ReactorCount = 1,
            // where a datagram has nowhere wrong to land. Issue #205.
            //
            // "The request succeeded" proves nothing: QUIC retransmits until something gets
            // through, so it passes even against a server that drops every migrated packet
            // (measured). What is real is whether datagrams arrived elsewhere and were handed on,
            // so the test drives the address until they do.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            const int reactors = 4;

            (int serverPort, Reactor[] fleet) = TestServer.StartQuicSharded(reactors,
                engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("migrated-ok")),
                routing: QuicRouting.Forward);

            long Forwarded()
            {
                long n = 0;
                foreach (Reactor reactor in fleet) { n += reactor.QuicForwardsSent; }
                return n;
            }

            long Dropped()
            {
                long n = 0;
                foreach (Reactor reactor in fleet) { n += reactor.QuicForwardsDropped; }
                return n;
            }

            using var forwarder = new UdpForwarder(serverPort);
            using var client = new H3TestClient("127.0.0.1", forwarder.Port);

            client.Connect();
            Assert.True(client.CompleteHandshake(10_000), "the handshake through the forwarder did not complete");

            (int status, string body) = client.Request("GET", "/before", null, 10_000);
            Assert.Equal(200, status);
            Assert.Equal("migrated-ok", body);

            // Change address until the kernel actually hands this connection to a DIFFERENT
            // reactor, which is the situation under test. Each change has a 1-in-4 chance of
            // landing back on the owner, so this settles at once in practice; the loop is here so
            // the test never rests on that coin.
            int swaps = 0;
            while (Forwarded() == 0 && swaps < 8)
            {
                swaps++;
                forwarder.SwapUpstream();

                (int afterStatus, string afterBody) = client.Request("GET", $"/after-{swaps}", null, 15_000);

                Assert.Equal(200, afterStatus);
                Assert.Equal("migrated-ok", afterBody);
            }

            Assert.True(Forwarded() > 0,
                $"after {swaps} address changes no datagram ever reached a reactor that did not own "
                + "the connection, so the routing was never exercised");

            // And it keeps working now that the packets are arriving at the wrong reactor every time.
            Assert.Equal(200, client.Request("GET", "/steady", null, 15_000).Status);

            Assert.Equal(0L, Dropped());
            Assert.True(forwarder.FromServerAfterSwap > 0,
                "the server never sent anything to the client's new address, so nothing migrated");
        });

        runner.Test("quic/migration: claiming the new address stops the forwarding", () =>
        {
            // Forwarding alone is permanent: the address does not change back, so every later
            // datagram pays a hop. The claim ends that. This asserts the forwarding STOPS, not that
            // a claim was made - a claim that never receives anything would satisfy that.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (int serverPort, Reactor[] fleet) = TestServer.StartQuicSharded(4,
                engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("migrated-ok")),
                routing: QuicRouting.Forward);

            long Forwarded()
            {
                long n = 0;
                foreach (Reactor reactor in fleet) { n += reactor.QuicForwardsSent; }
                return n;
            }

            long Pins()
            {
                long n = 0;
                foreach (Reactor reactor in fleet) { n += reactor.QuicPinsCreated; }
                return n;
            }

            using var forwarder = new UdpForwarder(serverPort);
            using var client = new H3TestClient("127.0.0.1", forwarder.Port);

            client.Connect();
            Assert.True(client.CompleteHandshake(10_000), "the handshake through the forwarder did not complete");
            Assert.Equal(200, client.Request("GET", "/before", null, 10_000).Status);

            // Move until the datagrams genuinely land on another reactor, which is what makes a
            // claim necessary at all.
            int swaps = 0;
            while (Forwarded() == 0 && swaps < 8)
            {
                swaps++;
                forwarder.SwapUpstream();
                Assert.Equal(200, client.Request("GET", $"/after-{swaps}", null, 15_000).Status);
            }

            Assert.True(Forwarded() > 0,
                $"after {swaps} address changes nothing was forwarded, so no claim was needed and "
                + "this test proved nothing");

            // ngtcp2 only reports the new path once it has probed it, so give the claim a request
            // to be made in, then measure from there.
            Assert.Equal(200, client.Request("GET", "/settle", null, 15_000).Status);
            Assert.True(Pins() > 0, "the new address was never claimed");

            long settled = Forwarded();
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(200, client.Request("GET", $"/steady-{i}", null, 15_000).Status);
            }

            Assert.Equal(settled, Forwarded());

            // One claim per address, not per report: ngtcp2 announces a path several times while
            // probing, and rebuilding on each closes a socket with datagrams queued on it. At most
            // `swaps` distinct addresses, plus the one it started on.
            Console.Error.WriteLine($"pins created: {Pins()} across {swaps} address change(s)");
            Assert.True(Pins() <= swaps + 1,
                $"{Pins()} claims for {swaps} address change(s): the same address is being "
                + "re-claimed on every path report");
        });

        runner.Test("quic/migration: kernel steering delivers a migrated client without any forwarding", () =>
        {
            // The other half of QuicRouting. Under Forward the datagrams arrive at the wrong
            // reactor and are handed on; under KernelFilter they should never arrive wrong in the
            // first place, so the forward path stays untouched. Asserting zero is only meaningful
            // alongside the sibling test above, which shows the same scenario produces forwards
            // when the kernel is not doing the routing.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            const int reactors = 4;

            (int serverPort, Reactor[] fleet) = TestServer.StartQuicSharded(reactors,
                engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("migrated-ok")),
                routing: QuicRouting.KernelFilter);

            // Without this the rest passes vacuously on any machine where the program will not
            // load - it would simply be measuring Forward again under another name.
            bool attached = false;
            foreach (Reactor reactor in fleet) { attached |= reactor.QuicKernelSteeringAttached; }
            Assert.True(attached, "the steering program never attached, so this ran as Forward");

            using var forwarder = new UdpForwarder(serverPort);
            using var client = new H3TestClient("127.0.0.1", forwarder.Port);

            client.Connect();
            Assert.True(client.CompleteHandshake(10_000), "the handshake through the forwarder did not complete");

            Assert.Equal(200, client.Request("GET", "/before", null, 10_000).Status);

            for (int swap = 1; swap <= 3; swap++)
            {
                forwarder.SwapUpstream();

                (int status, string body) = client.Request("GET", $"/after-{swap}", null, 15_000);

                Assert.Equal(200, status);
                Assert.Equal("migrated-ok", body);
            }

            long forwarded = 0;
            foreach (Reactor reactor in fleet) { forwarded += reactor.QuicForwardsSent; }

            Assert.Equal(0L, forwarded);
        });

        // What every other test here assumes and none checks: that the connection SURVIVED. A
        // client that quietly re-handshakes also answers 200 to everything, so status codes cannot
        // tell migration from reconnection. The handler names the connection object serving each
        // request; the name must not change, and the factory must run once.
        foreach ((string stack, Func<Reactor, QuicConnection, Task> handler) in
                 new (string, Func<Reactor, QuicConnection, Task>)[]
                 {
                     ("nghttp3", static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                         _ => Nghttp3Response.Text($"conn-{conn.GetHashCode():x8}"))),
                     ("pure-c#", static (_, conn) => new Http3Connection(conn).RunAsync(
                         _ => Http3Response.Text($"conn-{conn.GetHashCode():x8}"))),
                 })
        {
            string name = stack;
            Func<Reactor, QuicConnection, Task> h3 = handler;

            runner.Test($"quic/migration: {name} - the SAME connection serves after the address changes", () =>
            {
                (string certPath, string keyPath) = TestCert.Ensure();
                using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

                int accepts = 0;
                (int serverPort, Reactor[] fleet) = TestServer.StartQuicSharded(4,
                    engine.CreateFactory(),
                    quicHandle: (r, conn) =>
                    {
                        Interlocked.Increment(ref accepts);
                        return h3(r, conn);
                    },
                    routing: QuicRouting.Forward);

                long Forwarded()
                {
                    long n = 0;
                    foreach (Reactor reactor in fleet) { n += reactor.QuicForwardsSent; }
                    return n;
                }

                using var forwarder = new UdpForwarder(serverPort);
                using var client = new H3TestClient("127.0.0.1", forwarder.Port);

                client.Connect();
                Assert.True(client.CompleteHandshake(10_000), "the handshake through the forwarder did not complete");

                (int beforeStatus, string served) = client.Request("GET", "/before", null, 10_000);
                Assert.Equal(200, beforeStatus);
                Assert.True(served.StartsWith("conn-"),
                    $"expected the serving connection to name itself, got '{served}'");

                // Keep moving until the datagrams reach a reactor that does not own the connection -
                // the kernel may re-hash back to the owner, exercising nothing.
                int swaps = 0;
                while (Forwarded() == 0 && swaps < 8)
                {
                    swaps++;
                    forwarder.SwapUpstream();

                    (int afterStatus, string afterServed) = client.Request("GET", $"/after-{swaps}", null, 15_000);

                    Assert.Equal(200, afterStatus);
                    Assert.Equal(served, afterServed);
                }

                Assert.True(Forwarded() > 0,
                    $"after {swaps} address changes nothing was ever forwarded, so the connection "
                    + "never actually moved between reactors and this proves nothing");

                // And it is still the same connection several requests later, on the new address.
                for (int i = 0; i < 3; i++)
                {
                    (int status, string owner) = client.Request("GET", $"/settled-{i}", null, 15_000);
                    Assert.Equal(200, status);
                    Assert.Equal(served, owner);
                }

                // The discriminator against a client that re-handshaked: a reconnect would run the
                // factory again. Migration must not.
                Assert.Equal(1, Volatile.Read(ref accepts));
            });
        }

        runner.Test("quic/migration: a connection accepted on a migrated peer's pin sends from the serving socket", () =>
        {
            // When a peer migrates, the owning reactor claims its new address with a connected
            // socket (the pin). A NEW Initial from that same address then lands on the pin, not the
            // wildcard - and the pin's fd is closed when its claim is released, so a connection that
            // recorded the pin's fd would later send through a closed, maybe reused, descriptor.
            // The accepted connection must send from the shared serving socket instead.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            var accepts = new List<(Reactor R, int ArrivalFd, QuicConnection Conn)>();
            var gate = new object();

            (int serverPort, Reactor[] fleet) = TestServer.StartQuicSharded(4,
                (Reactor r, in UdpDatagram d, in QuicCid cid) =>
                {
                    QuicConnection? conn = engine.CreateFactory()(r, in d, in cid);
                    if (conn is not null)
                    {
                        lock (gate) { accepts.Add((r, d.SocketFd, conn)); }
                    }
                    return conn;
                },
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("ok")),
                routing: QuicRouting.Forward);

            long Pins() { long n = 0; foreach (Reactor r in fleet) n += r.QuicPinsCreated; return n; }

            // A reactor's first-ever accept is always on the wildcard (a pin needs a prior migrated
            // connection on it), so the earliest arrival fd seen for a reactor IS its serving fd.
            int ServingFdOf(Reactor r)
            {
                lock (gate)
                {
                    foreach ((Reactor rr, int fd, _) in accepts)
                    {
                        if (ReferenceEquals(rr, r)) return fd;
                    }
                    return -1;
                }
            }

            using var forwarder = new FanInForwarder(serverPort);

            using var first = new H3TestClient("127.0.0.1", forwarder.Port);
            first.Connect();
            Assert.True(first.CompleteHandshake(10_000), "the first handshake did not complete");
            Assert.Equal(200, first.Request("GET", "/before", null, 10_000).Status);

            // One address change, then settle: the single new address is the only one a claim can
            // name, and the pin's owner is the reactor that accepted the first client - so the
            // second client's Initial, arriving from that same address, lands on that pin.
            forwarder.SwapUpstream();
            int settle = 0;
            while (Pins() == 0 && settle < 40)
            {
                settle++;
                Assert.Equal(200, first.Request("GET", $"/settle-{settle}", null, 15_000).Status);
            }
            Assert.True(Pins() > 0, $"after {settle} requests no address was claimed, so there is no pin to accept onto");

            int acceptsBefore = Count(accepts, gate);

            using var second = new H3TestClient("127.0.0.1", forwarder.Port);
            second.Connect();
            Assert.True(second.CompleteHandshake(10_000),
                "the second handshake did not complete - its Initial never reached a server");
            Assert.Equal(200, second.Request("GET", "/second", null, 10_000).Status);

            Assert.True(Count(accepts, gate) > acceptsBefore, "the second connection was never accepted");
            (Reactor r2, int arrivalFd, QuicConnection secondConn) = Last(accepts, gate);
            int servingFd = ServingFdOf(r2);

            // The second Initial landed on a socket that is NOT r2's wildcard - the pin - or this
            // proves nothing. (A fresh accept on the wildcard would make arrival == serving.)
            Assert.True(arrivalFd != servingFd,
                $"the second Initial arrived on r{r2.ShardIndex}'s serving fd {arrivalFd}, not a pin, so this proves nothing");
            // The fix: it sends from the serving socket, not the pin it arrived on.
            Assert.Equal(servingFd, secondConn.SocketFd);
        });

        runner.Test("control: a fleet whose clients never move claims no addresses", () =>
        {
            // The cost side. The claim runs from the sweep, which visits every connection every
            // 250 ms, so a guard asking only "is this claimed yet" would spend a descriptor and an
            // armed receive on every connection on the server to change nothing.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (int serverPort, Reactor[] fleet) = TestServer.StartQuicSharded(4,
                engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("ok")),
                routing: QuicRouting.Forward);

            using var client = new H3TestClient("127.0.0.1", serverPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(10_000), "handshake did not complete");

            // Long enough to cross several sweeps, which is when a claim would be made.
            for (int i = 0; i < 6; i++)
            {
                Assert.Equal(200, client.Request("GET", $"/r{i}", null, 15_000).Status);
            }

            long pins = 0;
            long forwards = 0;
            foreach (Reactor reactor in fleet)
            {
                pins += reactor.QuicPinsCreated;
                forwards += reactor.QuicForwardsSent;
            }

            Assert.Equal(0L, pins);
            Assert.Equal(0L, forwards);
        });

        runner.Test("control: the same exchange through a forwarder that never swaps", () =>
        {
            // Without this, the test above is satisfied by a forwarder that works and a migration
            // that never happened - and it would also hide a forwarder too slow to relay in time.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int serverPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("migrated-ok")));

            using var forwarder = new UdpForwarder(serverPort);
            using var client = new H3TestClient("127.0.0.1", forwarder.Port);

            client.Connect();
            Assert.True(client.CompleteHandshake(10_000), "the handshake through the forwarder did not complete");

            Assert.Equal(200, client.Request("GET", "/one", null, 10_000).Status);
            Assert.Equal(200, client.Request("GET", "/two", null, 10_000).Status);
        });
    }

    private static int Count(List<(Reactor, int, QuicConnection)> list, object gate) { lock (gate) { return list.Count; } }
    private static (Reactor R, int ArrivalFd, QuicConnection Conn) Last(List<(Reactor, int, QuicConnection)> list, object gate) { lock (gate) { return list[^1]; } }

    /// <summary>
    /// Like <see cref="UdpForwarder"/>, but fans several clients onto ONE upstream socket and
    /// broadcasts each server reply to every client it has seen - so two connections appear to the
    /// server to come from the same (swappable) source address. Each client's ngtcp2 drops the
    /// datagrams whose connection id is not its own, so the broadcast is harmless.
    /// </summary>
    private sealed class FanInForwarder : IDisposable
    {
        private readonly Socket _front;
        private readonly IPEndPoint _server;
        private readonly Thread _pump;
        private volatile bool _running = true;
        private volatile Socket _upstream;
        private readonly object _swapGate = new();
        private readonly HashSet<EndPoint> _clients = [];

        public int Port { get; }

        public FanInForwarder(int serverPort)
        {
            _server = new IPEndPoint(IPAddress.Loopback, serverPort);
            _front = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _front.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _front.ReceiveTimeout = 50;
            Port = ((IPEndPoint)_front.LocalEndPoint!).Port;
            _upstream = NewUpstream();
            _pump = new Thread(Pump) { IsBackground = true, Name = "fanin-forwarder" };
            _pump.Start();
        }

        public void SwapUpstream()
        {
            lock (_swapGate)
            {
                Socket old = _upstream;
                _upstream = NewUpstream();
                old.Dispose();
            }
        }

        private static Socket NewUpstream()
        {
            var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            s.ReceiveTimeout = 50;
            return s;
        }

        private void Pump()
        {
            byte[] buffer = new byte[2048];
            while (_running)
            {
                Socket upstream = _upstream;
                upstream.ReceiveTimeout = 50;

                try
                {
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int n = _front.ReceiveFrom(buffer, ref from);
                    lock (_clients) { _clients.Add(from); }
                    upstream.SendTo(buffer, 0, n, SocketFlags.None, _server);
                }
                catch (SocketException) { }
                catch (ObjectDisposedException) { }

                try
                {
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int n = upstream.ReceiveFrom(buffer, ref from);
                    EndPoint[] clients;
                    lock (_clients) { clients = [.. _clients]; }
                    foreach (EndPoint client in clients)
                    {
                        _front.SendTo(buffer, 0, n, SocketFlags.None, client);
                    }
                }
                catch (SocketException) { }
                catch (ObjectDisposedException) { }
            }
        }

        public void Dispose()
        {
            _running = false;
            _pump.Join(2_000);
            _front.Dispose();
            _upstream.Dispose();
        }
    }

    /// <summary>
    /// Relays UDP between one client and one server, and can change the socket it uses towards the
    /// server - which is what the server sees as its peer moving. Deliberately a single thread:
    /// the interesting behaviour is on the server, and a forwarder with its own concurrency bugs
    /// would be indistinguishable from the defect under test.
    /// </summary>
    private sealed class UdpForwarder : IDisposable
    {
        private readonly Socket _front;               // faces the client
        private readonly IPEndPoint _server;
        private readonly Thread _pump;
        private volatile bool _running = true;
        private volatile Socket _upstream;            // faces the server; swapped mid-connection
        private readonly object _swapGate = new();
        private EndPoint? _client;
        private int _relayed;
        private int _fromServerAfterSwap;

        public int Port { get; }
        public int SwappedAt { get; private set; }
        public int RelayedAfterSwap { get; private set; }
        public int FromServerAfterSwap => _fromServerAfterSwap;

        public UdpForwarder(int serverPort)
        {
            _server = new IPEndPoint(IPAddress.Loopback, serverPort);

            _front = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _front.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            Port = ((IPEndPoint)_front.LocalEndPoint!).Port;

            _upstream = NewUpstream();

            _pump = new Thread(Pump) { IsBackground = true, Name = "udp-forwarder" };
            _pump.Start();
        }

        /// <summary>
        /// Change the source address the server sees, NOW. Deliberately synchronous: doing it
        /// lazily on the next relayed datagram let the request under test complete before the swap
        /// ever happened, and the test then passed against a server with no migration support at
        /// all - it was measuring nothing.
        /// </summary>
        public void SwapUpstream()
        {
            lock (_swapGate)
            {
                Socket replacement = NewUpstream();
                Socket old = _upstream;
                SwappedAt = _relayed;
                _upstream = replacement;
                old.Dispose();   // the pump's in-flight receive throws and retries on the new one
            }
        }

        private static Socket NewUpstream()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));   // a fresh source port
            socket.ReceiveTimeout = 50;                           // never inherit "block forever"
            return socket;
        }

        private void Pump()
        {
            byte[] buffer = new byte[2048];
            _front.ReceiveTimeout = 50;

            while (_running)
            {
                // Read the field ONCE per pass and set the timeout on the socket actually used.
                // Setting it on a stale capture while receiving through the volatile field left a
                // freshly swapped socket at its default of 0 - block forever - so the pump wedged
                // and only Dispose woke it. A background thread outliving its test is how one
                // suite starts perturbing another.
                Socket upstream = _upstream;
                upstream.ReceiveTimeout = 50;

                // client -> server
                try
                {
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int n = _front.ReceiveFrom(buffer, ref from);
                    _client = from;

                    upstream.SendTo(buffer, 0, n, SocketFlags.None, _server);
                    _relayed++;
                    if (SwappedAt > 0)
                    {
                        RelayedAfterSwap++;
                    }
                }
                catch (SocketException)
                {
                    // timeout, or the socket was swapped from under the receive - both ordinary
                }
                catch (ObjectDisposedException)
                {
                }

                // server -> client
                try
                {
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int n = upstream.ReceiveFrom(buffer, ref from);
                    if (_client is not null)
                    {
                        _front.SendTo(buffer, 0, n, SocketFlags.None, _client);
                        if (SwappedAt > 0) { _fromServerAfterSwap++; }
                    }
                }
                catch (SocketException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
            }
        }

        public void Dispose()
        {
            _running = false;
            _pump.Join(2_000);
            _front.Dispose();
            _upstream.Dispose();
        }
    }
}
