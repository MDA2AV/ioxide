using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The deferred-fault machinery: a callback that throws, a recv queue that overflows, and whether
/// either is acted on rather than merely recorded.
/// </summary>
/// <remarks>
/// Eight [UnmanagedCallersOnly] callbacks cross from ngtcp2 into managed code, and an exception
/// reaching that boundary aborts the PROCESS - there are native frames between it and any managed
/// caller. So each is guarded, the reason goes to <c>_deferredFault</c>, and EndEngineCycle acts on
/// it once ngtcp2's frames have unwound (tearing down inside the callback would free the connection
/// out from under the ngtcp2 call still on the stack below it).
///
/// Every test here therefore asserts three separate things, because each of the three plausible
/// mutations breaks a different one: the process and its reactor survive (delete a guard, or tear
/// down inside the callback, and they do not), the peer is TOLD - a CONNECTION_CLOSE, which the
/// client's ngtcp2 reports back as DRAINING (ignore the deferred fault and it hears nothing at all),
/// and a LATER connection is still served, since a test that only checks the faulting connection
/// passes just as well with the reactor dead.
/// </remarks>
internal static class QuicDeferredFaultTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic/fault: a callback that throws closes that connection and tells the peer", () =>
        {
            // OnHandshakeCompleted is one of the two protected virtuals the callbacks dispatch to -
            // i.e. user code reached directly from inside iq_conn_read, with ngtcp2 on the stack.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));
            var faults = new FaultCounter();

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(_ => new ThrowingHandshakeConnection(engine, faults)),
                quicHandle: EchoHandler);

            using var client = new QuicFaultClient("127.0.0.1", udpPort);
            client.Connect();
            client.CompleteHandshake(timeoutMs: 5000);

            // Vacuity guard: without this the test passes on a handshake that never got far enough
            // to reach the callback at all, which is every way this fixture can go wrong.
            Assert.True(client.WaitFor(() => faults.Count > 0, timeoutMs: 5000),
                "the throwing callback never ran, so nothing was being tested");

            Assert.True(client.WaitForClose(timeoutMs: 5000),
                "a callback that threw must close the connection with a CONNECTION_CLOSE, not leave "
                + "the peer waiting out its own timeout");
        });

        runner.Test("quic/fault: the reactor still serves a later connection after one faulted", () =>
        {
            // The connection is what dies, not the endpoint. Asserted with a SECOND connection that
            // has to complete a handshake and get its bytes echoed back, because a test that only
            // looks at the faulting connection reports exactly the same green with the reactor
            // thread dead underneath it.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));
            var faults = new FaultCounter();
            int adopted = 0;

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(_ => Interlocked.Increment(ref adopted) == 1
                    ? new ThrowingHandshakeConnection(engine, faults)
                    : new QuicEngineConnection(engine)),
                quicHandle: EchoHandler);

            using (var doomed = new QuicFaultClient("127.0.0.1", udpPort))
            {
                doomed.Connect();
                doomed.CompleteHandshake(timeoutMs: 5000);
                Assert.True(doomed.WaitFor(() => faults.Count > 0, timeoutMs: 5000),
                    "the throwing callback never ran, so no connection was ever faulted");
            }

            using var later = new QuicFaultClient("127.0.0.1", udpPort);
            later.Connect();
            Assert.True(later.CompleteHandshake(timeoutMs: 5000),
                "the reactor stopped handshaking after a connection faulted");
            Assert.Equal("later-connection", later.RequestEcho(Encoding.ASCII.GetBytes("later-connection"), timeoutMs: 5000));
        });

        runner.Test("quic/fault: an overflowing recv queue closes that connection and tells the peer", () =>
        {
            // The other way a fault is recorded, and the only one that needs no user code to throw:
            // OnStreamData drops the delivery and writes "recv queue overflow" into the same field.
            // The handler parks without ever reading, so the 256-entry queue fills and the peer's
            // 257th single-byte STREAM frame overflows it.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));

            var park = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: ParkedHandler(park));

            try
            {
                using var client = new QuicFaultClient("127.0.0.1", udpPort);
                client.Connect();
                Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

                int frames = client.SendSingleByteFrames(600, timeoutMs: 20_000);

                // Vacuity guard: a client that gave up at 40 frames proves nothing about a queue of
                // 256, and "the connection closed" would still be true - for the wrong reason.
                Assert.True(frames > 256,
                    $"only {frames} frames reached the server, which cannot have overflowed a 256-entry queue");

                Assert.True(client.WaitForClose(timeoutMs: 5000),
                    "an overflowed recv queue must close the connection with a CONNECTION_CLOSE - the "
                    + "deliveries were dropped, so leaving the peer connected leaves it talking to a "
                    + "stream with a hole in it");
            }
            finally
            {
                park.TrySetResult();
            }
        });

        runner.Test("quic/fault: a HandshakeCompleted callback that throws is logged, and the connection keeps serving", () =>
        {
            // Same event, same engine cycle, same class - and the opposite fault semantics.
            //
            // CbHandshakeCompleted dispatches to the protected virtual OnHandshakeCompleted inside a
            // guard, so a throw there is recorded and EndEngineCycle closes the connection (the first
            // test above). The public HandshakeCompleted action is raised for the SAME event a few
            // lines later, by FireHandshakeSignal, bare: nothing catches it, nothing reaches
            // _deferredFault. The throw unwinds OnDatagramCore, unwinds OnDatagram past the
            // reactor's QuicArmTimer, and dies in Reactor.Udp's datagram catch-all - after which the
            // connection is still registered, still routed and still answering requests, with the
            // peer never told that its handshake callback did not run.
            //
            // Asserted on the peer hearing a CONNECTION_CLOSE and NOT on the connection still
            // serving: the point is that this fault should be handled like the other eight, and a
            // Pending has to start passing the moment it is.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));
            var faults = new FaultCounter();

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(_ => new ThrowingSignalConnection(engine, faults)),
                quicHandle: EchoHandler);

            using var client = new QuicFaultClient("127.0.0.1", udpPort);
            client.Connect();
            client.CompleteHandshake(timeoutMs: 5000);

            Assert.True(client.WaitFor(() => faults.Count > 0, timeoutMs: 5000),
                "the throwing HandshakeCompleted never ran, so nothing was being tested");

            // Reviewed as a defect and kept, for two reasons. FireHandshakeSignal is not an ABI
            // boundary - it exists precisely so the hook is raised AFTER the engine call has
            // unwound, and all eight [UnmanagedCallersOnly] entry points are separately guarded, so
            // no managed exception can cross into an ngtcp2 frame. And keeping the connection is
            // this framework's consistent policy for a fault in USER code, not an oversight: a
            // faulted QUIC handler is logged and the connection released, and both h3 stacks answer
            // a faulted request handler with 500 rather than killing the connection. The engine
            // state here is intact; only the caller's post-handshake hook failed.
            Assert.True(!client.WaitForClose(timeoutMs: 1500),
                "a throwing HandshakeCompleted closed the connection - user-code faults are logged "
                + "and survived here, as they are everywhere else in the runtime");
        });
    }

    /// <summary>Counts callback invocations on the reactor thread, read from the test thread.</summary>
    private sealed class FaultCounter
    {
        private int _count;
        public int Count => Volatile.Read(ref _count);
        public void Hit() => Interlocked.Increment(ref _count);
    }

    /// <summary>Throws from the protected virtual the guarded CbHandshakeCompleted dispatches to.</summary>
    private sealed class ThrowingHandshakeConnection(QuicEngine engine, FaultCounter faults)
        : QuicEngineConnection(engine)
    {
        protected override void OnHandshakeCompleted()
        {
            faults.Hit();
            throw new InvalidOperationException("callback fault under test");
        }
    }

    /// <summary>Throws from the public HandshakeCompleted action, raised for the same event by
    /// FireHandshakeSignal rather than by a guarded callback.</summary>
    private sealed class ThrowingSignalConnection : QuicEngineConnection
    {
        public ThrowingSignalConnection(QuicEngine engine, FaultCounter faults) : base(engine)
        {
            HandshakeCompleted = () =>
            {
                faults.Hit();
                throw new InvalidOperationException("handshake-signal fault under test");
            };
        }
    }

    /// <summary>Never reads, so the recv queue fills instead of draining.</summary>
    private static Func<Reactor, QuicConnection, Task> ParkedHandler(TaskCompletionSource park)
        => async (_, conn) =>
        {
            try
            {
                await park.Task;
            }
            finally
            {
                conn.DecRef();
            }
        };

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
}

/// <summary>
/// A raw ngtcp2 client over a real loopback socket - the shape QuicTestClient has, plus the one
/// thing these tests turn on: whether the server said goodbye. A CONNECTION_CLOSE makes the client's
/// ngtcp2 return NGTCP2_ERR_DRAINING out of read, which is how "the peer was told" is observed
/// rather than inferred from silence. Silence is exactly what a hung server also produces.
/// </summary>
internal sealed unsafe class QuicFaultClient : IDisposable
{
    private const int NgtcpErrClosing  = -223;
    private const int NgtcpErrDraining = -224;

    private readonly UdpClient _udp;
    private readonly IPEndPoint _server;
    private readonly byte[] _scratch = new byte[1452];
    private readonly List<byte> _echo = [];
    private nint _clientEngine;
    private nint _conn;
    private bool _echoFin;

    /// <summary>The server sent a CONNECTION_CLOSE (or is closing), i.e. the peer WAS told.</summary>
    public bool SawClose { get; private set; }

    private static ulong NowNs() => (ulong)(System.Diagnostics.Stopwatch.GetTimestamp() *
                                            (1_000_000_000.0 / System.Diagnostics.Stopwatch.Frequency));

    public QuicFaultClient(string host, int port)
    {
        _udp = new UdpClient();
        _udp.Client.ReceiveTimeout = 50;
        _server = new IPEndPoint(IPAddress.Parse(host), port);
        _udp.Connect(_server);   // fixes the local port so the server's replies come back here
    }

    public void Connect()
    {
        var cbs = new IqCallbacks { StructSize = (nuint)sizeof(IqCallbacks), OnStreamData = &OnClientStreamData };
        _clientEngine = iq_client_engine_new_mtls("echo", null, null, cbs);
        Assert.True(_clientEngine != 0, "client engine init failed");

        Span<byte> local = stackalloc byte[16];
        Span<byte> remote = stackalloc byte[16];
        FillSockaddrIn(local, (ushort)((IPEndPoint)_udp.Client.LocalEndPoint!).Port, IPAddress.Loopback);
        FillSockaddrIn(remote, (ushort)_server.Port, IPAddress.Loopback);

        fixed (byte* l = local)
        fixed (byte* r = remote)
        {
            _conn = iq_client_connect(_clientEngine, l, 16, r, 16, "localhost", "echo",
                16, NowNs(), (void*)GCHandle.ToIntPtr(GCHandle.Alloc(this)), null);
        }
        Assert.True(_conn != 0, "client connect failed");
    }

    public bool CompleteHandshake(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline && !SawClose)
        {
            FlushOut();
            if (iq_conn_is_established(_conn) != 0)
            {
                return true;
            }
            PumpIn();
        }
        return false;
    }

    /// <summary>Keep the connection turning until <paramref name="condition"/> holds. The engine has
    /// to be pumped while waiting, or the server's datagrams sit unread in the socket buffer.</summary>
    public bool WaitFor(Func<bool> condition, int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (condition())
            {
                return true;
            }
            FlushOut();
            PumpIn();
        }
        return condition();
    }

    /// <summary>Whether a CONNECTION_CLOSE arrives within the deadline. A generous bound on an
    /// event, not an assertion about how fast it happened.</summary>
    public bool WaitForClose(int timeoutMs) => WaitFor(() => SawClose, timeoutMs);

    /// <summary>
    /// Open one bidirectional stream and dribble <paramref name="count"/> single-byte STREAM frames
    /// down it, one datagram each. The server's recv queue takes one entry per frame, and nothing
    /// merges them: they arrive in order, so ngtcp2 delivers each on its own. Returns how many the
    /// engine actually accepted, which is what the caller has to check before believing the queue
    /// was overflowed.
    /// </summary>
    public int SendSingleByteFrames(int count, int timeoutMs)
    {
        long streamId = iq_client_open_bidi(_conn);
        Assert.True(streamId >= 0, "failed to open a client stream");

        long deadline = Environment.TickCount64 + timeoutMs;
        byte[] one = [0x41];
        int sent = 0;

        while (sent < count && Environment.TickCount64 < deadline && !SawClose)
        {
            long consumed = 0;
            nint n;
            fixed (byte* dest = _scratch)
            fixed (byte* src = one)
            {
                n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, streamId,
                    src, 1, 0, &consumed, NowNs());
            }

            if ((int)n < 0)
            {
                break;   // stream refused or gone - the caller's frame-count assert reports it
            }
            if (n > 0)
            {
                _udp.Send(_scratch, (int)n);
            }
            if (consumed > 0)
            {
                sent++;
            }

            if (n == 0 && consumed == 0)
            {
                PumpIn();   // engine can take no more this instant: let its acks in
            }
            else
            {
                PumpInNonBlocking();
            }
        }
        return sent;
    }

    /// <summary>Send a payload with FIN on a fresh stream and collect what comes back.</summary>
    public string RequestEcho(byte[] payload, int timeoutMs)
    {
        long streamId = iq_client_open_bidi(_conn);
        Assert.True(streamId >= 0, "failed to open a client stream");

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
                int code = (int)n;
                if (code < 0)
                {
                    sid = -1;   // stream done/blocked - keep flushing the connection's own packets
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

        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline && !_echoFin && !SawClose)
        {
            FlushOut();
            PumpIn();
        }
        return Encoding.ASCII.GetString(_echo.ToArray());
    }

    private void FlushOut()
    {
        if (SawClose)
        {
            return;
        }
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
            Feed(_udp.Receive(ref from));
        }
        catch (SocketException)
        {
            // receive timeout - the caller loops
        }
    }

    private void PumpInNonBlocking()
    {
        while (_udp.Available > 0)
        {
            try
            {
                IPEndPoint? from = null;
                Feed(_udp.Receive(ref from));
            }
            catch (SocketException)
            {
                return;
            }
        }
    }

    private void Feed(byte[] packet)
    {
        int rv;
        fixed (byte* p = packet)
        {
            rv = iq_conn_read(_conn, null, 0, p, (nuint)packet.Length, 0, NowNs());
        }
        if (rv is NgtcpErrDraining or NgtcpErrClosing)
        {
            SawClose = true;
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
        var self = (QuicFaultClient)GCHandle.FromIntPtr((nint)user).Target!;
        self._echo.AddRange(new ReadOnlySpan<byte>(data, (int)len).ToArray());
        if (fin != 0)
        {
            self._echoFin = true;
        }
    }

    public void Dispose()
    {
        if (_conn != 0) iq_conn_free(_conn);
        if (_clientEngine != 0) iq_client_engine_free(_clientEngine);
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
    [DllImport(Lib)] private static extern void iq_conn_free(nint conn);
}
