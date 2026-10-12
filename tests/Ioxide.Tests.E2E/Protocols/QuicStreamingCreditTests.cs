using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// Flow-control credit on an app-paced receive stream (<see cref="QuicConnection.SetStreamPaced"/> +
/// <see cref="QuicConnection.ConsumeStreamData"/>) when the handler consumes OFF a datagram's engine
/// cycle - a streaming upload whose handler awaits something per chunk (a timer, a query) and so
/// resumes on that completion rather than inline on the peer's packet. The credit it opens must
/// still reach the peer, or a blocked uploader waits on its own timer to make progress.
/// </summary>
internal static class QuicStreamingCreditTests
{
    // 1 MiB over a 256 KiB stream window: it only finishes if credit opened by the consumer keeps
    // reaching the peer as the body drains.
    private const int Upload = 1024 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("quic: a paced upload whose handler credits off the engine cycle still completes", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            var obs = new UploadObserver();
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: PacedSink(obs, offCycle: true));

            using var client = new PacedUploadClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(5000), "handshake did not complete");

            bool done = client.Upload(Upload, obs, timeoutMs: 20_000);

            Assert.True(done && obs.Received == Upload,
                $"the upload stalled at {obs.Received} of {Upload} bytes: credit opened off the engine cycle "
                + "never reached the peer, so it waited on its own timer");
        });

        runner.Test("control: the same paced upload whose handler credits inside the engine cycle completes", () =>
        {
            // The discriminator: identical handler and client, crediting WITHOUT the off-cycle await,
            // so the credit is flushed at the cycle's end. If this did not complete, the test above
            // would be measuring a broken uploader rather than the missing off-cycle flush.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            var obs = new UploadObserver();
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: PacedSink(obs, offCycle: false));

            using var client = new PacedUploadClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(5000), "handshake did not complete");

            bool done = client.Upload(Upload, obs, timeoutMs: 20_000);

            Assert.True(done && obs.Received == Upload,
                $"the in-cycle control upload stalled at {obs.Received} of {Upload} bytes");
        });
    }

    internal sealed class UploadObserver
    {
        private long _received;
        public long Received => Interlocked.Read(ref _received);
        public void Add(int n) => Interlocked.Add(ref _received, n);
        public readonly TaskCompletionSource Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    // A server that paces the upload stream and credits each chunk it consumes. offCycle awaits a
    // RingTimer first, so the ConsumeStreamData call lands outside the datagram's engine cycle.
    private static Func<Reactor, QuicConnection, Task> PacedSink(UploadObserver obs, bool offCycle)
        => async (reactor, conn) =>
        {
            var timer = new RingTimer(reactor);
            bool paced = false;
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        if (item.Kind == QuicStreamEvent.Data)
                        {
                            if (!paced) { conn.SetStreamPaced(item.StreamId, true); paced = true; }
                            int len = item.Len;
                            long sid = item.StreamId;
                            bool fin = item.Fin;
                            conn.ReturnBuffer(in item);
                            obs.Add(len);

                            if (offCycle)
                            {
                                await timer.DelayAsync(1);   // resumes off the cycle that delivered this chunk
                            }
                            if (len > 0)
                            {
                                conn.ConsumeStreamData(sid, len);
                            }
                            if (fin)
                            {
                                obs.Done.TrySetResult();
                            }
                            continue;
                        }
                        conn.ReturnBuffer(in item);
                    }
                    if (snap.IsClosed) break;
                    conn.ResetRead();
                }
            }
            finally { conn.DecRef(); }
        };
}

/// <summary>
/// A raw ngtcp2 uploader: sends a body on one stream as the peer's window allows, services inbound
/// (acks and the credit that reopens the window), and does NOT retransmit on a timer of its own -
/// so it makes forward progress only from credit the SERVER sends. That is what makes "the upload
/// completed" evidence that the server opened the window without waiting to be prompted.
/// </summary>
internal sealed unsafe class PacedUploadClient : IDisposable
{
    private readonly UdpClient _udp;
    private readonly IPEndPoint _server;
    private readonly byte[] _scratch = new byte[1452];
    private nint _engine, _conn;
    private GCHandle _self;

    private static ulong NowNs() => (ulong)(Stopwatch.GetTimestamp() * (1_000_000_000.0 / Stopwatch.Frequency));

    public PacedUploadClient(string host, int port)
    {
        _udp = new UdpClient();
        _udp.Client.ReceiveTimeout = 20;
        _server = new IPEndPoint(IPAddress.Parse(host), port);
        _udp.Connect(_server);
    }

    public void Connect()
    {
        var cbs = new IqCallbacks { StructSize = (nuint)sizeof(IqCallbacks), OnStreamData = &OnData };
        _engine = iq_client_engine_new_mtls("echo", null, null, cbs);
        Assert.True(_engine != 0, "client engine init failed");

        Span<byte> l = stackalloc byte[16], r = stackalloc byte[16];
        Fill(l, (ushort)((IPEndPoint)_udp.Client.LocalEndPoint!).Port);
        Fill(r, (ushort)_server.Port);
        _self = GCHandle.Alloc(this);
        fixed (byte* lp = l) fixed (byte* rp = r)
        {
            _conn = iq_client_connect(_engine, lp, 16, rp, 16, "localhost", "echo", 16, NowNs(), (void*)GCHandle.ToIntPtr(_self), null);
        }
        Assert.True(_conn != 0, "client connect failed");
    }

    public bool CompleteHandshake(int ms)
    {
        long d = Environment.TickCount64 + ms;
        while (Environment.TickCount64 < d)
        {
            Flush();
            if (iq_conn_is_established(_conn) != 0) return true;
            In();
        }
        return false;
    }

    /// <summary>Send <paramref name="bytes"/> with FIN on one stream, pumping the wire; true once the
    /// server reports the whole body arrived (its FIN observer), false at the deadline.</summary>
    public bool Upload(int bytes, QuicStreamingCreditTests.UploadObserver obs, int timeoutMs)
    {
        long sid = iq_client_open_bidi(_conn);
        Assert.True(sid >= 0, "failed to open the upload stream");

        long deadline = Environment.TickCount64 + timeoutMs;
        int off = 0;
        bool finPending = true;
        long c;
        fixed (byte* dest = _scratch)
        {
            var body = new byte[bytes];   // zeros; content is irrelevant, only the count is
            fixed (byte* src = body)
            {
                while ((off < bytes || finPending) && Environment.TickCount64 < deadline && !obs.Done.Task.IsCompleted)
                {
                    byte* ptr = off < bytes ? src + off : null;
                    nint n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, sid, ptr, (nuint)(bytes - off), finPending ? 1 : 0, &c, NowNs());
                    if ((int)n < 0) { Flush(); In(); continue; }
                    if (c > 0) { off += (int)c; if (off >= bytes) finPending = false; }
                    else if (finPending && off >= bytes && n > 0) { finPending = false; }
                    if (n > 0) { _udp.Send(_scratch, (int)n); }
                    else if (c <= 0) { Flush(); In(); }   // window-blocked: pump until the server's credit arrives
                }
            }
        }

        while (!obs.Done.Task.IsCompleted && Environment.TickCount64 < deadline)
        {
            Flush();
            In();
        }
        return obs.Done.Task.IsCompleted;
    }

    private void Flush()
    {
        long c;
        fixed (byte* dest = _scratch)
        {
            while (true)
            {
                nint n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, -1, null, 0, 0, &c, NowNs());
                if (n <= 0) break;
                _udp.Send(_scratch, (int)n);
            }
        }
    }

    private void In()
    {
        try
        {
            IPEndPoint? f = null;
            byte[] p = _udp.Receive(ref f);
            fixed (byte* pp = p) iq_conn_read(_conn, null, 0, pp, (nuint)p.Length, 0, NowNs());
        }
        catch (SocketException) { }
    }

    private static void Fill(Span<byte> sa, ushort port)
    {
        sa.Clear(); sa[0] = 2; sa[2] = (byte)(port >> 8); sa[3] = (byte)(port & 0xff); sa[4] = 127; sa[7] = 1;
    }

    [UnmanagedCallersOnly] private static void OnData(void* u, long s, byte* d, nuint l, int f) { }

    public void Dispose()
    {
        if (_conn != 0) iq_conn_free(_conn);
        if (_engine != 0) iq_client_engine_free(_engine);
        if (_self.IsAllocated) _self.Free();
        _udp.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IqCallbacks
    {
        public nuint StructSize;
        public delegate* unmanaged<void*, long, byte*, nuint, int, void> OnStreamData;
        public delegate* unmanaged<void*, long, ulong, void> OnStreamClose;
        public delegate* unmanaged<void*, void> OnHandshakeCompleted;
        public delegate* unmanaged<void*, byte*, nuint, void> OnNewCid;
        public delegate* unmanaged<void*, byte*, nuint, void> OnRetireCid;
        public delegate* unmanaged<void*, long, ulong, void> OnStreamReset;
        public delegate* unmanaged<void*, long, ulong, void> OnStreamStopSending;
        public delegate* unmanaged<void*, long, ulong, ulong, void> OnAckedStreamData;
        public delegate* unmanaged<void*, void*, nuint, void> OnPathChange;
    }

    private const string Lib = "ioxide_ngtcp2";
    [DllImport(Lib)] private static extern nint iq_client_engine_new_mtls([MarshalAs(UnmanagedType.LPUTF8Str)] string a, [MarshalAs(UnmanagedType.LPUTF8Str)] string? c, [MarshalAs(UnmanagedType.LPUTF8Str)] string? k, IqCallbacks cbs);
    [DllImport(Lib)] private static extern void iq_client_engine_free(nint e);
    [DllImport(Lib)] private static extern nint iq_client_connect(nint e, byte* l, nuint ll, byte* r, nuint rl, [MarshalAs(UnmanagedType.LPUTF8Str)] string sn, [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn, nuint scl, ulong ts, void* u, byte* so);
    [DllImport(Lib)] private static extern long iq_client_open_bidi(nint c);
    [DllImport(Lib)] private static extern nint iq_conn_write(nint c, byte* d, nuint dl, long s, byte* data, nuint datal, int fin, long* pc, ulong ts);
    [DllImport(Lib)] private static extern int iq_conn_read(nint c, void* r, nuint rl, byte* p, nuint pl, byte ecn, ulong ts);
    [DllImport(Lib)] private static extern int iq_conn_is_established(nint c);
    [DllImport(Lib)] private static extern ulong iq_conn_expiry(nint c);
    [DllImport(Lib)] private static extern int iq_conn_handle_expiry(nint c, ulong ts);
    [DllImport(Lib)] private static extern void iq_conn_free(nint c);
}

