using System.Text;
using ioxide;
using ioxide.tls;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-openssl - the same TLS termination as Tls/Ktls with kernel TLS turned OFF. OpenSSL does
//  both directions: it decrypts what the ring delivers, and it encrypts responses before they
//  reach the write slab.
//
//      dotnet run -c Release --project Playground/Tls/OpenSsl     # NO modprobe needed
//      curl -ks https://127.0.0.1:8443/ | head -c 40
//
//  Why choose this over kTLS. It drops every constraint kTLS imposes: no 'tls' kernel module (so
//  it runs in a container that does not have it), no TLS-1.3-only restriction, no single-suite
//  restriction, session resumption is available again, and there is no handshake-alignment
//  problem. The cost on this rig is nothing - see the table below - though a deployment using
//  sendfile or a NIC that offloads TLS would see a real difference kTLS cannot give up.
//
//  The one thing the handler must do differently is on the write side: with kTLS the kernel makes
//  the records so you write plaintext, and without it OpenSSL has to encrypt first.
//  Everything else - the handshake, ALPN, the read loop, the framing - is identical.
//
//  Measured here, 4 reactors, wrk -t4 -c64, against the plaintext Tcp/Raw baseline:
//
//      response   plaintext     kTLS            OpenSSL
//         64 B    1,379,980     1,091,224 0.79x 1,093,361 0.79x
//        8 KiB    1,109,287       749,833 0.68x   802,325 0.72x
//       64 KiB      448,093       157,644 0.35x   196,486 0.44x
//      256 KiB      133,097        41,691 0.31x    49,801 0.37x
//
//  Read that as: which TLS backend you pick is worth far less than the cost of TLS itself.
//
//  PLAYGROUND_TLS_CERT/_KEY point at a real PEM pair; otherwise a self-signed localhost cert is
//  generated. PLAYGROUND_BODY sizes the response. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port      = 8443;                        // https://127.0.0.1:8443/
int    reactors  = Environment.ProcessorCount;  // one ring per reactor, one reactor per core
int    bodyBytes = 8 * 1024;                    // TLS cost is per-byte, so a 2-byte "ok" would hide it

Env.Override(ref port, ref reactors, ref bodyBytes);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring per reactor. The
// handler code is identical either way; this only changes how recv buffers are handed out.
bool incrementalBuffers = false;

Env.OverrideIncremental(ref incrementalBuffers);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = incrementalBuffers ? new IncrementalOptions { MaxConnections = 1024, RecvSlots = 8, RecvBufferSize = 16 * 1024 } : null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                 // no raw UDP sockets (TCP-only server)
    Quic           = null,                                 // no QUIC transport - see Http3/* and Quic/Alpn
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                          // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 64,                             // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

var tlsOptions = new TlsOptions
{
    CertificatePath = certPath,                            // PEM chain file (or CertificatePem for in-memory)
    KeyPath         = keyPath,                             // PEM key file (or KeyPem for in-memory)
    Alpn            = ["http/1.1"],                        // protocols this port serves, most-preferred first

    // KernelTx stays false (the default), so this sample IS the stock configuration: no TLS
    // ULP on the socket, OpenSSL encrypts and decrypts, MSG_WAITALL stays on, and nothing here
    // needs the 'tls' kernel module. Tls/Ktls is the sample that opts into the kernel path.
    KernelTx        = false,
    KernelRx        = false,                               // kTLS receive (experimental; requires KernelTx)
};

byte[] body = new byte[bodyBytes];
ReadOnlySpan<byte> fill = "ioxide-ktls-payload "u8;
for (int i = 0; i < bodyBytes; i++)
{
    body[i] = fill[i % fill.Length];
}
byte[] response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {bodyBytes}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // One TlsService per reactor: it owns the OpenSSL contexts and drives handshakes on this ring.
    reactor.OnStart = r => TlsService.Start(r, tlsOptions);

    reactor.TcpHandle = async (r, conn) =>
    {
        TlsSession? tls = null;

        // Decrypted bytes waiting to be framed. TLS hands back records, not requests: split one
        // request across two records and each decrypts on its own, so answering per decrypt
        // answers twice. The carry is what turns "some plaintext arrived" into "a request
        // arrived", exactly as the plaintext samples do - ioxide does not parse HTTP for you.
        var carry = new Carry();

        try
        {
            // The handshake reads and writes through this same connection. Unlike Tls/Ktls, no
            // ULP is attached afterwards - the socket stays an ordinary TCP socket and every
            // record is made and opened by OpenSSL.
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            // A request can ride in with the handshake's final flight - answer it before parking
            // in ReadAsync, or the client waits on a response we never send.
            carry.Append(tls.DrainPlaintext());
            if (Answer(conn, tls, carry, response))
            {
                await conn.FlushAsync();
            }

            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        // Records in, plaintext out - OpenSSL decrypts what the ring received.
                        Decrypt(tls, in item, carry);
                        conn.ReturnBuffer(in item);
                    }
                }

                if (Answer(conn, tls, carry, response))
                {
                    await conn.FlushAsync();
                }

                if (snapshot.IsClosed || tls.Closed) return;
                conn.ResetRead();
            }
        }
        catch (Exception e)
        {
            // Handlers run fire-and-forget, so a thrown handshake error would vanish silently.
            // Note what CANNOT happen here that can in Tls/Ktls: a missing 'tls' kernel module.
            Console.Error.WriteLine($"[tls-openssl] connection failed: {e.Message}");
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[tls-openssl] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"{bodyBytes}-byte body, cert {certPath}, no kernel TLS");

foreach (Thread thread in threads)
{
    thread.Join();
}

// Decrypt takes a raw pointer (the buffer belongs to the ring); the pointer work stays out of the
// async handler, which cannot contain unsafe code.
static unsafe void Decrypt(TlsSession tls, in SpscRecvRing.Item item, Carry carry)
    => carry.Append(tls.Decrypt(item.Ptr, item.Len));

// One response per COMPLETE request in the carry, and none for a partial one. Returns whether
// anything was written, so the caller flushes once for the batch rather than once per request.
static bool Answer(TcpConnection conn, TlsSession tls, Carry carry, ReadOnlyMemory<byte> response)
{
    bool wrote = false;
    int end;

    while ((end = carry.Span.IndexOf("\r\n\r\n"u8)) >= 0)
    {
        carry.Consume(end + 4);

        // The one line that differs from Tls/Ktls. There, kTLS is producing the records so the
        // handler writes plaintext; here OpenSSL has to encrypt before anything reaches the slab.
        tls.Write(conn, response.Span);

        wrote = true;
    }

    return wrote;
}

// Decrypted-but-unframed bytes: append at the end, consume from the front. A List<byte> pressed
// into this job needs CollectionsMarshal to be searched and RemoveRange to be consumed; a plain
// array does both directly.
sealed class Carry
{
    private byte[] _buf = new byte[8 * 1024];
    private int _len;

    public ReadOnlySpan<byte> Span => _buf.AsSpan(0, _len);

    public void Append(ReadOnlySpan<byte> bytes)
    {
        if (_buf.Length - _len < bytes.Length)
        {
            Array.Resize(ref _buf, Math.Max(_buf.Length * 2, _len + bytes.Length));
        }
        bytes.CopyTo(_buf.AsSpan(_len));
        _len += bytes.Length;
    }

    public void Consume(int count)
    {
        _buf.AsSpan(count, _len - count).CopyTo(_buf);
        _len -= count;
    }
}
