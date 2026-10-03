using System.Text;
using ioxide;
using ioxide.tls;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-ktls - FULL kernel TLS: the OpenSSL handshake runs over the ring, then both directions
//  are handed to the kernel - the handler writes plaintext, the kernel makes the records, and
//  recv delivers plaintext straight into ring memory. Experimental (see KernelRx below);
//  Tls/KtlsTx is the deployable drop-back - kernel TX, OpenSSL RX - and Tls/OpenSsl the default.
//
//      sudo modprobe tls                             # needs the Linux 'tls' module + OpenSSL 3
//      dotnet run -c Release --project Playground/Tls/Ktls
//      curl -ks https://127.0.0.1:8443/ | head -c 40
//
//  PLAYGROUND_TLS_CERT/_KEY point at a real PEM pair; otherwise a self-signed localhost cert is
//  generated. PLAYGROUND_BODY sizes the response (default 8 KB - a representative JSON/HTML-ish
//  payload, since TLS overhead only shows against real bodies). Needs: ioxide
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
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
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
        RecvQueueEntries = 4096,                           // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

var tlsOptions = new TlsOptions
{
    CertificatePath = certPath,                            // PEM chain file (or CertificatePem for in-memory)
    KeyPath         = keyPath,                             // PEM key file (or KeyPem for in-memory)
    Alpn            = ["http/1.1"],                        // protocols this port serves, most-preferred first

    // NOT the default - TLS is OpenSSL both ways unless you ask for this. It is what lets the
    // handler below write PLAINTEXT to the connection: the kernel turns it into records on send.
    // Remove this line and conn.Write would put cleartext on the wire.
    KernelTx        = true,

    // Full kTLS: the kernel decrypts inbound too. Experimental - about one first connection in
    // twelve fails outright, and a client sending a TLS 1.3 KeyUpdate loses the connection.
    // Tls/KtlsTx is this same server without this line: kernel TX, OpenSSL RX, deployable today.
    KernelRx        = true,
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
            // The handshake reads and writes through this same connection; after it, the socket
            // carries kTLS records the kernel en/decrypts.
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            // A request can ride in with the handshake's final flight - answer it before parking
            // in ReadAsync, or the client waits on a response we never send.
            carry.Append(tls.DrainPlaintext());
            if (Answer(conn, carry, response))
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
                        // Records in, plaintext out - the session decrypts what the ring received.
                        Decrypt(tls, in item, carry);
                        conn.ReturnBuffer(in item);
                    }
                }

                if (Answer(conn, carry, response))
                {
                    await conn.FlushAsync();   // plaintext: the kernel encrypts on send
                }

                if (snapshot.IsClosed || tls.Closed) return;
                conn.ResetRead();
            }
        }
        catch (Exception e)
        {
            // Handlers run fire-and-forget, so a thrown handshake error would vanish silently -
            // and a missing 'tls' kernel module manifests exactly here.
            Console.Error.WriteLine($"[tls-ktls] connection failed: {e.Message}");
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

Console.WriteLine($"[tls-ktls] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"{bodyBytes}-byte body, tx=kernel, rx=kernel (experimental), cert {certPath}");

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
static bool Answer(TcpConnection conn, Carry carry, ReadOnlyMemory<byte> response)
{
    bool wrote = false;
    int end;

    while ((end = carry.Span.IndexOf("\r\n\r\n"u8)) >= 0)
    {
        carry.Consume(end + 4);

        // PLAINTEXT into the slab - safe only because KernelTx = true above. TlsSession.Write
        // is the call that is correct either way, and is what every other sample uses; this one
        // spells it out because demonstrating the kTLS write path is the point of the file.
        conn.Write(response.Span);

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
