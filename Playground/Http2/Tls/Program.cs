using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.http2;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http2-tls - HTTP/2 over TLS, negotiated by ALPN, alongside HTTP/1.1 on the SAME port. This
//  is what a browser expects: it offers "h2,http/1.1" and the server chooses.
//
//  Note what Http2Connection is handed: a TlsConnectionDualPipe. It never learns that TLS is
//  involved - the pipe decrypts on the way in and encrypts on the way out - so the protocol
//  code here is byte-for-byte the h2c sample's.
//
//      dotnet run -c Release --project Playground/Http2/Tls
//      curl -k --http2 https://127.0.0.1:8443/          # negotiates h2
//      curl -k --http1.1 https://127.0.0.1:8443/        # same port, gets http/1.1
//
//  Two things make this work. TlsOptions.Alpn is an ORDERED list, most preferred first, and the
//  server walks it to pick the first entry the client also offered - so the order below is the
//  policy. And TlsSession.NegotiatedAlpn reports what was chosen, which is what lets one handler
//  run two different protocol loops.
//
//  Note what Http2Connection is handed: a TlsConnectionDualPipe. It never learns that TLS is
//  involved - the pipe decrypts on the way in and encrypts on the way out, so the protocol
//  code is byte-for-byte the same as the h2c sample. Needs: ioxide, ioxide.http2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port      = 8443;                        // https://127.0.0.1:8443/
int    reactors  = Environment.ProcessorCount;  // one ring per reactor, one reactor per core
int    bodyBytes = 2;                           // "ok" - this sample is about ALPN, not throughput

Env.Override(ref port, ref reactors, ref bodyBytes);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;

// Hand OUTBOUND encryption to the kernel: the handler writes plaintext and the kernel makes the
// records. Off by default - OpenSSL both ways is the portable path, and on loopback the kernel
// is not faster. Its real payoff is sendfile and NIC offload, which a benchmark here cannot see.
bool kernelTx = false;

// Hand INBOUND decryption to the kernel as well. Requires kernelTx - the RX handoff happens at
// the same moment as the TX one - and is experimental for a reason: a TLS 1.3 KeyUpdate cannot be
// read through IORING_OP_RECV, and roughly one first connection in twelve fails outright.
bool kernelRx = false;

Env.OverrideKtls(ref kernelTx, ref kernelRx);

// Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring per reactor. The
// handler code is identical either way; this only changes how recv buffers are handed out.
bool incrementalBuffers = false;

Env.OverrideIncremental(ref incrementalBuffers);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,                                              // io_uring rings/threads - one per core
    RingEntries    = 8192,                                                  // SQ/CQ depth per ring
    DualStack      = false,                                                 // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                                             // bytes per shared recv buffer
    RecvSlots      = 4096,                                                  // shared recv buffer-ring depth
    Incremental    = incrementalBuffers ? new IncrementalOptions { MaxConnections = 1024, RecvSlots = 8, RecvBufferSize = 16 * 1024 } : null,  // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                                  // no raw UDP sockets (TCP-only server)
    Quic           = null,                                                  // no QUIC transport - see Http3/* and Quic/Alpn
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

byte[] body = bodyBytes == 2 ? "ok"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes)];

byte[] http11Response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.OnStart = r => TlsService.Start(r, new TlsOptions
    {
        CertificatePath = certPath,                        // PEM certificate chain file (leaf first)
        CertificatePem  = null,                            // in-memory PEM alternative - set one, not both
        KeyPath         = keyPath,                         // PEM private key file
        KeyPem          = null,                            // in-memory PEM alternative to KeyPath
        Alpn            = ["h2", "http/1.1"],              // ORDERED, most preferred first - a client offering both gets h2
        KernelTx        = kernelTx,                        // kTLS encrypt: kernel makes the records (off = OpenSSL both ways)
        KernelRx        = kernelRx,                        // kTLS decrypt: needs KernelTx; experimental (see the knob above)
    });

    reactor.TcpHandle = async (r, conn) =>
    {
        TlsSession? tls = null;
        try
        {
            tls = await r.GetService<TlsService>()!.AcceptAsync(conn);

            if (tls.NegotiatedAlpn == "h2")
            {
                // The decrypt lives in the pipe, so the HTTP/2 code below is identical to the
                // cleartext sample. Which halves the pipe uses is decided by what the handshake
                // achieved, not by anything chosen here.
                await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);

                await new Http2Connection(pipe).RunBufferedAsync(_ => new Http2Response
                {
                    Status = 200,
                    Body = body,
                });
                return;
            }

            // Anything else: HTTP/1.1 on the same port.
            //
            // The carry is not incidental. TLS hands back RECORDS, not requests, so a request
            // split across two records decrypts twice - and answering on "plaintext arrived"
            // would answer twice to one request. Framing is ours; ioxide does not parse HTTP.
            var carry = new Carry();

            // The client's first request usually rides in with its Finished flight, so the
            // handshake already decrypted it and it is sitting in the session, not in any recv
            // buffer. Miss this and that request is dropped and the loop parks on bytes that
            // already arrived - which is exactly what happened here before.
            carry.Append(tls.DrainPlaintext());

            while (true)
            {
                bool wrote = false;
                int end;
                while ((end = carry.Span.IndexOf("\r\n\r\n"u8)) >= 0)
                {
                    carry.Consume(end + 4);
                    // Correct whichever backend the session ended up with.
                    tls.Write(conn, http11Response);
                    wrote = true;
                }

                if (wrote)
                {
                    await conn.FlushAsync();
                }

                RecvSnapshot snapshot = await conn.ReadAsync();

                unsafe
                {
                    while (conn.TryGetItem(snapshot, out ioxide.utils.SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            carry.Append(tls.Decrypt(item.Ptr, item.Len));
                            conn.ReturnBuffer(in item);
                        }
                    }
                }

                if (snapshot.IsClosed || tls.Closed) return;
                conn.ResetRead();
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[http2-tls] connection failed: {e.Message}");
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

Console.WriteLine($"[http2-tls] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"ALPN h2 then http/1.1, cert {certPath}, "
                + $"rx={(kernelTx && kernelRx ? "kernel" : "openssl")}, "
                + $"tx={(kernelTx ? "kernel" : "openssl")}");

foreach (Thread thread in threads)
{
    thread.Join();
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
