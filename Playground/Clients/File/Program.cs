using System.Buffers.Text;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.file;
using ioxide.tls;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  file - a static file server. ioxide.file opens every file under the root ONCE and shares the
//  descriptors across all reactors - stable and read positionally off the ring, so nothing is
//  locked and nothing is cached in memory. This sample frames HTTP/1.1 around the bytes; the same
//  file data can be handed to any protocol.
//
//  Two ways to move the bytes, selected by PLAYGROUND_FILE_BUFFERED:
//    - default: conn.ReadFileAsync reads the file STRAIGHT INTO the write slab, so the header and
//      body leave in a single flush - no intermediate buffer, no copy.
//    - buffered (=1): read into a reader buffer first, then copy those bytes into the slab.
//
//  PLAYGROUND_FILE_TLS picks the transport: none, ktls (kernel transmit) or openssl. Which paths
//  are legal follows from ONE question - what is the write slab supposed to contain when it is sent?
//    - none:    the slab IS the wire. Both paths legal.
//    - ktls:    the slab holds PLAINTEXT and the kernel makes the records. Both paths legal, so the
//               file still never gets copied. This is the pairing the sample exists for.
//    - openssl: the slab must hold CIPHERTEXT, so the body has to pass through TlsSession.Write -
//               which needs a source buffer to read from. That buffer IS the copy, so there is no
//               slab path at all and the sample refuses the combination rather than serving
//               cleartext. Choosing this backend is choosing to pay the copy.
//
//  Descriptors are trusted for the snapshot's lifetime - a deploy is picked up by reloading the
//  snapshot (SIGHUP), which reopens the files, not by re-stat'ing every request.
//
//      PLAYGROUND_DIR=/srv/www dotnet run -c Release --project Playground/Clients/File
//      curl http://127.0.0.1:8080/index.html
//      PLAYGROUND_FILE_BUFFERED=1 dotnet run ...   # buffer path instead of the slab
//      sudo modprobe tls && PLAYGROUND_FILE_TLS=ktls dotnet run ...  # then curl -k https://:8443/
//      kill -HUP <pid>        # reload the snapshot after a deploy
//
//  Needs: ioxide, ioxide.file
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/file-matrix.sh can drive the sample from outside; delete
// those lines when you copy this out and the literals above them are the entire configuration.

string dir = "/tmp/ioxide-assets";   // served root, walked once into a snapshot

// Which transport terminates here. This is what decides whether the slab path below is legal
// at all - see the header. none | ktls | openssl
string tlsMode = "none";

// Read the file into a pooled buffer and copy it into the slab, instead of reading it straight
// into the slab. Forced for openssl, which cannot use the slab path.
bool buffered = false;

int reactors = Environment.ProcessorCount;   // one ring per reactor, one reactor per core

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;

Env.OverrideFile(ref dir, ref buffered, ref tlsMode);

bool tlsOn = tlsMode is "ktls" or "openssl";
bool ktls  = tlsMode == "ktls";

ushort port = tlsOn ? (ushort)8443 : (ushort)8080;

Env.Override(ref port, ref reactors);
// ─────────────────────────────────────────────────────────────────────────────────────────────

// The constraint this sample exists to show, enforced instead of described: with OpenSSL owning
// transmit the slab must hold CIPHERTEXT, so a file read straight into it would go out in the
// clear. There is no slab path for that backend - refuse rather than serve cleartext.
if (tlsMode == "openssl" && !buffered)
{
    Console.Error.WriteLine("[file] openssl TLS has no slab path: the slab must hold ciphertext, so "
                          + "the body has to pass through TlsSession.Write. Use "
                          + "PLAYGROUND_FILE_BUFFERED=1, or PLAYGROUND_FILE_TLS=ktls for the slab.");
    Environment.Exit(1);
}

(string certPath, string keyPath) = tlsOn
    ? QuicCert.Ensure(certOverride, keyOverride)
    : (string.Empty, string.Empty);

SampleAssets.Ensure(dir);   // writes a demo index.html + style.css if the directory is empty

// Built once for the whole process, BEFORE the reactors start: every reactor shares this snapshot.
var assets = new StaticAssets(dir);   // served root (PLAYGROUND_DIR), walked once into a snapshot

var config = new ServerConfig
{
    ReactorCount   = reactors,                                                    // io_uring rings/threads - one per core
    RingEntries    = 8192,                                                        // SQ/CQ depth per ring
    DualStack      = false,                                                       // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                                                   // bytes per shared recv buffer
    RecvSlots      = 4096,                                                        // shared recv buffer-ring depth
    Incremental    = null,                                                        // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                                        // no raw UDP sockets (TCP-only server)
    Quic           = null,                                                        // no QUIC transport - see Http3/* and Quic/Alpn
    Tcp = new TcpOptions
    {
        Port             = port,                                                  // 8080 cleartext, 8443 with TLS
        ExtraPorts       = [],                                                    // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                                                  // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                                             // per-connection write buffer; ReadFileAsync grows it to fit a bigger file
        PoolMax          = 1024,                                                  // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,                            // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                                                 // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 4096,                                                  // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                                                // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                                                // close a connection whose flush takes this long to go out; 0 = off
    },
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.OnStart = r =>
    {
        r.AddService(assets);   // the shared snapshot
        // The buffer path needs a pool of native read buffers; the slab path reads into the
        // connection's own write slab and needs none, but registering it is harmless either way.
        AssetReader.CreatePool(r,
            readers:     4,         // concurrent ring reads bounded per reactor (pool size)
            bufferBytes: 1 << 20);  // native read buffer per reader (1 MiB) - size for the largest asset

        if (tlsOn)
        {
            TlsService.Start(r, new TlsOptions
            {
                CertificatePath = certPath,
                KeyPath         = keyPath,

                // The whole point: with transmit in the kernel the slab carries PLAINTEXT and the
                // kernel makes the records, so ReadFileAsync may still read the file straight into
                // it. With this false, OpenSSL encrypts and the slab must hold ciphertext - which
                // is why the slab path is refused above. Receive is OpenSSL either way.
                KernelTx = ktls,
            });
        }
    };

    reactor.TcpHandle = async (r, conn) =>
    {
        StaticAssets snapshot = r.GetService<StaticAssets>();
        RingPool<AssetReader> readers = r.GetService<RingPool<AssetReader>>();
        TlsSession? tls = null;

        // Request bytes waiting to be framed. Both transports go through this, so the two differ
        // only in how bytes get IN - otherwise the plaintext arm would answer once per recv batch
        // and the TLS arm once per record, and the two would not be comparable.
        var carry = new Carry();

        try
        {
            if (tlsOn)
            {
                tls = await r.GetService<TlsService>().AcceptAsync(conn);

                // A request can ride in with the handshake's final flight; serve it before parking
                // in ReadAsync or the client waits on a response that never comes.
                carry.Append(tls.DrainPlaintext());
                await ServeAsync(conn, tls, carry, snapshot, readers, buffered);
            }

            while (true)
            {
                RecvSnapshot recv = await conn.ReadAsync();

                while (conn.TryGetItem(recv, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        Append(tls, in item, carry);
                        conn.ReturnBuffer(in item);
                    }
                }

                await ServeAsync(conn, tls, carry, snapshot, readers, buffered);

                if (recv.IsClosed || (tls?.Closed ?? false)) return;
                conn.ResetRead();
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[file] connection failed: {e.Message}");
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

// Reload on SIGHUP (kill -HUP <pid>): a fresh snapshot is opened and swapped in atomically, and the
// old descriptors close after a grace period - so in-flight requests finish on the bytes they
// started with.
using var reload = PosixSignalRegistration.Create(PosixSignal.SIGHUP, context =>
{
    context.Cancel = true;   // handle it; don't let the default action terminate us
    assets.Reload();
    Console.WriteLine($"[file] reloaded - now serving {assets.Count} files");
});

Console.WriteLine($"[file] {config.ReactorCount} reactors on :{config.Tcp.Port} - "
                + $"{assets.Count} files under {assets.RootDir} "
                + $"({(buffered ? "buffer path" : "slab path")}, "
                + $"tls={tlsMode}, nothing cached)");

foreach (Thread thread in threads)
{
    thread.Join();
}

// Bytes in. Cleartext appends the ring buffer as-is; TLS decrypts it first. Decrypt takes a raw
// pointer because the buffer belongs to the ring, and the pointer work has to stay out of the
// async handler, which cannot contain unsafe code.
static unsafe void Append(TlsSession? tls, in SpscRecvRing.Item item, Carry carry)
    => carry.Append(tls is null ? item.AsSpan() : tls.Decrypt(item.Ptr, item.Len));

// One response per COMPLETE request in the carry, none for a partial one. Under kTLS the response
// bytes go into the slab as plaintext and the kernel encrypts them on send, so both the slab and
// buffer paths below are written exactly as they are for cleartext.
static async Task ServeAsync(TcpConnection conn, TlsSession? tls, Carry carry, StaticAssets snapshot,
    RingPool<AssetReader> readers, bool buffered)
{
    int end;
    while ((end = carry.Span.IndexOf("\r\n\r\n"u8)) >= 0)
    {
        bool found = false;
        AssetCache.Asset asset = default;

        // The lease pins the snapshot for the request, so a concurrent Reload() cannot close the
        // fd out from under an in-flight read.
        using (StaticAssets.Lease lease = snapshot.Acquire())
        {
            if (TryReadTarget(carry.Span[..end], out ReadOnlySpan<byte> target))
            {
                found = lease.TryGet(target, out asset);
            }

            carry.Consume(end + 4);

            if (found)
            {
                if (buffered)
                {
                    await SendBufferedAsync(conn, tls, readers, asset);
                }
                else
                {
                    await SendSlabAsync(conn, tls, asset);
                }
            }
        }

        if (!found)
        {
            Emit(conn, tls, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"u8);
            await conn.FlushAsync();
        }
    }
}


// Cleartext fast path: read the whole file STRAIGHT INTO the write slab (it grows to fit), right
// after the header, so header + body leave in one flush - no reader buffer, no copy. Ideal for the
// typical multi-KB web asset; a very large file grows the slab by its full size, so stream those
// with the buffer path instead.
static async Task SendSlabAsync(TcpConnection conn, TlsSession? tls, AssetCache.Asset asset)
{
    Span<byte> header = stackalloc byte[256];
    Emit(conn, tls, header[..WriteHeader(header, asset.Path, asset.Length)]);

    // io_uring positional read into the slab at the current tail; AdvanceWrite commits the bytes.
    int n = await conn.ReadFileAsync(asset.Fd, (int)asset.Length, fileOffset: 0);
    conn.AdvanceWrite(n);
    await conn.FlushAsync();
}

// Buffer path: read into a reader buffer, then move those bytes on. The copy into the slab stands in
// for the transform a TLS connection does here instead - tls.Write(conn, reader.Buffer[..n]), which
// encrypts into the slab. Files bigger than the buffer take several reads at advancing offsets,
// one flush each.
static async Task SendBufferedAsync(TcpConnection conn, TlsSession? tls, RingPool<AssetReader> readers, AssetCache.Asset asset)
{
    AssetReader reader = await readers.RentAsync();
    try
    {
        int first = await reader.ReadAsync(asset.Fd, offset: 0);   // io_uring positional read
        if (first < 0)
        {
            Emit(conn, tls, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"u8);
            await conn.FlushAsync();
            return;
        }

        // Header + first chunk go out together in one flush.
        Span<byte> header = stackalloc byte[256];
        Emit(conn, tls, header[..WriteHeader(header, asset.Path, asset.Length)]);
        WriteNative(conn, tls, reader.Buffer, first);
        await conn.FlushAsync();

        long offset = first;
        while (offset < asset.Length)
        {
            int read = await reader.ReadAsync(asset.Fd, offset);
            if (read <= 0) break;   // EOF or mid-stream error; the response is already committed
            WriteNative(conn, tls, reader.Buffer, read);
            await conn.FlushAsync();
            offset += read;
        }
    }
    finally
    {
        readers.Return(reader);
    }
}

// Copy native memory (a ring-read buffer) into the connection's write slab in one go.
static unsafe void WriteNative(TcpConnection conn, TlsSession? tls, nint data, int length)
    => Emit(conn, tls, new ReadOnlySpan<byte>((void*)data, length));

// Every response byte goes through here. TlsSession.Write is correct under BOTH backends - it
// writes plaintext to the slab when the kernel encrypts, and encrypts into the slab when OpenSSL
// does - so no call site has to know which one is in play. A bare conn.Write would be right only
// for cleartext and kTLS, and silently wrong for OpenSSL.
static void Emit(TcpConnection conn, TlsSession? tls, ReadOnlySpan<byte> bytes)
{
    if (tls is null) conn.Write(bytes);
    else             tls.Write(conn, bytes);
}

// Write the 200 status line + Content-Type + Content-Length for this file.
static int WriteHeader(Span<byte> destination, string path, long bodyLength)
{
    int h = 0;
    h += Copy(destination[h..], "HTTP/1.1 200 OK\r\nContent-Type: "u8);
    h += Copy(destination[h..], MimeFor(path));
    h += Copy(destination[h..], "\r\nContent-Length: "u8);
    Utf8Formatter.TryFormat(bodyLength, destination[h..], out int digits);
    h += digits;
    h += Copy(destination[h..], "\r\n\r\n"u8);
    return h;
}

static int Copy(Span<byte> destination, ReadOnlySpan<byte> source)
{
    source.CopyTo(destination);
    return source.Length;
}

static ReadOnlySpan<byte> MimeFor(string path) => Path.GetExtension(path) switch
{
    ".html"  => "text/html"u8,
    ".css"   => "text/css"u8,
    ".js"    => "application/javascript"u8,
    ".json"  => "application/json"u8,
    ".svg"   => "image/svg+xml"u8,
    ".png"   => "image/png"u8,
    ".webp"  => "image/webp"u8,
    ".woff2" => "font/woff2"u8,
    ".txt"   => "text/plain"u8,
    _        => "application/octet-stream"u8
};

static bool TryReadTarget(ReadOnlySpan<byte> request, out ReadOnlySpan<byte> target)
{
    target = default;

    int firstSpace = request.IndexOf((byte)' ');
    if (firstSpace < 0) return false;

    ReadOnlySpan<byte> afterMethod = request[(firstSpace + 1)..];
    int secondSpace = afterMethod.IndexOf((byte)' ');
    if (secondSpace < 0) return false;

    target = afterMethod[..secondSpace];

    int query = target.IndexOf((byte)'?');
    if (query >= 0) target = target[..query];

    return true;
}

// Plaintext waiting to be framed into requests. TLS hands back records, not requests: a request
// split across two records decrypts as two pieces, so answering per decrypt answers twice.
sealed class Carry
{
    private byte[] _buffer = new byte[8192];
    private int _length;

    public ReadOnlySpan<byte> Span => _buffer.AsSpan(0, _length);

    public void Append(ReadOnlySpan<byte> more)
    {
        if (more.IsEmpty) return;

        if (_length + more.Length > _buffer.Length)
        {
            Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, _length + more.Length));
        }

        more.CopyTo(_buffer.AsSpan(_length));
        _length += more.Length;
    }

    public void Consume(int count)
    {
        _buffer.AsSpan(count, _length - count).CopyTo(_buffer);
        _length -= count;
    }
}
