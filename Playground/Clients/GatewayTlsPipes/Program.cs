using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  gateway over TLS, through pipes - Clients/Gateway with an https front door, read and written
//  through an IDuplexPipe, and origins of either kind behind it: each origin's options carry a TLS
//  context of their own, or none. Every hop runs on this reactor's ring and resumes inline.
//
//      PLAYGROUND_PORT=8444 dotnet run -c Release --project Playground/Tls/OpenSsl   # "users", https
//      PLAYGROUND_PORT=8082 dotnet run -c Release --project Playground/Tcp/Raw       # "orders", http
//      dotnet run -c Release --project Playground/Clients/GatewayTlsPipes
//      curl -ki https://127.0.0.1:8443/users/42      # x-origin: users
//      curl -ki https://127.0.0.1:8443/orders/7      # x-origin: orders
//
//  Over the pipe the handler sees plaintext requests and writes plaintext responses; which TLS
//  backend encrypts them is the session's business - see Tls/OpenSslPipes. It forwards GETs only;
//  a real gateway parses the whole request and forwards its method, headers and body too.
//
//  Needs: ioxide, ioxide.httpclient
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment; the literal is what
// applies otherwise. Delete those lines when you copy this out and the literals above them are
// the entire configuration.

ushort port     = 8443;                        // https://127.0.0.1:8443/ - what this gateway serves
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// A real PEM pair for the front door, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
Env.OverrideTlsCert(ref certOverride, ref keyOverride);

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

// The origins, matched by path prefix in this order, each with its own options. "users" is https
// by name: the name is resolved off the reactor, sent as SNI and checked against the certificate -
// here the playground's self-signed one, trusted by file rather than the system store. "orders" is
// plain http, by address.
Origin[] origins =
[
    new("users",  "/users/",  new HttpClientOptions { Host = "localhost", Port = 8444, PoolSize = 8 },
        new TlsClientOptions { CaFile = certPath, AlpnProtocols = ["http/1.1"] }),
    new("orders", "/orders/", new HttpClientOptions { Host = "127.0.0.1", Port = 8082, PoolSize = 4 }),
];
// ─────────────────────────────────────────────────────────────────────────────────────────────

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
        RecvQueueEntries = 64,                             // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

var tlsOptions = new TlsOptions
{
    CertificatePath = certPath,                            // PEM chain file (or CertificatePem for in-memory)
    KeyPath         = keyPath,                             // PEM key file (or KeyPem for in-memory)
    Alpn            = ["http/1.1"],                        // the front door speaks one protocol, so it offers one
};

var threads = new Thread[config.ReactorCount];

for (int id = 0; id < threads.Length; id++)
{
    var reactor = new Reactor(id, config);

    reactor.OnStart = r =>
    {
        // Inbound: terminate TLS for clients, on this reactor.
        TlsService.Start(r, tlsOptions);

        // Outbound: a pool per origin, opened on THIS reactor's ring, with a TLS context of its own
        // when the origin is https - one per reactor, shared by that pool's connections. Start also
        // registers each pool as the reactor's HttpClientPool service, every call replacing the
        // last, so the handler finds the pools through Gateway instead.
        r.AddService(new Gateway([.. origins.Select(origin => new Route(origin, HttpClientPool.Start(r,
            origin.Options with { Tls = origin.Tls is null ? null : TlsClientContext.Create(origin.Tls) })))]));
    };

    reactor.TcpHandle = async (r, conn) =>
    {
        Gateway gateway = r.GetService<Gateway>();
        TlsSession? tls = null;

        try
        {
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            // From here down the connection is a pipe: plaintext in, plaintext out.
            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);

            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();

                // TLS hands back RECORDS, so a request head can arrive split across reads. Take one
                // whole head and leave the rest - a pipelined request - for the next read, or examine
                // everything and wait for more.
                if (TryReadHead(read.Buffer, out SequencePosition end, out string? target))
                {
                    pipe.Input.AdvanceTo(end);
                    await ForwardAsync(pipe.Output, gateway, target);
                    continue;
                }

                pipe.Input.AdvanceTo(read.Buffer.Start, read.Buffer.End);

                if (read.IsCompleted || read.IsCanceled)
                {
                    return;
                }
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[gateway-tls-pipes] connection failed: {e.Message}");
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    };

    threads[id] = new Thread(reactor.Run) { Name = $"reactor-{id}" };
    threads[id].Start();
}

Console.WriteLine($"[gateway-tls-pipes] {config.ReactorCount} reactors, https on :{config.Tcp!.Port} -> "
                + string.Join(", ", origins.Select(o => $"{o.Prefix} {(o.Tls is null ? "http" : "https")}://{o.Options.Host}:{o.Options.Port}"))
                + ", a pool each per reactor");

foreach (Thread thread in threads)
{
    thread.Join();
}

// One request out to its origin, one response back through the pipe.
static async ValueTask ForwardAsync(PipeWriter output, Gateway gateway, string? target)
{
    if (target is null)
    {
        output.Write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"u8);
    }
    else if (gateway.Match(target) is not Route route)
    {
        output.Write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"u8);
    }
    else
    {
        try
        {
            // The same call whether the origin is http or https - its pool's options decide.
            using HttpClientResponse response = await route.Pool.GetAsync(target);

            output.Write(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {response.Status} OK\r\nx-origin: {route.Origin.Name}\r\n"
              + $"Content-Length: {response.Body.Length}\r\n\r\n"));
            output.Write(response.Body.Span);   // bytes straight through, no decode
        }
        catch (Exception e)
        {
            // A dead origin - or a certificate that does not check out, since the handshake is
            // part of opening a connection - fails only that origin's routes.
            byte[] message = Encoding.ASCII.GetBytes($"{route.Origin.Name}: {e.Message}");
            output.Write(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {message.Length}\r\n\r\n"));
            output.Write(message);
        }
    }

    await output.FlushAsync();
}

// One whole request head: where it ends, and its target - "GET /users/42?x=1 HTTP/1.1" ->
// "/users/42?x=1", forwarded whole - or null when its first line is not a request. The target is
// cut at that line's first CR or LF, so nothing a client sends can add lines to the request an
// origin sees.
static bool TryReadHead(ReadOnlySequence<byte> buffer, out SequencePosition end, out string? target)
{
    var reader = new SequenceReader<byte>(buffer);
    if (!reader.TryReadTo(out ReadOnlySequence<byte> head, "\r\n\r\n"u8))
    {
        end = default;
        target = null;
        return false;
    }

    end = reader.Position;

    ReadOnlySpan<byte> bytes = head.IsSingleSegment ? head.FirstSpan : head.ToArray();
    int lineEnd = bytes.IndexOfAny((byte)'\r', (byte)'\n');
    ReadOnlySpan<byte> line = lineEnd < 0 ? bytes : bytes[..lineEnd];
    int first = line.IndexOf((byte)' ');
    int last = line.LastIndexOf((byte)' ');
    target = first < 0 || last <= first + 1 || line[first + 1] != (byte)'/' || line.Contains((byte)0)
        ? null
        : Encoding.ASCII.GetString(line[(first + 1)..last]);
    return true;
}

// An origin, the paths sent to it, and its TLS settings when it is https.
record Origin(string Name, string Prefix, HttpClientOptions Options, TlsClientOptions? Tls = null);

// An origin and this reactor's pool for it.
record Route(Origin Origin, HttpClientPool Pool);

// One reactor's routes: the first prefix that matches wins.
sealed class Gateway(Route[] routes)
{
    public Route? Match(string target)
    {
        foreach (Route route in routes)
        {
            if (target.StartsWith(route.Origin.Prefix, StringComparison.Ordinal)) return route;
        }
        return null;
    }
}
