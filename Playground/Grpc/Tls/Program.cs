using System.Buffers;
using Greet;
using Grpc.Core;
using ioxide;
using ioxide.grpc;
using ioxide.http2;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  grpc-tls - gRPC over TLS, h2 negotiated by ALPN, the way gRPC is usually deployed. The same
//  port answers plain HTTP/2 too: GrpcServices.IsGrpc tells the two kinds of request apart.
//
//      dotnet run -c Release --project Playground/Grpc/Tls
//      grpcurl -insecure -proto Playground/Grpc/Tls/greet.proto \
//        -d '{"name": "ioxide"}' 127.0.0.1:8443 greet.Greeter/SayHello
//      curl -k --http2 https://127.0.0.1:8443/                   # the plain HTTP/2 side
//
//  With no certificate given, a self-signed localhost one is made on first run, which is why the
//  clients above skip verification. A gRPC client offers only h2, so h2 is all ALPN lists.
//  Needs: ioxide, ioxide.http2, ioxide.grpc
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort port     = 8443;
int    reactors = Environment.ProcessorCount;

Env.Override(ref port, ref reactors);

// A real PEM pair, or null to generate a self-signed localhost certificate on first run.
string? certOverride = null;
string? keyOverride  = null;
Env.OverrideTlsCert(ref certOverride, ref keyOverride);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,   // io_uring rings/threads - one per core
    RingEntries    = 8192,       // SQ/CQ depth per ring
    RecvBufferSize = 32 * 1024,  // bytes per shared recv buffer
    RecvSlots      = 4096,       // shared recv buffer-ring depth
    Tcp = new TcpOptions
    {
        Port          = port,
        ReadTimeoutMs = 60_000,  // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs = 60_000,  // close a connection whose flush takes this long to go out; 0 = off
    },
};

var grpc = new GrpcServices().Add(Greeter.BindService, new GreeterService());

// The plain side: one small page, its headers shared by every response.
var pageHeaders = new Http2Response { Status = 200 };
pageHeaders.Headers.Add("content-type"u8.ToArray(), "text/plain"u8.ToArray());
byte[] pageBody = "ioxide: gRPC and plain HTTP/2 on one port\n"u8.ToArray();

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.OnStart = r => TlsService.Start(r, new TlsOptions
    {
        CertificatePath = certPath,   // PEM certificate chain file (leaf first)
        KeyPath         = keyPath,    // PEM private key file
        Alpn            = ["h2"],
    });

    reactor.TcpHandle = async (r, conn) =>
    {
        TlsSession? tls = null;
        try
        {
            tls = await r.GetService<TlsService>()!.AcceptAsync(conn);
            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);

            await new Http2Connection(pipe).RunAsync((request, body, writer) => GrpcServices.IsGrpc(request)
                ? grpc.HandleAsync(request, body, writer)
                : Page(writer));
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[grpc-tls] connection failed: {e.Message}");
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

Console.WriteLine($"[grpc-tls] {config.ReactorCount} reactors on :{config.Tcp!.Port}, greet.Greeter and a page over h2, cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}

// Not gRPC: the page, and the connection ends the stream.
async ValueTask Page(Http2ResponseWriter writer)
{
    writer.WriteHeaders(pageHeaders);
    writer.Write(pageBody);
    await writer.FlushAsync();
}

sealed class GreeterService : Greeter.GreeterBase
{
    public override Task<HelloReply> SayHello(HelloRequest request, ServerCallContext context)
        => Task.FromResult(new HelloReply { Message = $"Hello, {request.Name}" });
}
