using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ioxide;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

// A minimal ASP.NET Core app that runs on either the ioxide io_uring transport or Kestrel's stock
// sockets transport. Pick with the TRANSPORT environment variable (default: ioxide):
//
//   TRANSPORT=ioxide  dotnet run     # ioxide.Kestrel transport (io_uring, one reactor per core)
//   TRANSPORT=sockets dotnet run     # stock Kestrel sockets transport (the framework default)
//   TRANSPORT=h3      dotnet run     # stock Kestrel + HTTP/3 over msquic on udp :8443 - the
//                                    # ASP.NET twin of the ioxide `quic-h3` example, same port,
//                                    # for side-by-side h2load/h3x runs. Needs libmsquic
//                                    # (sudo apt install libmsquic). TLS is mandatory for h3,
//                                    # so the endpoint rides a self-signed localhost cert.
//
// Then: curl http://localhost:8080/  and  curl http://localhost:8080/plaintext
// h3:   curl --http3-only -k https://localhost:8443/plaintext
//       h2load --alpn-list=h3 -n 100000 -c 32 -m 32 https://127.0.0.1:8443/plaintext

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();   // turn off all logging (no per-request info: lines)

var transport = (Environment.GetEnvironmentVariable("TRANSPORT") ?? "ioxide").Trim().ToLowerInvariant();

builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8080));

switch (transport)
{
    case "ioxide":
        builder.WebHost.UseIoxide(o =>
        {
            o.ReactorCount = 16;   // io_uring transport, 16 reactors (one ring per thread)

            // Kestrel times requests itself (KeepAliveTimeout, RequestHeadersTimeout), so ReadTimeoutMs
            // only bounds a client that never closes after Kestrel is done; SendTimeoutMs bounds a
            // response the client stopped reading. 0 = off.
            o.ConfigureServer = c => c with
            {
                Tcp = (c.Tcp ?? new TcpOptions()) with { ReadTimeoutMs = 60_000, SendTimeoutMs = 60_000 },
            };
        });
        break;

    case "sockets":
    case "kestrel":
        // Stock Kestrel sockets transport — the framework default, nothing to wire up.
        break;

    case "h3":
        // HTTP/3 rides Kestrel's msquic multiplexed transport, so this mode is necessarily the
        // stock stack (the ioxide transport is TCP-only). :8443 serves h1+h2 over TCP and h3
        // over UDP on the same port (Alt-Svc advertises the upgrade); :8080 stays plain h1.
        // Don't run this alongside the ioxide quic-h3 example - both bind udp :8443.
        if (!System.Net.Quic.QuicListener.IsSupported)
        {
            Console.Error.WriteLine("[Examples.AspNet] warning: QUIC is not supported on this box " +
                                    "(libmsquic missing? try: sudo apt install libmsquic) - :8443 will serve h1/h2 only");
        }

        builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8443, ep =>
        {
            ep.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
            ep.UseHttps(H3Cert());
        }));
        break;

    default:
        Console.Error.WriteLine($"Unknown TRANSPORT '{transport}'. Use 'ioxide', 'sockets' or 'h3'.");
        return;
}

var app = builder.Build();

app.MapGet("/", () => $"Hello from ioxide.Kestrel! transport={transport}");
app.MapGet("/plaintext", () => "Hello, World!");

Console.WriteLine(transport == "h3"
    ? "[Examples.AspNet] listening on http://localhost:8080 and https://localhost:8443 (h1+h2+h3, msquic)"
    : $"[Examples.AspNet] listening on http://localhost:8080  (transport={transport})");
app.Run();
return;

// Self-signed localhost cert for the h3 endpoint. The PKCS#12 round-trip re-imports the ephemeral
// private key in the shape the TLS stacks (msquic included) accept.
static X509Certificate2 H3Cert()
{
    using var rsa = RSA.Create(2048);
    var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12), null);
}
