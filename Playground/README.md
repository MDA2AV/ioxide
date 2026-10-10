# Playground

One project per sample, and **each `Program.cs` is a complete ioxide server you can copy out and
run**. The config, the reactors, the threads, the connection loop and the handler are all there in
the file - nothing that touches an ioxide API is hidden behind a helper.

```bash
dotnet run -c Release --project Playground/Tcp/Raw
curl http://127.0.0.1:8080/
```

Linux only - the engine is io_uring. Every sample takes its configuration from plain literals at
the top of the file under a `Knobs` banner: edit them, or leave them alone and the sample runs.
The `Env.Override` line beneath them exists only so `bench/` can drive the sample from outside;
delete it when you copy the file out and the literals are the whole configuration.

## Start here

| Project | Lines | Shows | Packages |
| --- | --- | --- | --- |
| [`Tcp.Raw`](Tcp/Raw/Program.cs) | 121 | The whole shape: `ServerConfig`, a reactor per core, the read/respond/`DecRef` loop. Start here. | `ioxide` |
| [`Tcp.Pipe`](Tcp/Pipe/Program.cs) | 116 | The same server through `PipeReader`/`PipeWriter`, if your code already speaks Pipelines. Run it against `Tcp/Raw` to price the adapter. | `ioxide` |
| [`Tcp.Incremental`](Tcp/Incremental/Program.cs) | 130 | `Tcp/Raw` with the per-connection buffer-ring mode - one config block is the whole diff. Kernel 6.12+. | `ioxide` |
| [`Tcp.Big`](Tcp/Big/Program.cs) | 120 | The write path under a 100 KB body: `SEND_ZC`, slab overflow (`Grow` vs `Segmented`), and a checksum that must not move. | `ioxide` |
| [`Tcp.Hop`](Tcp/Hop/Program.cs) | 101 | Leaving the reactor on purpose (`Task.Yield`) and coming back - what it costs. | `ioxide` |
| [`Tcp.TaskRun`](Tcp/TaskRun/Program.cs) | 109 | Awaiting ordinary thread-pool work and still resuming on the reactor. | `ioxide` |

## Certificates

The samples that are about the certificate rather than about the transport. TLS exists twice in
ioxide and they are not one stack with two doors: on TCP, OpenSSL terminates **above** the
transport and each reactor owns its own `TlsService`; on QUIC, TLS 1.3 lives **inside** the
transport (picotls, bundled with ngtcp2) and one `QuicEngine` is shared by every reactor. The same
feature therefore reads differently on each side, which is why each has its own sample.

| | h1 (TCP) | h2 (TCP) | h3 (QUIC) |
| --- | --- | --- | --- |
| **A certificate per host name (SNI)** | [`Tls/Sni`](Tls/Sni/Program.cs) | [`Http2/Sni`](Http2/Sni/Program.cs) | [`Http3/Sni`](Http3/Sni/Program.cs) |
| **Renewal on a running server** | see `Http2/Rotate` | [`Http2/Rotate`](Http2/Rotate/Program.cs) | [`Http3/Rotate`](Http3/Rotate/Program.cs) |
| **The client proves who it is (mTLS)** | [`Tls/MtlsOpenSslPipes`](Tls/MtlsOpenSslPipes/Program.cs), [`Tls/MtlsKtlsPipes`](Tls/MtlsKtlsPipes/Program.cs) | see `Tls/Mtls*` | [`Http3/MutualTls`](Http3/MutualTls/Program.cs) |

ioxide ships no HTTP/1.1 library - `Tcp/Raw` and the TLS samples frame h1 by hand, in a few lines,
because that is all it takes. So the h1 column is not a different mechanism: it is the same TCP
socket with the same TLS on top of it, with a hand-rolled loop where the h2 samples construct an
`Http2Connection`. `Http2/Rotate`'s certificate handling is the h1 rotation verbatim; only the
loop above it differs.

Both rotation samples rotate on **SIGHUP** - what an ACME hook sends after rewriting the PEM - and
also on a timer so a plain `dotnet run` shows the feature. Each alternates between two
certificates for the same names, so you can pin one with `curl --cacert` and watch which one the
server answers with. A rotation you cannot prove from outside is a rotation you have to take on
trust.

## TLS over TCP

The certificate is terminated above the transport, by OpenSSL or by the kernel. All of these serve
HTTP/1.1 framed by hand.

| Project | Lines | Shows | Packages |
| --- | --- | --- | --- |
| [`Tls.OpenSsl`](Tls/OpenSsl/Program.cs) | 243 | **The default**: OpenSSL both ways - no kernel module, and TLS 1.2 / any suite / resumption. | `ioxide` |
| [`Tls.KtlsTx`](Tls/KtlsTx/Program.cs) | 225 | The deployable kernel mode: kernel TX (the handler writes plaintext), OpenSSL RX. `Tls/Ktls` minus one line. `modprobe tls`. | `ioxide` |
| [`Tls.Ktls`](Tls/Ktls/Program.cs) | 225 | **Full kernel TLS** - both directions in the kernel. Experimental: a TLS 1.3 KeyUpdate cannot be read through `IORING_OP_RECV`. | `ioxide` |
| [`Tls.OpenSslPipes`](Tls/OpenSslPipes/Program.cs) | 186 | The default backend through an `IDuplexPipe`. | `ioxide` |
| [`Tls.KtlsPipes`](Tls/KtlsPipes/Program.cs) | 184 | Full kTLS through an `IDuplexPipe`. Its serve loop is byte-identical to `Tls/OpenSslPipes` - over a pipe the backend is invisible. | `ioxide` |
| [`Tls.SslStream`](Tls/SslStream/Program.cs) | 127 | The BCL `SslStream` over `TcpConnectionStream` - portable userspace TLS, the comparison point. | `ioxide` |
| [`Tls.MultiPort`](Tls/MultiPort/Program.cs) | 176 | Plaintext on `:8080`, TLS on `:8081`, ONE pipe serve loop for both doors - multi-port made concrete. | `ioxide` |
| [`Tls.Sni`](Tls/Sni/Program.cs) | 170 | One port, several hosts, a certificate each, chosen by the name in the handshake. | `ioxide` |
| [`Tls.MtlsOpenSslPipes`](Tls/MtlsOpenSslPipes/Program.cs) | 219 | The client presents a certificate too, and the handler is told which peer it got. | `ioxide` |
| [`Tls.MtlsKtlsPipes`](Tls/MtlsKtlsPipes/Program.cs) | 226 | The same mutual TLS with the kernel encrypting outbound records. | `ioxide` |

## HTTP/2

Two interchangeable stacks: `ioxide.http2` is pure C# (framing, HPACK, flow control), `ioxide.nghttp2`
binds the reference implementation. A sample named `Managed*` uses the first, `Nghttp2*` the second;
the handler code is the same either way.

| Project | Lines | Shows | Packages |
| --- | --- | --- | --- |
| [`Http2.ManagedBuffered`](Http2/ManagedBuffered/Program.cs) | 98 | h2c with **zero native code** - framing, HPACK and flow control in C#. The one to read first. | `ioxide.http2` |
| [`Http2.Nghttp2Buffered`](Http2/Nghttp2Buffered/Program.cs) | 98 | The same server on nghttp2. Drop-in for the above, and the parity check for it. | `ioxide.nghttp2` |
| [`Http2.ManagedStreamedRequest`](Http2/ManagedStreamedRequest/Program.cs) | 121 | The request body arrives a chunk at a time: the handler runs once the headers are in, while the upload is still coming. | `ioxide.http2` |
| [`Http2.ManagedStreamedResponse`](Http2/ManagedStreamedResponse/Program.cs) | 128 | The response body pushed as it is produced - each flush becomes a DATA frame. | `ioxide.http2` |
| [`Http2.ManagedStreamedBoth`](Http2/ManagedStreamedBoth/Program.cs) | 136 | Both directions streamed in one handler. | `ioxide.http2` |
| [`Http2.Nghttp2Response`](Http2/Nghttp2Response/Program.cs) | 105 | The streamed response on the reference implementation. | `ioxide.nghttp2` |
| [`Http2.Nghttp2StreamedRequest`](Http2/Nghttp2StreamedRequest/Program.cs) | 119 | The streamed request body on the reference implementation. | `ioxide.nghttp2` |
| [`Http2.Tls`](Http2/Tls/Program.cs) | 234 | h2 **and** http/1.1 on one port, chosen by ALPN. The HTTP/2 code is unchanged - only the pipe differs. | `ioxide.http2` |
| [`Http2.Sni`](Http2/Sni/Program.cs) | 167 | A certificate per host name under h2, and why the handshake name and `:authority` are not the same question. | `ioxide.http2` |
| [`Http2.Rotate`](Http2/Rotate/Program.cs) | 247 | Renewing a certificate on a running server: one `TlsService` per reactor, so every one of them has to be rotated. | `ioxide.http2` |
| [`Http2.SslStream`](Http2/SslStream/Program.cs) | 127 | The same HTTP/2 over the BCL `SslStream`, via a ten-line `Stream`-to-`IDuplexPipe` adapter. | `ioxide.http2` |

## HTTP/3

The same split: `ioxide.http3` is pure C# above the QUIC transport, `ioxide.nghttp3` binds the
reference implementation. QUIC itself is always ngtcp2 + picotls, bundled as one native library.

| Project | Lines | Shows | Packages |
| --- | --- | --- | --- |
| [`Http3.ManagedBuffered`](Http3/ManagedBuffered/Program.cs) | 89 | HTTP/3 in **pure C#** - frames, QPACK and Huffman all managed. Nothing native ships but the transport. | `ioxide.ngtcp2`, `ioxide.http3` |
| [`Http3.ManagedStreamedBoth`](Http3/ManagedStreamedBoth/Program.cs) | 166 | The same, with the request pulled and the response pushed a chunk at a time under flow control. | `ioxide.ngtcp2`, `ioxide.http3` |
| [`Http3.Nghttp3Request`](Http3/Nghttp3Request/Program.cs) | 220 | HTTP/3 on nghttp3 with **streamed** dispatch, and a `SIGTERM` GOAWAY drain. | `ioxide.ngtcp2`, `ioxide.nghttp3` |
| [`Http3.Nghttp3Buffered`](Http3/Nghttp3Buffered/Program.cs) | 205 | The same server with **buffered** dispatch - one method call is the whole difference. | `ioxide.ngtcp2`, `ioxide.nghttp3` |
| [`Http3.Nghttp3Response`](Http3/Nghttp3Response/Program.cs) | 120 | The other direction: a response body produced over time. | `ioxide.ngtcp2`, `ioxide.nghttp3` |
| [`Http3.Nghttp3StreamedBoth`](Http3/Nghttp3StreamedBoth/Program.cs) | 190 | Both directions at once on nghttp3 - `/echo` reads a chunk and writes a chunk. The fourth corner the other three leave empty. | `ioxide.ngtcp2`, `ioxide.nghttp3` |
| [`Http3.Sni`](Http3/Sni/Program.cs) | 118 | A certificate per host name on QUIC, registered before the engine starts serving. | `ioxide.ngtcp2`, `ioxide.http3` |
| [`Http3.Rotate`](Http3/Rotate/Program.cs) | 195 | Renewal on QUIC: one shared engine, so a single call covers every reactor - the contrast with `Http2/Rotate`. | `ioxide.ngtcp2`, `ioxide.http3` |
| [`Http3.MutualTls`](Http3/MutualTls/Program.cs) | 122 | The client proves who it is during the QUIC handshake, and the handler is told which peer it got. | `ioxide.ngtcp2`, `ioxide.http3` |

## QUIC, below HTTP

| Project | Lines | Shows | Packages |
| --- | --- | --- | --- |
| [`Quic.Raw`](Quic/Raw/Program.cs) | 113 | EVERY stream on the connection, each delivery carrying its stream id - the surface `ioxide.nghttp3` sits on. | `ioxide.ngtcp2` |
| [`Quic.Pipe`](Quic/Pipe/Program.cs) | 115 | QUIC behind an `IDuplexPipe`, the transport's twin of `Tcp/Pipe`. No `TlsService`: the certificate IS the configuration. | `ioxide.ngtcp2` |
| [`Quic.Alpn`](Quic/Alpn/Program.cs) | 141 | One QUIC listener, two protocols by ALPN: h3, or raw stream echo over the dual pipe. QUIC-only - `Tcp = null`. | `ioxide.ngtcp2`, `ioxide.nghttp3` |

## Calling out, serving files, proxying

| Project | Lines | Shows | Packages |
| --- | --- | --- | --- |
| [`Clients.Http`](Clients/Http/Program.cs) | 145 | Calling an origin over HTTP/1.1 from inside a handler - both hops on the same ring, resumed inline. | `ioxide.httpclient` |
| [`Clients.Https`](Clients/Https/Program.cs) | 198 | The other direction of ioxide TLS: speaking it outbound to reach an `https://` origin. | `ioxide.httpclient` |
| [`Clients.Quic`](Clients/Quic/Program.cs) | 166 | The client half of QUIC, and the thing that drives `Quic/Raw`. No listener of any kind. | `ioxide.ngtcp2` |
| [`Clients.File`](Clients/File/Program.cs) | 422 | A static file server: every file opened ONCE, descriptors shared across reactors, read positionally off the ring. | `ioxide.file` |
| [`Clients.Pg`](Clients/Pg/Program.cs) | 224 | A Postgres-backed server, whole: a pool per reactor, connect/query/row streaming all ring operations. | `ioxide.pg` |
| [`Clients.Redis`](Clients/Redis/Program.cs) | 236 | A `RedisPool` per reactor; concurrent requests share connections and pipeline automatically. | `ioxide.redis` |
| [`Clients.Timer`](Clients/Timer/Program.cs) | 184 | A deadline that stays on the ring: `GET /<ms>` answers after that long, one `IORING_OP_TIMEOUT` per wait. A knob swaps in `Task.Delay` to price the difference. | `ioxide.timer` |
| [`Proxy.H1ToH1`](Proxy/H1ToH1/Program.cs) | 251 | A reverse proxy with TLS on BOTH hops - ioxide TLS in, `TlsClientContext` out. Read this one first. | `ioxide.httpclient` |
| [`Proxy.H2ToH1`](Proxy/H2ToH1/Program.cs) | 217 | The classic edge: h2 over TLS in (browsers refuse h2c), h1 origin behind. | `ioxide.http2`, `ioxide.httpclient` |
| [`Proxy.H3ToH1`](Proxy/H3ToH1/Program.cs) | 172 | An HTTP/3 front door for an h1 upstream. `Tcp = null`, so every TCP socket the process owns is an outbound one. | `ioxide.ngtcp2`, `ioxide.nghttp3`, `ioxide.httpclient` |
| [`AspNet`](AspNet/Program.cs) | 83 | ASP.NET Core on the ioxide Kestrel transport, or on stock sockets, or on msquic h3 - `TRANSPORT=` picks. | `ioxide.Kestrel` |

The upstream client speaks HTTP/1.1 only, so there is no `Proxy/*ToH2` or `*ToH3`: those samples
existed and were removed when the client became h1-only.

## Certificates the samples use

Nothing here needs a real certificate. `Playground/Shared/QuicCert.cs` mints what is missing into
`/tmp/ioxide-playground-quic/` on first run and reuses it afterwards:

| File | What it is |
| --- | --- |
| `quic.crt` / `quic.key` | the default self-signed `localhost` pair, used by every sample that just needs TLS |
| `sni-<host>.crt` / `.key` | one self-signed pair per name, for the SNI samples (`alpha.test`, `beta.test`) |
| `sni-<host>-renewed.crt` / `.key` | a SECOND pair for the same name - same subject and SAN, new key and serial - which is what a renewal produces, and what the rotation samples flip to |

Each is self-signed, so pinning one with `curl --cacert` accepts exactly that certificate and
refuses the other. That is what makes SNI and rotation observable from outside rather than only
in the server's own log line. Point a sample at real PEM files with `PLAYGROUND_TLS_CERT` and
`PLAYGROUND_TLS_KEY` (or the `certOverride`/`keyOverride` knobs) instead.

## Benchmarks

Every sample is a regression fixture, and `bench/samples.tsv` has a row for each one - what
protocol it speaks, on which port, and what it needs. `bash bench/any.sh --list` prints the
registry and says which ones are runnable on this box; `bash bench/any.sh Tls/OpenSsl` runs one.
Rows marked `none` are samples no load generator here can drive: mutual TLS needs a client
certificate, and neither wrk nor h2load can present one.
