# ioxide

[![nuget](https://img.shields.io/nuget/v/ioxide?label=nuget&color=blue)](https://www.nuget.org/packages/ioxide/)
[![HTTP Arena](https://img.shields.io/endpoint?url=https://www.http-arena.com/badge/genhttp-ioxide/h1.json)](https://www.http-arena.com/#sort=rps:-1)
[![net](https://img.shields.io/badge/.NET-10%20%7C%2011-blue)](https://dotnet.microsoft.com/)
[![linux](https://img.shields.io/badge/linux-6.1%2B-blue)](https://kernel.org/)

**A shared-nothing io_uring runtime for .NET.**

One ring per reactor thread, one reactor per core. Each reactor owns its ring, its SO_REUSEPORT
listener, its connections and its clients outright, so nothing is shared and nothing is locked - a
request never leaves the core it arrived on, inbound and outbound alike. What makes that practical
in .NET is that you do not give up the platform's async model to get it: handlers are ordinary
`async Task` code, ring completions resume their continuations **inline on the reactor thread**, and
a per-reactor `SynchronizationContext` catches everything that would otherwise escape - timers,
`HttpClient`, `Task.Run`. You always wake up on your reactor, so connection, pool and handler state
stays single-threaded without a lock in sight.

ioxide hands you raw bytes and stays out of HTTP; when you want a framework on top,
`ioxide.Kestrel` swaps the transport under an existing ASP.NET Core app with your endpoints
unchanged.

> Linux 6.1+ · .NET 10 / .NET 11 · experimental

**[Documentation](https://mda2av.github.io/ioxide/)** - architecture, guides, and every example as
runnable code side by side.

## Packages

Every package shares one version and depends only on the runtime. Start with
**[`ioxide`](https://www.nuget.org/packages/ioxide/)** - reactors, TCP/UDP transports, connections,
the ring-native client seam, and TLS termination (OpenSSL handshake over the ring, then kTLS, so
handlers keep writing plaintext) - then add exactly what you use.

**Protocols.** HTTP/2 and HTTP/3 each come twice: a bundled native, or the same surface in pure C#.

| Package | What it does |
| --- | --- |
| [`ioxide.ngtcp2`](https://www.nuget.org/packages/ioxide.ngtcp2/) | QUIC. ngtcp2 + picotls as one bundled native; only system dependency is OpenSSL 3. |
| [`ioxide.nghttp3`](https://www.nuget.org/packages/ioxide.nghttp3/) | HTTP/3 + QPACK (nghttp3), bundled native. Rides any QUIC connection. |
| [`ioxide.http3`](https://www.nuget.org/packages/ioxide.http3/) | HTTP/3 in pure C# - frames, QPACK, Huffman. Zero native code, drop-in for `ioxide.nghttp3`. |
| [`ioxide.nghttp2`](https://www.nuget.org/packages/ioxide.nghttp2/) | HTTP/2 (nghttp2), bundled native. h2c, or h2 over TLS via ALPN. |
| [`ioxide.http2`](https://www.nuget.org/packages/ioxide.http2/) | HTTP/2 in pure C# - framing, HPACK, flow control. Zero native code, drop-in for `ioxide.nghttp2`. |

**Clients.** One pool per reactor, opened on the reactor thread, so every call rides the ring that
accepted the request.

| Package | What it does |
| --- | --- |
| [`ioxide.httpclient`](https://www.nuget.org/packages/ioxide.httpclient/) | The HTTP/1.1 upstream leg between a proxy and an origin, with client-side TLS and mutual TLS for `https://`. |
| [`ioxide.pg`](https://www.nuget.org/packages/ioxide.pg/) | Postgres. Connect, query and stream rows on the owning ring. |
| [`ioxide.redis`](https://www.nuget.org/packages/ioxide.redis/) | Redis. RESP2, pipelining, pub/sub. |
| [`ioxide.file`](https://www.nuget.org/packages/ioxide.file/) | Static assets. Immutable snapshots, baked responses, positional ring reads. |
| [`ioxide.timer`](https://www.nuget.org/packages/ioxide.timer/) | Deadlines. A wait is one `IORING_OP_TIMEOUT` on the caller's own ring - no timer thread, nothing allocated per wait. |

**Serving.**

| Package | What it does |
| --- | --- |
| [`ioxide.Kestrel`](https://www.nuget.org/packages/ioxide.Kestrel/) | ASP.NET Core transport: `UseIoxide()` and Kestrel runs one ring per core, its request loop pinned to the reactor thread. |

## Where the code is

Nothing here is pseudocode. Every pattern above exists as something you can run:

| | What you get |
| --- | --- |
| **[Documentation](https://mda2av.github.io/ioxide/)** | The examples browser - TCP with and without kTLS, HTTP/2, QUIC, HTTP/3, every client, and all nine proxy combinations, side by side. |
| **[Playground](Playground/)** | One project per workload, grouped by topic. Each `Program.cs` is a **complete** server - config, reactors, threads, handler - so you can copy the file out and run it. |
| **[Playground/AspNet](Playground/AspNet/)** | `UseIoxide()` measured against a stock Kestrel baseline. |
