# tests

One project per area, each a plain executable with its own entry point, so a suite can be run on
its own and a failure names the area immediately.

```bash
dotnet build -c Release ioxide.slnx
for s in Unit E2E Http Pg Redis Tls File Chaos; do
  dotnet run --project tests/Ioxide.Tests.$s -c Release --no-build
done
```

| Suite | Covers | Needs |
| --- | --- | --- |
| `Unit` | The pure logic: QUIC demux packet parse, Alt-Svc negotiation parser, shared HTTP message types | nothing |
| `E2E` | Reactor lifecycle, TCP read/write paths, hardening, UDP, **QUIC and HTTP/3 including their TLS** | nothing |
| `Http` | The HTTP client: h1, h2c, h3 and the negotiating layer | h2c tests need an HTTP/2 server |
| `Pg` | The Postgres driver | a postgres |
| `Redis` | The Redis client | a redis |
| `Tls` | **TLS over TCP**: handshake, pipes, mutual TLS, SNI, rotation, posture, PEM formats | the `tls` kernel module for the kTLS cases (`sudo modprobe tls`) |
| `File` | Static assets: cache, ring reads, revalidation | nothing |
| `Chaos` | Malformed and hostile inputs across TCP, TLS, h2c and QUIC/HTTP/3 | nothing |

Anything missing **skips** rather than fails, so every suite is safe to run anywhere.

## Where does my test go?

TLS exists twice, on two deliberately separate stacks, and that is the one question this layout
gets asked most:

| The behaviour is… | Suite | File |
| --- | --- | --- |
| TLS over **TCP** (OpenSSL) | `Ioxide.Tests.Tls` | `MutualTlsTests`, `SniTests`, `RotationTests`, `PostureTests`, `FormatTests`, `TlsPipeTests` |
| TLS over **QUIC** (picotls/ngtcp2) | `Ioxide.Tests.E2E/Protocols` | `QuicMutualTlsTests`, `QuicSniTests`, `QuicRotationTests` |
| The QUIC transport itself, or the shim | `Ioxide.Tests.E2E` | `Core/QuicTests`, `Protocols/QuicEngineTests` |
| HTTP/3 above the transport | `Ioxide.Tests.E2E/Protocols` | `H3Tests` (nghttp3), `Http3Tests` (pure C#) |
| A hostile or malformed input | `Ioxide.Tests.Chaos` | by transport |

The QUIC-side files carry a `Quic` prefix because the concepts collide: a rotation test exists on
both stacks and means different things. Test names carry the stack too (`rotate/quic: …`).

Keep a file to roughly one theme and under ~15 tests. Past that, split by theme rather than
appending - `MutualTlsTests` has separate groups for the decision matrix, for certificates that are
validly signed and must still be refused, and for configuration refusals, and each is a private
`RegisterX` method.

## Writing a test

**Prove it fails first.** A test that has never been seen to fail has not been shown to test
anything. Before committing, break the thing under test - revert the fix, flip the constant, delete
the guard - and confirm the test goes red for the reason it names. This is not a formality: three
tests written during the last review passed against the very defect they were written for, and one
of them asserted something that could never have been true. The commit message should say it was
confirmed both ways.

**Never break the source to prove a test fails.** Reverting a fix to watch a test go red is the
right instinct and the wrong method here: the working tree is shared, and anyone building while it
is broken - CI, another contributor, another reviewer - gets results that are quietly wrong and no
reason to suspect it. Show the test discriminates from inside your own file instead: assert the
*defect's* expectation, confirm it fails against real observed values, then restore the assertion.
Where that is impossible, write the test against the behaviour as it is and say in the commit that
the red-check needs the pre-fix source, describing the exact change. A described red-check is worth
more than one that corrupted somebody else's run.

**A finding without a fix is still worth committing.** Use `runner.Pending`:

```csharp
runner.Pending("tls: a rotation that drops the last host stops serving it", () =>
{
    // …the reproduction…
}, "issue #201 - the table is rebuilt from the new set only");
```

It reports `PEND` while it still fails and keeps the suite green, and it **fails the run the moment
it starts passing**, saying so - at which point the defect is fixed and it becomes an ordinary
`Test()` that can never regress. Do not use it for a test that is merely slow or environment-
dependent; that is what `skip:` is for.

**Assert why, not that.** `Assert.Throws` takes a fragment of the expected message, and refusal
helpers classify the outcome rather than catching `Exception`:

```csharp
Client.TlsOutcome outcome = Client.TryGetTls(port, "/", cert, key);
Assert.True(outcome != Client.TlsOutcome.Served, "…");
```

A bare try/catch is satisfied by the server hanging, by it crashing, by the port being held by
something else, and by the fixture failing to load. Each of those is a green test reporting the
refusal it was looking for while the refusal never happened. `TlsOutcome.TimedOut` is never a
refusal - a server that hangs has refused nothing, and it is holding the connection too.

**Guard against passing vacuously.** If a test can pass because the thing under test never ran,
assert that it ran: a count of observations, a byte count that had to be exceeded, a body that had
to contain a specific name. `TlsPipeTests` requires two reactor-affinity observations before it
trusts an empty drift list; without them, a handler that never ran would pass.

**Pair a negative with a control.** "The server refused X" means little unless something very close
to X is served by the same server. Where the two cannot share a server, put the control next to it
as its own test and say so in the name (`control: …`).

**Never assert on timing or throughput.** A test that fails on a slow machine is a bug in the test.
Bounding an operation with a generous deadline is fine; asserting it was fast is not.

**Name it as a claim.** `area: what is true` - `mtls: an expired client certificate is refused`,
not `TestExpiredCert`. The name is what a failure prints, so it should say what stopped being true.

## The harness

`Ioxide.Tests.Harness` is shared by every suite:

| Type | For |
| --- | --- |
| `Runner` | `Test`, `Pending`, `skip:`, a 120 s per-test watchdog, and the summary. A reactor that dies unobserved fails the run at the end |
| `TestServer` | Starts a real reactor on a unique port. Returns only once `OnStart` has finished, and rethrows what it threw |
| `Client` | Socket-level HTTP and TLS: `GetTls`, `GetTlsClientCert`, `TryGetTls`, raw and fragmented senders |
| `TestCert` | Certificate fixtures, cross-process locked and written atomically |
| `H3TestClient` | A native ngtcp2 + nghttp3 driver. `Alpn` and `ServerName` are settable, for the negative cases |
| `Handlers` | Generic connection handlers, so a test does not hand-roll one to answer 200 |
| `Externals` | Docker sidecars, `curl`, `curl-h3`. Each reports absence rather than failing |

Module-specific handlers live with their suite - `PgHandlers` in the Pg project, not here - so the
harness never references a module it does not need.

### Certificate fixtures

The clean shapes: `Ensure()` (a default server pair), `EnsureNamed(host)` (self-signed, for SNI),
`EnsureMutualTls()` (a CA, a server pair, a client pair, and a client from a CA nobody trusts),
`EnsureNamedFromCa` / `EnsureRenewedFromCa` (validatable by a real client, and a renewal of it).

The awkward ones, which exist because a suite that only ever mints clean certificates cannot tell a
server that checks anything from a server that checks the signature and stops:

```csharp
TestCert.EnsureClientCert(new TestCert.ClientCertSpec
{
    Subject = "CN=expired-alice",
    NotBefore = TimeSpan.FromHours(-23),   // must stay inside the CA's own window
    NotAfter = TimeSpan.FromHours(-1),
});

TestCert.EnsureClientCert(new() { ExtendedKeyUsage = "1.3.6.1.5.5.7.3.1" });   // serverAuth only
TestCert.EnsureClientCert(new() { EllipticCurve = true });                     // an EC key
TestCert.EnsureChainedClientCert();                                            // root -> intermediate -> leaf
TestCert.EnsureServerCert(TestCert.PemShape.Pkcs1Key);                         // and CrlfEndings, Utf8Bom, …
```

Two things learned the hard way, both of which will bite the next person: .NET refuses to issue a
leaf whose `notBefore` precedes its issuer's, so an "expired" fixture has to sit inside the CA's
window; and an EC leaf cannot be signed through `Create(issuer, …)`, because that overload picks
the algorithm from the request's key rather than the issuer's.

Fixtures are cached in `/tmp` across suites and processes, so creation takes a cross-process lock,
writes through a temporary name, and re-mints anything whose validity window has passed. Do not
write to those directories directly from a test; add a fixture instead.
