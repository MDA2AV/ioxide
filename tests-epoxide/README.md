# tests-epoxide

epoxide's suites, beside ioxide's in `tests/`. Same shape - one executable per area, a shared
harness - and the same rules: [tests/README.md](../tests/README.md) has them (prove it fails first,
never by breaking the source; assert why, not that; guard against passing vacuously; name it as a
claim).

```bash
for s in Unit E2E Chaos; do
  dotnet build -c Release tests-epoxide/Epoxide.Tests.$s
  dotnet run -c Release --no-build --project tests-epoxide/Epoxide.Tests.$s
done
```

One argument runs only the tests whose name contains it:
`dotnet run -c Release --no-build --project tests-epoxide/Epoxide.Tests.E2E -- "threadpool:"`.

| Suite | Covers | Needs |
| --- | --- | --- |
| `Unit` | The version, the clock, the errno the syscall wrappers report, the config sizes refused at construction | nothing |
| `E2E` | Reactor lifecycle, the TCP read and write paths, hardening, the clocks - and what is epoxide's own: connections used from the thread pool, and outbound connects | nothing |
| `Chaos` | Malformed and hostile TCP input; TLS chaos joins it with the TLS suite | nothing |

## Where does my test go?

| The behaviour is… | File |
| --- | --- |
| A connection read, written or let go from a thread that is not its reactor's | `E2E/ThreadPoolTests` |
| `Reactor.ConnectAsync`, or an await on one reactor of another's connection | `E2E/ConnectTests` |
| The read and write paths, framing, overflow, ExtraPorts | `E2E/CoreTests` |
| Read and send timeouts, the FIN a release sends, half-close | `E2E/TcpTimeoutTests` |
| `ReactorTimer`, tickers | `E2E/TimerTests` |
| Setup failures, `Stop()`, what a teardown frees | `E2E/ReactorSetupTeardownTests` |
| A hostile or malformed input | `Chaos` |

## Ported from ioxide

Names and assertions are ioxide's wherever the behaviour is the same. A test that guards something
only io_uring has is translated to what it protects on epoll - each file's remarks say which and
how - or left out when epoxide has nothing like it: zero-copy send, MSG_WAITALL, incremental buffer
rings, ring setup, UDP and QUIC.

## Known core bugs

`runner.KnownCoreBug(name, body, bug)` registers a test that reproduces a reported, unfixed epoxide
core bug. It is listed as `KNOWN` and not run, so the suite stays green; `EPOXIDE_KNOWN_CORE_BUGS=run`
runs every one as an ordinary test. Once the core is fixed and they pass, make each a `Test()`.
Not `Pending`, which wants a tracked issue and runs its body - some of these hang a caller or hold a
descriptor for the rest of the process.

## The harness

`Epoxide.Tests.Harness` is `tests/Ioxide.Tests.Harness` on `src/epoxide`: the same `Runner`,
`TestServer` (with the per-process port windows - SO_REUSEPORT listeners of two processes co-bind
silently), `Client`, `TestCert`, `Handlers`, `FdCount` and the rest. Its own additions:

| Type | For |
| --- | --- |
| `Internals` | What epoxide does not expose, read by UnsafeAccessor and reflection: the recv pool's counts, a connection's generation and refs, the timer queue |
| `Hop` | `await Hop.ToThreadPool()` - a handler leaving its reactor. Only in tests about that; everywhere else a handler waits with `ReactorTimer` |
| `CountingContext` | The reactor's SynchronizationContext with a count of what is posted through it. Installed in OnStart, it tells an inline resume from a posted one |
| `TestServer.StartClientOnly` | A reactor with no listener, for `ConnectAsync` |

`Handlers` and `Wire` are partial: a suite whose handlers need a module of its own (TLS) adds them
in a file of its own instead of the harness referencing that module.
