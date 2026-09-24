# bench

The Playground samples are the regression fixtures. They are not demo code that happens to be
runnable - every knob is a literal you edit AND an environment variable a harness can drive, which
is what lets one build be measured in every configuration without rebuilding.

```bash
dotnet build -c Release ioxide.slnx     # once

bash bench/any.sh                       # every registered sample
bash bench/any.sh Tcp/Raw Tls/OpenSsl   # just these
bash bench/any.sh --list                # what is registered, and what is runnable here
```

## any.sh - the suite

`bench/samples.tsv` registers every sample: protocol, port, request path, the origin to start
first, and extra environment. It is asserted complete against the Playground tree, so a sample
nobody can benchmark shows up as a gap rather than as silence.

`any.sh` reads that table and needs no per-sample code. For each row it starts an origin when the
fixture proxies or calls out, waits until the sample actually answers, warms it, measures, tears
it down, and waits for the port to be released before the next row.

It records **throughput and CPU microseconds per request**. The second one is the point: on
loopback throughput saturates and stops separating implementations, while CPU per request keeps
going. A cell is **discarded rather than reported** when

- the reactors were not saturated (below `MIN_UTIL`% of `REACTORS` cores) - an idle reactor polls
  an empty ring, that time lands in `utime`, and CPU per request comes out inflated,
- the load generator saw non-2xx responses or socket errors,
- the sample served a different byte count than the row asks for,
- more than one process is listening on the port. Under `SO_REUSEPORT` a leaked server from an
  earlier run will happily bind alongside the new one and take half the load, which has produced
  phantom numbers here before.

A number from a broken fixture is worse than no number.

| variable | default | |
| --- | --- | --- |
| `REACTORS` | 2 | keep it small, so the load generator is never the ceiling |
| `SECONDS_` | 10 | measured seconds per sample |
| `CONNS` | 64 | connections |
| `THREADS` | 8 | load generator threads |
| `MIN_UTIL` | 90 | reject a cell whose reactors were not saturated |
| `BASELINE` | `results/latest.json` | compare against this instead of the previous run |
| `H3X` | `~/h3x/build/h3x` | the HTTP/3 driver |

## Results are kept

Every run writes `bench/results/<utc>.json` - commit, host, kernel, settings and one row per
sample - and updates `latest.json`. Each sample prints against its previous value:

```
Tcp/Raw          889608   2.30us   -3.3%
Clients/File     681472   3.00us   +1.2%
```

A number with nothing to compare against cannot catch a regression, which is the whole point.

**Only diff runs taken at the same settings.** Every result file records `reactors`, `conns`,
`threads` and `seconds`, because a single operating point can rank two implementations either way
- see the HTTP/2 note below.

## Load generators

| protocol | driver |
| --- | --- |
| `h1`, `h1s` | `wrk` |
| `h2c`, `h2` | `h2load` (nghttp2) |
| `h3` | [`h3x`](https://github.com/MDA2AV) - the `h2load` in most distributions is built without ngtcp2/nghttp3 and cannot drive HTTP/3 (it reports 0 started) |
| `echo` | `Playground/Clients/Quic` - the QUIC echo servers speak no HTTP, so nothing off the shelf can drive them. The driver is itself a sample, not a bench-only artifact |

`Bench.Clients` drives ioxide's own HTTP clients (`h1`/`h2`/`h3`) against an external server, for
the rows where the thing under test is our client rather than our server. With `BENCH_TLS=1` it
also drives the `h1s` samples, which is how `ab.sh` measures where `wrk` is not installed.

Anything missing **skips with a note** instead of failing the run.

## The focused matrices

These answer one question each, holding everything else constant, and exist because the suite
deliberately does not.

- **`tls-matrix.sh`** - h1 and h2 across plaintext / OpenSSL / kTLS-TX / kTLS-both, at 64 B and
  8 KB. There is no kTLS-RX-only cell: RX is programmed at the same handoff as TX, so asking for
  it alone silently gets you OpenSSL.
- **`file-matrix.sh`** - static files, reading straight into the write slab versus through a
  buffer, crossed with cleartext / kTLS / OpenSSL. Whether the slab path is legal at all follows
  from what the slab must hold when it is sent, so there is no OpenSSL+slab cell. Runs **one
  saturated reactor**: an earlier four-reactor version reported an 11% win where the
  single-reactor method measures 22%.
- **`h2-matrix.sh`** - nghttp2 versus the pure-C# HTTP/2, with and without TLS, on one load
  generator, interleaved so drift hits both arms equally.
- **`ab.sh`** - one sample, two git refs: each built in its own worktree under `bench/.work/ab/`,
  runs interleaved a, b, a, b so drift hits both, and requests/s plus the server's CPU per request
  from `/proc`. The driver is `Bench.Clients`, built once from the current tree, so it needs no
  `wrk` - and its numbers compare only with each other, never with `wrk`'s:
  `bash bench/ab.sh origin/main HEAD Tls/OpenSslPipes`.

## A caution the HTTP/2 matrix earned

Measured here at 2 reactors, 64 connections, 32 streams, a 2-byte body, the pure-C# server runs
2.7x nghttp2 cleartext and 2.5x over TLS, at about a third of the CPU per request. TLS costs
**both** the same 0.05us per request - identical absolute cost from the same OpenSSL - so it only
looks like a bigger hit on the faster server.

That ordering narrows as reactors rise and connections-per-reactor falls (2.76x at 2 reactors,
1.48x at 16), and a 2-byte body measures framing and HPACK rather than moving data, so it should
not be read as a general claim.

The reason this section exists: a previously documented run of the same comparison used
`h2load -n 300000`, which **completes in 190 milliseconds** - connection setup and ramp, never
steady state - and reported the two as equal. Prefer `-D` over `-n`, and check the reported
duration before believing a throughput number.

Numbers are hardware-specific. Compare runs on one machine; never commit them as truth.


## What a number here can and cannot be compared to

Every figure is hardware-specific and driver-specific. Two runs are comparable when the recorded
`cpu`, `reactors`, `conns`, `threads` and `seconds` match and `dirty` is `false` on both. Nothing
else is comparable, however similar the samples look.

The harness records that context because leaving it out cost a day. The traps below are all real,
all seen on this repo, and all guarded now.

### The driver is the thing being measured

Reactor utilisation does not tell you whether you measured the server. A run can peg both reactors
and still be limited by the load generator: fewer requests in flight means less batching per wakeup,
so the server burns more CPU per request while looking fully busy.

`Http3/Nghttp3Buffered` measured 260k req/s at 7.5 us/req under one driver and 505k at 3.8 us/req
under another, on the same binary and the same cores, both at ~97% utilisation. After each measured
run the harness re-runs briefly at double the load; if throughput climbs, the row is marked
`driver-bound` rather than reported as a server number.

### Two scripts, two answers

The divergence above was `run.sh` driving HTTP/3 as `-t 4 --connections 64 -m 8 --send-batch 8`
while `any.sh` used `--connections 64 -m 32`. Both were real measurements of the same server and
neither file said they were different.

Every driver now lives in `lib.sh` and every script sources it. Change an invocation there or
nowhere.

### Use the parameters that measure the server

    bash bench/any.sh --tune            # sweep the load ladder, keep the peak per sample
    bash bench/any.sh                   # reuse it

`--tune` sweeps connection counts per sample, records the winner in `bench/tuned.tsv`, and later
runs reuse it - so a measurement is reproducible *and* near the server's peak instead of wherever a
fixed default happens to land. Each row records the shape it was measured at, and two rows are only
comparable when those match.

It is worth the run. `Http3/Nghttp3Buffered` on this hardware:

    conns=4     678797 req/s   2.61us/req
    conns=8     790815 req/s   2.53us/req
    conns=16    792865 req/s   2.52us/req   <- peak
    conns=32    747587 req/s   2.68us/req
    conns=64    462803 req/s   4.32us/req   <- the old fixed default
    conns=128   458343 req/s   4.36us/req

The default was reporting 462k for a server that does 810k, and every recorded result for that
sample was taken there.

### Connection count is not a free parameter

On this hardware `Http3/Nghttp3Buffered` at 2 reactors does ~800k req/s at 16 connections and 442k
at 64, with CPU per request nearly doubling across that step - per-connection cost dominates once a
reactor is juggling enough of them. `CONNS` is therefore part of the result, not a detail of how it
was taken, and the default of 64 sits on the far side of that cliff. Raising it does not make a
server look better.

### Hybrid CPUs decide the result

On an i9-14900K the same HTTP/3 server measures ~490k req/s on the performance cores and 96k on the
efficiency ones. Left alone the scheduler picks, and its choice reads as a regression.

So the server is pinned to the performance cores - all of them, not a chosen few. Narrower is worse,
measured at 2 reactors:

    pinned to two cores        465k req/s
    pinned to the 6GHz pair    482k
    pinned to all P-cores      494k
    unpinned                   505k

Denying the scheduler any choice costs more than the placement gains. Giving it every P-core and no
E-core keeps almost all of that freedom and removes the cliff; the driver is not pinned at all,
since confining it would only move the bottleneck onto the driver. `SERVER_CPUS` overrides.

### A leaked server is measured too

Under SO_REUSEPORT the kernel fans connections across every process bound to the port, so a server
left over from an earlier run silently blends into the next result. Starting a sample refuses a port
that is already bound; `bench_assert_single_listener` checks the socket count afterwards.

Beware `pkill -f playground` for cleanup - the pattern matches the shell running it.

### A result must name the tree it came from

`bench/results/20260810T001150Z.json` records `commit: 96137b9` alongside samples that did not exist
until 15 hours later. The commit was stamped correctly; the samples were sitting uncommitted in the
working tree at the time. Chasing that as a performance regression found nothing, because there was
nothing to find.

Runs now record `dirty`, along with `cpu`, `governor` and `server_cpus`. A result taken on a dirty
tree is a note to yourself, not a baseline.
