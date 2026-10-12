# Benchmark

StackExchange.Redis over this package's transport, against StackExchange.Redis on its own sockets.

These numbers come from one machine. Only compare them with runs taken on the same machine with
the same settings.

## Running it

```bash
dotnet build -c Release Playground/Clients/RedisStackExchange
bash bench/redis-matrix.sh
AVOID_CPUS=8,9 bash bench/redis-matrix.sh    # keep a core out of every role
```

`bench/redis-matrix.sh` runs `Playground/Clients/RedisStackExchange` once per arm in every pass,
selecting the arm with the sample's `PLAYGROUND_REDIS_TRANSPORT` knob (`ioxide` or `sockets`). The
HTTP server, the handler and the Redis command are identical in both arms.

- **Same CPUs for both arms.** The server is pinned with `taskset`, so StackExchange.Redis's own
  threads cannot use cores the ioxide arm does not get.
- **Redis has its own core.** It runs in a container of its own on the host network. A `-p` port
  mapping would put `docker-proxy` in the path of every command.
- **wrk** runs on the remaining performance cores.
- **The arms are interleaved.** A cell with errors is discarded, and one whose server did not
  saturate is flagged.

Each request is `GET /`, which does one Redis `GET`.

## Results

Measured at 9682608.

- **Machine:** i9-14900K, kernel 6.14, governor `powersave`, .NET 11.0 RC1, with `AVOID_CPUS=8,9`.
- **Placement:** the server on CPUs 2 and 4 with 2 reactors, Redis 7 on CPUs 6–7, and
  `wrk -t4 -c64 -d10s` on CPUs 10–15.

| Pass | ioxide req/s | ioxide CPU/req | sockets req/s | sockets CPU/req |
|---|---|---|---|---|
| 1 | 587,001 | 3.30 us | 387,642 | 4.36 us |
| 2 | 620,193 | 3.16 us | 386,708 | 4.34 us |
| 3 | 585,868 | 3.28 us | 388,956 | 4.35 us |

**Best of three: the ioxide transport serves 1.59x the requests per second at 0.73x the CPU per
request.**

The ioxide arm kept its two CPUs 97–99% busy. StackExchange.Redis on its own sockets used 85% of the
same two and went no further, so CPU is not what limits it there.

## Receive buffer: pinned array or native memory

The receive buffer moved from a pinned array to native memory with an `UnmanagedMemoryManager` view.
That change was measured on its own, in three interleaved rounds with the pinned version run twice
as a control. This was an earlier setup: the server was not pinned, `wrk -t2 -c64 -d10s` drove it,
and Redis sat behind `docker-proxy`. The rows are means of the three rounds; compare them only
with each other.

| | Requests per second | CPU per request |
|---|---|---|
| Pinned array | 464k | 3.90 us |
| Native memory | 469k | 3.85 us |
| Pinned array (control) | 462k | 3.91 us |

The difference is within noise.

## Earlier numbers

Pull request #335 reported 448k–456k req/s at about 4.0 us, against 422k–431k at about 8.5 us.
That setup was unpinned, with Redis behind `docker-proxy`. StackExchange.Redis's threads could
spread over every core, so its CPU per request there is not comparable with the pinned results
above.
