#!/usr/bin/env bash
# StackExchange.Redis over the ioxide transport versus StackExchange.Redis on its own sockets.
#
# One sample, Clients/RedisStackExchange, whose PLAYGROUND_REDIS_TRANSPORT knob switches only the
# transport: the HTTP server, the handler and the Redis command are identical in both arms. Both
# arms run on the SAME CPUs, so StackExchange.Redis's own threads cannot borrow cores the ioxide
# arm does not get. Redis and the load generator are pinned to cores of their own, and the arms are
# interleaved so drift hits both equally.
#
# Redis runs in a container of its own on the host network, pinned to its own core: a -p port
# mapping would put docker-proxy in the path of every command, and it would be measured too.
#
#   bash bench/redis-matrix.sh
#   SERVER_CPUS=2,4 REDIS_CPUS=6,7 CLIENT_CPUS=10-15 bash bench/redis-matrix.sh
#   AVOID_CPUS=8,9 bash bench/redis-matrix.sh        # keep a core out of every role
#   REDIS_HOST=127.0.0.1 REDIS_PORT=6379 bash bench/redis-matrix.sh   # a Redis you run (unpinned)
set -uo pipefail
cd "$(dirname "$0")/.."
. bench/lib.sh

REACTORS=${REACTORS:-2}
DURATION=${DURATION:-10}
CONNS=${CONNS:-64}
THREADS=${THREADS:-4}
PASSES=${PASSES:-3}
PORT=${PORT:-8080}
REDIS_PORT=${REDIS_PORT:-6390}
REDIS_HOST=${REDIS_HOST:-}
MIN_UTIL=${MIN_UTIL:-90}
OUT=${OUT:-/tmp/redis-matrix}
mkdir -p "$OUT"

# ── placement ────────────────────────────────────────────────────────────────────────────────
#
# Whole performance cores, in order, skipping the first (interrupts and housekeeping land there):
# one thread of each of the next REACTORS cores for the server - their siblings stay idle - then a
# whole core for Redis, then every remaining performance core for the driver.
pick_cpus() {
  local fast=",$(bench_perf_cpus)," avoid=",${AVOID_CPUS:-},"
  local -a cores
  mapfile -t cores < <(lscpu -e=CPU,CORE 2>/dev/null | awk 'NR>1 {print $2, $1}' \
    | awk -v f="$fast" -v a="$avoid" 'index(f, "," $2 ",") && !index(a, "," $2 ",") { if ($1 in c) c[$1] = c[$1] "," $2; else c[$1] = $2 }
                                      END { for (k in c) print k, c[k] }' | sort -n | cut -d' ' -f2)

  if [ "${#cores[@]}" -lt $((REACTORS + 3)) ]; then
    SERVER_CPUS=${SERVER_CPUS:-$(seq -s, 0 $((REACTORS - 1)))}
    return
  fi

  local server="" client="" i
  for i in $(seq 1 "$REACTORS"); do server+="${server:+,}${cores[$i]%%,*}"; done
  for i in $(seq $((REACTORS + 2)) $((${#cores[@]} - 1))); do client+="${client:+,}${cores[$i]}"; done
  SERVER_CPUS=${SERVER_CPUS:-$server}
  REDIS_CPUS=${REDIS_CPUS-${cores[$((REACTORS + 1))]}}
  CLIENT_CPUS=${CLIENT_CPUS-$client}
}
pick_cpus
REDIS_CPUS=${REDIS_CPUS:-}
CLIENT_CPUS=${CLIENT_CPUS:-}
NSERVER=$(taskset -c "$SERVER_CPUS" nproc)

DRIVER=(); [ -n "$CLIENT_CPUS" ] && DRIVER=(taskset -c "$CLIENT_CPUS")

BIN=$(bench_binary Clients/RedisStackExchange)
[ -n "$BIN" ] || { echo "build it first: dotnet build -c Release Playground/Clients/RedisStackExchange" >&2; exit 1; }
command -v wrk >/dev/null || { echo "wrk not found" >&2; exit 1; }

# ── redis ────────────────────────────────────────────────────────────────────────────────────

REDIS_NAME=ioxide-bench-redis
STARTED_REDIS=0
start_redis() {
  [ -n "$REDIS_HOST" ] && return 0
  command -v docker >/dev/null || { echo "docker not found: set REDIS_HOST and REDIS_PORT to a running Redis" >&2; exit 1; }
  bench_assert_port_free "$REDIS_PORT" || exit 1

  local cpuset=(); [ -n "$REDIS_CPUS" ] && cpuset=(--cpuset-cpus "$REDIS_CPUS")
  docker rm -f "$REDIS_NAME" >/dev/null 2>&1
  docker run -d --rm --name "$REDIS_NAME" --network host "${cpuset[@]}" redis:7-alpine \
    redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no >/dev/null || exit 1
  STARTED_REDIS=1
  REDIS_HOST=127.0.0.1

  for _ in $(seq 100); do
    docker exec "$REDIS_NAME" redis-cli -p "$REDIS_PORT" ping 2>/dev/null | grep -q PONG && return 0
    sleep 0.1
  done
  echo "redis did not answer on $REDIS_PORT" >&2; exit 1
}

# ── one cell ─────────────────────────────────────────────────────────────────────────────────

PID=""
stop() {
  [ -z "$PID" ] && return 0
  kill "$PID" 2>/dev/null
  for _ in $(seq 40); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""
}
cleanup() { stop; [ "$STARTED_REDIS" = 1 ] && docker rm -f "$REDIS_NAME" >/dev/null 2>&1; }
trap cleanup EXIT

await_free() {
  for _ in $(seq 60); do ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN || return 0; sleep 0.1; done
  return 1
}

cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

declare -A BEST CPU UTIL

cell() {  # cell <transport: ioxide|sockets>
  local arm=$1 url="http://127.0.0.1:$PORT/"
  await_free "$PORT" || { echo "  !! port $PORT busy"; return; }
  bench_assert_port_free "$PORT" || return

  PLAYGROUND_PORT=$PORT PLAYGROUND_REACTORS=$REACTORS PLAYGROUND_REDIS_TRANSPORT=$arm \
    PLAYGROUND_REDIS_HOST=$REDIS_HOST PLAYGROUND_REDIS_PORT=$REDIS_PORT \
    taskset -c "$SERVER_CPUS" "$BIN" >"$OUT/server-$arm.log" 2>&1 &
  PID=$!

  bench_await_listeners "$PORT" "$REACTORS" || { stop; return; }
  bench_assert_single_listener "$PORT" "$REACTORS" || { stop; return; }

  # Reactor 0 seeds the key a moment after start; until then "/" answers an empty value.
  local body=""
  for _ in $(seq 100); do
    body=$(curl -s --max-time 1 "$url")
    [ "$body" = "redis = 42" ] && break
    sleep 0.1
  done
  [ "$body" = "redis = 42" ] || { echo "  !! $arm answered '$body', expected 'redis = 42'"; tail -3 "$OUT/server-$arm.log"; stop; return; }

  "${DRIVER[@]}" wrk -t"$THREADS" -c"$CONNS" -d3s "$url" >/dev/null 2>&1   # warm

  local t0 t1; t0=$(cpu_ticks "$PID")
  "${DRIVER[@]}" wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" "$url" >"$OUT/$arm.txt" 2>&1
  t1=$(cpu_ticks "$PID")
  stop

  local rps reqs
  rps=$(grep -oP 'Requests/sec:\s+\K[\d.]+' "$OUT/$arm.txt" | head -1)
  reqs=$(grep -oP '^\s*\K\d+(?= requests in)' "$OUT/$arm.txt" | head -1)
  if grep -q "Non-2xx\|Socket errors" "$OUT/$arm.txt"; then
    echo "  !! $arm: $(grep -h "Non-2xx\|Socket errors" "$OUT/$arm.txt" | tr -s ' ' | paste -sd';') - discarded"
    return
  fi
  [ -n "$rps" ] && [ -n "$reqs" ] && [ "$reqs" != 0 ] || { echo "  !! $arm: no result"; return; }

  local us util
  us=$(awk -v t="$((t1 - t0))" -v q="$reqs" 'BEGIN{ printf "%.2f", (t / 100.0) / q * 1e6 }')
  util=$(awk -v t="$((t1 - t0))" -v d="$DURATION" -v n="$NSERVER" 'BEGIN{ printf "%.0f", (t / 100.0) / d / n * 100 }')
  local note=""; [ "$util" -lt "$MIN_UTIL" ] && note="  (not saturated)"
  printf '    %-10s %10.0f req/s   %6s us cpu/req   %3s%% of %s cpus%s\n' "$arm" "$rps" "$us" "$util" "$NSERVER" "$note"

  if awk -v a="$rps" -v b="${BEST[$arm]:-0}" 'BEGIN{exit !(a>b)}'; then
    BEST[$arm]=$rps; CPU[$arm]=$us; UTIL[$arm]=$util
  fi
}

# ── run ──────────────────────────────────────────────────────────────────────────────────────

start_redis
echo "== redis: StackExchange.Redis over ioxide vs on its own sockets"
echo "   server on CPUs $SERVER_CPUS ($REACTORS reactors), redis on ${REDIS_CPUS:-any} ($REDIS_HOST:$REDIS_PORT), wrk on ${CLIENT_CPUS:-any}"
echo "   wrk -t$THREADS -c$CONNS -d${DURATION}s, GET / -> one Redis GET per request"
for pass in $(seq "$PASSES"); do
  echo "-- pass $pass/$PASSES"
  cell ioxide
  cell sockets
done

echo
echo "== best of $PASSES passes"
printf '   %-10s %12s %12s\n' TRANSPORT 'REQ/S' 'CPU/REQ'
for arm in ioxide sockets; do
  printf '   %-10s %12.0f %10sus\n' "$arm" "${BEST[$arm]:-0}" "${CPU[$arm]:-?}"
done
awk -v a="${BEST[ioxide]:-0}" -v b="${BEST[sockets]:-0}" -v x="${CPU[ioxide]:-0}" -v y="${CPU[sockets]:-0}" \
  'BEGIN{ if (a > 0 && b > 0 && x > 0) printf "   ioxide: %.2fx the requests per second, at %.2fx the CPU per request\n", a / b, x / y }'
