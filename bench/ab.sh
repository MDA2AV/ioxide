#!/usr/bin/env bash
# A/B one Playground sample between two git refs, with ioxide's own HTTP/1.1 client as the load
# driver - so it runs where wrk and h2load are not installed.
#
#     bash bench/ab.sh <ref-a> <ref-b> [sample]      # sample defaults to Tls/OpenSslPipes
#     bash bench/ab.sh origin/main HEAD Tcp/Raw      # TLS=0 for a plain-http sample
#
# Each ref is checked out into its own worktree under bench/.work/ab/ and built in Release. The
# driver (bench/Bench.Clients) is built once, from THIS tree, so both sides are measured by the
# same client. Runs alternate a, b, a, b, ... so drift in the machine - thermals, a background
# job - lands on both sides. Each run reports requests/s from the driver and the server's CPU
# microseconds per request, read from /proc/<pid>/stat over the measured window, plus how many
# cores the server used: a server that is not saturated measures the load, not itself.
#
# Compare the two columns of one run of this script with each other - never with wrk's numbers
# or with another machine's.
#
#   ROUNDS=5            pairs of runs
#   SECONDS_=10         measured seconds per run, after a 2 s warm-up
#   REACTORS=2          server reactors (PLAYGROUND_REACTORS)
#   SERVER_CPUS=0-3     server pinning; keep it disjoint from the driver's
#   CLIENT_CPUS=        driver pinning (default: every CPU after SERVER_CPUS)
#   CONNS=64            connections, spread over DRIVER_REACTORS, one request in flight on each
#   DRIVER_REACTORS=4   driver reactors
#   PORT=8443           the sample's port
#   TLS=1               1 for an https sample, 0 for plain http
set -uo pipefail
cd "$(dirname "$0")/.."

if [ $# -lt 2 ]; then
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit 2
fi

REF_A=$1
REF_B=$2
SAMPLE=${3:-Tls/OpenSslPipes}
ROUNDS=${ROUNDS:-5}
SECONDS_=${SECONDS_:-10}
REACTORS=${REACTORS:-2}
SERVER_CPUS=${SERVER_CPUS:-0-3}
CONNS=${CONNS:-64}
DRIVER_REACTORS=${DRIVER_REACTORS:-4}
PORT=${PORT:-8443}
TLS=${TLS:-1}

LAST_CPU=$(($(nproc) - 1))
if [ -z "${CLIENT_CPUS:-}" ]; then
  first=$((${SERVER_CPUS##*[-,]} + 1))
  CLIENT_CPUS=$([ "$first" -le "$LAST_CPU" ] && echo "$first-$LAST_CPU" || echo "0-$LAST_CPU")
fi

WORK=bench/.work/ab
mkdir -p "$WORK"
TICK=$(getconf CLK_TCK)
PER_REACTOR=$((CONNS / DRIVER_REACTORS))

SERVER_PID=""
DRIVER_PID=""
cleanup() {
  [ -n "$DRIVER_PID" ] && kill "$DRIVER_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; }
ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }

build() {   # <tree> <project>
  if ! dotnet build -c Release "$1/$2" --nodeReuse:false -v q -clp:ErrorsOnly >"$WORK/build.log" 2>&1; then
    cat "$WORK/build.log" >&2
    exit 1
  fi
}

# One worktree per ref, kept between runs of this script and moved to the ref's current commit.
tree_for() {
  local ref=$1 sha dir
  sha=$(git rev-parse --verify --quiet "$ref^{commit}") || return 1
  dir="$WORK/$(printf '%s' "$ref" | tr '/:~^' '____')"
  if [ -d "$dir" ]; then
    git -C "$dir" checkout --quiet --detach "$sha" || return 1
  else
    git worktree add --quiet --detach "$dir" "$sha" || return 1
  fi
  printf '%s' "$dir"
}

if listening; then
  echo "something already listens on :$PORT - a leaked server would be measured too" >&2
  exit 1
fi

TREE_A=$(tree_for "$REF_A") || { echo "cannot check out $REF_A" >&2; exit 2; }
TREE_B=$(tree_for "$REF_B") || { echo "cannot check out $REF_B" >&2; exit 2; }

PROJECT=$(cd "$TREE_A" && ls Playground/"$SAMPLE"/*.csproj 2>/dev/null | head -1)
[ -n "$PROJECT" ] || { echo "no Playground sample $SAMPLE" >&2; exit 2; }
NAME=$(basename "$PROJECT" .csproj)

echo "== building $SAMPLE at $REF_A ($(git -C "$TREE_A" rev-parse --short HEAD)) and $REF_B ($(git -C "$TREE_B" rev-parse --short HEAD)), and the driver"
build "$TREE_A" "$PROJECT"
build "$TREE_B" "$PROJECT"
build . bench/Bench.Clients/Bench.Clients.csproj
DRIVER=bench/Bench.Clients/bin/Release/net11.0/Bench.Clients

# One measured run, into RUN_RPS, RUN_CPU (us per request), RUN_CORES and RUN_FAILED. Not called
# in a subshell, so the trap above can always reach the server and the driver.
run() {   # <tree>
  local bin="$1/$(dirname "$PROJECT")/bin/Release/net11.0/$NAME" t0 t1 line ok
  PLAYGROUND_REACTORS=$REACTORS taskset -c "$SERVER_CPUS" "$bin" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 100); do listening && break; sleep 0.1; done

  BENCH_REACTORS=$DRIVER_REACTORS BENCH_POOL=$PER_REACTOR BENCH_TLS=$TLS \
    taskset -c "$CLIENT_CPUS" "$DRIVER" 127.0.0.1 "$PORT" "$SECONDS_" "$PER_REACTOR" >"$WORK/client.log" 2>&1 &
  DRIVER_PID=$!

  # The driver warms up for 2 s and then measures SECONDS_; the server's CPU is read over the same
  # window.
  sleep 2
  t0=$(ticks "$SERVER_PID")
  sleep "$SECONDS_"
  t1=$(ticks "$SERVER_PID")
  wait "$DRIVER_PID"
  DRIVER_PID=""

  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
  for _ in $(seq 100); do listening || break; sleep 0.1; done

  line=$(grep 'req/s' "$WORK/client.log")
  ok=$(printf '%s' "$line" | grep -oP '\(\K\d+(?= ok)')
  RUN_RPS=$(printf '%s' "$line" | grep -oP '\d+(?= req/s)')
  RUN_FAILED=$(printf '%s' "$line" | grep -oP '\d+(?= failed)')
  RUN_CPU=$(awk -v d=$((t1 - t0)) -v tick="$TICK" -v ok="${ok:-0}" 'BEGIN { printf "%.3f", (ok > 0 ? d * 1e6 / tick / ok : 0) }')
  RUN_CORES=$(awk -v d=$((t1 - t0)) -v tick="$TICK" -v s="$SECONDS_" 'BEGIN { printf "%.2f", d / tick / s }')
  RUN_RPS=${RUN_RPS:-0}
  RUN_FAILED=${RUN_FAILED:-?}
}

median() { sort -n | awk '{ v[NR] = $1 } END { if (NR) print v[int((NR + 1) / 2)] }'; }

RESULTS="$WORK/$(date -u +%Y%m%dT%H%M%SZ).tsv"
printf 'round\tside\tref\treq_s\tcpu_us_per_req\tserver_cores\tfailed\n' >"$RESULTS"
echo "== $SAMPLE, $ROUNDS rounds of ${SECONDS_}s, server $REACTORS reactors on $SERVER_CPUS, driver $DRIVER_REACTORS reactors x $PER_REACTOR connections on $CLIENT_CPUS"
printf '   %-5s %-4s %-24s %10s %12s %7s %7s\n' round side ref req/s cpu/req cores failed

for round in $(seq "$ROUNDS"); do
  for side in a b; do
    if [ "$side" = a ]; then tree=$TREE_A; ref=$REF_A; else tree=$TREE_B; ref=$REF_B; fi
    run "$tree"
    printf '   %-5s %-4s %-24s %10s %10sus %7s %7s\n' "$round" "$side" "$ref" "$RUN_RPS" "$RUN_CPU" "$RUN_CORES" "$RUN_FAILED"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$round" "$side" "$ref" "$RUN_RPS" "$RUN_CPU" "$RUN_CORES" "$RUN_FAILED" >>"$RESULTS"
  done
done

echo "== summary ($ROUNDS runs per side)"
for side in a b; do
  column() { awk -F'\t' -v side="$side" -v c="$1" 'NR > 1 && $2 == side { print $c }' "$RESULTS"; }
  ref=$([ "$side" = a ] && echo "$REF_A" || echo "$REF_B")
  printf '   %s %-24s req/s mean %s median %s (min %s max %s)   cpu/req mean %sus median %sus\n' "$side" "$ref" \
    "$(column 4 | awk '{ t += $1 } END { if (NR) printf "%.0f", t / NR }')" "$(column 4 | median)" \
    "$(column 4 | sort -n | head -1)" "$(column 4 | sort -n | tail -1)" \
    "$(column 5 | awk '{ t += $1 } END { if (NR) printf "%.3f", t / NR }')" "$(column 5 | median)"
done
echo "   saved $RESULTS"
