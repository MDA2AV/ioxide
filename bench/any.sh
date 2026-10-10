#!/usr/bin/env bash
# Run a benchmark against ANY Playground sample, and keep the result.
#
#     bash bench/any.sh                      # every sample in bench/samples.tsv
#     bash bench/any.sh Tcp/Raw Tls/OpenSsl  # just these
#     bash bench/any.sh --list               # what is registered, and what is runnable here
#
# The samples are the regression fixtures, so the point is the LAST RUN: every run is written to
# bench/results/<utc>.json and bench/results/latest.json, and each sample is printed against its
# previous value with the delta. A number with nothing to compare it to cannot catch a regression.
#
#   REACTORS=2     reactors under test - keep it small so the load generator is never the
#                  bottleneck, and so the reactors actually saturate (an idle reactor polls
#                  an empty ring, that time lands in utime, and cpu/req comes out inflated)
#   SECONDS_=10    measured seconds per sample
#   CONNS=64       connections
#   THREADS=8      load generator threads - must outrun the server
#   MIN_UTIL=90    reject a sample whose reactors were not saturated (% of REACTORS cores)
#   BASELINE=path  compare against this file instead of the previous run
#
# Numbers are hardware-specific: compare runs on one machine, never across machines.
set -uo pipefail
cd "$(dirname "$0")/.."

REACTORS=${REACTORS:-2}
SECONDS_=${SECONDS_:-10}
CONNS=${CONNS:-64}
THREADS=${THREADS:-8}
MIN_UTIL=${MIN_UTIL:-90}
HEADROOM_PCT=${HEADROOM_PCT:-8}

# --tune sweeps the load ladder per sample and writes the winner to bench/tuned.tsv; later runs
# reuse it, so a measurement is both reproducible and near the server's peak rather than wherever
# a fixed default happens to land.
TUNE=0
ARGS=()
for a in "$@"; do
  if [ "$a" = --tune ]; then TUNE=1; else ARGS+=("$a"); fi
done
set -- ${ARGS+"${ARGS[@]}"}
SERVER_CPUS=${SERVER_CPUS:-$(. "$(dirname "$0")/lib.sh"; bench_server_cpus)}

# One definition of how each protocol is driven, shared with every other script under bench/.
. "$(dirname "$0")/lib.sh"
OUT=bench/results
WORK=bench/.work
mkdir -p "$OUT" "$WORK" /tmp/ioxide-bench-assets
[ -s /tmp/ioxide-bench-assets/f.bin ] || head -c 4096 /dev/urandom | base64 | head -c 4096 > /tmp/ioxide-bench-assets/f.bin

SERVER_PID=""; ORIGIN_PID=""

kill_tree() {
  local pid=$1
  [ -z "$pid" ] && return 0
  kill "$pid" 2>/dev/null
  for _ in $(seq 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
}
cleanup() { kill_tree "$SERVER_PID"; SERVER_PID=""; kill_tree "$ORIGIN_PID"; ORIGIN_PID=""; }

# The kernel releases a port slightly after the process goes. Starting the next sample before it
# does re-creates the SO_REUSEPORT trap - two servers on one port, load split, number meaningless.
await_port_free() {
  local port=$1
  for _ in $(seq 60); do
    ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN  || \
    ss -lun "sport = :$port" 2>/dev/null | grep -q ":$port" || return 0
    sleep 0.1
  done
  return 1
}
trap cleanup EXIT

binary() { bench_binary "$1"; }

cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# Does this sample answer yet? Also the correctness gate - a sample that 500s or refuses is not a
# benchmark result, it is a broken fixture, and it should say so rather than produce a number.
probe() {
  local proto=$1 port=$2 path=${3:-/}
  case $proto in
    h1)   curl -s  -o /dev/null --max-time 2 "http://127.0.0.1:$port$path" ;;
    h1s)  curl -sk -o /dev/null --max-time 2 "https://127.0.0.1:$port$path" ;;
    h2c)  curl -s  -o /dev/null --max-time 2 --http2-prior-knowledge "http://127.0.0.1:$port$path" ;;
    h2)   curl -sk -o /dev/null --max-time 2 --http2 "https://127.0.0.1:$port$path" ;;
    h3)   ss -lun "sport = :$port" 2>/dev/null | grep -q ":$port" ;;
    echo) ss -lun "sport = :$port" 2>/dev/null | grep -q ":$port" ;;
    *)    return 1 ;;
  esac
}

start() { # start <role> <sample> <proto> <port> <path> <extra env...>
  local role=$1 sample=$2 proto=$3 port=$4 path=$5; shift 5
  local exe; exe=$(binary "$sample")
  [ -z "$exe" ] && { echo "    no binary for $sample - build first"; return 1; }

  if ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN || \
     ss -lun "sport = :$port" 2>/dev/null | grep -q UNCONN; then
    echo "    port $port already held"; return 1
  fi

  local portvar=PLAYGROUND_PORT
  [ "$proto" = h3 ] && portvar=PLAYGROUND_QUIC_PORT

  # Pinned to the performance cores. On a hybrid CPU the scheduler is free to put a reactor on an
  # efficiency core, and the same server then measures a third of its throughput - a difference
  # that shows up as a regression and is only where the thread landed.
  local pin=()
  command -v taskset >/dev/null 2>&1 && pin=(taskset -c "$SERVER_CPUS")

  "${pin[@]}" env PLAYGROUND_REACTORS="$REACTORS" "$portvar=$port" "$@" \
      "$exe" > "$WORK/$role.log" 2>&1 < /dev/null &
  local pid=$!
  [ "$role" = server ] && SERVER_PID=$pid || ORIGIN_PID=$pid

  for _ in $(seq 120); do
    kill -0 "$pid" 2>/dev/null || { echo "    $sample exited: $(tail -2 "$WORK/$role.log"|tr '\n' ' ')"; return 1; }
    if probe "$proto" "$port" "$path"; then
      local kind=tcp; case $proto in h3|echo) kind=udp ;; esac
      bench_await_listeners "$port" "$REACTORS" "$kind" && return 0
      echo "    $sample: not every reactor is listening"; return 1
    fi
    sleep 0.1
  done
  echo "    $sample never answered on $port: $(tail -2 "$WORK/$role.log"|tr '\n' ' ')"
  return 1
}

# wrk reports failures separately from throughput; a partly-failing run is not a result.
bad_run() {
  local out=$1
  local n; n=$(grep -oP 'Non-2xx or 3xx responses: \K\d+' "$out" | head -1)
  [ -n "${n:-}" ] && [ "${n:-0}" != 0 ] && { echo "non-2xx=$n"; return 0; }
  grep -q 'Socket errors' "$out" && { echo "socket errors"; return 0; }
  grep -qE '^\s*[1-9][0-9]* failed' "$out" && { echo "failed requests"; return 0; }
  grep -qP '^requests: .* [1-9]\d* (failed|errored|timeout)' "$out" && { echo "failed requests"; return 0; }   # h2load
  grep -qP '^status codes: .* [1-9]\d* [345]xx' "$out" && { echo "non-2xx"; return 0; }                         # h2load
  # h2load counts a request killed with its connection as neither failed nor errored, only not done.
  grep -qP '^requests: .* [1-9]\d* started, 0 done' "$out" && { echo "no request completed"; return 0; }        # h2load
  grep -qP '^req/s\s+:\s+0\.00\s' "$out" && { echo "a connection completed nothing"; return 0; }                # h2load
  return 1
}

registry() { grep -vE '^\s*#|^\s*$' bench/samples.tsv; }

if [ "${1:-}" = "--list" ]; then
  printf '%-26s %-7s %-6s %-11s %-20s %s\n' SAMPLE PROTO PORT PATH ORIGIN RUNNABLE
  while read -r sample proto port path origin extra; do
    r=yes
    [ "$proto" = driver ] && r="no (it IS a driver, not a server workload)"
    [ "$proto" = none ] && r="no (no load generator here can drive it)"
    [ "$proto" = echo ] && [ ! -x Playground/Clients/Quic/bin/Release/net11.0/Playground.Clients.Quic ] \
        && r="no (Clients/Quic not built)"
    [ "$proto" = h3 ] && [ ! -x "$H2LOAD_H3" ] && r="no (no h2load with HTTP/3 - set H2LOAD_H3)"
    [ -z "$(binary "$sample")" ] && r="no (not built)"
    printf '%-26s %-7s %-6s %-11s %-20s %s\n' "$sample" "$proto" "$port" "$path" "$origin" "$r"
  done < <(registry)
  exit 0
fi

WANT=("$@")
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULT="$OUT/$STAMP.json"
PREV=${BASELINE:-$OUT/latest.json}
declare -A OLD
if [ -f "$PREV" ]; then
  while IFS=$'\t' read -r k v; do OLD["$k"]=$v; done < <(
    python3 -c "
import json,sys
d=json.load(open('$PREV'))
for s in d.get('samples',[]):
    if s.get('rps'): print(s['sample'], s['rps'], sep='\t')
" 2>/dev/null)
fi

echo "== bench $STAMP  ($REACTORS reactor(s), $CONNS conns, ${SECONDS_}s, saturation >=${MIN_UTIL}% of $REACTORS cores)"
[ -f "$PREV" ] && echo "   comparing against $PREV" || echo "   no baseline yet - this run becomes it"
printf '   %-24s %12s %10s %10s  %s\n' SAMPLE 'REQ/S' 'CPU/REQ' 'VS PREV' NOTE

ROWS=()
while read -r sample proto port path origin extra; do
  if [ ${#WANT[@]} -gt 0 ]; then
    hit=0; for w in "${WANT[@]}"; do [ "$w" = "$sample" ] && hit=1; done
    [ $hit -eq 0 ] && continue
  fi

  skip=""
  [ "$proto" = driver ] && skip="a load driver, not a server workload"
  [ "$proto" = none ] && skip="no load generator here can drive it"
  [ "$proto" = echo ] && [ ! -x Playground/Clients/Quic/bin/Release/net11.0/Playground.Clients.Quic ] \
      && skip="Clients/Quic (the driver) not built"
  [ "$proto" = h3 ] && [ ! -x "$H2LOAD_H3" ] && skip="no h2load with HTTP/3 (H2LOAD_H3)"
  [ -z "$(binary "$sample")" ] && skip="not built"
  if [ -n "$skip" ]; then
    printf '   %-24s %12s %10s %10s  %s\n' "$sample" - - - "skipped: $skip"
    ROWS+=("{\"sample\":\"$sample\",\"skipped\":\"$skip\"}")
    continue
  fi

  env_extra=(); [ "$extra" != "-" ] && [ -n "$extra" ] && read -ra env_extra <<< "$extra"

  # An origin first, when the fixture proxies or calls out. Its port is handed to the sample.
  upstream=()
  if [ "$origin" != "-" ]; then
    oport=$((port + 1000))
    oproto=$(registry | awk -v s="$origin" '$1==s{print $2}')
    # The origin's port needs the same grace as the sample's - an origin torn down by the previous
    # row can still hold it, and SO_REUSEPORT would let the next one bind alongside it.
    await_port_free "$oport" || echo "    origin port $oport never freed"
    opath=$(registry | awk -v s="$origin" '$1==s{print $4}')
    if ! start origin "$origin" "$oproto" "$oport" "${opath:-/}"; then
      printf '   %-24s %12s %10s %10s  %s\n' "$sample" - - - "skipped: origin $origin failed"
      ROWS+=("{\"sample\":\"$sample\",\"skipped\":\"origin $origin failed\"}")
      cleanup; continue
    fi
    upstream=(PLAYGROUND_UPSTREAM_PORT="$oport")
  fi

  await_port_free "$port" || { echo "    port $port never freed"; }
  if ! start server "$sample" "$proto" "$port" "$path" "${env_extra[@]}" "${upstream[@]}"; then
    printf '   %-24s %12s %10s %10s  %s\n' "$sample" - - - "skipped: did not start"
    ROWS+=("{\"sample\":\"$sample\",\"skipped\":\"did not start\"}")
    cleanup; continue
  fi

  # The shape this sample was tuned at, or the global default. Load shape decides the number, so
  # it is part of the fixture rather than a knob to leave at whatever it happened to be.
  CONNS=$(bench_tuned_conns "$sample")

  if [ "$TUNE" = 1 ]; then
    echo "    tuning $sample ..."
    read -r tc trps tcpu < <(bench_sweep "$proto" "$port" 4 "$WORK/tune.txt" "$path" "$SERVER_PID")
    if [ "${tc:-0}" != 0 ]; then
      grep -v "^$sample\t" bench/tuned.tsv 2>/dev/null > "$WORK/tuned.tmp" || true
      printf '%s\t%s\n' "$sample" "$tc" >> "$WORK/tuned.tmp"
      sort -o bench/tuned.tsv "$WORK/tuned.tmp"
      CONNS=$tc
      echo "    -> peak at $tc connections (${trps%%.*} req/s, ${tcpu}us/req)"
    fi
  fi

  bench_load "$proto" "$port" 4 "$WORK/warm.txt" "$path" >/dev/null      # warm: JIT, slabs, handshakes
  t0=$(cpu_ticks "$SERVER_PID")
  rps=$(bench_load "$proto" "$port" "$SECONDS_" "$WORK/$STAMP.txt" "$path")
  t1=$(cpu_ticks "$SERVER_PID")
  cleanup

  note=""; rps=${rps:-0}
  if [ "$(awk -v r="$rps" 'BEGIN{print (r == 0)}')" = 1 ]; then note="driver produced no number"; rps=0
  fi
  if bad=$(bad_run "$WORK/$STAMP.txt"); then note="discarded: $bad"; rps=0
  fi
  if full=$(bench_conntrack_full); then note="discarded: conntrack table full ($full)"; rps=0
  fi

  # As a percentage of REACTORS cores, not one - two pegged reactors burn 200% of a core.
  util=$(awk -v t="$((t1 - t0))" -v d="$SECONDS_" -v r="$REACTORS" \
        'BEGIN{printf "%.0f", (t/100.0)/d*100/r}')
  cpu=$(awk -v t="$((t1 - t0))" -v r="$rps" -v d="$SECONDS_" \
        'BEGIN{ if (r>0) printf "%.2f", (t/100.0)/(r*d)*1e6; else print "0" }')
  if [ "$rps" != 0 ] && [ "$util" -lt "$MIN_UTIL" ]; then
    note="unsaturated (${util}%) - raise CONNS/THREADS"
  fi

  delta="-"
  if [ -n "${OLD[$sample]:-}" ] && [ "$rps" != 0 ]; then
    delta=$(awk -v a="$rps" -v b="${OLD[$sample]}" 'BEGIN{printf "%+.1f%%", (a/b-1)*100}')
  fi
  printf '   %-24s %12.0f %8sus %10s  %s\n' "$sample" "$rps" "$cpu" "$delta" "$note"
  ROWS+=("{\"sample\":\"$sample\",\"proto\":\"$proto\",\"rps\":$rps,\"cpu_us_per_req\":$cpu,\"util_pct\":$util,\"conns\":$CONNS,\"note\":\"$note\"}")
done < <(registry)

{
  printf '{\n  "stamp": "%s",\n  "host": "%s",\n  "kernel": "%s",\n' \
         "$STAMP" "$(hostname)" "$(uname -r)"
  printf '  "reactors": %s, "conns": %s, "threads": %s, "seconds": %s,\n' \
         "$REACTORS" "$CONNS" "$THREADS" "$SECONDS_"
  printf '  "commit": "%s", "dirty": %s,\n' "$(bench_commit)" "$(bench_dirty)"
  printf '  "cpu": "%s", "governor": "%s", "server_cpus": "%s",\n' "$(bench_cpu)" "$(bench_gov)" "$SERVER_CPUS"
  printf '  "samples": [\n    '
  (IFS=$',\n'; printf '%s' "${ROWS[*]}")
  printf '\n  ]\n}\n'
} > "$RESULT"

cp "$RESULT" "$OUT/latest.json"
echo
echo "   saved $RESULT  (and $OUT/latest.json)"
