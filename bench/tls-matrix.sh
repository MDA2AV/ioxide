#!/usr/bin/env bash
# The TLS backend matrix: h1 and h2, each in plaintext and in all three TLS configurations.
#
#   plaintext        no TLS at all - the baseline everything else is measured against
#   openssl          BoringSSL encrypts and decrypts.             KernelTx=0 KernelRx=0  (default)
#   ktls-tx          kernel encrypts, BoringSSL decrypts.         KernelTx=1 KernelRx=0
#   ktls             kernel does both.                            KernelTx=1 KernelRx=1
#
# There is no ktls-rx-only cell: RX is programmed at the same handoff as TX, so TlsService gates
# it on both (src/ioxide/Tls/TlsService.cs). Asking for RX alone is refused at startup.
#
# Everything here is LOOPBACK. That is the honest caveat on the whole table: kTLS exists to enable
# sendfile and NIC crypto offload, and neither is reachable over lo. What this measures is the
# cost of the kernel path itself, with none of its upside.
set -uo pipefail
cd "$(dirname "$0")/.."

REACTORS=${REACTORS:-4}          # 4 of 32 cores, so the load generator is never the bottleneck
DURATION=${DURATION:-10}
CONNS=${CONNS:-64}
THREADS=${THREADS:-4}
PASSES=${PASSES:-2}              # interleaved: the whole matrix twice, best of both per cell
BODIES=${BODIES:-"64 8192"}
OUT=${OUT:-/tmp/tls-matrix}

mkdir -p "$OUT"
SERVER_PID=""

stop_server() {
  [[ -z "$SERVER_PID" ]] && return 0
  kill "$SERVER_PID" 2>/dev/null
  for _ in $(seq 40); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
}
trap stop_server EXIT

# Start a sample and block until it actually answers. Waiting on the PORT is not enough: with
# SO_REUSEPORT a stale process from a previous run would also bind it, and the load would be split
# between two servers - which is exactly how three phantom failures got into an earlier report.
start_server() {
  local bin=$1 port=$2 proto=$3; shift 3
  if ss -ltn "sport = :$port" | grep -q LISTEN; then
    echo "  !! port $port is already held - refusing to start" >&2; return 1
  fi
  env "$@" "$bin" >"$OUT/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 100); do
    kill -0 "$SERVER_PID" 2>/dev/null || { echo "  !! server exited"; tail -3 "$OUT/server.log"; return 1; }
    case $proto in
      h1)   curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/"     && return 0 ;;
      h1s)  curl -sk -o /dev/null --max-time 1 "https://127.0.0.1:$port/"   && return 0 ;;
      h2c)  curl -s -o /dev/null --max-time 1 --http2-prior-knowledge "http://127.0.0.1:$port/" && return 0 ;;
      h2)   curl -sk -o /dev/null --max-time 1 --http2 "https://127.0.0.1:$port/" && return 0 ;;
    esac
    sleep 0.1
  done
  echo "  !! server never answered on $port"; tail -3 "$OUT/server.log"; return 1
}

# A cell whose server quietly ignored PLAYGROUND_BODY would still produce a number, and that
# number would be compared against cells serving a different payload. Assert instead.
assert_body() {
  local port=$1 proto=$2 want=$3 got
  case $proto in
    h1)  got=$(curl -s   "http://127.0.0.1:$port/"  | wc -c) ;;
    h1s) got=$(curl -sk  "https://127.0.0.1:$port/" | wc -c) ;;
    h2c) got=$(curl -s --http2-prior-knowledge "http://127.0.0.1:$port/" | wc -c) ;;
    h2)  got=$(curl -sk --http2 "https://127.0.0.1:$port/" | wc -c) ;;
  esac
  [[ "$got" == "$want" ]] && return 0
  echo "  !! body mismatch on $port: asked $want, served $got" >&2; return 1
}

# utime+stime of the server process, in ticks. Divided by the request count this is the metric
# that actually separates the backends - throughput saturates, CPU per request does not.
cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# rps, printed bare so the caller can do arithmetic on it
run_load() {
  local proto=$1 port=$2 tag=$3
  case $proto in
    h1|h1s)
      local scheme=http; [[ $proto == h1s ]] && scheme=https
      wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency \
          "$scheme://127.0.0.1:$port/" >"$OUT/$tag.txt" 2>&1
      grep -oP 'Requests/sec:\s+\K[\d.]+' "$OUT/$tag.txt" | head -1
      ;;
    h2c|h2)
      local scheme=https extra=()
      [[ $proto == h2c ]] && { scheme=http; extra=(--no-tls-proto=h2c); }
      h2load -t"$THREADS" -c"$CONNS" -m 32 -D "$DURATION" "${extra[@]}" \
             "$scheme://127.0.0.1:$port/" >"$OUT/$tag.txt" 2>&1
      grep -oP 'finished in .*, \K[\d.]+(?= req/s)' "$OUT/$tag.txt" | head -1
      ;;
  esac
}

declare -A BEST
declare -A CPU

cell() {                     # cell <label> <bin> <port> <proto> <body> [env...]
  local label=$1 bin=$2 port=$3 proto=$4 body=$5; shift 5
  local tag="${label//[^a-z0-9]/_}_$body"
  start_server "$bin" "$port" "$proto" \
      PLAYGROUND_REACTORS="$REACTORS" PLAYGROUND_PORT="$port" PLAYGROUND_BODY="$body" "$@" || {
    stop_server; BEST["$label|$body"]=${BEST["$label|$body"]:-0}; return; }

  # A failed pass is reported, not recorded - it must not erase a number a passing pass measured.
  # For the ktls cells this is routine, not hypothetical: kTLS-RX kills about one first connection
  # in twelve, and one of them landing on the probe would otherwise zero a measured cell.
  if ! assert_body "$port" "$proto" "$body"; then
    stop_server; BEST["$label|$body"]=${BEST["$label|$body"]:-0}; return
  fi

  # One short warm pass the numbers are taken after: JIT, the pool's first slabs, and for TLS the
  # first handshake per reactor all land here instead of in the measurement.
  run_load "$proto" "$port" "warm_$tag" >/dev/null

  local t0 t1 rps; t0=$(cpu_ticks "$SERVER_PID")
  rps=$(run_load "$proto" "$port" "$tag")
  t1=$(cpu_ticks "$SERVER_PID")
  stop_server

  rps=${rps:-0}
  # ticks are 1/100 s; (ticks/100) / (rps*DURATION) seconds per request, printed as microseconds
  local us; us=$(awk -v t="$((t1 - t0))" -v r="$rps" -v d="$DURATION" \
    'BEGIN{ if (r>0) printf "%.2f", (t/100.0)/(r*d)*1e6; else print "0" }')

  local prev=${BEST["$label|$body"]:-0}
  if awk -v a="$rps" -v b="$prev" 'BEGIN{exit !(a>b)}'; then
    BEST["$label|$body"]=$rps
    CPU["$label|$body"]=$us
  fi
  printf '    %-22s body=%-5s %12s req/s   %7s us cpu/req\n' "$label" "$body" "$rps" "$us"
}

B=Playground
for pass in $(seq "$PASSES"); do
  echo "== pass $pass/$PASSES  (${REACTORS} reactors, ${CONNS} conns, ${DURATION}s)"
  for body in $BODIES; do
    cell h1-plaintext $B/Tcp/Raw/bin/Release/net11.0/Playground.Tcp.Raw           8080 h1  "$body"
    cell h1-openssl   $B/Tls/OpenSsl/bin/Release/net11.0/Playground.Tls.OpenSsl   8443 h1s "$body"
    cell h1-ktls-tx   $B/Tls/KtlsTx/bin/Release/net11.0/Playground.Tls.KtlsTx     8444 h1s "$body"
    cell h1-ktls      $B/Tls/Ktls/bin/Release/net11.0/Playground.Tls.Ktls         8445 h1s "$body"

    cell h2-plaintext $B/Http2/Nghttp2/bin/Release/net11.0/Playground.Http2.Nghttp2 8081 h2c "$body"
    cell h2-openssl   $B/Http2/Tls/bin/Release/net11.0/Playground.Http2.Tls         8446 h2  "$body" PLAYGROUND_KTLS_TX=0 PLAYGROUND_KTLS_RX=0
    cell h2-ktls-tx   $B/Http2/Tls/bin/Release/net11.0/Playground.Http2.Tls         8447 h2  "$body" PLAYGROUND_KTLS_TX=1 PLAYGROUND_KTLS_RX=0
    cell h2-ktls      $B/Http2/Tls/bin/Release/net11.0/Playground.Http2.Tls         8448 h2  "$body" PLAYGROUND_KTLS_TX=1 PLAYGROUND_KTLS_RX=1
  done
done

echo
echo "== best of $PASSES passes"
printf '   %-3s %-10s %12s  %7s  %9s  %s\n' proto backend req/s vs-plain cpu/req vs-plain
for body in $BODIES; do
  echo "-- body $body bytes"
  for proto in h1 h2; do
    base=${BEST["$proto-plaintext|$body"]:-0}
    basecpu=${CPU["$proto-plaintext|$body"]:-0}
    for variant in plaintext openssl ktls-tx ktls; do
      v=${BEST["$proto-$variant|$body"]:-0}
      c=${CPU["$proto-$variant|$body"]:-0}
      awk -v p="$proto" -v n="$variant" -v v="$v" -v b="$base" -v c="$c" -v bc="$basecpu" \
        'BEGIN{printf "   %-3s %-10s %12.0f  %7s  %7.2fus  %s\n", p, n, v,
                 (b>0 && v>0)? sprintf("%.2fx", v/b) : "-", c,
                 (bc>0 && c>0)? sprintf("%.2fx", c/bc) : "-"}'
    done
  done
done
