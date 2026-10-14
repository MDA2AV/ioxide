#!/usr/bin/env bash
# nghttp2 versus the pure-C# HTTP/2, with and without TLS, on one load generator.
#
# The reason this exists as its own script: the two implementations TRADE PLACES depending on the
# load shape. At 32 connections over 4 reactors nghttp2 is ahead; at 64 over 2 the managed one is,
# by a lot. So a single cell proves nothing, and the only honest comparison holds everything
# constant except the implementation - same h2load invocation, same reactor count, same body, same
# TLS backend, interleaved so drift hits both arms equally.
#
# TLS here is BoringSSL both ways, which is the default. Which backend does not matter for this
# question: both arms carry the identical TLS cost, so it cancels.
set -uo pipefail
cd "$(dirname "$0")/.."

REACTORS=${REACTORS:-2}
DURATION=${DURATION:-10}
CONNS=${CONNS:-64}
THREADS=${THREADS:-8}
STREAMS=${STREAMS:-32}
PASSES=${PASSES:-3}
OUT=${OUT:-/tmp/h2-matrix}
mkdir -p "$OUT"

PID=""
stop() {
  [ -z "$PID" ] && return 0
  kill "$PID" 2>/dev/null
  for _ in $(seq 40); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""
}
trap stop EXIT

await_free() {
  for _ in $(seq 60); do ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN || return 0; sleep 0.1; done
  return 1
}

cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

declare -A BEST CPU

cell() {  # cell <label> <sample> <port> <tls:0|1>
  local label=$1 sample=$2 port=$3 tls=$4
  await_free "$port" || { echo "  !! $port busy"; return; }

  PLAYGROUND_PORT=$port PLAYGROUND_REACTORS=$REACTORS \
    "Playground/$sample/bin/Release/net11.0/Playground.${sample//\//.}" >"$OUT/server.log" 2>&1 &
  PID=$!

  local url="http://127.0.0.1:$port/" extra=(--no-tls-proto=h2c)
  [ "$tls" = 1 ] && { url="https://127.0.0.1:$port/"; extra=(); }

  local up=0
  for _ in $(seq 100); do
    kill -0 "$PID" 2>/dev/null || break
    if [ "$tls" = 1 ]; then curl -sk -o /dev/null --max-time 1 --http2 "$url" && { up=1; break; }
    else curl -s -o /dev/null --max-time 1 --http2-prior-knowledge "$url" && { up=1; break; }; fi
    sleep 0.1
  done
  [ $up = 0 ] && { echo "  !! $label never answered"; tail -2 "$OUT/server.log"; stop; return; }

  # Same bytes out of every arm, or this is not one comparison but four.
  local n; n=$(curl -sk --http2 --http2-prior-knowledge "$url" 2>/dev/null | wc -c)
  [ "$n" != 2 ] && { echo "  !! $label served $n bytes, expected 2"; stop; return; }

  h2load -t"$THREADS" -c"$CONNS" -m "$STREAMS" -D 4 "${extra[@]}" "$url" >/dev/null 2>&1   # warm

  local t0 t1 rps; t0=$(cpu_ticks "$PID")
  h2load -t"$THREADS" -c"$CONNS" -m "$STREAMS" -D "$DURATION" "${extra[@]}" "$url" >"$OUT/$label.txt" 2>&1
  t1=$(cpu_ticks "$PID")
  rps=$(grep -oP 'finished in .*, \K[\d.]+(?= req/s)' "$OUT/$label.txt" | head -1)
  local bad; bad=$(grep -oP 'requests: .*, \K\d+(?= failed)' "$OUT/$label.txt" | head -1)
  stop

  rps=${rps:-0}
  if [ "${bad:-0}" != 0 ]; then echo "  !! $label had $bad failed requests - discarded"; return; fi

  local us; us=$(awk -v t="$((t1 - t0))" -v r="$rps" -v d="$DURATION" \
    'BEGIN{ if (r>0) printf "%.2f", (t/100.0)/(r*d)*1e6; else print "0" }')
  if awk -v a="$rps" -v b="${BEST[$label]:-0}" 'BEGIN{exit !(a>b)}'; then
    BEST[$label]=$rps; CPU[$label]=$us
  fi
  printf '    %-22s %12s req/s   %7s us cpu/req\n' "$label" "$rps" "$us"
}

echo "== h2: nghttp2 vs pure C#   ($REACTORS reactors, $CONNS conns, $STREAMS streams, ${DURATION}s)"
for pass in $(seq "$PASSES"); do
  echo "-- pass $pass/$PASSES"
  cell nghttp2-h2c   Http2/Nghttp2    8080 0
  cell managed-h2c   Http2/ManagedBuffered    8080 0
  cell nghttp2-tls   Http2/Tls        8443 1
  cell managed-tls   Http2/Tls 8443 1
done

echo
echo "== best of $PASSES passes"
printf '   %-14s %12s %12s %10s\n' TRANSPORT NGHTTP2 'PURE C#' 'C# / NGHTTP2'
awk -v a="${BEST[nghttp2-h2c]:-0}" -v b="${BEST[managed-h2c]:-0}" \
    'BEGIN{printf "   %-14s %12.0f %12.0f %9.2fx\n", "cleartext", a, b, (a>0)? b/a : 0}'
awk -v a="${BEST[nghttp2-tls]:-0}" -v b="${BEST[managed-tls]:-0}" \
    'BEGIN{printf "   %-14s %12.0f %12.0f %9.2fx\n", "tls", a, b, (a>0)? b/a : 0}'
echo
printf '   %-14s %12s %12s\n' 'cpu/req' 'nghttp2' 'pure C#'
printf '   %-14s %12s %12s\n' cleartext "${CPU[nghttp2-h2c]:-?}us" "${CPU[managed-h2c]:-?}us"
printf '   %-14s %12s %12s\n' tls       "${CPU[nghttp2-tls]:-?}us" "${CPU[managed-tls]:-?}us"
echo
awk -v c="${BEST[nghttp2-h2c]:-0}" -v t="${BEST[nghttp2-tls]:-0}" \
    'BEGIN{ if (c>0) printf "   TLS costs nghttp2  %.2fx\n", t/c }'
awk -v c="${BEST[managed-h2c]:-0}" -v t="${BEST[managed-tls]:-0}" \
    'BEGIN{ if (c>0) printf "   TLS costs pure C#  %.2fx\n", t/c }'
