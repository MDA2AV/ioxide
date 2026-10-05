#!/usr/bin/env bash
#
# The regression bench: every workload the repo can serve or drive, one number each.
#
#     dotnet build -c Release ioxide.slnx     # once
#     bash bench/run.sh                       # ~4 minutes
#
# Servers run 4 reactors (BENCH_REACTORS to override); the tcp-raw/tcp-pipe pair repeats at 12
# reactors as the io_uring baseline. Loads: wrk for everything TCP (fixed -c 64 -t 4,
# time-bounded), h2load built with HTTP/3 for the HTTP/3 server (H2LOAD_H3 to point at it), Bench.Clients for the
# ring-native clients. Sidecars (redis, postgres, an h2c nginx) start via docker when available;
# anything missing skips with a note instead of failing the run.
#
# Numbers are hardware-specific: compare runs on one machine, never across machines.
set -u
cd "$(dirname "$0")/.."

R=${BENCH_REACTORS:-4}
DUR=${BENCH_SECONDS:-8}

# The drivers live in one place. This file used to carry its own HTTP/3 invocation that differed
# from any.sh's, and the same server measured 260k under one and 505k under the other.
. "$(dirname "$0")/lib.sh"
BIN=bench/.work
mkdir -p $BIN
RESULTS=()

say()  { printf '%s\n' "$*" >&2; }
note() { RESULTS+=("$(printf '%-16s %3s  %s' "$1" "$2" "$3")"); }

play() { # $1 subdir, rest env; starts a playground binary detached
  local dir=$1; shift
  local exe
  exe=$(bench_binary "$dir")
  [ -z "$exe" ] && { say "missing binary for $dir"; return 1; }
  env "$@" setsid "$exe" > $BIN/server.log 2>&1 < /dev/null &
  sleep 3
}

# Scoped to this run's own children, not every Playground process on the machine - a developer
# with a sample running should not have it killed by a bench.
stop_play() { pkill -P $$ -f 'Playground[.]' 2>/dev/null; pkill -f "$BIN/" 2>/dev/null; sleep 1; }

wait_http() { # $1 url: poll until it answers (up to ~8s) so a slow start reads as fail-with-log
  for _ in $(seq 16); do
    curl -s -o /dev/null --max-time 1 "$1" && return 0
    sleep 0.5
  done
  return 1
}

wrk_h1() { # $1 url, $2 threads (default 4), $3 conns (default 64) -> req/s
  # wrk has no warm-up flag: a short throwaway run heats the server, then the measured one.
  local proto=h1; case "$1" in https://*) proto=h1s ;; esac
  local port; port=$(printf '%s' "$1" | sed -E 's|.*://[^:]+:([0-9]+).*|\1|')
  local path; path=$(printf '%s' "$1" | sed -E 's|.*://[^/]+||'); path=${path:-/}

  THREADS=${2:-4} CONNS=${3:-64} bench_load "$proto" "$port" 2 /dev/null "$path" >/dev/null 2>&1
  THREADS=${2:-4} CONNS=${3:-64} bench_load "$proto" "$port" "$DUR" "$BIN/wrk.txt" "$path" | cut -d. -f1
}

# ── tcp raw + pipes, 4 reactors and the 12-reactor baseline ─────────────────────────────────
# The classic plaintext workload: default 2-byte "ok" body, matching how this repo's numbers
# have always been quoted. The baseline rows scale the DRIVER too (-t18 -c512): an undersized
# wrk saturates itself before a 12-reactor server and the row measures the client instead.
for rc in $R 12; do
  T=4; C=64
  [ "$rc" = "12" ] && { T=18; C=512; }
  play Tcp/Raw PLAYGROUND_REACTORS=$rc PLAYGROUND_PORT=18080 \
    && note "tcp-raw" "${rc}r" "$(wrk_h1 http://127.0.0.1:18080/ $T $C) req/s"
  stop_play
  play Tcp/Pipe PLAYGROUND_REACTORS=$rc PLAYGROUND_PORT=18080 \
    && note "tcp-pipe" "${rc}r" "$(wrk_h1 http://127.0.0.1:18080/ $T $C) req/s"
  stop_play
done

# ── tls ─────────────────────────────────────────────────────────────────────────────────────
play Tls/SslStream PLAYGROUND_REACTORS=$R PLAYGROUND_PORT=18443 \
  && note "tls-sslstream" "${R}r" "$(wrk_h1 https://127.0.0.1:18443/) req/s"
stop_play
play Tls/OpenSsl PLAYGROUND_REACTORS=$R PLAYGROUND_PORT=18443 \
  && note "tls-openssl" "${R}r" "$(wrk_h1 https://127.0.0.1:18443/) req/s"
stop_play
if [ -d /sys/module/tls ]; then
  # The deployable hybrid (kernel TX, OpenSSL RX) - matches the matrix's ktls-tx cell.
  play Tls/KtlsTx PLAYGROUND_REACTORS=$R PLAYGROUND_PORT=18443 \
    && note "tls-ktls-tx" "${R}r" "$(wrk_h1 https://127.0.0.1:18443/) req/s"
  stop_play
else
  note "tls-ktls-tx" "${R}r" "SKIP (no 'tls' kernel module - sudo modprobe tls)"
fi

# ── h3 server ───────────────────────────────────────────────────────────────────────────────
play Http3/Nghttp3Request PLAYGROUND_REACTORS=$R PLAYGROUND_QUIC_PORT=18444 PLAYGROUND_PORT=18090
if [ -x "$H2LOAD_H3" ]; then
  N=$(CONNS=${CONNS:-64} THREADS=${THREADS:-8} REACTORS=$R \
      bench_load h3 18444 "$DUR" "$BIN/h3-server.txt" / | cut -d. -f1)
  note "h3-server" "${R}r" "${N:-fail} req/s"
else
  note "h3-server" "${R}r" "SKIP (no h2load with HTTP/3 - set H2LOAD_H3=/path/to/h2load)"
fi
# the h3 server stays up: the h3 client bench below dials it

# ── ring-native clients (Bench.Clients also runs $R reactors) ───────────────────────────────
CLI=bench/Bench.Clients/bin/Release/net11.0/Bench.Clients
note "client-h3" "${R}r" "$(BENCH_REACTORS=$R $CLI h3 127.0.0.1 18444 $DUR 2>$BIN/client-h3.log | grep -oE '[0-9]+ req/s' || echo fail)"
stop_play

play Tcp/Raw PLAYGROUND_REACTORS=$R PLAYGROUND_PORT=18081 PLAYGROUND_BODY=1024
note "client-h1" "${R}r" "$(BENCH_REACTORS=$R $CLI h1 127.0.0.1 18081 $DUR 2>$BIN/client-h1.log | grep -oE '[0-9]+ req/s' || echo fail)"
stop_play

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  cat > $BIN/h2c.conf <<'NGINX'
worker_processes 4;
events { worker_connections 4096; }
http { access_log off; server { listen 18464; http2 on;
  location / { return 200 "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; } } }
NGINX
  docker rm -f bench-h2c >/dev/null 2>&1
  docker run -d --name bench-h2c --network host -v "$PWD/$BIN/h2c.conf":/etc/nginx/nginx.conf:ro nginx >/dev/null 2>&1
  wait_http http://127.0.0.1:18464/ || say "h2c upstream slow to start"
  note "client-h2" "${R}r" "$(BENCH_REACTORS=$R $CLI h2 127.0.0.1 18464 $DUR 2>$BIN/client-h2.log | grep -oE '[0-9]+ req/s' || echo fail)"
  docker rm -f bench-h2c >/dev/null 2>&1
else
  note "client-h2" "${R}r" "SKIP (docker unavailable for the h2c upstream)"
fi

# ── redis / pg / file ───────────────────────────────────────────────────────────────────────
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker rm -f bench-redis >/dev/null 2>&1
  docker run -d --name bench-redis --network host redis:7-alpine >/dev/null 2>&1
  sleep 2
  play Clients/Redis PLAYGROUND_REACTORS=$R PLAYGROUND_PORT=18085 \
    && note "redis" "${R}r" "$(wrk_h1 http://127.0.0.1:18085/) req/s"
  stop_play
  docker rm -f bench-redis >/dev/null 2>&1

  docker rm -f bench-pg >/dev/null 2>&1
  docker run -d --name bench-pg --network host \
    -e POSTGRES_USER=bench -e POSTGRES_PASSWORD=bench -e POSTGRES_DB=bench \
    -e POSTGRES_HOST_AUTH_METHOD=trust postgres:18 >/dev/null 2>&1
  sleep 6
  play Clients/Pg PLAYGROUND_REACTORS=$R PLAYGROUND_PORT=18086 \
    && note "pg" "${R}r" "$(wrk_h1 http://127.0.0.1:18086/) req/s"
  stop_play
  docker rm -f bench-pg >/dev/null 2>&1
else
  note "redis" "${R}r" "SKIP (docker unavailable)"
  note "pg" "${R}r" "SKIP (docker unavailable)"
fi

play Clients/File PLAYGROUND_REACTORS=$R PLAYGROUND_PORT=18087 \
  && note "file" "${R}r" "$(wrk_h1 http://127.0.0.1:18087/index.html) req/s"
stop_play

# ── report ──────────────────────────────────────────────────────────────────────────────────
echo
echo "ioxide bench - $(date -u +%F) $(uname -r) - servers ${R}r (baseline 12r driven -t18 -c512), wrk -c64 -t4, ${DUR}s"
echo "────────────────────────────────────────────────────────"
for line in "${RESULTS[@]}"; do echo "$line"; done
