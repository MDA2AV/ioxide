#!/usr/bin/env bash
# Kotlin vs C# ioxide on one box, the bench/.work/wake-cq/ab.sh way: every round runs every build back to
# back in a rotated order, so drift hits all of them, and the verdict is the median of each build's per-round
# ratio to the reference. cs2 (a second C# worktree at the same commit) and kt2 (the same Kotlin build run
# again) are the noise controls.
#
# Per cell: req/s (wrk), server CPU us/req and util from /proc/PID/stat - every thread of the process, so the
# JVM's JIT and GC threads count, on the same CPUs as the reactors.
#
# Raw and Pipe are the Tcp samples under wrk. Base, Pipelined and Churn are HttpArena's h1 load shapes under
# gcannon (baseline's GET, pipelined's -p 16, limited-conn's -r 10), against the counting servers (tcp-count and
# cs-count, one response per request); cs2 runs the same cs-count binary again.
#
#   BUILDS="cs kt cs2 kt2" SAMPLES="Raw Pipe Base Pipelined Churn" ROUNDS=5 kotlin/bench/ab.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
KT=$(cd "$HERE/.." && pwd)
WT=/home/diogo/Desktop/Socket/ioxide/.claude/worktrees
declare -A CSTREE=([cs]=${CS:-$WT/bench-wake-a} [cs2]=${CS2:-$WT/bench-wake-a2})
JAVA=${JAVA:-$HOME/.jdks/jdk-25.0.5+8/bin/java}
read -ra JFLAGS <<<"${JFLAGS:---enable-native-access=ALL-UNNAMED}"
KLIB=${KLIB:-$KT/playground/build/install/playground/lib}
CSCOUNT=${CSCOUNT:-$HERE/cs-count/bin/Release/net11.0/CsCount}
GCANNON=${GCANNON:-/home/diogo/Desktop/Socket/gcannon/gcannon}
REQ=${REQ:-/home/diogo/Desktop/Socket/ioxide/bench/.work/arena-sweep/requests}
CONNTRACK=/proc/sys/net/netfilter/nf_conntrack_count
OUT=${OUT:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"

read -ra BUILDS <<<"${BUILDS:-cs kt cs2 kt2}"
read -ra SAMPLES <<<"${SAMPLES:-Raw}"
ROUNDS=${ROUNDS:-5}
SECS=${SECS:-10}
WARM=${WARM:-5}
CONNS=${CONNS:-64}
GCONNS=${GCONNS:-128}
THREADS=${THREADS:-4}
REACTORS=${REACTORS:-2}
SERVER_CPUS=${SERVER_CPUS:-2,6}
CLIENT_CPUS=${CLIENT_CPUS:-0,1,14,15}
PORT=${PORT:-8080}
BODY=${BODY:-2}

listeners() { ss -ltnH "sport = :$PORT" 2>/dev/null | wc -l; }

counting() { case $1 in Base | Pipelined | Churn) return 0 ;; *) return 1 ;; esac; }

start() {  # build sample log; sets PID to the server process itself, so /proc/$PID is what gets measured
  local b=$1 s=$2 log=$3 bin sample=tcp-${2,,}
  counting "$s" && sample=tcp-count
  case $b in
    cs | cs2)
      bin=${CSTREE[$b]}/Playground/Tcp/$s/bin/Release/net11.0/Playground.Tcp.$s
      counting "$s" && bin=$CSCOUNT
      [ -x "$bin" ] || { echo "missing $bin" >&2; return 1; }
      PLAYGROUND_PORT=$PORT PLAYGROUND_REACTORS=$REACTORS PLAYGROUND_BODY=$BODY taskset -c "$SERVER_CPUS" "$bin" >"$log" 2>&1 &
      ;;
    kt | kt2)
      PLAYGROUND_PORT=$PORT PLAYGROUND_REACTORS=$REACTORS PLAYGROUND_BODY=$BODY taskset -c "$SERVER_CPUS" \
        "$JAVA" "${JFLAGS[@]}" -cp "$KLIB/*" playground.MainKt "$sample" >"$log" 2>&1 &
      ;;
  esac
  PID=$!
}

load() {  # sample seconds output
  local g=(taskset -c "$CLIENT_CPUS" "$GCANNON" "http://127.0.0.1:$PORT" -c "$GCONNS" -t "$THREADS" -d "${2}s" --json)
  case $1 in
    Base) "${g[@]}" --raw "$REQ/get.raw" -p 1 ;;
    Pipelined) "${g[@]}" --raw "$REQ/pipeline.raw" -p 16 ;;
    Churn) "${g[@]}" --raw "$REQ/get.raw" -p 1 -r 10 ;;
    *) taskset -c "$CLIENT_CPUS" wrk -t"$THREADS" -c"$CONNS" -d"${2}s" "http://127.0.0.1:$PORT/" ;;
  esac >"$3" 2>&1
}

cell() {  # build sample round
  local b=$1 s=$2 r=$3 pid res=$OUT/$2-$1-$3.wrk
  counting "$s" && res=$OUT/$s-$b-$r.json
  for _ in $(seq 100); do [ "$(listeners)" = 0 ] && break; sleep 0.1; done
  [ "$(listeners)" = 0 ] || { echo "!! port $PORT still held" >&2; return; }
  # Churn makes ~100K connections/s and each leaves a conntrack entry; a full table drops SYNs silently.
  if [ "$s" = Churn ] && [ -r $CONNTRACK ]; then
    for _ in $(seq 300); do [ "$(<$CONNTRACK)" -lt 150000 ] && break; sleep 0.1; done
  fi

  start "$b" "$s" "$OUT/$s-$b-$r.log" || return
  pid=$PID
  for _ in $(seq 150); do [ "$(listeners)" -ge "$REACTORS" ] && break; sleep 0.1; done
  if [ "$(listeners)" != "$REACTORS" ]; then echo "!! $s/$b: $(listeners) listeners" >&2; kill "$pid"; wait "$pid" 2>/dev/null; return; fi

  load "$s" "$WARM" /dev/null
  local t0 t1
  t0=$(awk '{print $14 + $15}' "/proc/$pid/stat")
  load "$s" "$SECS" "$res"
  t1=$(awk '{print $14 + $15}' "/proc/$pid/stat")
  kill "$pid"; wait "$pid" 2>/dev/null

  local rps reqs bad
  if counting "$s"; then
    read -r reqs rps bad < <(python3 -Ic 'import json, sys
t = open(sys.argv[1]).read(); j = json.loads(t[t.index("{"):]); ok = j["status"]["2xx"]
print(ok, ok / j["elapsed_sec"], j["responses"] - ok + sum(j["errors"].values()))' "$res" 2>/dev/null)
    if [ -z "$reqs" ] || [ "$bad" != 0 ]; then
      echo "!! $s/$b round $r discarded: ${bad:-unparsable} non-2xx responses or errors" >&2
      return
    fi
  else
    rps=$(grep -oP 'Requests/sec:\s+\K[\d.]+' "$res")
    reqs=$(grep -oP '^\s*\K\d+(?= requests in)' "$res")
    if grep -q "Non-2xx\|Socket errors" "$res" || [ -z "$reqs" ]; then
      echo "!! $s/$b round $r discarded: $(grep -h 'Non-2xx\|Socket errors' "$res" | tr -s ' ')" >&2
      return
    fi
  fi
  awk -v s="$s" -v b="$b" -v r="$r" -v rps="$rps" -v q="$reqs" -v t="$((t1 - t0))" -v d="$SECS" -v n="$REACTORS" \
    'BEGIN { printf "%s\t%s\t%s\t%.0f\t%.3f\t%.0f\n", s, b, r, rps, t / 100.0 / q * 1e6, t / 100.0 / d / n * 100 }' \
    | tee -a "$OUT/rows.tsv"
}

echo "builds: ${BUILDS[*]}  samples: ${SAMPLES[*]}  rounds: $ROUNDS x ${SECS}s (+${WARM}s warm)  $REACTORS reactors on $SERVER_CPUS, -t$THREADS on $CLIENT_CPUS (wrk -c$CONNS, gcannon -c$GCONNS), body $BODY"
echo "jvm: $JAVA ${JFLAGS[*]}"
echo -e "sample\tbuild\tround\treq/s\tcpu_us/req\tutil%" | tee "$OUT/rows.tsv"
for r in $(seq "$ROUNDS"); do
  for s in "${SAMPLES[@]}"; do
    n=${#BUILDS[@]}
    for i in $(seq 0 $((n - 1))); do
      cell "${BUILDS[$(((i + r) % n))]}" "$s" "$r"
    done
  done
done

python3 - "$OUT/rows.tsv" "${BUILDS[0]}" <<'EOF'
import sys, statistics as st
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]).readlines()[1:]]
ref = sys.argv[2]
cell = {(s, b, r): (float(q), float(c), float(u)) for s, b, r, q, c, u in rows}
samples, builds = [], []
for s, b, *_ in rows:
    if s not in samples: samples.append(s)
    if b not in builds: builds.append(b)
print(f"\nmedians, and the median of each round's ratio to {ref} (paired):")
for s in samples:
    print(f"  {s}")
    for b in builds:
        rs = sorted({r for (ss, bb, r) in cell if ss == s and bb == b})
        if not rs: continue
        q, c, u = (st.median(cell[(s, b, r)][k] for r in rs) for k in range(3))
        pair = [r for r in rs if (s, ref, r) in cell]
        rq = st.median(cell[(s, b, r)][0] / cell[(s, ref, r)][0] for r in pair) if pair else float("nan")
        rc = st.median(cell[(s, b, r)][1] / cell[(s, ref, r)][1] for r in pair) if pair else float("nan")
        print(f"    {b:4} {q:10.0f} req/s {c:7.3f} us/req {u:4.0f}% util   vs {ref}: req/s {100*(rq-1):+5.1f}%  cpu/req {100*(rc-1):+5.1f}%  (n={len(rs)})")
EOF
echo "rows: $OUT/rows.tsv"
