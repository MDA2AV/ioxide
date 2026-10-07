#!/usr/bin/env bash
# Shared benchmark plumbing. Every script under bench/ sources this, so there is exactly one
# definition of how each protocol is driven.
#
# This file exists because there used to be two. run.sh drove HTTP/3 with
# "-t 4 --connections 64 -m 8 --send-batch 8" while any.sh used "--connections 64 -m 32", and the
# same server measured 260k under one and 505k under the other. Two numbers, both real, neither
# comparable - and nothing in either file said so. Change a driver here or nowhere.

# ── the machine ──────────────────────────────────────────────────────────────────────────────
#
# Hybrid CPUs make placement worth more than most optimisations: on an i9-14900K the same HTTP/3
# server measures 259k req/s on P-cores and 96k on E-cores. Left to the scheduler that difference
# lands wherever it lands, so the server is pinned to performance cores and the load generator is
# kept off them.

# Every thread of every performance core.
#
# The split that matters is P against E. On an i9-14900K the same HTTP/3 server measures ~490k req/s
# on the performance cores and 96k on the efficiency ones, and left alone the scheduler picks - so
# that hazard is worth removing. Which P-core is not worth choosing: measured at 2 reactors,
#
#   pinned to two cores        465k req/s
#   pinned to the 6GHz pair    482k
#   pinned to all P-cores      494k
#   unpinned                   505k
#
# Denying the scheduler any choice costs more than it saves; giving it the P-cores and no E-cores
# keeps almost all of the freedom and none of the cliff. The frequency tiers (6000/5700 here) are
# deliberately not distinguished - only the slowest tier is excluded.
bench_perf_cpus() {
    local low
    low=$(lscpu -e=CPU,MAXMHZ 2>/dev/null | awk 'NR>1{print $2}' | sort -n | head -1)

    if [ -z "$low" ]; then
        seq -s, 0 $(($(nproc) - 1))
        return
    fi

    local fast
    fast=$(lscpu -e=CPU,MAXMHZ 2>/dev/null | awk -v l="$low" 'NR>1 && $2>l {print $1}' | paste -sd,)

    [ -n "$fast" ] && echo "$fast" || seq -s, 0 $(($(nproc) - 1))
}

# The server gets the performance cores; the reactor count does not narrow it further.
bench_server_cpus() { bench_perf_cpus; }

# The driver is left to the scheduler. It has the rest of the machine either way, and confining it
# to the efficiency cores would only move the bottleneck onto the driver.
bench_client_cpus() { seq -s, 0 $(($(nproc) - 1)); }

bench_is_hybrid() {
    [ "$(lscpu -e=MAXMHZ 2>/dev/null | awk 'NR>1{print $1}' | sort -u | wc -l)" -gt 1 ]
}

# ── preconditions ────────────────────────────────────────────────────────────────────────────

# A leaked server from an earlier run co-binds the port under SO_REUSEPORT, the kernel fans
# connections across every process bound to it, and the result is a blend of two builds that looks
# like a clean number. Refuse to start rather than measure that.
bench_assert_port_free() {
    local port=$1 tcp udp
    tcp=$(ss -tlnH 2>/dev/null | grep -c ":$port ")
    udp=$(ss -ulnH 2>/dev/null | grep -c ":$port ")

    if [ "$tcp" != 0 ] || [ "$udp" != 0 ]; then
        echo "port $port already bound (tcp=$tcp udp=$udp) - a leaked server would be measured too" >&2
        return 1
    fi
    return 0
}

# After the server starts, its listeners must be its own and no one else's.
bench_assert_single_listener() {
    local port=$1 expect=$2 kind=${3:-tcp} n
    if [ "$kind" = udp ]; then
        n=$(ss -ulnH 2>/dev/null | grep -c ":$port ")
    else
        n=$(ss -tlnH 2>/dev/null | grep -c ":$port ")
    fi

    # One socket per reactor under SO_REUSEPORT; more than that means another process is listening.
    if [ "$n" -gt "$expect" ]; then
        echo "port $port has $n $kind listeners, expected $expect - another server is bound" >&2
        return 1
    fi
    return 0
}

# Each reactor binds its own socket and the port answers from the first one, so load started then
# reaches only the reactors bound so far.
bench_await_listeners() {
    local port=$1 expect=$2 kind=${3:-tcp} n=0
    for _ in $(seq 100); do
        if [ "$kind" = udp ]; then
            n=$(ss -ulnH 2>/dev/null | grep -c ":$port ")
        else
            n=$(ss -tlnH 2>/dev/null | grep -c ":$port ")
        fi
        [ "$n" -ge "$expect" ] && return 0
        sleep 0.1
    done
    echo "port $port has $n of $expect $kind listeners after 10 s" >&2
    return 1
}

# With nf_conntrack loaded (Docker's NAT rules load it) every connection, loopback included, holds a
# table entry for 120 s after it closes. A full table drops new SYNs without a word, so a cell that
# opens connections faster than they expire stalls and reads as a slow server. Prints "count/max".
bench_conntrack_full() {
    local dir=${1:-/proc/sys/net/netfilter} count max
    count=$(cat "$dir/nf_conntrack_count" 2>/dev/null) || return 1
    max=$(cat "$dir/nf_conntrack_max" 2>/dev/null) || return 1
    [ "$count" -ge $((max * 95 / 100)) ] || return 1
    echo "$count/$max"
}

# A sample's apphost is named after its project; a renamed sample leaves the old one in bin/.
bench_binary() {
    local dir=Playground/$1 proj name
    proj=$(ls "$dir"/*.csproj 2>/dev/null | head -1)
    [ -n "$proj" ] || return 0
    name=$(grep -oP '<AssemblyName>\K[^<]+' "$proj" | head -1)
    name=${name:-$(basename "$proj" .csproj)}
    [ -x "$dir/bin/Release/net11.0/$name" ] && echo "$dir/bin/Release/net11.0/$name"
    return 0
}

# ── the drivers ──────────────────────────────────────────────────────────────────────────────
#
# $1 proto, $2 port, $3 seconds, $4 output file, $5 path, $6 scale (1 = the standard load).
# Scale multiplies the concurrency and exists for the headroom probe below; a measured run always
# uses 1.

# HTTP/3 needs an h2load built with ngtcp2/nghttp3 - most distributions' is not, and reports 0 started.
H2LOAD_H3=${H2LOAD_H3:-$HOME/h3x/bench/h2load}

bench_load() {
    local proto=$1 port=$2 secs=$3 out=$4 path=$5 scale=${6:-1}
    local conns=$((CONNS * scale)) threads=$THREADS streams=$((32 * scale))
    local pin=()

    # The driver is not pinned - see bench_client_cpus.
    pin=()

    case $proto in
        h1|h1s)
            local scheme=http; [ "$proto" = h1s ] && scheme=https
            "${pin[@]}" wrk -t"$threads" -c"$conns" -d"${secs}s" "$scheme://127.0.0.1:$port$path" >"$out" 2>&1
            grep -oP 'Requests/sec:\s+\K[\d.]+' "$out" | head -1 ;;
        h2c|h2)
            local scheme=https extra=()
            [ "$proto" = h2c ] && { scheme=http; extra=(--no-tls-proto=h2c); }
            "${pin[@]}" h2load -t"$threads" -c"$conns" -m "$streams" -D "$secs" "${extra[@]}" \
                   "$scheme://127.0.0.1:$port$path" >"$out" 2>&1
            grep -oP 'finished in .*, \K[\d.]+(?= req/s)' "$out" | head -1 ;;
        echo)
            # The driver is a Playground sample too - Clients/Quic, the client half of Quic/Raw.
            local drv=Playground/Clients/Quic/bin/Release/net11.0/Playground.Clients.Quic
            [ -x "$drv" ] || { echo ""; return; }
            "${pin[@]}" env PLAYGROUND_QUIC_PORT="$port" PLAYGROUND_ECHO_CONNS="$conns" \
                PLAYGROUND_ECHO_SECONDS="$secs" "$drv" >"$out" 2>&1
            grep -oP '^\K[\d.]+(?= req/s)' "$out" | head -1 ;;
        h3)
            # Not h3x: its rate divides by the whole run, which waits ~30 s on any request that never
            # finishes - a dozen stuck streams made a 300k req/s server read as 50k.
            [ -x "$H2LOAD_H3" ] || { echo "" ; return; }
            "${pin[@]}" "$H2LOAD_H3" --alpn-list=h3 -D "$secs" -c "$conns" -m "$streams" \
                -t "$(( threads < conns ? threads : conns ))" "https://127.0.0.1:$port$path" >"$out" 2>&1
            grep -oP 'finished in [\d.]+s, \K[\d.]+(?= req/s)' "$out" | head -1 ;;
    esac
}

# ── did we measure the server, or the driver? ────────────────────────────────────────────────
#
# Reactor utilisation does not answer this. A run can peg both reactors and still be driver-bound:
# fewer requests in flight means less batching per wakeup, so the server burns more CPU per request
# while looking fully busy. The HTTP/3 case that started all this sat at 97% utilisation and 7.5us
# per request; the same server under a heavier driver did 3.8us.
#
# So ask the machine instead. Re-run briefly with more concurrency: if throughput climbs, the
# measured number was the driver's ceiling and not the server's.
bench_headroom() {
    local proto=$1 port=$2 out=$3 path=$4 measured=$5
    local probe

    probe=$(bench_load "$proto" "$port" 4 "$out" "$path" 2)

    [ -z "$probe" ] || [ "$measured" = 0 ] && { echo 0; return; }

    awk -v a="$probe" -v b="$measured" 'BEGIN{ printf "%.0f", (a/b-1)*100 }'
}

# ── provenance ───────────────────────────────────────────────────────────────────────────────
#
# A result that cannot be tied to a tree is archaeology. One recorded run carries commit 96137b9
# and samples that did not exist until 15 hours later, because the samples were sitting uncommitted
# when it ran - so the honest field is not the commit alone but whether the tree was clean.
bench_commit()  { git rev-parse --short HEAD 2>/dev/null || echo unknown; }
bench_dirty()   { [ -n "$(git status --porcelain 2>/dev/null)" ] && echo true || echo false; }
bench_cpu()     { grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'; }
bench_gov()     { cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown; }

# ── finding the parameters that measure the server ───────────────────────────────────────────
#
# The load shape is not a detail of how a number was taken - it decides the number. The same HTTP/3
# server does ~800k req/s driven by 16 connections and 442k by 64, because per-connection cost
# dominates once a reactor is juggling enough of them. A fixed default therefore reports whatever
# that default happens to hit, which for CONNS=64 is the far side of a cliff.
#
# So sweep, and keep the peak. Prints "<conns> <rps> <cpu_us>" for the best rung on stdout and the
# whole ladder on stderr, so a tuning run shows its working.
bench_sweep() {
    local proto=$1 port=$2 secs=$3 out=$4 path=$5 pid=$6
    local best_c=0 best_rps=0 best_cpu=0

    for c in ${BENCH_LADDER:-4 8 16 32 64 128}; do
        local t0 t1 rps
        t0=$(awk '{print $14+$15}' /proc/"$pid"/stat 2>/dev/null || echo 0)
        rps=$(CONNS=$c bench_load "$proto" "$port" "$secs" "$out" "$path")
        t1=$(awk '{print $14+$15}' /proc/"$pid"/stat 2>/dev/null || echo 0)

        rps=${rps:-0}
        [ "${rps%%.*}" = 0 ] && continue

        local cpu
        cpu=$(awk -v t="$((t1 - t0))" -v r="$rps" -v d="$secs" \
              'BEGIN{ if (r>0) printf "%.2f", (t/100.0)/(r*d)*1e6; else print 0 }')

        printf '      conns=%-4s %12.0f req/s  %6sus/req\n' "$c" "$rps" "$cpu" >&2

        awk -v a="$rps" -v b="$best_rps" 'BEGIN{exit !(a>b)}' && { best_c=$c; best_rps=$rps; best_cpu=$cpu; }
    done

    echo "$best_c $best_rps $best_cpu"
}

# Per-sample connection count chosen by a tuning run, falling back to the global default. Keeping
# the winner per sample is what makes a later run both reproducible and near the server's peak.
bench_tuned_conns() {
    local sample=$1 file=bench/tuned.tsv
    [ -f "$file" ] || { echo "${CONNS:-64}"; return; }
    awk -v s="$sample" '$1==s {print $2; found=1} END{if(!found) print ""}' "$file" \
        | grep -E '^[0-9]+$' || echo "${CONNS:-64}"
}
