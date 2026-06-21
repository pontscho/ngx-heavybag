#!/usr/bin/env bash
# run-stress-tests.sh -- heavybag reproducible stress / load campaign orchestrator.
# Ledger: docs/stress-campaign.md. Mirrors run-replay-tests.sh (hb_render, getcnt
# lifted to JSON snapshots, exit-2-is-SKIP, committed-corpus determinism).
#
# SCENARIOS (mapped to the partner's focus list):
#   S1  perf-overhead     h2load H1/H2[/H3] baseline(waf off) vs enforce; req/s + latency
#   S2  rate-precision    wrk2 constant-arrival sweep on the shared rate zone
#   S3  correctness       mixed high-concurrency load; per-head counter invariants (THE gate)
#   S4  cpu-burst         warmup->burst->cooldown CPU%/RSS timeseries + burst-window HDR
#   S5  soak (opt-in)     long run: RSS/fd trend + reload cycling + leak regression
#
# USAGE:
#   bash run-stress-tests.sh --quick     # ~10s/scenario smoke; S3 invariants are the gate (this is the ctest)
#   bash run-stress-tests.sh             # full reference run (fills docs/stress-campaign.md)
#   bash run-stress-tests.sh --soak      # S5 only (opt-in; long)
#
# Reproducibility: nginx-side knobs are BAKED in the conf; only the load-side
# params are env-tunable and every one is recorded into each scenario's params.env
# + summary.json. The reproducible metric is the enforce-vs-off RATIO, not the
# machine-specific absolute req/s.
#
# Env params (all recorded):
#   HB_DUR(s)=20  HB_REQS=20000  HB_CONN=50  HB_STREAMS=10  HB_THREADS=4
#   HB_RATE=2000 (wrk2 arrival rate center)  HB_WORKERS=2 (worker_processes override)
#   HB_SOAK_DUR(s)=3600  HB_STRESS_CURL_FALLBACK=0 (dev-only: drive load with curl when h2load absent)
#
# Exit: 0 = ran + every executed invariant passed; 1 = an invariant FAILED (bug);
#       2 = preflight SKIP (sandbox not built, or load tool absent without fallback).

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
HERE=$ROOT/modules/ngx_http_heavybag/tests
# shellcheck source=/dev/null
. "$HERE/stress/stress-lib.sh"

SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
SRC_CONF=$HERE/stress/heavybag-stress-test.conf
CORPUS=$HERE/corpus
ARTI=$CORPUS/.stress
VERSIONS=$ROOT/tools/stress/versions.env
URLS=$CORPUS/stress-urls.txt
GEODB=$ROOT/geodb/location.db
STAT=http://127.0.0.1:28390/waf/stat

# fixed port band (283xx); see heavybag-stress-test.conf
P_BASE=28300 P_ENF=28301 P_DET=28302 P_RATE=28303 P_H3B=28304 P_H3E=28305
P_GEO=28306 P_MAIL=28381 P_STREAM=28391

# load-side params (env-tunable, all recorded)
HB_DUR=${HB_DUR:-20}
HB_REQS=${HB_REQS:-20000}
HB_CONN=${HB_CONN:-50}
HB_STREAMS=${HB_STREAMS:-10}
HB_THREADS=${HB_THREADS:-4}
HB_RATE=${HB_RATE:-2000}
HB_WORKERS=${HB_WORKERS:-2}
HB_SOAK_DUR=${HB_SOAK_DUR:-3600}
HB_STRESS_CURL_FALLBACK=${HB_STRESS_CURL_FALLBACK:-0}

# Mode comes from $1, falling back to HB_STRESS_MODE env (CTest passes it via ENV
# since heavybag_add_test has no positional-arg channel).
MODE=${HB_STRESS_MODE:-full}
case "${1:-}" in
    --quick) MODE=quick ;;
    --soak)  MODE=soak ;;
    "")      : ;;
    *)       echo "unknown arg: $1" >&2; exit 2 ;;
esac

# Soak is opt-in: a bare `ctest` must not spend an hour here. The registered
# heavybag_soak test sets HB_STRESS_MODE=soak; without the explicit opt-in it
# SKIPs (exit 2 -> CTest SKIPPED) immediately.
if [ "$MODE" = soak ] && [ "${HB_STRESS_SOAK_OPT_IN:-0}" != 1 ]; then
    echo "soak is opt-in -- set HB_STRESS_SOAK_OPT_IN=1 (and HB_SOAK_DUR) to run it; SKIP"
    exit 2
fi

# quick mode shrinks the workload to a ~10s/scenario smoke.
if [ "$MODE" = quick ]; then
    HB_REQS=2000; HB_CONN=20; HB_DUR=5
fi

# ---------------------------------------------------------------------------
# Render the conf: rewrite the baked /mnt prefix to $ROOT (hb_render) AND apply
# the worker_processes override. The nginx-side knobs are otherwise fixed.
# ---------------------------------------------------------------------------
RENDER_DIR=$CORPUS/.render
mkdir -p "$RENDER_DIR" "$ARTI"
CONF=$RENDER_DIR/heavybag-stress-test.conf
sed -e "s#/mnt/nvme/imaginarium/openresty#$ROOT#g" \
    -e "s/^worker_processes  2;/worker_processes  $HB_WORKERS;/" \
    "$SRC_CONF" > "$CONF"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[ -x "$NGINX" ] || { echo "sandbox nginx not built ($NGINX) -- SKIP"; exit 2; }
[ -f "$SBX/modules/ngx_http_heavybag_module.so" ] || { echo "deployed .so missing -- SKIP"; exit 2; }

GEO_OK=1; [ -f "$GEODB" ] || { GEO_OK=0; echo "NOTE: $GEODB absent -- geo dimension will SKIP"; }

echo "=== heavybag stress campaign ($MODE) ==="
VER_FRAG=$(mktemp); hb_versions_report "$VERSIONS" "$VER_FRAG"
HAVE_H2=0; [ -n "${HB_H2LOAD_BIN:-}" ] && HAVE_H2=1
HAVE_WRK=0; [ -n "${HB_WRK2_BIN:-}" ] && HAVE_WRK=1

if [ "$HAVE_H2" = 0 ] && [ "$HB_STRESS_CURL_FALLBACK" != 1 ]; then
    echo "h2load absent and HB_STRESS_CURL_FALLBACK!=1 -- SKIP (install nghttp2's h2load, or set the fallback for a curl-driven dev smoke)"
    exit 2
fi

# ---------------------------------------------------------------------------
# nginx lifecycle
# ---------------------------------------------------------------------------
stop_nginx() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
    local pf="$SBX/logs/nginx-stress.pid"
    [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null || true
}
trap stop_nginx EXIT

start_nginx() {
    "$NGINX" -p "$SBX/" -c "$CONF" -t 2>/dev/null || { echo "CONFIG TEST FAILED"; "$NGINX" -p "$SBX/" -c "$CONF" -t; exit 2; }
    stop_nginx; sleep 1
    "$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
    sleep 1
    curl -sf "$STAT/plain" >/dev/null || { echo "stat endpoint unreachable"; exit 2; }
}

NGINX_PIDFILE="$SBX/logs/nginx-stress.pid"

# ---------------------------------------------------------------------------
# machine header
# ---------------------------------------------------------------------------
hb_machine_json() {
    local cpu kern cores
    cpu=$(awk -F: '/model name/{gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo)
    kern=$(uname -r); cores=$(nproc)
    perl -e '
        sub esc { my $s=shift//""; $s=~s/\\/\\\\/g; $s=~s/"/\\"/g; return $s; }
        printf q({"cpu":"%s","kernel":"%s","cores":%d,"worker_processes":%d}),
            esc($ARGV[0]),esc($ARGV[1]),$ARGV[2],$ARGV[3];
    ' "$cpu" "$kern" "$cores" "$HB_WORKERS"
}

# write the common params.env into an artifact dir
hb_write_params() {
    local d="$1"
    {
        echo "MODE=$MODE"
        echo "HB_DUR=$HB_DUR HB_REQS=$HB_REQS HB_CONN=$HB_CONN HB_STREAMS=$HB_STREAMS"
        echo "HB_THREADS=$HB_THREADS HB_RATE=$HB_RATE HB_WORKERS=$HB_WORKERS"
        echo "HB_SOAK_DUR=$HB_SOAK_DUR HB_STRESS_CURL_FALLBACK=$HB_STRESS_CURL_FALLBACK"
        echo "GEO_OK=$GEO_OK HAVE_H2=$HAVE_H2 HAVE_WRK=$HAVE_WRK"
    } > "$d/params.env"
}

# timestamp passed in from the environment is not available (Date.now banned in
# scripts only); use date here -- this is a shell harness, not a workflow.
hb_artifact_dir() {
    local scen="$1" ts
    ts=$(date +%Y%m%d-%H%M%S)
    local d="$ARTI/${scen}-${ts}"
    mkdir -p "$d"
    hb_write_params "$d"
    echo "$d"
}

# ---------------------------------------------------------------------------
# load generators
# ---------------------------------------------------------------------------

# hb_h2load_proto_flags <proto> -> echoes the h2load flag(s) for h1|h2|h3
hb_h2load_proto_flags() {
    case "$1" in
        h1) echo "--h1" ;;
        h2) echo "" ;;
        h3) echo "--alpn-list=h3" ;;
    esac
}

# hb_load_single <proto> <url> <nreq> <conn> <streams> <logfile|""> <stdoutfile> [hdr...]
# Single-target load. Uses h2load if present, else the curl fallback (dev only).
hb_load_single() {
    local proto="$1" url="$2" n="$3" c="$4" m="$5" log="$6" so="$7"; shift 7
    local -a hdrs=(); local h; for h in "$@"; do hdrs+=(-H "$h"); done
    if [ "$HAVE_H2" = 1 ]; then
        local -a pf=(); local f; for f in $(hb_h2load_proto_flags "$proto"); do pf+=("$f"); done
        local -a logarg=(); [ -n "$log" ] && logarg=(--log-file="$log")
        "$HB_H2LOAD_BIN" -n "$n" -c "$c" -m "$m" "${pf[@]}" "${logarg[@]}" "${hdrs[@]}" "$url" >"$so" 2>&1
    else
        # curl fallback: -P concurrency, fixed request count. No latency log.
        printf '%s\n' $(seq "$n") | xargs -P "$c" -I_ curl -s -o /dev/null "${hdrs[@]}" "$url"
        echo "curl-fallback: sent $n requests to $url (proto=$proto ignored)" >"$so"
    fi
}

# hb_load_corpus <proto> <base-url> <nreq> <conn> <streams> <stdoutfile>
# Multi-target load over the committed stress corpus (scanner-path mix). h2load
# cycles the supplied URIs to reach -n; the curl fallback loops the list.
hb_load_corpus() {
    local proto="$1" base="$2" n="$3" c="$4" m="$5" so="$6"
    local -a paths=(); local p
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        case "$p" in \#*) continue ;; esac
        paths+=("$base$p")
    done < "$URLS"
    if [ "$HAVE_H2" = 1 ]; then
        local -a pf=(); local f; for f in $(hb_h2load_proto_flags "$proto"); do pf+=("$f"); done
        "$HB_H2LOAD_BIN" -n "$n" -c "$c" -m "$m" "${pf[@]}" "${paths[@]}" >"$so" 2>&1
    else
        local i=0
        while [ "$i" -lt "$n" ]; do
            printf '%s\n' "${paths[@]}" | xargs -P "$c" -I_ curl -s -o /dev/null _
            i=$((i + ${#paths[@]}))
        done
        echo "curl-fallback: looped ${#paths[@]} corpus URLs to ~$n requests on $base" >"$so"
    fi
}

# ---------------------------------------------------------------------------
# summary.json assembler
# ---------------------------------------------------------------------------
# hb_write_summary <dir> <scenario> <invariant-pass:0|1|na> <metrics-json>
hb_write_summary() {
    local d="$1" scen="$2" inv="$3" metrics="$4"
    local mach; mach=$(hb_machine_json)
    local ver; ver=$(cat "$VER_FRAG")
    perl -e '
        my ($scen,$mach,$ver,$inv,$metrics)=@ARGV;
        my $invj = $inv eq "na" ? "null" : ($inv eq "1" ? "true" : "false");
        print qq({\n);
        print qq(  "scenario": "$scen",\n);
        print qq(  "machine": $mach,\n);
        print qq(  "tools": $ver,\n);
        print qq(  "invariant_pass": $invj,\n);
        print qq(  "metrics": $metrics\n);
        print qq(}\n);
    ' "$scen" "$mach" "$ver" "$inv" "$metrics" > "$d/summary.json"
    echo "  summary: $d/summary.json"
}

# ===========================================================================
# S1 -- perf overhead
# ===========================================================================
run_s1() {
    echo "--- S1 perf-overhead ---"
    local d; d=$(hb_artifact_dir s1-perf)
    local protos="h1 h2"
    if [ "$HAVE_H2" = 1 ] && [ "${HB_H2LOAD_H3:-0}" = 1 ]; then protos="$protos h3"; else
        echo "  H3 dimension SKIP (h2load not QUIC-capable)"
    fi
    local metrics="{"
    local first=1 proto
    for proto in $protos; do
        local burl eurl
        case "$proto" in
            h3) burl="https://127.0.0.1:$P_H3B/"; eurl="https://127.0.0.1:$P_H3E/" ;;
            *)  burl="http://127.0.0.1:$P_BASE/"; eurl="http://127.0.0.1:$P_ENF/" ;;
        esac
        hb_load_single "$proto" "$burl" "$HB_REQS" "$HB_CONN" "$HB_STREAMS" "$d/$proto-baseline.log" "$d/$proto-baseline.out"
        hb_load_single "$proto" "$eurl" "$HB_REQS" "$HB_CONN" "$HB_STREAMS" "$d/$proto-enforce.log"  "$d/$proto-enforce.out"
        hb_parse_h2load_stdout "$d/$proto-baseline.out" "$d/$proto-baseline.kv"
        hb_parse_h2load_stdout "$d/$proto-enforce.out"  "$d/$proto-enforce.kv"
        [ -s "$d/$proto-enforce.log" ] && hb_h2load_log_to_hdr "$d/$proto-enforce.log" "$d/$proto-enforce.hdr"
        # overhead ratio = enforce_rps / baseline_rps (machine-relative)
        local brps erps ratio
        brps=$(awk -F= '/^req_per_sec=/{print $2}' "$d/$proto-baseline.kv")
        erps=$(awk -F= '/^req_per_sec=/{print $2}' "$d/$proto-enforce.kv")
        ratio=$(perl -e 'my($e,$b)=@ARGV; print(($b && $b>0)?sprintf("%.4f",$e/$b):"null")' "${erps:-0}" "${brps:-0}")
        [ "$first" = 1 ] || metrics="$metrics,"; first=0
        metrics="$metrics\"$proto\":{\"baseline_rps\":${brps:-null},\"enforce_rps\":${erps:-null},\"overhead_ratio\":$ratio}"
        echo "  $proto: baseline=${brps:-?} rps  enforce=${erps:-?} rps  ratio=$ratio"
    done
    metrics="$metrics}"
    hb_write_summary "$d" s1-perf na "$metrics"
}

# ===========================================================================
# S2 -- rate precision (wrk2 constant arrival rate)
# ===========================================================================
run_s2() {
    echo "--- S2 rate-precision ---"
    if [ "$HAVE_WRK" = 0 ]; then echo "  wrk2 absent -- S2 SKIP"; return 0; fi
    local d; d=$(hb_artifact_dir s2-rate)
    # the rate vhost limit (must match heavybag-stress-test.conf vhost 28303)
    local limit=100
    local rates
    if [ "$MODE" = quick ]; then rates="50 200"; else rates="50 100 200 500 $HB_RATE"; fi
    local metrics="{\"limit_rps\":$limit,\"sweep\":[" first=1 R
    for R in $rates; do
        local before after delta so
        before=$(mktemp); after=$(mktemp); delta="$d/delta-R$R.json"; so="$d/wrk2-R$R.out"
        hb_stat_snapshot "$STAT" "$before"
        local dur=$HB_DUR; [ "$MODE" = quick ] && dur=5
        "$HB_WRK2_BIN" -t"$HB_THREADS" -c"$HB_CONN" -d"${dur}s" -R"$R" --latency "http://127.0.0.1:$P_RATE/" >"$so" 2>&1 || true
        hb_stat_snapshot "$STAT" "$after"
        hb_counter_delta "$before" "$after" "$delta"
        hb_parse_wrk2_stdout "$so" "$d/wrk2-R$R.kv"
        # measured 429-share from the ground-truth counter delta
        local d429 dtot share theo
        d429=$(perl -MJSON::PP -e 'local $/;open$f,"<",$ARGV[0];my$D=JSON::PP->new->decode(<$f>);print $D->{http_blocked_rate_limit}//0' "$delta")
        dtot=$(perl -MJSON::PP -e 'local $/;open$f,"<",$ARGV[0];my$D=JSON::PP->new->decode(<$f>);print $D->{http_requests_total}//0' "$delta")
        share=$(perl -e 'my($a,$b)=@ARGV;print(($b>0)?sprintf("%.4f",$a/$b):"null")' "$d429" "$dtot")
        theo=$(perl -e 'my($R,$L)=@ARGV;my$x=$R-$L;$x=0 if $x<0;print(($R>0)?sprintf("%.4f",$x/$R):"null")' "$R" "$limit")
        [ "$first" = 1 ] || metrics="$metrics,"; first=0
        metrics="$metrics{\"R\":$R,\"requests\":$dtot,\"blocked_429\":$d429,\"measured_share\":$share,\"theoretical_share\":$theo}"
        echo "  R=$R: req=$dtot 429=$d429 measured_share=$share theoretical=$theo"
        rm -f "$before" "$after"
        # let the bucket refill between sweep points
        sleep 2
    done
    metrics="$metrics]}"
    hb_write_summary "$d" s2-rate na "$metrics"
}

# ===========================================================================
# S3 -- correctness under load (THE gate)
# ===========================================================================
# mail wire-only verdict: returns "OK" or "DENY" read off Auth-Status.
hb_mail_verdict() {
    local ip="$1"
    curl -s -D - -o /dev/null -H "Client-IP: $ip" "http://127.0.0.1:$P_MAIL/waf-mail-auth" \
        | awk 'tolower($1)=="auth-status:"{ $1=""; sub(/^ /,""); print; exit }'
}

run_s3() {
    echo "--- S3 correctness-under-load (counter invariants) ---"
    local d; d=$(hb_artifact_dir s3-correctness)
    local before after delta
    before="$d/before.json"; after="$d/after.json"; delta="$d/counter-delta.json"

    hb_stat_snapshot "$STAT" "$before"

    # Concurrent mixed load on ALL waf-active heads sharing the rate shm zone:
    #   enforce (corpus mix) + detect (corpus mix) + rate + stream(L4) -- fired in
    #   parallel so the shared per-IP buckets + status counters see real cross-head,
    #   cross-worker contention (the sharpest lock-free race surface).
    hb_load_corpus h2 "http://127.0.0.1:$P_ENF"  "$HB_REQS" "$HB_CONN" "$HB_STREAMS" "$d/enforce.out" &
    local pid_enf=$!
    hb_load_corpus h2 "http://127.0.0.1:$P_DET"  "$HB_REQS" "$HB_CONN" "$HB_STREAMS" "$d/detect.out" &
    local pid_det=$!
    hb_load_single h2 "http://127.0.0.1:$P_RATE/" "$HB_REQS" "$HB_CONN" "$HB_STREAMS" "" "$d/rate.out" &
    local pid_rate=$!
    hb_load_single h1 "http://127.0.0.1:$P_STREAM/" "$HB_REQS" "$HB_CONN" "$HB_STREAMS" "" "$d/stream.out" &
    local pid_stream=$!
    wait "$pid_enf" "$pid_det" "$pid_rate" "$pid_stream"

    hb_stat_snapshot "$STAT" "$after"
    hb_counter_delta "$before" "$after" "$delta"

    echo "  counter delta -> $delta"
    local inv_pass=1
    if hb_check_invariants "$delta" > "$d/invariants.txt"; then
        cat "$d/invariants.txt"
    else
        inv_pass=0
        cat "$d/invariants.txt"
    fi

    # mail head: WIRE-ONLY (no status counter). Assert allow+deny mix on the wire.
    local deny allow mail_ok=1
    deny=$(hb_mail_verdict 10.1.2.3)
    allow=$(hb_mail_verdict 203.0.113.7)
    echo "  mail wire: Client-IP=10.1.2.3 -> '$deny'   Client-IP=203.0.113.7 -> '$allow'"
    case "$deny"  in *[Oo][Kk]*) mail_ok=0; echo "  FAIL mail: blocked range returned OK" ;; esac
    case "$allow" in *[Oo][Kk]*) : ;; *) mail_ok=0; echo "  FAIL mail: allowed IP did not return OK ('$allow')" ;; esac
    [ "$mail_ok" = 1 ] && echo "  PASS mail: deny range denied, allow IP OK (wire-only)"
    [ "$mail_ok" = 1 ] || inv_pass=0

    local metrics; metrics=$(perl -MJSON::PP -e '
        local $/; open my $f,"<",$ARGV[0]; my $D=JSON::PP->new->decode(<$f>);
        my @r = split /\s+/, $ARGV[1];
        my $bsum=0; $bsum+=($D->{"http_blocked_$_"}//0) for @r;
        my $dsum=0; $dsum+=($D->{"stream_denied_$_"}//0) for @r;
        printf q({"http_requests_total":%d,"http_allowed":%d,"http_blocked_sum":%d,"stream_connections_total":%d,"stream_allowed":%d,"stream_denied_sum":%d,"mail_deny":"%s","mail_allow":"%s"}),
            $D->{http_requests_total}//0,$D->{http_allowed}//0,$bsum,
            $D->{stream_connections_total}//0,$D->{stream_allowed}//0,$dsum,
            $ARGV[2],$ARGV[3];
    ' "$delta" "$HB_REASONS" "$deny" "$allow")
    hb_write_summary "$d" s3-correctness "$inv_pass" "$metrics"

    S3_RESULT=$inv_pass
}

# ===========================================================================
# S4 -- CPU usage under burst
# ===========================================================================
run_s4() {
    echo "--- S4 cpu-burst ---"
    if [ "$HAVE_H2" = 0 ]; then echo "  h2load absent -- S4 SKIP"; return 0; fi
    local d; d=$(hb_artifact_dir s4-cpu)
    local pids; pids=$(hb_worker_pids "$NGINX_PIDFILE") || { echo "  no worker pids -- SKIP"; return 0; }
    echo "  sampling pids: $pids"
    local sampler; sampler=$(hb_proc_sampler "$pids" 1 "$d/cpu-rss.csv")
    # warmup (light) -> burst (high concurrency, short) -> cooldown
    echo "  warmup";  hb_load_single h2 "http://127.0.0.1:$P_ENF/" "$((HB_REQS/2))" 10 "$HB_STREAMS" "" "$d/warmup.out"
    echo "  BURST";   hb_load_single h2 "http://127.0.0.1:$P_ENF/" "$((HB_REQS*4))" "$((HB_CONN*4))" "$HB_STREAMS" "$d/burst.log" "$d/burst.out"
    echo "  cooldown"; sleep 3
    kill "$sampler" 2>/dev/null || true
    [ -s "$d/burst.log" ] && hb_h2load_log_to_hdr "$d/burst.log" "$d/burst.hdr"
    hb_parse_h2load_stdout "$d/burst.out" "$d/burst.kv"
    local brps; brps=$(awk -F= '/^req_per_sec=/{print $2}' "$d/burst.kv")
    local metrics="{\"burst_rps\":${brps:-null},\"sample_rows\":$(grep -vc '^#\|^epoch' "$d/cpu-rss.csv" 2>/dev/null || echo 0)}"
    echo "  burst rps=${brps:-?}; CPU/RSS timeseries -> $d/cpu-rss.csv"
    hb_write_summary "$d" s4-cpu na "$metrics"
}

# ===========================================================================
# S5 -- soak (opt-in)
# ===========================================================================
run_s5() {
    echo "--- S5 soak (${HB_SOAK_DUR}s) ---"
    if [ "$HAVE_H2" = 0 ]; then echo "  h2load absent -- S5 SKIP"; return 0; fi
    local d; d=$(hb_artifact_dir s5-soak)
    local master; master=$(cat "$NGINX_PIDFILE")
    local trend="$d/rss-fd-trend.csv"
    echo "epoch_s,rss_kb,fd_count" > "$trend"
    local end=$(( $(date +%s) + HB_SOAK_DUR ))
    local pgkb; pgkb=$(( $(getconf PAGESIZE)/1024 ))
    local reloads=0
    while [ "$(date +%s)" -lt "$end" ]; do
        hb_load_corpus h2 "http://127.0.0.1:$P_ENF" "$HB_REQS" "$HB_CONN" "$HB_STREAMS" /dev/null
        local rss fd
        rss=$(( $(awk '{print $2}' "/proc/$master/statm" 2>/dev/null || echo 0) * pgkb ))
        fd=$(hb_fd_count "$master")
        echo "$(date +%s),$rss,$fd" >> "$trend"
        # reload under load every ~5 iterations
        reloads=$((reloads+1))
        if [ $((reloads % 5)) = 0 ]; then "$NGINX" -p "$SBX/" -c "$CONF" -s reload 2>/dev/null && echo "  reloaded under load"; sleep 1; master=$(cat "$NGINX_PIDFILE"); fi
    done
    # leak gate: least-squares slope of RSS over time (KiB/s). The perl prints ONLY
    # the slope (or empty when there are too few samples); the bash side decides.
    local slope
    slope=$(perl -e '
        my (@x,@y);
        open my $f,"<",$ARGV[0] or exit 0;
        <$f>;                                   # header
        while (<$f>) { my @c=split/,/; next if @c<2; push @x,$c[0]; push @y,$c[1]; }
        exit 0 if @x < 3;
        my $n=@x; my ($sx,$sy,$sxx,$sxy)=(0,0,0,0);
        $sx+=$_ for @x; $sy+=$_ for @y;
        for my $i (0..$n-1){ $sxx+=$x[$i]*$x[$i]; $sxy+=$x[$i]*$y[$i]; }
        my $den=$n*$sxx-$sx*$sx; exit 0 if $den==0;
        printf "%.4f\n", ($n*$sxy-$sx*$sy)/$den;
    ' "$trend")
    echo "  RSS slope (KiB/s): ${slope:-n/a (too few samples)}"
    # threshold: > 64 KiB/s sustained growth flags a probable leak.
    local inv=1
    if [ -n "$slope" ] && ! awk -v s="$slope" 'BEGIN{exit (s>64)?1:0}'; then inv=0; fi
    hb_write_summary "$d" s5-soak "$inv" "{\"soak_seconds\":$HB_SOAK_DUR,\"reloads\":$reloads,\"rss_slope_kib_s\":${slope:-null}}"
    [ "$inv" = 1 ] || { echo "  FAIL: RSS trend suggests a leak"; return 1; }
}

# ===========================================================================
# dispatch
# ===========================================================================
start_nginx
S3_RESULT=na

case "$MODE" in
    quick)
        run_s1
        run_s2
        run_s3
        ;;
    soak)
        run_s5 || exit 1
        ;;
    full)
        run_s1
        run_s2
        run_s3
        run_s4
        ;;
esac

echo
echo "======================================================================"
echo "stress campaign ($MODE) complete; artifacts under $ARTI/"
if [ "${S3_RESULT:-na}" != na ]; then
    if [ "$S3_RESULT" = 1 ]; then echo "S3 correctness gate: PASS"; else echo "S3 correctness gate: FAIL"; fi
fi
echo "======================================================================"
rm -f "$VER_FRAG"

# exit nonzero iff an executed correctness gate failed
[ "${S3_RESULT:-na}" = 0 ] && exit 1
exit 0
