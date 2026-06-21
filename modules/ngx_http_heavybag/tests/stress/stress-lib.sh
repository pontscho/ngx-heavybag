#!/usr/bin/env bash
# stress-lib.sh -- shared helpers for the heavybag stress campaign.
# Sourced by run-stress-tests.sh. Pure bash + perl(JSON::PP) + curl + /proc, so
# it carries no build-time deps of its own; the only external load tools are
# h2load and wrk2, whose presence the caller probes via the hb_tool_* helpers.
#
# Ground truth everywhere is the status endpoint counter delta -- the same
# /waf/stat/plain `key value` stream run-replay-tests.sh reads with getcnt(),
# lifted here to a before/after JSON snapshot + a checked-invariant delta.

# ---------------------------------------------------------------------------
# The 16 verdict reason slots (heavybag_reason_str minus NONE). These are the
# ONLY addends of the block/deny sum. Everything else on the wire -- the
# http_scanner_path_{403,404,444} code breakdown, the http_resp_* tallies, the
# http_flag_* per-bit breakdown, the http_ua* classifications -- is an OVERLAY
# that must NOT be summed into the invariant (it would double-count).
# ---------------------------------------------------------------------------
HB_REASONS="allowlist blocklist geo geo_whitelist flag scanner_ua empty_ua scanner_path asn method args cookie referer fake_bot rate_limit spoof"

# ---------------------------------------------------------------------------
# Tool presence + version/capability probing
# ---------------------------------------------------------------------------

# hb_tool_h2load_bin -> echoes the h2load binary name if present, else nothing.
hb_tool_h2load_bin() { command -v h2load 2>/dev/null; }

# hb_tool_wrk2_bin -> echoes wrk2 or wrk (in that order) if present, else nothing.
# Presence only -- capability is a SEPARATE check (see hb_wrk2_rate_capable):
# Debian ships the original wrk (Will Glozer) AS `wrk`, which lacks the constant
# arrival-rate flag the campaign requires. Finding a binary is not enough.
hb_tool_wrk2_bin() {
    command -v wrk2 2>/dev/null && return 0
    command -v wrk  2>/dev/null && return 0
    return 1
}

# hb_wrk2_rate_capable <bin> -> 0 if the binary supports constant arrival rate
# (-R/--rate), i.e. it is Gil Tene's wrk2 fork (coordinated-omission-free), NOT
# the original wrk. S2 is meaningless without it, so the orchestrator treats a
# rate-incapable wrk as ABSENT and SKIPs S2.
hb_wrk2_rate_capable() {
    local bin="$1"
    [ -n "$bin" ] || return 1
    "$bin" --help 2>&1 | grep -qE '(^|[^a-zA-Z])-R(,|[[:space:]])|--rate|connections.*[Rr]ate'
}

# hb_h2load_h3_capable <h2load-bin> -> 0 if the build advertises HTTP/3.
# Probes the CAPABILITY (the --alpn-list / HTTP/3 help text), not the version
# string -- a distro h2load can be current yet built without ngtcp2/nghttp3.
hb_h2load_h3_capable() {
    local bin="$1"
    [ -n "$bin" ] || return 1
    "$bin" --help 2>&1 | grep -qiE 'http/3|--alpn-list|ngtcp2|quic'
}

# hb_versions_report <versions.env> <out-json-fragment-file>
# Sources the pins, probes live versions + H3 capability, WARNs (never fails) on
# drift, and writes a JSON fragment of {expected,found,h3_capable} for summary.json.
hb_versions_report() {
    local envf="$1" out="$2"
    # shellcheck disable=SC1090
    [ -f "$envf" ] && . "$envf"

    local h2bin wrkbin h2ver wrkver h3cap=0
    h2bin=$(hb_tool_h2load_bin || true)
    wrkbin=$(hb_tool_wrk2_bin || true)

    if [ -n "$h2bin" ]; then
        h2ver=$("$h2bin" --version 2>&1 | head -1)
        hb_h2load_h3_capable "$h2bin" && h3cap=1
        if [ -n "${HB_STRESS_H2LOAD_VERSION:-}" ] && [ "$h2ver" != "$HB_STRESS_H2LOAD_VERSION" ]; then
            echo "  WARN: h2load version drift: pinned='$HB_STRESS_H2LOAD_VERSION' found='$h2ver' (recorded, not fatal)" >&2
        fi
    else
        h2ver="ABSENT"
    fi

    if [ -n "$wrkbin" ]; then
        wrkver=$("$wrkbin" --version 2>&1 | head -1)
        if ! hb_wrk2_rate_capable "$wrkbin"; then
            echo "  WARN: '$wrkbin' has no constant-rate flag (-R) -- it is the original wrk, not wrk2." >&2
            echo "        S2 (rate precision) requires wrk2 (Gil Tene's fork); treating wrk2 as ABSENT." >&2
            wrkver="$wrkver (NOT rate-capable -> unusable)"
            wrkbin=""
        fi
    else
        wrkver="ABSENT"
    fi

    HB_H2LOAD_BIN="$h2bin"; HB_WRK2_BIN="$wrkbin"; HB_H2LOAD_H3="$h3cap"
    export HB_H2LOAD_BIN HB_WRK2_BIN HB_H2LOAD_H3

    HB_J="$(command -v perl)"
    perl -e '
        my ($h2e,$h2f,$wrke,$wrkf,$h3)=@ARGV;
        sub esc { my $s=shift//""; $s=~s/\\/\\\\/g; $s=~s/"/\\"/g; return $s; }
        printf qq({"h2load":{"expected":"%s","found":"%s","h3_capable":%s},"wrk2":{"expected":"%s","found":"%s"}}),
            esc($h2e),esc($h2f),($h3?"true":"false"),esc($wrke),esc($wrkf);
    ' "${HB_STRESS_H2LOAD_VERSION:-}" "$h2ver" "${HB_STRESS_WRK2_VERSION:-}" "$wrkver" "$h3cap" > "$out"

    echo "  h2load: $h2ver (H3-capable=$h3cap)   wrk2: $wrkver"
}

# ---------------------------------------------------------------------------
# Counter snapshot / delta / invariants -- ground truth
# ---------------------------------------------------------------------------

# hb_stat_snapshot <stat-base-url> <out-json>
# Pulls /waf/stat/plain and serialises the whole `key value` stream to a JSON
# object {key:int}. The plain format is the proven getcnt() source.
hb_stat_snapshot() {
    local url="$1" out="$2"
    curl -s "$url/plain" | perl -e '
        my %h;
        while (<STDIN>) {
            next unless /^(\S+)\s+(-?\d+)\s*$/;
            $h{$1} = $2 + 0;
        }
        my @k = sort keys %h;
        print "{";
        for my $i (0..$#k) {
            printf "%s\"%s\":%d", ($i?",":""), $k[$i], $h{$k[$i]};
        }
        print "}\n";
    ' > "$out"
}

# hb_counter_delta <before-json> <after-json> <out-delta-json>
# Per-key (after-before). Keys present in either side are emitted.
hb_counter_delta() {
    local before="$1" after="$2" out="$3"
    perl -MJSON::PP -e '
        my $j = JSON::PP->new;
        local $/; open my $b,"<",$ARGV[0] or die; my $B=$j->decode(<$b>);
        open my $a,"<",$ARGV[1] or die; my $A=$j->decode(<$a>);
        my %all = (%$B, %$A);
        my @k = sort keys %all;
        print "{";
        for my $i (0..$#k) {
            my $d = ($A->{$k[$i]}//0) - ($B->{$k[$i]}//0);
            printf "%s\"%s\":%d", ($i?",":""), $k[$i], $d;
        }
        print "}\n";
    ' "$before" "$after" > "$out"
}

# hb_check_invariants <delta-json> [reasons]
# The hard correctness gate (S3). Prints one PASS/FAIL line per check and
# returns nonzero if ANY check fails. Checks, per the audited plan:
#   HTTP:   d(http_requests_total) == d(http_allowed) + sum d(http_blocked[reason])
#   STREAM: d(stream_connections_total) == d(stream_allowed) + sum d(stream_denied[reason])
#   SUB:    d(http_allowlist_hits) <= d(http_allowed)        (subset, not addend)
#   MONO:   no counter delta is negative                    (monotonic)
# The would_block[*] overlay and waf-off traffic are excluded by construction
# (would_block is never summed here; waf-off vhosts move no counter).
hb_check_invariants() {
    local delta="$1"
    local reasons="${2:-$HB_REASONS}"
    perl -MJSON::PP -e '
        my $j = JSON::PP->new;
        local $/; open my $f,"<",$ARGV[0] or die; my $D=$j->decode(<$f>);
        my @reasons = split /\s+/, $ARGV[1];
        my $ok = 1;

        my $req = $D->{http_requests_total} // 0;
        my $alw = $D->{http_allowed} // 0;
        my $bsum = 0; $bsum += ($D->{"http_blocked_$_"} // 0) for @reasons;
        if ($req == $alw + $bsum) {
            printf "  PASS http: d(requests_total)=%d == d(allowed)=%d + sum d(blocked)=%d\n", $req,$alw,$bsum;
        } else {
            $ok = 0;
            printf "  FAIL http: d(requests_total)=%d != d(allowed)=%d + sum d(blocked)=%d (diff=%d)\n",
                $req,$alw,$bsum,$req-($alw+$bsum);
        }

        my $sc = $D->{stream_connections_total} // 0;
        my $sa = $D->{stream_allowed} // 0;
        my $dsum = 0; $dsum += ($D->{"stream_denied_$_"} // 0) for @reasons;
        if ($sc == $sa + $dsum) {
            printf "  PASS stream: d(connections_total)=%d == d(allowed)=%d + sum d(denied)=%d\n", $sc,$sa,$dsum;
        } else {
            $ok = 0;
            printf "  FAIL stream: d(connections_total)=%d != d(allowed)=%d + sum d(denied)=%d (diff=%d)\n",
                $sc,$sa,$dsum,$sc-($sa+$dsum);
        }

        my $ah = $D->{http_allowlist_hits} // 0;
        if ($ah <= $alw) {
            printf "  PASS http: d(allowlist_hits)=%d <= d(allowed)=%d\n", $ah,$alw;
        } else {
            $ok = 0;
            printf "  FAIL http: d(allowlist_hits)=%d > d(allowed)=%d\n", $ah,$alw;
        }

        my @neg = grep { ($D->{$_}//0) < 0 } sort keys %$D;
        if (@neg) {
            $ok = 0;
            printf "  FAIL mono: negative counter delta(s): %s\n", join(", ", map { "$_=$D->{$_}" } @neg);
        } else {
            print "  PASS mono: no counter delta went negative\n";
        }

        exit($ok ? 0 : 1);
    ' "$delta" "$reasons"
}

# ---------------------------------------------------------------------------
# CPU / RSS sampling (S4 / S5)
# ---------------------------------------------------------------------------

# hb_worker_pids <pidfile> -> echoes "master w1 w2 ..." (master first).
hb_worker_pids() {
    local pidfile="$1" master
    [ -f "$pidfile" ] || return 1
    master=$(cat "$pidfile")
    echo -n "$master"
    # nginx workers are direct children of the master.
    local w
    for w in $(pgrep -P "$master" 2>/dev/null); do echo -n " $w"; done
    echo
}

# hb_proc_sampler <space-sep-pids> <interval-sec> <out-csv>
# Background loop: every <interval>, append one CSV row per pid with the cumulative
# CPU jiffies (utime+stime from /proc/PID/stat fields 14,15) and RSS (statm field 2
# in pages). The CALLER converts jiffy/page deltas to %CPU / KiB using the header
# constants the sampler writes first. Echoes the sampler PID; kill it to stop.
hb_proc_sampler() {
    local pids="$1" interval="$2" out="$3"
    local clk pgsz
    clk=$(getconf CLK_TCK 2>/dev/null || echo 100)
    pgsz=$(getconf PAGESIZE 2>/dev/null || echo 4096)
    {
        echo "# CLK_TCK=$clk PAGESIZE=$pgsz"
        echo "epoch_s,pid,utime_jiffies,stime_jiffies,rss_pages"
        while :; do
            local now p
            now=$(date +%s 2>/dev/null || echo 0)
            for p in $pids; do
                [ -r "/proc/$p/stat" ] || continue
                # field 14=utime 15=stime; the comm field (2) can contain spaces,
                # so split on the last ')' to realign the numeric tail.
                local tail u s rss
                tail=$(sed -e 's/^.*) //' "/proc/$p/stat" 2>/dev/null) || continue
                # after removing 'pid (comm) ', field 1 is state; utime=12 stime=13 here.
                u=$(echo "$tail" | awk '{print $12}')
                s=$(echo "$tail" | awk '{print $13}')
                rss=$(awk '{print $2}' "/proc/$p/statm" 2>/dev/null)
                [ -n "$u" ] && [ -n "$s" ] && [ -n "$rss" ] && echo "$now,$p,$u,$s,$rss"
            done
            sleep "$interval"
        done
    } > "$out" &
    echo $!
}

# hb_fd_count <pid> -> open fd count for a pid (S5 fd-leak trend).
hb_fd_count() {
    local p="$1"
    [ -d "/proc/$p/fd" ] || { echo 0; return; }
    ls "/proc/$p/fd" 2>/dev/null | wc -l
}

# ---------------------------------------------------------------------------
# Latency-distribution parsing (S1 / S4)
# ---------------------------------------------------------------------------

# hb_h2load_log_to_hdr <h2load-log-file> <out-file>
# h2load --log-file writes tab-separated per-request rows; the documented format
# is: <request-start-us> <status> <duration-us>. We read the duration column and
# emit an HDR-style percentile table (us). Defensive: takes the last all-digit
# field of each >=3-column row as the duration, so a minor format shift degrades
# to a warning rather than garbage.
hb_h2load_log_to_hdr() {
    local log="$1" out="$2"
    perl -e '
        my @v;
        while (<STDIN>) {
            my @f = split /\s+/;
            next if @f < 3;
            my $d = $f[-1];
            next unless $d =~ /^\d+$/;
            push @v, $d + 0;
        }
        if (!@v) { print "# no parseable latency samples in h2load log\n"; exit 0; }
        @v = sort { $a <=> $b } @v;
        my $n = @v;
        sub pct { my $p=shift; my $i=int($p/100*($n-1)+0.5); $i=$n-1 if $i>$n-1; return $v[$i]; }
        printf "# h2load latency distribution (microseconds), n=%d\n", $n;
        printf "min=%d\n", $v[0];
        for my $p (50,75,90,95,99,99.9,99.99) { printf "p%s=%d\n", $p, pct($p); }
        printf "max=%d\n", $v[-1];
        my $sum=0; $sum+=$_ for @v; printf "mean=%.1f\n", $sum/$n;
    ' < "$log" > "$out"
}

# hb_parse_h2load_stdout <stdout-file> <out-kv-file>
# Extracts the headline numbers from h2load stdout into key=value lines.
hb_parse_h2load_stdout() {
    local in="$1" out="$2"
    perl -e '
        my %k;
        while (<STDIN>) {
            $k{req_per_sec}=$1     if /finished in .*?,\s*([\d.]+)\s*req\/s/;
            $k{status_2xx}=$1      if /status codes:\s*(\d+)\s*2xx/;
            $k{status_3xx}=$1      if /(\d+)\s*3xx/;
            $k{status_4xx}=$1      if /(\d+)\s*4xx/;
            $k{status_5xx}=$1      if /(\d+)\s*5xx/;
            $k{req_total}=$1       if /requests:\s*(\d+)\s*total/;
        }
        print "$_=$k{$_}\n" for sort keys %k;
    ' < "$in" > "$out"
}

# hb_parse_wrk2_stdout <stdout-file> <out-kv-file>
# Pulls Requests/sec + the HdrHistogram percentile block + our Lua-emitted status
# tallies (STATUS_<code>=<n> lines printed by stress.lua done()).
hb_parse_wrk2_stdout() {
    local in="$1" out="$2"
    perl -e '
        my %k;
        while (<STDIN>) {
            $k{req_per_sec}=$1 if /Requests\/sec:\s*([\d.]+)/;
            $k{total_requests}=$1 if /^\s*(\d+)\s+requests in/;
            # HdrHistogram percentile lines:  50.000%    1.23ms
            if (/^\s*([\d.]+)%\s+([\d.]+)(us|ms|s)\s*$/) {
                my ($p,$val,$u)=($1,$2,$3);
                my $ms = $u eq "us" ? $val/1000 : $u eq "s" ? $val*1000 : $val;
                (my $pk=$p)=~s/\.?0+$//; $pk=~s/\./_/;
                $k{"lat_p${pk}_ms"}=sprintf("%.3f",$ms);
            }
            $k{$1}=$2 if /^(STATUS_\d+)=(\d+)/;   # stress.lua status tallies
        }
        print "$_=$k{$_}\n" for sort keys %k;
    ' < "$in" > "$out"
}
