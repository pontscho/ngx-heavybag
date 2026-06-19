#!/usr/bin/env bash
#
# run-spoof-fuzz.sh - deep-fuzz the JA4<->UA spoof detector ("self-swap")
#
# The QA-campaign critic's "un-probed spoof self-swap" surface. Drives the full
# {fam_ja4} x {fam_ua} matrix of ngx_http_heavybag_ua_spoof_eval against
# heavybag-spoof-fuzz.conf, plus the independent cidr_signal path.
#
# The host curl has ONE observed JA4; the runner maps it to a chosen family per
# ja4.list reload, so the whole fam_ja4 axis is reachable with one client. The
# fam_ua axis is the UA header. Key properties proven:
#   - SELF-SWAP SYMMETRY: tool-JA4+Chrome-UA AND chromium-JA4+curl-UA both spoof;
#     tool+curl AND chromium+Chrome both pass -> the `fam_ja4 != fam_ua` compare
#     is symmetric, no asymmetry / self-compare misfire.
#   - UNKNOWN guard on EITHER side suppresses the signal (no false positive).
#   - same-family different browser (Edge == Chrome family) is NOT a spoof.
#   - observe (spoof_block off) + detect (waf detect): detected, X-Spoof=1, 200.
#   - cidr_signal: fake verified-bot from an IP outside its CIDR -> spoof.
#
# TLS vectors need OpenSSL curl (present). Exit 0 = all pass + log clean;
# exit 2 = sandbox not built / live JA4 unreadable (CTest SKIPPED).

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
TESTS=$ROOT/modules/ngx_http_heavybag/tests
SRC_CONF=$TESTS/heavybag-spoof-fuzz.conf
ELOG=$SBX/logs/error-spoof.log
TMP=$TESTS/corpus/.freeze-tmp
ENF=$TMP/spoof-enf-ja4.list
OBS=$TMP/spoof-obs-ja4.list
CIDR=$TMP/spoof-verified-bot.cidr
mkdir -p "$TMP"

HB_RENDER_DIR=$TESTS/corpus/.render
mkdir -p "$HB_RENDER_DIR"
CONF=$HB_RENDER_DIR/heavybag-spoof-fuzz.conf
sed "s#/mnt/nvme/imaginarium/openresty#$ROOT#g" "$SRC_CONF" > "$CONF"

UA_CHROME='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
UA_EDGE='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
UA_FF='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
UA_SAFARI='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
UA_CURL='curl/7.81.0'
UA_MYSTERY='MysteryBrowser/1.0'
UA_GBOT='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

cleanup() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
    local pf="$SBX/logs/nginx-spoof.pid"
    [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null || true
}
trap cleanup EXIT

ja4_of() { grep -i '^x-ja4:' | tr -d '\r' | sed -n 's/.*\[\(.*\)\].*/\1/p' | head -1; }
# tprobe PORT UA -> "CODE SPOOF"  (TLS; X-Spoof = $waf_ua_is_spoofed, 0/1)
tprobe() {
    curl -sk -A "$2" "https://127.0.0.1:$1/index.html" -D - -o /dev/null 2>/dev/null | tr -d '\r' \
        | awk 'BEGIN{c="?";s="?"} /^HTTP\//{c=$2} tolower($1)=="x-spoof:"{s=$2} END{print c" "s}'
}
# cprobe UA XFF -> "CODE REASON"  (plaintext cidr vhost; X-WAF-Reason)
cprobe() {
    curl -s -A "$1" -H "X-Forwarded-For: $2" "http://127.0.0.1:28802/index.html" -D - -o /dev/null 2>/dev/null | tr -d '\r' \
        | awk 'BEGIN{c="?";r="none"} /^HTTP\//{c=$2} tolower($1)=="x-waf-reason:"{r=$2} END{print c" "r}'
}
chkt() {  # DESC PORT UA WANT_CODE WANT_SPOOF
    local c s; read -r c s <<<"$(tprobe "$2" "$3")"
    if [ "$c" = "$4" ] && [ "$s" = "$5" ]; then ok "$1 -> $c spoof=$s"; else bad "$1 -> got $c spoof=$s (want $4 $5)"; fi
}
chkc() {  # DESC UA XFF WANT_CODE WANT_REASON
    local c r; read -r c r <<<"$(cprobe "$2" "$3")"
    if [ "$c" = "$4" ] && [ "$r" = "$5" ]; then ok "$1 -> $c/$r"; else bad "$1 -> got $c/$r (want $4/$5)"; fi
}
reload_enf() { printf '%s %s\n' "$JA4" "$1" > "$ENF"; "$NGINX" -p "$SBX/" -c "$CONF" -s reload 2>/dev/null; sleep 1; }

echo "=== WAF JA4<->UA spoof deep-fuzz harness (self-swap) ==="

# --- scratch lists must exist for nginx -t / start --------------------------
: > "$ENF"; : > "$OBS"
printf '66.249.64.0/19\n' > "$CIDR"      # Google's published range; excludes 127/8 + 8.8.8.8

"$NGINX" -p "$SBX/" -c "$CONF" -t || { echo "CONFIG TEST FAILED"; exit 2; }
np=$(grep -cE '^[[:space:]]*proxy_pass' "$CONF")
[ "$np" -eq 0 ] && ok "conf has zero proxy_pass directives (no off-box egress)" \
    || bad "conf has $np proxy_pass directive(s) -- egress risk"

cleanup 2>/dev/null; sleep 1
: > "$ELOG" 2>/dev/null || true
"$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
sleep 1

# --- read the live JA4, then map it -> tool on both enf+obs lists -----------
JA4=$(curl -sk "https://127.0.0.1:28843/index.html" -D - -o /dev/null 2>/dev/null | ja4_of)
if [ -z "$JA4" ]; then echo "could not read live JA4 from 28843"; exit 2; fi
ok "spoof-nginx up (live curl JA4 = $JA4)"
printf '%s tool\n' "$JA4" > "$OBS"      # fixed: obs+det vhosts see fam_ja4=tool
reload_enf tool                          # enf list starts at tool too

echo
echo "================  observe + detect (spoof_block off / waf detect)  ==="
chkt "observe: tool-JA4 + Chrome-UA, block OFF -> detected, allowed" 28845 "$UA_CHROME" 200 1
chkt "observe control: tool-JA4 + curl-UA -> match, not spoofed"     28845 "$UA_CURL"   200 0
chkt "detect: tool-JA4 + Chrome-UA, waf detect -> would-block, allowed" 28846 "$UA_CHROME" 200 1

echo
echo "================  fam_ja4 = tool  ================"
chkt "tool-JA4 + Chrome-UA  -> SPOOF (403)"                       28843 "$UA_CHROME"   403 1
chkt "tool-JA4 + curl-UA    -> match (200)"                      28843 "$UA_CURL"     200 0
chkt "tool-JA4 + mystery-UA -> fam_ua UNKNOWN guard (200)"       28843 "$UA_MYSTERY"  200 0

echo
echo "================  fam_ja4 = chromium (self-swap reverse)  ========"
reload_enf chromium
chkt "chromium-JA4 + curl-UA -> SPOOF (reverse of tool+Chrome)"  28843 "$UA_CURL"     403 1
chkt "chromium-JA4 + Chrome-UA -> match (200)"                   28843 "$UA_CHROME"   200 0
chkt "chromium-JA4 + Edge-UA -> same TLS family, no spoof (200)" 28843 "$UA_EDGE"     200 0
chkt "chromium-JA4 + Firefox-UA -> SPOOF (firefox vs chromium)"  28843 "$UA_FF"       403 1

echo
echo "================  fam_ja4 = firefox / safari  ================"
reload_enf firefox
chkt "firefox-JA4 + Chrome-UA -> SPOOF"                          28843 "$UA_CHROME"   403 1
chkt "firefox-JA4 + Firefox-UA -> match (200)"                  28843 "$UA_FF"       200 0
reload_enf safari
chkt "safari-JA4 + curl-UA -> SPOOF"                            28843 "$UA_CURL"     403 1
chkt "safari-JA4 + Safari-UA -> match (200)"                    28843 "$UA_SAFARI"   200 0

echo
echo "================  fam_ja4 = UNKNOWN (live JA4 absent from list)  =="
printf 't13d000000_000000000000_000000000000 chromium\n' > "$ENF"
"$NGINX" -p "$SBX/" -c "$CONF" -s reload 2>/dev/null; sleep 1
chkt "unknown-JA4 + Chrome-UA -> fam_ja4 UNKNOWN guard (200)"    28843 "$UA_CHROME"   200 0

echo
echo "================  cidr_signal (fake verified-bot, plaintext)  ===="
chkc "fake Googlebot OUTSIDE verified CIDR -> SPOOF"  "$UA_GBOT"   8.8.8.8       403 spoof
chkc "Googlebot INSIDE verified CIDR -> allowed"      "$UA_GBOT"   66.249.64.10  200 none
chkc "non-crawler UA outside CIDR (no JA4) -> allowed" "$UA_CHROME" 8.8.8.8       200 none

echo
echo "================  error.log clean  ================"
# NB: benign '[notice] worker process N exited with code 0' lines from each -s
# reload are NOT crashes -- only flag non-zero exits, signals, or crit/alert/emerg.
if grep -Ei '\[crit\]|\[alert\]|\[emerg\]|segfault|exited on signal|exited with code [1-9]' "$ELOG" >/tmp/sp_errs 2>/dev/null; [ -s /tmp/sp_errs ]; then
    echo "  --- suspicious error.log lines:"; sed 's/^/      /' /tmp/sp_errs
    bad "error.log has crash/abort lines"
else
    ok "error.log clean (no crash/abort/worker-exit)"
fi
rm -f /tmp/sp_errs

echo
echo "================== RESULT: $pass passed, $fail failed =================="
[ "$fail" -eq 0 ]
