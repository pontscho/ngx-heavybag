#!/usr/bin/env bash
#
# run-protocol-tests.sh - WAF protocol-lifecycle + decode/cookie integration net
#
# Live-fire complement to the unit suite (tests/unit/). Drives the request-
# lifecycle paths that only exist with a real ngx_http_request_t / TLS handshake
# against heavybag-protocol-test.conf:
#
#   Part A (protocol-lifecycle, docs/qa-campaign.md):
#     A1  keepalive fresh ctx (blocked-A-then-clean-B, both orders)
#     A2  keepalive TLS JA4 stable across requests on one connection
#     A3  H2 multiplex: shared connection JA4 + per-stream verdict
#     A4  internal-redirect count-once (requests_total +1, not +2)
#     A5  SSI subrequest never re-scanned (r != r->main)
#     A7  plaintext listener JA4 no-op ($waf_ja4_hash empty, no crash)
#     A8  TLS resumption JA4 behaviour (observed + frozen) + no crash
#     A9  XFF client IP honoured under waf_trusted_proxy (blocklist on XFF IP)
#     A10 spoof body-filter: spoofed -> 403 single coherent body; control -> 200
#     A12 mail auth_http reputation path (no ctx/JA4): blocklisted Client-IP
#     A13 log-phase lazy ctx: $waf_* vars on a waf-off vhost, no crash
#
#   Part B (module.c percent-decode + Cookie ngx_list walk):
#     B1  basic single decode (%75nion -> union)
#     B2  %2g 3-byte delete (uni%2gon -> union)
#     B3  single-pass contract (%27union=404 vs double-encoded %2527union=403)
#     B4  %00 NUL: token-break (un%00ion no-match) + NO truncation (safe%00union match)
#     B5  bare trailing % dropped (union% -> union)
#     B6  all-% contraction, no crash (%%%% -> %%)
#     B7  empty args short-circuit (no query -> DECLINED)
#     B8  Cookie WHOLE-value match (no ;/= pair-walk)
#     B9  multi-Cookie ngx_list walk (2nd header matches)
#     B10 empty Cookie short-circuit
#
# H3/QUIC is NOT exercised: the system curl (7.81) has no HTTP/3 client. The
# QUIC JA4 path shares ngx_http_heavybag_ja4_compute with the TLS path (covered
# by A2/A3 + the Phase 6c extractor unit), so the only H3-specific gap is the
# transport, not the fingerprint logic.
#
# Standalone entrypoint (like run-regression-tests.sh). No CI; run manually.
# Usage:  bash run-protocol-tests.sh
# Exit 0 = every assertion passed and the error log is clean.

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
TESTS=$ROOT/modules/ngx_http_heavybag/tests
CONF=$TESTS/heavybag-protocol-test.conf
# portability: render the committed conf with the active ROOT so its baked absolute
# paths follow a relocated checkout (the sed is a no-op on the default root).
HB_RENDER_DIR=$ROOT/modules/ngx_http_heavybag/tests/corpus/.render
mkdir -p "$HB_RENDER_DIR"
hb_render() { local d="$HB_RENDER_DIR/$(basename "$1")"; sed "s#/mnt/nvme/imaginarium/openresty#$ROOT#g" "$1" > "$d"; printf '%s' "$d"; }
CONF=$(hb_render "$CONF")
TMP=$TESTS/corpus/.freeze-tmp
ELOG=$SBX/logs/error-protocol.log
LPLOG=$SBX/logs/protocol-logphase.log
JA4LIST=$TMP/protocol-ja4.list
SSI=$SBX/html/.protocol-ssi.html
mkdir -p "$TMP"

S=http://127.0.0.1:28500/waf/stat/plain

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

cleanup() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
    local pf="$SBX/logs/nginx-protocol.pid"
    [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null || true
    rm -f "$SSI"
}
trap cleanup EXIT

# scrape a single counter value from the plain status endpoint.
cval() { curl -s "$S" | awk -v k="$1" '$1==k{print $2; exit}'; }

echo "=== WAF protocol-lifecycle + decode/cookie integration harness ==="
echo

# --- preflight: ja4 scratch list must exist for nginx -t / start ------------
: > "$JA4LIST"               # empty list: no JA4->family mapping yet (discovery pass)

# --- nginx -t + [security] zero-proxy_pass invariant ------------------------
"$NGINX" -p "$SBX/" -c "$CONF" -t || { echo "CONFIG TEST FAILED"; exit 2; }
np=$(grep -cE '^[[:space:]]*proxy_pass' "$CONF")
[ "$np" -eq 0 ] && ok "conf has zero proxy_pass directives (no off-box egress)" \
    || bad "conf has $np proxy_pass directive(s) -- egress risk"

# --- SSI test asset (created here, removed by cleanup) ----------------------
printf '<html><body>main<!--#include virtual="/wp-login.php" -->end</body></html>\n' > "$SSI"

# --- start ------------------------------------------------------------------
cleanup 2>/dev/null; sleep 1
: > "$ELOG" 2>/dev/null || true
"$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
sleep 1
curl -sf "$S" >/dev/null || { echo "stat endpoint not reachable"; exit 2; }
ok "protocol-nginx up (stat reachable)"

# helper: extract the X-JA4 header's bracketed payload ([hash] -> hash).
ja4_of() { grep -i '^x-ja4:' | tr -d '\r' | sed -n 's/.*\[\(.*\)\].*/\1/p' | head -1; }

echo
echo "================  Part A: protocol-lifecycle  ================"

# --- A1 keepalive fresh ctx -------------------------------------------------
# Two requests on ONE keepalive connection; the per-request verdict must be
# independent (a blocked A must not poison a clean B, and vice versa).
A1a=$(curl -s -o /dev/null -w '%{http_code} ' http://127.0.0.1:28501/wp-login.php --next -s -o /dev/null -w '%{http_code} %{num_connects}' http://127.0.0.1:28501/index.html 2>/dev/null)
# A1a = "<codeA> <codeB> <total_connects>"  (num_connects==1 over the reused transfer)
read -r ca cb nconn <<<"$A1a"
if [ "$ca" = "404" ] && [ "$cb" = "200" ]; then
    ok "A1 keepalive blocked-then-clean: /wp-login.php=404 /index.html=200 (fresh ctx; connects=$nconn)"
else
    bad "A1 keepalive blocked-then-clean: got A=$ca B=$cb (want 404,200)"
fi
A1b=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:28501/index.html --next -s -o /dev/null -w ' %{http_code}' http://127.0.0.1:28501/phpmyadmin/ 2>/dev/null)
read -r cc cd <<<"$A1b"
if [ "$cc" = "200" ] && [ "$cd" = "403" ]; then
    ok "A1 keepalive clean-then-blocked: /index.html=200 /phpmyadmin/=403 (no suppression)"
else
    bad "A1 keepalive clean-then-blocked: got A=$cc B=$cd (want 200,403)"
fi

# --- A2 keepalive TLS JA4 stable --------------------------------------------
A2=$(curl -sk --http1.1 https://127.0.0.1:28543/index.html -D - -o /dev/null \
        --next -sk --http1.1 https://127.0.0.1:28543/index.html -D - -o /dev/null 2>/dev/null)
mapfile -t j2 < <(printf '%s\n' "$A2" | grep -i '^x-ja4:' | tr -d '\r' | sed -n 's/.*\[\(.*\)\].*/\1/p')
if [ "${#j2[@]}" -ge 2 ] && [ -n "${j2[0]}" ] && [ "${j2[0]}" = "${j2[1]}" ]; then
    ok "A2 keepalive TLS JA4 stable across requests: ${j2[0]}"
else
    bad "A2 keepalive TLS JA4 unstable/empty: got [${j2[*]:-none}]"
fi

# --- A3 H2 multiplex: shared JA4, per-stream verdict ------------------------
A3=$(curl -sk --http2 https://127.0.0.1:28543/index.html -D - -o /dev/null -w 'CODE %{http_code}\n' \
        --next -sk --http2 https://127.0.0.1:28543/wp-login.php -D - -o /dev/null -w 'CODE %{http_code}\n' 2>/dev/null)
mapfile -t j3 < <(printf '%s\n' "$A3" | grep -i '^x-ja4:' | tr -d '\r' | sed -n 's/.*\[\(.*\)\].*/\1/p')
mapfile -t c3 < <(printf '%s\n' "$A3" | sed -n 's/^CODE //p')
if [ "${#j3[@]}" -ge 2 ] && [ -n "${j3[0]}" ] && [ "${j3[0]}" = "${j3[1]}" ] \
   && [ "${c3[0]:-}" = "200" ] && [ "${c3[1]:-}" = "404" ]; then
    ok "A3 H2 shared JA4 (${j3[0]}) + per-stream verdict (200 / 404)"
else
    bad "A3 H2 multiplex: JA4=[${j3[*]:-none}] codes=[${c3[*]:-none}] (want equal JA4, 200/404)"
fi

# --- A4 internal-redirect count-once ----------------------------------------
pre=$(cval http_requests_total); preA=$(cval http_allowed)
curl -s -o /dev/null http://127.0.0.1:28503/no-such-file-xyz 2>/dev/null   # 404 -> error_page -> /index.html
post=$(cval http_requests_total); postA=$(cval http_allowed)
dR=$((post-pre)); dA=$((postA-preA))
if [ "$dR" -eq 1 ]; then
    ok "A4 internal-redirect count-once: http_requests_total +$dR (not +2), allowed +$dA"
else
    bad "A4 internal-redirect count-once: http_requests_total +$dR (want +1)"
fi

# --- A5 SSI subrequest never re-scanned -------------------------------------
# Direct hit on the scanner path bumps blocked_scanner_path; the SSI page whose
# include targets the SAME scanner path must NOT (subrequest -> r != r->main).
bDir0=$(cval http_blocked_scanner_path)
curl -s -o /dev/null http://127.0.0.1:28505/wp-login.php 2>/dev/null            # direct: blocked
bDir1=$(cval http_blocked_scanner_path)
curl -s -o /dev/null http://127.0.0.1:28505/.protocol-ssi.html 2>/dev/null      # SSI include subrequest
bSub=$(cval http_blocked_scanner_path)
if [ $((bDir1-bDir0)) -eq 1 ] && [ $((bSub-bDir1)) -eq 0 ]; then
    ok "A5 SSI subrequest not re-scanned: direct +1, SSI-include +0 blocked_scanner_path"
else
    bad "A5 SSI subrequest: direct +$((bDir1-bDir0)) sub +$((bSub-bDir1)) (want +1, +0)"
fi

# --- A7 plaintext JA4 no-op -------------------------------------------------
A7=$(curl -s http://127.0.0.1:28502/index.html -D - -o /dev/null -w 'CODE %{http_code}\n' 2>/dev/null)
j7=$(printf '%s\n' "$A7" | grep -i '^x-ja4:' | tr -d '\r')
c7=$(printf '%s\n' "$A7" | sed -n 's/^CODE //p')
if [ "$c7" = "200" ] && printf '%s' "$j7" | grep -q '\[\]'; then
    ok "A7 plaintext JA4 no-op: X-JA4 empty ([]) + 200, no crash"
else
    bad "A7 plaintext JA4: code=$c7 hdr='$j7' (want 200 + X-JA4: [])"
fi

# --- A9 XFF client IP honoured (waf_trusted_proxy) --------------------------
# blocklisted 198.51.100.9 via XFF -> reputation block (before content/redirect).
A9b=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 198.51.100.9' http://127.0.0.1:28503/index.html 2>/dev/null)
A9r=$(curl -s -D - -o /dev/null -H 'X-Forwarded-For: 198.51.100.9' http://127.0.0.1:28503/index.html 2>/dev/null | grep -i '^x-waf-reason:' | tr -d '\r' | awk '{print $2}')
A9c=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.50' http://127.0.0.1:28503/index.html 2>/dev/null)
# blocklist block action is 403 (FORBIDDEN); benign XFF is served 200.
if [ "$A9b" = "403" ] && [ "$A9r" = "blocklist" ] && [ "$A9c" = "200" ]; then
    ok "A9 XFF client IP honoured: blocklisted XFF=403 (reason=blocklist), benign XFF=200"
else
    bad "A9 XFF client IP: blocklisted=$A9b reason=$A9r benign=$A9c (want 403, blocklist, 200)"
fi

# --- A13 log-phase lazy ctx -------------------------------------------------
: > "$LPLOG" 2>/dev/null || true
A13=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:28504/index.html 2>/dev/null)
sleep 0.3
if [ "$A13" = "200" ] && grep -q 'type=' "$LPLOG" 2>/dev/null; then
    ok "A13 log-phase lazy ctx: 200 + \$waf_* logged ($(tail -1 "$LPLOG")), no crash"
else
    bad "A13 log-phase lazy ctx: code=$A13 log='$(tail -1 "$LPLOG" 2>/dev/null)'"
fi

# --- A12 mail auth_http reputation (no ctx/JA4) -----------------------------
# The waf_mail_auth handler runs reputation on the Client-IP header; 203.0.113.7
# is blocklisted on that vhost. Plain HTTP, no TLS, no request ctx -> still decides.
A12=$(curl -s -D - -o /dev/null http://127.0.0.1:28506/waf-mail-auth \
        -H 'Auth-Method: none' -H 'Auth-Protocol: smtp' -H 'Auth-SMTP-Helo: x' \
        -H 'Auth-SMTP-From: <a@b>' -H 'Auth-SMTP-To: <c@d>' \
        -H 'Client-IP: 203.0.113.7' 2>/dev/null | tr -d '\r')
A12ok=$(curl -s -D - -o /dev/null http://127.0.0.1:28506/waf-mail-auth \
        -H 'Auth-Method: none' -H 'Auth-Protocol: smtp' -H 'Auth-SMTP-Helo: x' \
        -H 'Auth-SMTP-From: <a@b>' -H 'Auth-SMTP-To: <c@d>' \
        -H 'Client-IP: 203.0.113.50' 2>/dev/null | tr -d '\r')
echo "    [A12 blocklisted Client-IP headers]"; printf '%s\n' "$A12" | sed 's/^/      /'
a12bl=$(printf '%s' "$A12" | grep -i '^Auth-Status:' | tr -d '\r')
a12be=$(printf '%s' "$A12ok" | grep -i '^Auth-Status:' | tr -d '\r')
if printf '%s' "$a12bl" | grep -qi 'blocklist' && [ "$a12bl" != "$a12be" ]; then
    ok "A12 mail auth_http reputation (no ctx/JA4): blocklisted -> '$a12bl', benign -> '$a12be'"
else
    bad "A12 mail auth_http: blocklisted='$a12bl' benign='$a12be' (want distinct, blocklisted rejected)"
fi

# --- A10 spoof body-filter (discover live JA4, map -> tool, reload) ---------
LIVEJA4=$(curl -sk https://127.0.0.1:28545/index.html -D - -o /dev/null 2>/dev/null | ja4_of)
if [ -z "$LIVEJA4" ]; then
    bad "A10 spoof: could not read live JA4 from 28545"
else
    printf '%s tool\n' "$LIVEJA4" > "$JA4LIST"
    "$NGINX" -p "$SBX/" -c "$CONF" -s reload 2>/dev/null; sleep 1
    # spoofed: UA claims Chrome, JA4 maps to tool -> contradiction -> 403, body once.
    SP=$(curl -sk -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' \
            https://127.0.0.1:28545/index.html -D - -o "$TMP/spoof.body" -w 'CODE %{http_code} CL %{size_download}\n' 2>/dev/null)
    spc=$(printf '%s' "$SP" | sed -n 's/.*CODE \([0-9]*\).*/\1/p')
    spx=$(printf '%s' "$SP" | grep -i '^x-spoof:' | tr -d '\r' | awk '{print $2}')
    spcl=$(printf '%s' "$SP" | grep -i '^content-length:' | tr -d '\r' | awk '{print $2}')
    spdl=$(printf '%s' "$SP" | sed -n 's/.*CL \([0-9]*\).*/\1/p')
    # control: UA=curl (tool family) matches JA4 tool -> no contradiction -> 200.
    CT=$(curl -sk -A 'curl/7.81.0' https://127.0.0.1:28545/index.html -D - -o /dev/null -w 'CODE %{http_code}\n' 2>/dev/null)
    ctc=$(printf '%s' "$CT" | sed -n 's/.*CODE \([0-9]*\).*/\1/p')
    ctx=$(printf '%s' "$CT" | grep -i '^x-spoof:' | tr -d '\r' | awk '{print $2}')
    if [ "$spc" = "403" ] && [ "$spx" = "1" ] && [ -n "$spcl" ] && [ "$spcl" = "$spdl" ]; then
        ok "A10 spoof enforce: 403 X-Spoof:1, body emitted once (CL=$spcl==recv=$spdl)"
    else
        bad "A10 spoof enforce: code=$spc spoof=$spx CL=$spcl recv=$spdl (want 403,1,CL==recv)"
    fi
    if [ "$ctc" = "200" ] && [ "${ctx:-0}" = "0" ]; then
        ok "A10 spoof control (curl UA == tool JA4): 200 X-Spoof:0 (no false positive)"
    else
        bad "A10 spoof control: code=$ctc spoof=$ctx (want 200,0)"
    fi
fi

# --- A8 TLS resumption JA4 behaviour (observed + frozen) --------------------
# Full handshake -> JA4 present. Resumed session -> observe + freeze; either way
# the server must NOT crash and must return an HTTP response.
REQ=$'GET /index.html HTTP/1.1\r\nHost: prot-tls\r\nConnection: close\r\n\r\n'
rm -f "$TMP/sess.pem"
FULL=$(printf '%s' "$REQ" | openssl s_client -connect 127.0.0.1:28543 -sess_out "$TMP/sess.pem" -quiet 2>/dev/null)
fj=$(printf '%s\n' "$FULL" | ja4_of)
if [ -s "$TMP/sess.pem" ]; then
    RES=$(printf '%s' "$REQ" | openssl s_client -connect 127.0.0.1:28543 -sess_in "$TMP/sess.pem" -quiet 2>/dev/null)
    rj=$(printf '%s\n' "$RES" | ja4_of)
    reused=$(printf '%s\n' "$RES" | grep -ci 'Reused\|session-id reused' )
    if [ -n "$fj" ] && printf '%s' "$RES" | grep -q 'HTTP/1.1'; then
        ok "A8 TLS resumption: full JA4=$fj, resumed JA4='${rj:-<empty>}', server responded, no crash"
    else
        bad "A8 TLS resumption: full JA4='$fj' resumed responded=$(printf '%s' "$RES" | grep -qc 'HTTP/1.1' && echo y || echo n)"
    fi
else
    echo "  NOTE: A8 no session ticket captured (openssl/TLS1.3) -- resumption not exercised"
fi

echo
echo "================  Part B: decode + cookie  ================"
# helper: status code for a GET, plus the X-WAF-Reason.
hit() { curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }
reason() { curl -s -D - -o /dev/null "$@" 2>/dev/null | grep -i '^x-waf-reason:' | tr -d '\r' | awk '{print $2}'; }

AR=http://127.0.0.1:28507
CK=http://127.0.0.1:28508

assert_code() {  # <label> <want> <actual>
    if [ "$3" = "$2" ]; then ok "$1 (=$3)"; else bad "$1: got $3 want $2"; fi
}

assert_code "B1 basic decode %75nion->union->403"        403 "$(hit "$AR/?q=%75nion")"
assert_code "B2 %2g 3-byte delete uni%2gon->union->403"  403 "$(hit "$AR/?q=uni%2gon")"
assert_code "B3a single-encoded %27union->'union->404"   404 "$(hit "$AR/?q=%27union")"
assert_code "B3b double-encoded %2527union->%27union->403 (single-pass: quote stays encoded)" 403 "$(hit "$AR/?q=%2527union")"
assert_code "B4a %00 token-break un%00ion->no-match->200" 200 "$(hit "$AR/?q=un%00ion")"
assert_code "B4b %00 no-truncation safe%00union->match->403" 403 "$(hit "$AR/?q=safe%00union")"
assert_code "B5 trailing % dropped union%->union->403"   403 "$(hit "$AR/?q=union%")"
assert_code "B6 all-% contraction %%%%->%%->no-match->200" 200 "$(hit "$AR/?q=%%%%")"
assert_code "B7 empty args short-circuit (no query)->200" 200 "$(hit "$AR/index.html")"

assert_code "B8a Cookie whole-value substring a=sqlmap->404" 404 "$(hit "$CK/" -H 'Cookie: a=sqlmap')"
assert_code "B8b Cookie no pair-walk a=evilcookie vs ^evilcookie\$->200" 200 "$(hit "$CK/" -H 'Cookie: a=evilcookie')"
assert_code "B8c Cookie anchored whole-match evilcookie->403" 403 "$(hit "$CK/" -H 'Cookie: evilcookie')"
assert_code "B9 multi-Cookie ngx_list walk (2nd header matches)->404" 404 "$(hit "$CK/" -H 'Cookie: clean=1' -H 'Cookie: junk=sqlmap')"
assert_code "B10 empty Cookie short-circuit->200" 200 "$(hit "$CK/" -H 'Cookie;')"

# reason attribution spot-checks (the X-WAF-Reason tuple, non-444 paths)
r1=$(reason "$AR/?q=%75nion"); [ "$r1" = "args" ] && ok "B reason: args hit -> X-WAF-Reason: args" || bad "B reason: args -> '$r1' (want args)"
r2=$(reason "$CK/" -H 'Cookie: a=sqlmap'); [ "$r2" = "cookie" ] && ok "B reason: cookie hit -> X-WAF-Reason: cookie" || bad "B reason: cookie -> '$r2' (want cookie)"

# --- error log must be clean ------------------------------------------------
echo
echo "--- error log scan ---"
badlog=$(grep -aiE 'panic|segfault|assertion|\[alert\]|\[emerg\]|alloc.*fail|not binary compatible' "$ELOG" 2>/dev/null | grep -viE 'could not open error log|using the "epoll"' | head)
if [ -z "$badlog" ]; then
    ok "error log clean (no crash/alert/emerg/alloc-fail)"
else
    bad "error log has concerning lines:"; printf '%s\n' "$badlog" | sed 's/^/      /'
fi

echo
echo "==================  RESULT: $pass passed, $fail failed  =================="
[ "$fail" -eq 0 ]
