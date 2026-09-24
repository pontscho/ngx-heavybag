#!/usr/bin/env bash
#
# run-mailauth-fuzz.sh - deep-fuzz the SMTP/IMAP auth_http content handler
#
# The QA-campaign critic's "un-probed authhttp SMTP" surface. The existing
# protocol A12 + stat SMTP-auth stanzas cover only the trusted-loopback-peer +
# well-formed IPv4 happy path. This harness drives the fedetlen edges of
# modules/ngx_http_heavybag/src/heavybag_authhttp.c against
# heavybag-mailauth-fuzz.conf:
#
#   #1 missing Client-IP           -> fail-open (allow) + WARN, no crash
#   #2 garbage/oversized/inject    -> clean fail-open, no crash, no reflection
#   #3 IPv6 Client-IP              -> v6 reputation path (blocklisted v6 denies)
#   #4 multiple Client-IP headers  -> first-wins, deterministic
#   #5 untrusted-peer spoof        -> Client-IP IGNORED, connection peer judged
#   #6 geo / asn / flag verdict    -> Auth-Status carries the non-blocklist reason
#   #7 missing waf_mail_backend    -> ERR-log-but-allow, no Auth-Server/Auth-Port
#   #8 rate + geo rule-select      -> for_geo=CC rule chosen via verdict.geo_valid
#   #9 waf_mail_failopen off       -> missing/garbage Client-IP fails CLOSED (deny)
#      + a PIN on the actual merged default (fail-OPEN), so a silent flip fails
#  #10 X-WAF-Key trust model       -> Client-IP honoured ONLY on an authenticated
#      channel; missing / wrong key, or no configured secret, judges the REAL peer
#  #11 allowlist bypasses the rate stage (a trusted relay cannot DoS itself)
#  #12 exported counter invariant  -> requests_total == allowed + sum(blocked)
#
# TRUST MODEL (T4.d / SV11). The handler honours the forwarded Client-IP only
# when the caller authenticates with `X-WAF-Key: <waf_mail_trusted_secret>` over
# a loopback/unix connection -- in production that header comes from the mail
# side's `auth_http_header X-WAF-Key "<token>"`. probe() therefore sends the key
# by default (the "the mail proxy is talking to us" case); probe_nokey() and the
# $BADKEY_* vectors drive the unauthenticated / spoofing cases.
#
# Geo-dependent edges (#6/#8) self-validate ground truth at runtime via the
# oracle reference/geolookup.c against geodb/location.db; if the DB is absent or
# has drifted they SKIP (not fail). The #5 edges need a real non-loopback IPv4;
# on a loopback-only host they SKIP. The suite still exits 0 in those cases.
#
# Standalone entrypoint (like run-protocol-tests.sh). No CI; run manually or via
# CTest (heavybag_mailauth). Exit 0 = every RUN assertion passed + log clean.
# Exit 2 = sandbox not built (preflight), reported by CTest as SKIPPED.

set -u

ROOT=${HEAVYBAG_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
TESTS=$ROOT/modules/ngx_http_heavybag/tests
SRC_CONF=$TESTS/heavybag-mailauth-fuzz.conf
GEODB=$ROOT/geodb/location.db
ELOG=$SBX/logs/error-mailauth.log

# The shared secret baked into the rendered conf (waf_mail_trusted_secret) and
# sent as X-WAF-Key by probe(). BADKEY_EQLEN is the same LENGTH as SECRET with
# one differing byte -- it drives the constant-time compare's XOR loop rather
# than its length short-circuit; BADKEY_SHORT drives the length mismatch.
SECRET='hb-mailauth-shared-secret-2026'
BADKEY_EQLEN='hb-mailauth-shared-secret-2027'
BADKEY_SHORT='x'

# non-loopback IPv4 for the #5 untrusted-peer vhosts (empty -> #5 SKIP).
EXTIP=$(ip -4 route get 192.0.2.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)
if [ -z "$EXTIP" ]; then
    EXTIP=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -vE '^127\.|^$' | head -1)
fi
EXT_AVAIL=1
if [ -z "$EXTIP" ]; then EXTIP=127.0.0.1; EXT_AVAIL=0; fi

# portability: render the committed conf with the active ROOT, the detected
# EXTIP and the shared secret (the first two seds are no-ops on the default root
# / when EXTIP is unused).
HB_RENDER_DIR=$TESTS/corpus/.render
mkdir -p "$HB_RENDER_DIR"
CONF=$HB_RENDER_DIR/heavybag-mailauth-fuzz.conf
sed -e "s#@HB_ROOT@#$ROOT#g" \
    -e "s#__HB_EXTIP__#$EXTIP#g" \
    -e "s#__HB_SECRET__#$SECRET#g" "$SRC_CONF" > "$CONF"

pass=0; fail=0; skip=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }
skp()  { echo "  SKIP: $1"; skip=$((skip+1)); }

cleanup() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
    local pf="$SBX/logs/nginx-mailauth.pid"
    [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null || true
}
trap cleanup EXIT

# Issue a mail auth_http probe to a port with the standard ngx_mail headers plus
# whatever extra args (e.g. -H 'Client-IP: ...') the caller passes; echo the raw
# response header block (CR stripped).
#   probe        -- AUTHENTICATED caller (sends the correct X-WAF-Key), i.e. the
#                   real mail proxy; this is what makes Client-IP authoritative
#   probe_nokey  -- unauthenticated local caller (no X-WAF-Key at all)
MU="-H Auth-Method:none -H Auth-Protocol:smtp -H Auth-SMTP-Helo:x -H Auth-SMTP-From:<a@b> -H Auth-SMTP-To:<c@d>"
KEYH="-H X-WAF-Key:$SECRET"
probe() {
    local port=$1; shift
    curl -s -D - -o /dev/null $MU $KEYH "$@" \
        "http://127.0.0.1:$port/waf-mail-auth" 2>/dev/null | tr -d '\r'
}
probe_nokey() {
    local port=$1; shift
    curl -s -D - -o /dev/null $MU "$@" \
        "http://127.0.0.1:$port/waf-mail-auth" 2>/dev/null | tr -d '\r'
}
# probe a vhost bound on EXTIP (the #5 untrusted-peer vhosts); _key sends a
# VALID X-WAF-Key to prove a remote caller gains nothing from holding the token.
probe_ext() {
    local port=$1; shift
    curl -s -D - -o /dev/null $MU "$@" \
        "http://$EXTIP:$port/waf-mail-auth" 2>/dev/null | tr -d '\r'
}
probe_ext_key() {
    local port=$1; shift
    curl -s -D - -o /dev/null $MU $KEYH "$@" \
        "http://$EXTIP:$port/waf-mail-auth" 2>/dev/null | tr -d '\r'
}
# extract the Auth-Status value (lowercased, leading ws trimmed) from headers.
astat() { printf '%s' "$1" | grep -i '^Auth-Status:' | head -1 \
            | cut -d: -f2- | sed 's/^[[:space:]]*//' | tr 'A-Z' 'a-z'; }
# read one counter out of the text /waf/stat rendering
cval() { printf '%s\n' "$1" | awk -v k="$2" '$1==k {print $2; exit}'; }

echo "=== WAF mail auth_http deep-fuzz harness ==="
echo "    EXTIP=$EXTIP (avail=$EXT_AVAIL)  GEODB=$([ -f "$GEODB" ] && echo present || echo absent)"
echo

# --- nginx -t + [security] zero-proxy_pass invariant ------------------------
"$NGINX" -p "$SBX/" -c "$CONF" -t || { echo "CONFIG TEST FAILED"; exit 2; }
np=$(grep -cE '^[[:space:]]*proxy_pass' "$CONF")
[ "$np" -eq 0 ] && ok "conf has zero proxy_pass directives (no off-box egress)" \
    || bad "conf has $np proxy_pass directive(s) -- egress risk"

# --- start ------------------------------------------------------------------
cleanup 2>/dev/null; sleep 1
: > "$ELOG" 2>/dev/null || true
"$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
sleep 1
# liveness: the base vhost must answer with an Auth-Status.
base_live=$(probe 28601 -H 'Client-IP: 8.8.8.8')
[ -n "$(astat "$base_live")" ] || { echo "mailauth base vhost not reachable"; exit 2; }
ok "mailauth-nginx up (base vhost answers Auth-Status)"

# --- ground-truth self-validation via the oracle ----------------------------
# Build reference/geolookup.c (libc-only) and confirm the IPs we bake into the
# conf still resolve as expected; if not, the geo edges SKIP rather than mislead.
GEO_OK=0; ASN_OK=0; FLAG_OK=0
if [ -f "$GEODB" ] && cc -O2 -o "$HB_RENDER_DIR/geolookup-mf" "$ROOT/reference/geolookup.c" 2>/dev/null; then
    gl=$(printf '185.177.72.1\n8.8.8.8\n' | "$HB_RENDER_DIR/geolookup-mf" "$GEODB" 2>/dev/null)
    fr_cc=$(printf '%s\n' "$gl" | awk '$1=="185.177.72.1"{print $2}')
    us_cc=$(printf '%s\n' "$gl" | awk '$1=="8.8.8.8"{print $2}')
    us_asn=$(printf '%s\n' "$gl" | awk '$1=="8.8.8.8"{print $3}')
    us_flags=$(printf '%s\n' "$gl" | awk '$1=="8.8.8.8"{print $4}')
    [ "$fr_cc" = FR ] && [ "$us_cc" = US ] && GEO_OK=1
    [ "$us_asn" = 15169 ] && ASN_OK=1
    # anycast bit 0x0004 set in the hex flags field
    case "$us_flags" in *[0-9a-fA-F]) [ $(( 0x${us_flags#0x} & 0x4 )) -ne 0 ] && FLAG_OK=1 ;; esac
    echo "    oracle: 185.177.72.1->$fr_cc  8.8.8.8->$us_cc AS$us_asn $us_flags"
else
    echo "    oracle/geodb unavailable -> geo edges (#6/#8-geo) will SKIP"
fi
echo

# ============================================================================
echo "================  #1 missing Client-IP -> fail-open  ================"
# No Client-IP header at all, from an AUTHENTICATED caller: the handler logs a
# WARN and allows (never breaks mail delivery).
r=$(probe 28601)
[ "$(astat "$r")" = ok ] && ok "#1 missing Client-IP -> Auth-Status OK (fail-open)" \
    || bad "#1 missing Client-IP -> '$(astat "$r")' (want ok)"
sleep 0.2
grep -q 'mail auth without parseable Client-IP' "$ELOG" \
    && ok "#1 fail-open logged the WARN (parseable Client-IP missing)" \
    || bad "#1 expected WARN 'mail auth without parseable Client-IP' not in log"

# ============================================================================
echo "================  #2 garbage / oversized / inject -> crash-safety  ==="
# Every malformed Client-IP must hit the same fail-open branch (allow) without
# crashing the worker or reflecting attacker bytes into a response header.
for cv in 'not-an-ip' '1.2.3.4 5.6.7.8' '999.999.999.999' '::ffzz::1' '0x7f000001'; do
    r=$(probe 28601 -H "Client-IP: $cv")
    [ "$(astat "$r")" = ok ] && ok "#2 garbage Client-IP '$cv' -> fail-open OK" \
        || bad "#2 garbage Client-IP '$cv' -> '$(astat "$r")' (want ok)"
done
# oversized (8 KB) value: no buffer mishandling.
BIG=$(printf 'A%.0s' $(seq 1 8000))
r=$(probe 28601 -H "Client-IP: $BIG")
[ "$(astat "$r")" = ok ] && ok "#2 oversized 8KB Client-IP -> fail-open OK (no overflow)" \
    || bad "#2 oversized Client-IP -> '$(astat "$r")' (want ok)"
# header-injection attempt: literal %0d%0a payload must NOT appear as a real
# response header (Client-IP is parsed as an address, never reflected).
r=$(probe 28601 -H 'Client-IP: 1.2.3.4%0d%0aX-Injected: pwned')
if printf '%s' "$r" | grep -qi '^X-Injected:'; then
    bad "#2 Client-IP header-injection REFLECTED (X-Injected present) -- REAL BUG"
else
    ok "#2 Client-IP inject payload not reflected (no X-Injected header)"
fi

# ============================================================================
echo "================  #3 IPv6 Client-IP -> v6 reputation path  ==========="
# blocklisted v6 (2001:db8:bad::/48) must deny; a benign v6 must pass.
r=$(probe 28601 -H 'Client-IP: 2001:db8:bad::1')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#3 blocklisted IPv6 -> 'static blocklist' (v6 reputation path live)" \
    || bad "#3 blocklisted IPv6 -> '$(astat "$r")' (want 'static blocklist')"
r=$(probe 28601 -H 'Client-IP: 2001:db8:good::1')
[ "$(astat "$r")" = ok ] && ok "#3 benign IPv6 -> OK" \
    || bad "#3 benign IPv6 -> '$(astat "$r")' (want ok)"
# IPv4-mapped form of the blocklisted v4: observe + assert a definite verdict.
r=$(probe 28601 -H 'Client-IP: ::ffff:203.0.113.7')
rs=$(astat "$r")
[ -n "$rs" ] && ok "#3 IPv4-mapped Client-IP -> definite verdict '$rs' (no crash)" \
    || bad "#3 IPv4-mapped Client-IP -> no Auth-Status (handler stalled?)"

# ============================================================================
echo "================  #4 multiple Client-IP headers -> first-wins  ======="
# Two Client-IP headers: the FIRST is authoritative (the headers_in walk in
# ngx_http_heavybag_authhttp_header() returns on the first case-insensitive hit).
r=$(probe 28601 -H 'Client-IP: 203.0.113.7' -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#4 [blocklisted, benign] -> first wins -> 'static blocklist'" \
    || bad "#4 [blocklisted, benign] -> '$(astat "$r")' (want 'static blocklist')"
r=$(probe 28601 -H 'Client-IP: 8.8.8.8' -H 'Client-IP: 203.0.113.7')
[ "$(astat "$r")" = ok ] \
    && ok "#4 [benign, blocklisted] -> first wins -> OK" \
    || bad "#4 [benign, blocklisted] -> '$(astat "$r")' (want ok)"

# ============================================================================
echo "================  #5 untrusted-peer spoof -> Client-IP ignored  ======"
if [ "$EXT_AVAIL" -eq 0 ]; then
    skp "#5a untrusted-peer spoof: no non-loopback IPv4 on this host"
    skp "#5b untrusted-peer blocklisted Client-IP ignored: no non-loopback IPv4"
    skp "#5c remote peer WITH a valid X-WAF-Key: no non-loopback IPv4"
else
    # #5a: peer (EXTIP) is blocklisted; a benign Client-IP must NOT save it.
    r=$(probe_ext 28607 -H 'Client-IP: 8.8.8.8')
    [ "$(astat "$r")" = 'static blocklist' ] \
        && ok "#5a untrusted peer + benign Client-IP -> peer judged -> 'static blocklist'" \
        || bad "#5a untrusted peer spoof-clean -> '$(astat "$r")' (want 'static blocklist')"
    # #5b: peer (EXTIP) NOT blocklisted; a blocklisted Client-IP must be ignored.
    r=$(probe_ext 28608 -H 'Client-IP: 203.0.113.7')
    [ "$(astat "$r")" = ok ] \
        && ok "#5b untrusted peer + blocklisted Client-IP -> ignored -> OK" \
        || bad "#5b untrusted peer blocklisted-header -> '$(astat "$r")' (want ok)"
    # #5c: holding a VALID token buys a remote caller nothing -- the loopback /
    # unix peer-class filter is a necessary condition, not a replaceable one.
    r=$(probe_ext_key 28607 -H 'Client-IP: 8.8.8.8')
    [ "$(astat "$r")" = 'static blocklist' ] \
        && ok "#5c remote peer WITH valid X-WAF-Key -> still peer-judged -> 'static blocklist'" \
        || bad "#5c remote peer with valid key -> '$(astat "$r")' (want 'static blocklist')"
    sleep 0.2
    grep -q 'mail auth from untrusted peer' "$ELOG" \
        && ok "#5 untrusted-peer path logged the WARN" \
        || bad "#5 expected WARN 'mail auth from untrusted peer' not in log"
fi

# ============================================================================
echo "================  #6 geo / asn / flag verdict mapping  ==============="
if [ "$GEO_OK" -eq 1 ]; then
    r=$(probe 28602 -H 'Client-IP: 185.177.72.1')
    [ "$(astat "$r")" = 'geo country' ] \
        && ok "#6a geo block (FR) -> Auth-Status 'geo country'" \
        || bad "#6a geo block (FR) -> '$(astat "$r")' (want 'geo country')"
    r=$(probe 28602 -H 'Client-IP: 8.8.8.8')
    [ "$(astat "$r")" = ok ] && ok "#6a non-FR (US) -> OK (geo control)" \
        || bad "#6a US on FR-block vhost -> '$(astat "$r")' (want ok)"
else
    skp "#6a geo verdict: oracle/geodb unavailable or drifted"
fi
if [ "$ASN_OK" -eq 1 ]; then
    r=$(probe 28603 -H 'Client-IP: 8.8.8.8')
    [ "$(astat "$r")" = asn ] \
        && ok "#6b asn block (AS15169) -> Auth-Status 'asn'" \
        || bad "#6b asn block (AS15169) -> '$(astat "$r")' (want 'asn')"
    r=$(probe 28603 -H 'Client-IP: 185.177.72.1')
    [ "$(astat "$r")" = ok ] && ok "#6b non-AS15169 -> OK (asn control)" \
        || bad "#6b FR-IP on AS-block vhost -> '$(astat "$r")' (want ok)"
else
    skp "#6b asn verdict: oracle/geodb unavailable or drifted"
fi
if [ "$FLAG_OK" -eq 1 ]; then
    r=$(probe 28604 -H 'Client-IP: 8.8.8.8')
    [ "$(astat "$r")" = 'network flag' ] \
        && ok "#6c flag block (anycast) -> Auth-Status 'network flag'" \
        || bad "#6c flag block (anycast) -> '$(astat "$r")' (want 'network flag')"
    r=$(probe 28604 -H 'Client-IP: 185.177.72.1')
    [ "$(astat "$r")" = ok ] && ok "#6c non-anycast (FR-IP) -> OK (flag control)" \
        || bad "#6c FR-IP on flag-block vhost -> '$(astat "$r")' (want ok)"
else
    skp "#6c flag verdict: oracle/geodb unavailable or drifted"
fi

# ============================================================================
echo "================  #7 missing waf_mail_backend -> allow w/o backend  =="
# benign Client-IP: allowed, but no Auth-Server/Auth-Port (backend unset);
# the handler logs an ERR yet still returns OK.
r=$(probe 28605 -H 'Client-IP: 8.8.8.8')
as=$(astat "$r")
has_srv=$(printf '%s' "$r" | grep -ci '^Auth-Server:')
if [ "$as" = ok ] && [ "$has_srv" -eq 0 ]; then
    ok "#7 no-backend allow -> Auth-Status OK, no Auth-Server header"
else
    bad "#7 no-backend allow -> status='$as' auth-server-count=$has_srv (want ok / 0)"
fi
grep -q 'waf_mail_backend is not set' "$ELOG" \
    && ok "#7 missing-backend ERR logged" \
    || bad "#7 expected ERR 'waf_mail_backend is not set' not in log"
# deny still works without a backend.
r=$(probe 28605 -H 'Client-IP: 203.0.113.7')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#7 no-backend deny -> 'static blocklist' (deny independent of backend)" \
    || bad "#7 no-backend deny -> '$(astat "$r")' (want 'static blocklist')"

# ============================================================================
echo "================  #8 rate + geo rule-select (for_geo)  ==============="
if [ "$GEO_OK" -eq 1 ]; then
    # FR -> for_geo=FR strict rule (burst=1): req1 OK, req2 rate-limited.
    r1=$(probe 28606 -H 'Client-IP: 185.177.72.1')
    r2=$(probe 28606 -H 'Client-IP: 185.177.72.1')
    if [ "$(astat "$r1")" = ok ] && [ "$(astat "$r2")" = 'rate limit' ]; then
        ok "#8 for_geo=FR strict rule selected: req1 OK, req2 'rate limit'"
    else
        bad "#8 for_geo=FR: req1='$(astat "$r1")' req2='$(astat "$r2")' (want ok, rate limit)"
    fi
    # US -> no for_geo match -> default lenient rule (burst=1000): stays OK.
    u1=$(probe 28606 -H 'Client-IP: 8.8.8.8')
    u2=$(probe 28606 -H 'Client-IP: 8.8.8.8')
    if [ "$(astat "$u1")" = ok ] && [ "$(astat "$u2")" = ok ]; then
        ok "#8 US -> default rule (no for_geo match): both OK (geo-select gates on country)"
    else
        bad "#8 US default rule: u1='$(astat "$u1")' u2='$(astat "$u2")' (want ok, ok)"
    fi
else
    skp "#8 rate+geo rule-select: oracle/geodb unavailable or drifted"
fi

# ============================================================================
echo "================  #9 waf_mail_failopen off -> fail-CLOSED  ==========="
# With waf_mail_failopen off, a missing / unparseable Client-IP from an
# AUTHENTICATED caller must DENY (the synthetic reason "mail client-ip
# missing"), NOT fail open.
r=$(probe 28609)
[ "$(astat "$r")" = 'mail client-ip missing' ] \
    && ok "#9 failopen-off + missing Client-IP -> deny 'mail client-ip missing'" \
    || bad "#9 failopen-off + missing Client-IP -> '$(astat "$r")' (want 'mail client-ip missing')"
r=$(probe 28609 -H 'Client-IP: not-an-ip')
[ "$(astat "$r")" = 'mail client-ip missing' ] \
    && ok "#9 failopen-off + garbage Client-IP -> deny (fail-closed)" \
    || bad "#9 failopen-off + garbage Client-IP -> '$(astat "$r")' (want 'mail client-ip missing')"
sleep 0.2
grep -q 'denying (waf_mail_failopen off)' "$ELOG" \
    && ok "#9 fail-closed logged the deny WARN" \
    || bad "#9 expected WARN 'denying (waf_mail_failopen off)' not in log"
# control: a well-formed Client-IP still judges normally (knob governs only the
# missing/garbage edge) -- benign allowed, blocklisted denied.
r=$(probe 28609 -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = ok ] \
    && ok "#9 failopen-off + benign well-formed Client-IP -> OK (happy path intact)" \
    || bad "#9 failopen-off + benign Client-IP -> '$(astat "$r")' (want ok)"
r=$(probe 28609 -H 'Client-IP: 203.0.113.7')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#9 failopen-off + blocklisted Client-IP -> 'static blocklist' (normal deny intact)" \
    || bad "#9 failopen-off + blocklisted Client-IP -> '$(astat "$r")' (want 'static blocklist')"
# --- PIN THE ACTUAL DEFAULT (T4.c) ------------------------------------------
# The partner decision (2026-08-28) is that waf_mail_failopen keeps its
# fail-OPEN default. 28601 sets no waf_mail_failopen, so it runs on the merged
# default: an authenticated caller with NO Client-IP must be ALLOWED. If anyone
# silently flips ngx_conf_merge_value(conf->mail_failopen, ..., 1) to 0, this
# assertion -- and only this assertion -- goes red and names the reason.
r=$(probe 28601)
[ "$(astat "$r")" = ok ] \
    && ok "#9 DEFAULT waf_mail_failopen is ON (no directive + missing Client-IP -> OK)" \
    || bad "#9 DEFAULT waf_mail_failopen appears FLIPPED: got '$(astat "$r")' (want ok = fail-open)"
grep -q 'allowing (waf_mail_failopen on)' "$ELOG" \
    && ok "#9 default fail-open logs it explicitly ('allowing (waf_mail_failopen on)')" \
    || bad "#9 expected WARN 'allowing (waf_mail_failopen on)' not in log"

# ============================================================================
echo "================  #10 X-WAF-Key trust model (T4.d / SV11)  ==========="
# mf-trust (28621) blocklists the LOOPBACK PEER itself, so the two trust
# directions give opposite verdicts and neither can pass by accident.
# #10a feature works: authenticated caller -> the forwarded IP is judged.
r=$(probe 28621 -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = ok ] \
    && ok "#10a correct X-WAF-Key + Client-IP 8.8.8.8 -> forwarded IP judged -> OK" \
    || bad "#10a authenticated forward -> '$(astat "$r")' (want ok; the feature is broken)"
# #10b evasion closed: NO key -> the header is ignored, the real peer is judged.
r=$(probe_nokey 28621 -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#10b MISSING X-WAF-Key -> Client-IP IGNORED, real peer judged -> 'static blocklist'" \
    || bad "#10b missing key -> '$(astat "$r")' (want 'static blocklist'; SPOOF ACCEPTED)"
# #10b2 wrong key, SAME LENGTH as the secret (drives the constant-time XOR loop).
r=$(probe_nokey 28621 -H "X-WAF-Key: $BADKEY_EQLEN" -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#10b2 wrong X-WAF-Key (equal length) -> Client-IP ignored -> 'static blocklist'" \
    || bad "#10b2 equal-length wrong key -> '$(astat "$r")' (want 'static blocklist')"
# #10b3 wrong key, DIFFERENT length (drives the length short-circuit).
r=$(probe_nokey 28621 -H "X-WAF-Key: $BADKEY_SHORT" -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#10b3 wrong X-WAF-Key (short) -> Client-IP ignored -> 'static blocklist'" \
    || bad "#10b3 short wrong key -> '$(astat "$r")' (want 'static blocklist')"
# #10c fail-closed default: mf-nosecret (28622) configures NO secret, so even a
# "correct" key cannot make Client-IP authoritative.
r=$(probe 28622 -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = 'static blocklist' ] \
    && ok "#10c no waf_mail_trusted_secret -> Client-IP never trusted -> peer judged (fail-closed)" \
    || bad "#10c unconfigured secret -> '$(astat "$r")' (want 'static blocklist'; NOT fail-closed)"
sleep 0.2
grep -q 'waf_mail_trusted_secret is not configured' "$ELOG" \
    && ok "#10c unconfigured-secret path logged the actionable WARN" \
    || bad "#10c expected WARN 'waf_mail_trusted_secret is not configured' not in log"
grep -q 'X-WAF-Key missing' "$ELOG" \
    && ok "#10b missing-key path logged 'X-WAF-Key missing'" \
    || bad "#10b expected WARN 'X-WAF-Key missing' not in log"
grep -q 'X-WAF-Key mismatched' "$ELOG" \
    && ok "#10b2 wrong-key path logged 'X-WAF-Key mismatched'" \
    || bad "#10b2 expected WARN 'X-WAF-Key mismatched' not in log"

# ============================================================================
echo "================  #11 allowlist bypasses the rate stage (T4.b)  ======"
# mf-allowrate (28623): rate=1r/m burst=1. 198.51.100.9 is allowlisted, so with
# the default waf_allowlist_scope full the rate stage is skipped entirely and a
# trusted relay cannot throttle itself; .10 is the non-allowlisted control.
a1=$(probe 28623 -H 'Client-IP: 198.51.100.9')
a2=$(probe 28623 -H 'Client-IP: 198.51.100.9')
a3=$(probe 28623 -H 'Client-IP: 198.51.100.9')
if [ "$(astat "$a1")" = ok ] && [ "$(astat "$a2")" = ok ] && [ "$(astat "$a3")" = ok ]; then
    ok "#11 allowlisted peer + exhausted bucket -> all 3 OK (rate stage skipped)"
else
    bad "#11 allowlisted peer throttled: '$(astat "$a1")' '$(astat "$a2")' '$(astat "$a3")' (want ok ok ok)"
fi
c1=$(probe 28623 -H 'Client-IP: 198.51.100.10')
c2=$(probe 28623 -H 'Client-IP: 198.51.100.10')
if [ "$(astat "$c1")" = ok ] && [ "$(astat "$c2")" = 'rate limit' ]; then
    ok "#11 non-allowlisted control -> req1 OK, req2 'rate limit' (enforce-always intact)"
else
    bad "#11 non-allowlisted control: c1='$(astat "$c1")' c2='$(astat "$c2")' (want ok, rate limit)"
fi

# ============================================================================
echo "================  worker liveness + error.log clean  ================"
# after the malformed barrage the worker must still serve.
r=$(probe 28601 -H 'Client-IP: 8.8.8.8')
[ "$(astat "$r")" = ok ] && ok "worker alive after fuzz barrage (clean request -> OK)" \
    || bad "worker not serving after fuzz -> '$(astat "$r")'"

# ============================================================================
echo "================  #12 counter invariant (observability-01 / T4.a)  ==="
# Every vhost in this config runs `waf off`, so the HTTP PREACCESS handler never
# counts anything: every counter below was moved by the MAIL head. The exported
# invariant requests_total == allowed + sum(http_blocked_*) must hold across the
# whole run -- mixed allow / rate-deny / reputation-deny. Before T4.a a mail
# rate-deny bumped http_blocked[RATE_LIMIT] without ever bumping requests_total
# (and reputation denies were invisible), so this sum could not balance.
#
# The two edges that reach NO verdict -- fail-open (#1/#2) and fail-closed (#9)
# on an unparseable Client-IP -- are deliberately outside the accounting, so
# they cannot skew either side.
st=$(curl -s "http://127.0.0.1:28624/waf/stat" 2>/dev/null)
tot=$(cval "$st" http_requests_total)
alw=$(cval "$st" http_allowed)
blk=$(printf '%s\n' "$st" | awk 'index($1,"http_blocked_")==1 {s+=$2} END {print s+0}')
bl_list=$(cval "$st" http_blocked_blocklist)
bl_rate=$(cval "$st" http_blocked_rate_limit)
echo "    /waf/stat: requests_total=$tot allowed=$alw blocked_sum=$blk (blocklist=$bl_list rate_limit=$bl_rate)"
if [ -z "$tot" ] || [ -z "$alw" ]; then
    bad "#12 /waf/stat did not render http_requests_total / http_allowed"
elif [ "$tot" -eq 0 ]; then
    bad "#12 http_requests_total is 0 -- the mail head moved no counter at all"
elif [ "$tot" -eq $((alw + blk)) ]; then
    ok "#12 invariant holds: requests_total=$tot == allowed=$alw + blocked_sum=$blk"
else
    bad "#12 invariant BROKEN: requests_total=$tot != allowed=$alw + blocked_sum=$blk"
fi
# the specific regression #5 called out: mail reputation blocks must be visible.
[ -n "$bl_list" ] && [ "$bl_list" -gt 0 ] \
    && ok "#12 mail reputation blocks are visible (http_blocked_blocklist=$bl_list)" \
    || bad "#12 http_blocked_blocklist=$bl_list -- mail rep-blocks still invisible"
[ -n "$bl_rate" ] && [ "$bl_rate" -gt 0 ] \
    && ok "#12 mail rate denies still booked (http_blocked_rate_limit=$bl_rate)" \
    || bad "#12 http_blocked_rate_limit=$bl_rate -- mail rate denies not booked"

# ============================================================================
if grep -Ei '\[crit\]|\[alert\]|\[emerg\]|segfault|worker process [0-9]+ exited' "$ELOG" >/tmp/mf_errs 2>/dev/null; [ -s /tmp/mf_errs ]; then
    echo "  --- suspicious error.log lines:"; sed 's/^/      /' /tmp/mf_errs
    bad "error.log has crash/abort lines"
else
    ok "error.log clean (no crash/abort/worker-exit)"
fi
rm -f /tmp/mf_errs

echo
echo "================== RESULT: $pass passed, $fail failed, $skip skipped =================="
[ "$fail" -eq 0 ]
