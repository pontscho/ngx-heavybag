#!/usr/bin/env bash
#
# ngx_http_waf_module - pure-core unit tests (standalone, no nginx).
#
# Each test includes one module .c under a -D*_UNIT_TEST guard, pulling in only
# the nginx-free core (no nginx / SSL headers), and links just what that core
# needs. The full module build covers -Werror cleanliness; here we keep the
# flags minimal so the vendored ctest.h compiles cleanly.
#
#   test-ja4.c           -> JA4 core            (needs -lcrypto for SHA256)
#   test_waf_ua_parse.c  -> UA descriptive core (no extra libs)
#
# Usage:  bash run-unit-tests.sh [suite[:test]]
# Exit 0 = all tests in all binaries passed.

set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../../src"
CC="${CC:-cc}"
TMP="${TMPDIR:-/tmp}"

# -Wno-attributes: the vendored ctest.h uses a no_sanitize attribute this gcc
# does not recognise; it is harmless test-harness noise, not our code.
COMMON="-I$SRC -O2 -Wall -Wno-attributes"

rc=0

# ---- JA4 core -------------------------------------------------------------
BIN_JA4="$TMP/waf-test-ja4"
if "$CC" -DWAF_JA4_UNIT_TEST $COMMON "$DIR/test-ja4.c" -lcrypto -o "$BIN_JA4"; then
    echo "== JA4 core =="
    "$BIN_JA4" "$@" || rc=1
else
    echo "JA4 unit test COMPILE FAILED"; rc=1
fi

# ---- UA descriptive parser core ------------------------------------------
BIN_UA="$TMP/waf-test-ua-parse"
if "$CC" -DWAF_UA_PARSE_UNIT_TEST $COMMON "$DIR/test_waf_ua_parse.c" -o "$BIN_UA"; then
    echo "== UA parser core =="
    "$BIN_UA" "$@" || rc=1
else
    echo "UA parser unit test COMPILE FAILED"; rc=1
fi

exit $rc
