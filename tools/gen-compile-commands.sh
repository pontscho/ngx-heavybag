#!/usr/bin/env bash
#
# gen-compile-commands.sh — regenerate build/compile_commands.json for clangd.
#
# WHY THIS EXISTS:
#   The clangd MCP server is launched with --compile-commands-dir=build/, but the
#   nginx/openresty build never emits a compile_commands.json (the heavybag module
#   is compiled by nginx's own objs/Makefile, not by cmake directly). Without a CDB
#   clangd background-indexes blind and drifts. This script synthesizes the CDB by
#   lifting the EXACT compile flags (CC, CFLAGS, ALL_INCS) out of the nginx
#   objs/Makefile recipe — no rebuild required, so it never trips the OpenSSL
#   rebuild trap.
#
#   The CDB is a gitignored build artifact AND the build-matrix can swap objs/ for
#   a stub, so re-run this after any clean rebuild / build-matrix run, then
#   reconnect the clangd MCP server (kill its wrapper PID + /mcp reconnect) so a
#   fresh clangd picks it up.
#
# USAGE: tools/gen-compile-commands.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NGINX_BUILD="${NGINX_BUILD:-$REPO/build/nginx_ext-prefix/src/nginx_ext}"
MK="$NGINX_BUILD/objs/Makefile"
SRC_DIR="${SRC_DIR:-$REPO/modules/ngx_http_heavybag/src}"
OUT="${OUT:-$REPO/build/compile_commands.json}"

die() { echo "gen-compile-commands: ERROR: $*" >&2; exit 1; }

[ -f "$MK" ] || die "nginx objs/Makefile not found at $MK
  (run the cmake build / ./configure first; override with NGINX_BUILD=...)"
[ -d "$SRC_DIR" ] || die "module source dir not found: $SRC_DIR"

# Extract a make variable value, joining backslash-continued lines and
# collapsing whitespace. Works for single-line (CC, CFLAGS) and multi-line
# (ALL_INCS) assignments alike.
extract_var() {
  local var="$1"
  awk -v var="$var" '
    $0 ~ "^" var "[ \t]*=" {
      sub("^" var "[ \t]*=[ \t]*", "")
      cont = sub(/\\[ \t]*$/, "")
      buf = $0
      while (cont) {
        if ((getline line) <= 0) break
        cont = sub(/\\[ \t]*$/, "", line)
        buf = buf " " line
      }
      gsub(/[ \t]+/, " ", buf)
      sub(/^ /, "", buf); sub(/ $/, "", buf)
      print buf
      exit
    }
  ' "$MK"
}

CC="$(extract_var CC)"
CFLAGS="$(extract_var CFLAGS)"
ALL_INCS="$(extract_var ALL_INCS)"

[ -n "$CC" ]       || die "could not parse CC from $MK"
[ -n "$ALL_INCS" ] || die "could not parse ALL_INCS from $MK (objs stub? re-run ./configure)"

# Sanity: the Makefile must actually carry the heavybag addon build (guards against
# the build-matrix objs-nopcre stub that lacks the module rules).
grep -q 'ngx_http_heavybag_module' "$MK" \
  || die "Makefile has no heavybag addon rules — looks like a build-matrix stub; re-run canonical ./configure"

shopt -s nullglob
srcs=( "$SRC_DIR"/*.c )
[ "${#srcs[@]}" -gt 0 ] || die "no .c sources under $SRC_DIR"

# The compile recipe in objs/Makefile is: $(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) ...
# directory MUST be the nginx build root so relative includes (-I src/core, -I objs)
# resolve correctly.
{
  echo "["
  first=1
  for f in "${srcs[@]}"; do
    b="$(basename "$f" .c)"
    if [ "$first" -eq 1 ]; then first=0; else echo ","; fi
    printf '  {\n    "directory": "%s",\n    "command": "%s -c -fPIC %s %s -o objs/addon/src/%s.o %s",\n    "file": "%s"\n  }' \
      "$NGINX_BUILD" "$CC" "$CFLAGS" "$ALL_INCS" "$b" "$f" "$f"
  done
  echo
  echo "]"
} > "$OUT"

# Validate JSON if python3 is available (non-fatal if absent).
if command -v python3 >/dev/null 2>&1; then
  python3 -c "import json,sys; d=json.load(open('$OUT')); print('gen-compile-commands: wrote %d entries -> $OUT' % len(d))" \
    || die "generated $OUT is not valid JSON"
else
  echo "gen-compile-commands: wrote ${#srcs[@]} entries -> $OUT (json validation skipped: no python3)"
fi

echo "gen-compile-commands: done. Reconnect the clangd MCP (kill wrapper PID + /mcp reconnect) to pick it up."
