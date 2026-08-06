#!/usr/bin/env bash
#
# run-sandbox.sh - render sandbox/nginx.conf (@HB_ROOT@ -> $ROOT) into
# sandbox/.render/ and launch the sandbox nginx against it. The committed
# nginx.conf holds NO absolute path; ROOT is derived from this script's own
# location so the checkout can be renamed/moved freely (override: HEAVYBAG_ROOT).
#
# Usage:
#   bash sandbox/run-sandbox.sh          # render + start nginx
#   bash sandbox/run-sandbox.sh -t       # render + config-test only
#   bash sandbox/run-sandbox.sh -s stop  # render + stop a running instance
#   bash sandbox/run-sandbox.sh -s reload
#
set -euo pipefail

ROOT=${HEAVYBAG_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
RENDER=$SBX/.render
CONF=$RENDER/nginx.conf

[ -x "$NGINX" ] || { echo "sandbox nginx not built: $NGINX (run the build first)" >&2; exit 2; }

mkdir -p "$RENDER"
sed "s#@HB_ROOT@#$ROOT#g" "$SBX/nginx.conf" > "$CONF"

exec "$NGINX" -p "$SBX/" -c "$CONF" "$@"
