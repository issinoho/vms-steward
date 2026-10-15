#!/usr/bin/env bash
# run.sh - the front end's UI tests (make ui-test): the dev server on the stub, and
# each tests/ui/*.mjs in node with jsdom as the DOM. jsdom is not vendored: once,
#     (cd tests/ui && npm install jsdom@24)
# Without it, the tests are skipped with a message.
set -euo pipefail
top=$(cd "$(dirname "$0")/../.." && pwd)
cd "$top"
[ -d tests/ui/node_modules/jsdom ] || { echo "ui-test: skipped (cd tests/ui && npm install jsdom@24)"; exit 0; }
port=${STEWARD_UI_PORT:-8188}
work=$(mktemp -d)
trap 'kill $srv 2>/dev/null || true; rm -rf "$work"' EXIT
# The modules as ES modules node can import, beside the test's jsdom.
mkdir "$work/js" && cp www/js/*.js "$work/js/" && echo '{"type":"module"}' > "$work/js/package.json"
STEWARD_DEV_FCGI_PORT=$((port + 11000)) python3 tools/devserver.py build/steward "$port" >"$work/dev.log" 2>&1 &
srv=$!
for _ in $(seq 50); do curl -sf -o /dev/null "http://127.0.0.1:$port/api/v1/health" && break; sleep 0.2; done
rc=0
for t in tests/ui/*.mjs; do
    echo "== $t"
    STEWARD_UI_BASE="http://127.0.0.1:$port/" STEWARD_UI_JS="$work/js" NODE_PATH="$top/tests/ui/node_modules" \
        node "$t" || rc=1
done
exit $rc
