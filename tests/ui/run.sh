#!/bin/sh
# Run the Playwright UI tests: creates tests/ui/.venv (gitignored) on first use,
# installs requirements.txt, tries to download Playwright's Chromium (falls back
# to /usr/bin/brave-browser or $FP_UI_BROWSER when that is not possible) and runs
# pytest. Extra arguments go to pytest, e.g.:
#   tests/ui/run.sh -k mobile -x
#   FP_UI_BASE_URL=https://fileparcel.local:8443 FP_UI_CA=ca.crt ... tests/ui/run.sh   (existing server)
# See tests/ui/conftest.py for all FP_UI_* variables.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
VENV=${FP_UI_VENV:-$HERE/.venv}
if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
fi
if ! "$VENV/bin/python" -c 'import playwright, pytest' 2>/dev/null; then
    "$VENV/bin/pip" install -q -r "$HERE/requirements.txt"
fi
if [ -z "${FP_UI_BROWSER:-}" ] && [ ! -f "$VENV/.chromium-ok" ]; then
    if "$VENV/bin/python" -m playwright install chromium >/dev/null 2>&1; then
        : >"$VENV/.chromium-ok"
    else
        echo "run.sh: could not download Playwright's Chromium; using the fallback browser" >&2
    fi
fi
cd "$HERE"
exec "$VENV/bin/python" -m pytest "$@"
