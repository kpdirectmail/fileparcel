#!/bin/bash
# Full end-to-end smoke run against a fresh FileParcel home.
set -u
SRC="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SRC/../.." && pwd)"
D="${FP_SMOKE_DIR:-${TMPDIR:-/tmp}/fileparcel-smoke}"
mkdir -p "$D"
# The server refuses an upload that would leave less than 1 GiB or 2 % of the
# file system free (DESIGN §16 "Limits"), whatever the upload's size. On a
# small or busy $TMPDIR that turns phase 3 onwards into a cascade of HTTP 507
# "quota_exceeded" that looks like a product bug, so check here instead: that
# reserve + the ~500 MiB the suite writes. `df -Pk` field 2 is the total and
# field 4 the available 1024-blocks, i.e. exactly the Blocks*Bsize and
# Bavail*Bsize that internal/uploads/diskfree_unix.go reads. No second line
# (df missing or unparseable) means no output and no complaint.
short=$(df -Pk "$D" 2>/dev/null | awk 'NR == 2 {
        reserve = $2 / 50                           # 2 % of the file system
        if (reserve < 1048576) reserve = 1048576    # ... but at least 1 GiB
        need = reserve + 524288
        if ($4 < need) printf "%d %d", $4 / 1024, need / 1024
    }')
if [ -n "$short" ]; then
  echo "FP_SMOKE_DIR=$D has only ${short% *} MiB free; the suite needs about ${short#* } MiB."
  echo "The server refuses every upload that would leave less than 1 GiB or 2 % of the"
  echo "file system free, so point FP_SMOKE_DIR at a larger disk."
  exit 1
fi
PORT="${FP_PORT:-18443}"
HTTP_PORT="${FP_HTTP_PORT:-18080}"
HOST_NAME="${FP_HOST:-fileparcel.local}"
# FP_HOST has to be exported too: srv.sh is started again from inside
# phases 8 and 10, and fp.py reads it in every phase.
export FP_HOME="$D/h1" FP_SMOKE_DIR="$D" FP_PORT="$PORT" FP_HTTP_PORT="$HTTP_PORT" FP_HOST="$HOST_NAME"
export FILEPARCEL_TAILSCALE_SOCKET="$D/no-tailscaled.sock" # never the real tailscaled (Tailscale "not running")
cd "$D" || exit 1
exec > >(tee "$D/run_all.log") 2>&1

# Cheap and server-free, so it runs before anything is built: no phase may
# print failure-phrased text on a PASS line (see lint_details.py).
python3 "$SRC/lint_details.py" || exit 1

# The suite starts a detached server (srv.sh outlives this script) and must not
# leave it holding the ports, however the run ends: the summary, a failed
# start, a Ctrl-C or a CI kill. FP_KEEP_SERVER=1 keeps it up for poking at.
# "rc=$?" captures the status the script is exiting with (the explicit exit at
# the end of the file) and "exit $rc" re-raises it, so a red run stays red:
# before this, the last statement executed decided the status and a caller saw
# a completely broken run as green.
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  rc=$?
  if [ "${FP_KEEP_SERVER:-0}" = 1 ]; then
    echo "server left running on $HOST_NAME:$PORT (FP_KEEP_SERVER=1); stop it with tests/smoke/srv.sh stop"
  else
    "$SRC/srv.sh" stop >/dev/null 2>&1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=================== BUILD ==================="
# shellcheck disable=SC1091 # sourced relative to $REPO
( cd "$REPO" && . scripts/env.sh && GOFLAGS=-mod=mod go build -o "$D/fileparcel" ./cmd/fileparcel ) || { echo "BUILD FAILED"; exit 1; }
echo "build ok"

echo "=================== STOP + FRESH HOME ==================="
"$SRC/srv.sh" stop
rm -rf "$D/h1" "$D/state.json" "$D/mbox.txt" "$D/backup.fpbak" "$D/old-ca.crt" "$D/cli" "$D/dbcheck" \
  "$D/identity.txt" "$D/st.json" "$D/cli-audit.jsonl"
: > "$D/serve.log"
./fileparcel init --home "$D/h1" --port "$PORT" --http-port "$HTTP_PORT" \
  --admin admin --admin-email admin@example.org --generate-password --non-interactive > "$D/init.log" 2>&1
rc=$?
echo "init exit=$rc"
[ $rc -eq 0 ] || { tail -20 "$D/init.log"; exit 1; }
PW=$(grep -E '^[[:space:]]+password:' "$D/init.log" | head -1 | awk '{print $2}')

# Pin the host name the suite talks to into the leaf certificate. On a LAN
# where fileparcel.local is already taken, mDNS renames the instance
# (fileparcel-2.local, -3.local, ...) and the leaf is reissued for the
# published name only, which breaks every later phase mid-run.
./fileparcel --home "$D/h1" --offline config set tls.extra_sans "$HOST_NAME" >/dev/null 2>&1 ||
  echo "WARNING: could not pin tls.extra_sans=$HOST_NAME"
# Same reason for the WebAuthn RP ID: without an explicit value it follows the
# *effective* mDNS name, so after a collision rename /auth/state reports
# fileparcel-2.local while the suite talks to $HOST_NAME.
./fileparcel --home "$D/h1" --offline config set auth.webauthn_rp_id "$HOST_NAME" >/dev/null 2>&1 ||
  echo "WARNING: could not pin auth.webauthn_rp_id=$HOST_NAME"
echo "generated owner password captured: ${PW:0:4}…(${#PW} chars)"

echo "=================== START ==================="
"$SRC/srv.sh" start || exit 1

# A space-separated list, not an array: "${#a[@]}" on an empty array is an
# error under "set -u" in bash 3.2 (the /bin/bash of macOS).
FAILED=""
# timeout(1) is GNU coreutils; run the phase unwrapped where it is missing.
if command -v timeout >/dev/null 2>&1; then
  with_timeout() { timeout 1800 "$@"; }
else
  with_timeout() { "$@"; }
fi
run() {
  echo
  echo "=================== $1 ==================="
  shift
  local name="$1"; shift
  with_timeout "$@"
  local rc=$?
  if [ $rc -ne 0 ]; then FAILED="$FAILED $name"; fi
  return 0
}
run "PHASE 1 auth"        t01 python3 "$SRC"/t01_auth.py "$PW"
run "PHASE 2 users"       t02 python3 "$SRC"/t02_users.py
run "PHASE 3 files"       t03 python3 "$SRC"/t03_files.py
run "PHASE 4 shares"      t04 python3 "$SRC"/t04_shares.py
run "PHASE 5 admin"       t05 python3 "$SRC"/t05_admin.py
run "PHASE 6 pages"       t06 python3 "$SRC"/t06_pages.py
FP_PAT=$(python3 -c "import json,os;print(json.load(open(os.environ['FP_SMOKE_DIR']+'/state.json')).get('pat',''))" 2>/dev/null)
export FP_PAT
run "PHASE 7 CLI"         t07 "$SRC/t07_cli.sh"
run "PHASE 8 sealed"      t08 python3 "$SRC"/t08_sealed.py
run "PHASE 9 rest"        t09 python3 "$SRC"/t09_rest.py
run "PHASE 10 destructive" t10 python3 "$SRC"/t10_destructive.py
run "PHASE 11 maintenance" t11 python3 "$SRC"/t11_maintenance.py

# Through run() as well: coverage.py exits non-zero when it cannot find the
# route table or the access log, and that has to turn the run red too.
run "ROUTE COVERAGE"      cov python3 "$SRC/coverage.py"

echo
echo "=================== SUMMARY ==================="
if [ -z "$FAILED" ]; then echo "ALL PHASES PASSED"; else printf 'PHASES WITH FAILURES:%s\n' "$FAILED"; fi

# The server is stopped by the EXIT trap, which re-raises this status.
if [ -n "$FAILED" ]; then exit 1; fi
exit 0
