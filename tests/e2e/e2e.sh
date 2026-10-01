#!/bin/sh
# FileParcel end-to-end test (DESIGN §17 "E2E").
#
# Builds the binary for this machine (or uses --bin), creates a scratch home
# on free ports, starts "fileparcel serve" and drives it over HTTPS exactly like
# a client would: curl --resolve fileparcel.local:PORT:127.0.0.1 --cacert ca.crt.
# Every step prints PASS / FAIL / SKIP; the exit status is 0 only when no step
# failed. The server is always stopped on exit.
#
# Usage: tests/e2e/e2e.sh [options]
#   --bin PATH      test this binary instead of building one
#   --work DIR      working directory (default: a new mktemp -d under $TMPDIR);
#                   a directory named here is always kept, never removed
#   --keep          keep the working directory (it is always kept after a failure)
#   --name NAME     server name; the host name used is NAME.local (default fileparcel)
#   --big-mb N      size of the large upload in MiB (default 50)
#   -h, --help      show this help
#
# Environment:
#   E2E_SKIP="step step"   skip these steps      E2E_ONLY="step ..."  run only these
#   NO_COLOR=1             plain output
#
# Needs: sh, curl, python3 (stdlib), openssl, unzip, tar, dd; Go >= 1.26 unless --bin.
# POSIX sh; works with dash, bash (incl. macOS bash 3.2) and zsh.
set -u

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(CDPATH='' cd -- "$HERE/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$HERE/lib.sh"

BIN=""
WORK=""
KEEP=0
FP_LABEL=fileparcel
BIG_MB=50

usage() { sed -n '2,/^# POSIX sh/{s/^# \{0,1\}//;p;}' "$HERE/e2e.sh"; }
while [ $# -gt 0 ]; do
    case $1 in
        --bin) [ $# -ge 2 ] || die "--bin needs a path"; BIN=$2; shift ;;
        --work) [ $# -ge 2 ] || die "--work needs a directory"; WORK=$2; shift ;;
        --keep) KEEP=1 ;;
        --name) [ $# -ge 2 ] || die "--name needs a value"; FP_LABEL=$2; shift ;;
        --big-mb) [ $# -ge 2 ] || die "--big-mb needs a number"; BIG_MB=$2; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
case $BIG_MB in ''|*[!0-9]*) die "--big-mb needs a number" ;; esac

for c in curl python3 openssl unzip tar dd; do
    have "$c" || die "missing required tool: $c"
done

# ---------- working directory ----------
# WORK_OWNED: the script made this directory itself, so cleanup may delete it.
# A directory named with --work is never deleted — it may be a directory the
# caller also keeps other things in.
WORK_OWNED=0
if [ -z "$WORK" ]; then
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/fp-e2e.XXXXXX") || die "mktemp failed"
    WORK_OWNED=1
else
    mkdir -p "$WORK" || die "cannot create $WORK"
    WORK=$(CDPATH='' cd -- "$WORK" && pwd -P) || die "cannot enter $WORK"
    [ -n "$WORK" ] || die "cannot resolve the working directory"
fi
# Never reach this machine's real tailscaled (its operator may be the user running the tests): point the server
# and every CLI call at a socket that does not exist (Tailscale "not running"; no CLI fallback).
export FILEPARCEL_TAILSCALE_SOCKET="$WORK/no-tailscaled.sock"
case $WORK in
    "$REPO/server" | "$REPO/server/"*) die "refusing to run inside the live installation" ;;
esac
# The server refuses an upload that would leave less than 1 GiB or 2 % of the
# blob store's file system free (DESIGN §16 "Limits"), whatever the upload's
# size, so a small or busy $TMPDIR turns every upload step into HTTP 507
# "quota_exceeded" and looks like a product bug. Need: that reserve + the big
# file three times (client copy + parts + blob). `df -Pk` field 2 is the total
# and field 4 the available 1024-blocks, i.e. exactly the Blocks*Bsize and
# Bavail*Bsize that internal/uploads/diskfree_unix.go reads. No second line
# (df missing or unparseable) means no output and no complaint.
short=$(df -Pk "$WORK" 2>/dev/null | awk -v big="$BIG_MB" 'NR == 2 {
        reserve = $2 / 50                           # 2 % of the file system
        if (reserve < 1048576) reserve = 1048576    # ... but at least 1 GiB
        need = reserve + big * 1024 * 3
        if ($4 < need) printf "%d %d", $4 / 1024, need / 1024
    }')
if [ -n "$short" ]; then
    [ "$WORK_OWNED" -eq 1 ] && rmdir "$WORK" 2>/dev/null
    die "$WORK has only ${short% *} MiB free; this run needs about ${short#* } MiB (the server refuses uploads that would leave less than 1 GiB or 2 % of the file system free). Use --work DIR on a larger filesystem."
fi
H="$WORK/home"
FILES="$WORK/files"
mkdir -p "$FILES" "$WORK/parts"
JAR="$WORK/cookies.txt"
ANON_JAR="$WORK/anon-cookies.txt"
BODY="$WORK/body"
HDRS="$WORK/headers"
: >"$JAR"
: >"$ANON_JAR"

FP_NAME="$FP_LABEL.local"
PORT=$(free_port)
HTTP_PORT=$(free_port)
while [ "$HTTP_PORT" = "$PORT" ]; do HTTP_PORT=$(free_port); done
BASE="https://$FP_NAME:$PORT"
CA="$H/certs/ca/ca.crt"
CSRF=""
STATUS=""
SERVER_PID=""

ADMIN_USER="admin"
ADMIN_PW="E2e-$(rand_hex 12)"
SEAL_PW="seal-$(rand_hex 16)"
SHARE_PW="share-$(rand_hex 8)"
TOTP_SECRET=""
TOTP_URI=""
RECOVERY_CODE=""
SHARE_TOKEN=""

ROOT=""
BIG_NODE=""
A_NODE=""
TRIP=""
BIG="$FILES/big.bin"

info "FileParcel E2E"
info "  work dir  $WORK"
info "  server    $BASE  (127.0.0.1, HTTP redirect port $HTTP_PORT)"

# ---------- server control ----------
server_alive() { [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; }

healthy() {
    [ "$(curl -s --cacert "$CA" --resolve "$FP_NAME:$PORT:127.0.0.1" --max-time 3 "$BASE/healthz" 2>/dev/null)" = ok ] ||
        [ "$(curl -s --cacert "$CA" --max-time 3 "https://127.0.0.1:$PORT/healthz" 2>/dev/null)" = ok ]
}

start_server() {
    "$BIN" serve --home "$H" >>"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    if ! wait_until 60 healthy; then
        server_alive || why "the server exited: $(tail -n 5 "$WORK/server.log" | tr '\n' ' ')"
        return 1
    fi
    return 0
}

stop_server() {
    if server_alive; then
        kill -TERM "$SERVER_PID" 2>/dev/null
        ss_i=0
        while server_alive && [ "$ss_i" -lt 80 ]; do
            sleep 0.5 2>/dev/null || sleep 1
            ss_i=$((ss_i + 1))
        done
        if server_alive; then
            kill -KILL "$SERVER_PID" 2>/dev/null
            WHY="the server did not stop within 40 s after SIGTERM (killed)"
            wait "$SERVER_PID" 2>/dev/null
            SERVER_PID=""
            return 1
        fi
        wait "$SERVER_PID" 2>/dev/null
    fi
    SERVER_PID=""
    return 0
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
    rc=$?
    stop_server >/dev/null 2>&1
    if [ "$N_FAIL" -eq 0 ] && [ "$KEEP" -eq 0 ] && [ "$rc" -eq 0 ] && [ "$WORK_OWNED" -eq 1 ]; then
        rm -rf "$WORK"
    else
        info "Kept the working directory for inspection: $WORK (server log: $WORK/server.log)"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# refresh_csrf: take the CSRF token from the last body, else from GET /me.
refresh_csrf() {
    rc_t=$(jget 'd.get("csrf")' 2>/dev/null || true)
    if [ -z "$rc_t" ]; then
        api GET /api/v1/me
        rc_t=$(jget 'd.get("csrf")' || true)
    fi
    [ -z "$rc_t" ] || CSRF=$rc_t
}

# login_full: password (+ TOTP when enrolled). Leaves a full session.
login_full() {
    CSRF=""
    : >"$JAR"
    EXPECT_CTX="login"
    api POST /api/v1/auth/login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}"
    expect 200 || return 1
    if [ "$(jget 'd.get("mfa_required")')" = true ]; then
        refresh_csrf
        [ -n "$TOTP_SECRET$TOTP_URI" ] || why "MFA required but no TOTP secret is known" || return 1
        api POST /api/v1/auth/totp "{\"code\":\"$(totp_code)\"}"
        EXPECT_CTX="TOTP login step"
        expect 200 || return 1
    fi
    refresh_csrf
    return 0
}

# ensure_login: makes sure there is a full (MFA-complete) session, signing in
# again when an earlier step failed half-way (so later steps still run).
ensure_login() {
    server_alive || { why "server not running"; return 1; }
    api GET /api/v1/me
    if [ "$STATUS" = 200 ] && [ "$(jget 'd.get("mfa_pending")')" = false ]; then
        [ -n "$CSRF" ] || refresh_csrf
        return 0
    fi
    login_full
}

# upload_small BATCH REF FILE: PUT a small file into a batch.
upload_small() {
    api PUT "/api/v1/upload-batches/$1/small?ref=$2" "" -H "X-FP-SHA256: $(sha256 "$3")" \
        -H 'Content-Type: application/octet-stream' --data-binary "@$3"
}

# poll_job ID [TIMEOUT]: waits for a job to finish; succeeds when it succeeded.
poll_job() {
    pj_end=$(($(date +%s) + ${2:-120}))
    while :; do
        api GET "/api/v1/jobs/$1"
        if [ "$STATUS" != 200 ]; then api GET "/api/v1/admin/jobs/$1"; fi
        pj_state=$(jget 'd["state"]' || true)
        case $pj_state in
            succeeded) return 0 ;;
            failed | canceled) why "job $1 $pj_state: $(jget 'd.get("error")')"; return 1 ;;
        esac
        [ "$(date +%s)" -lt "$pj_end" ] || { why "job $1 did not finish (state '$pj_state', HTTP $STATUS)"; return 1; }
        sleep 1
    done
}

# ======================================================================
# steps
# ======================================================================

t_build() {
    if [ -n "$BIN" ]; then
        [ -x "$BIN" ] || why "--bin $BIN is not executable" || return 1
        BIN=$(CDPATH='' cd -- "$(dirname -- "$BIN")" && pwd -P)/$(basename -- "$BIN")
        return 0
    fi
    sh "$REPO/scripts/build.sh" -q -o "$WORK/bin" -v e2e host >"$WORK/build.log" 2>&1 ||
        why "scripts/build.sh failed: $(tail -n 5 "$WORK/build.log" | tr '\n' ' ')" || return 1
    BIN="$WORK/bin/fileparcel"
    "$BIN" version >/dev/null 2>&1 || why "the built binary does not run" || return 1
}

t_init() {
    [ -x "$BIN" ] || skip_because "no binary" || return
    (umask 077 && printf '%s\n' "$ADMIN_PW" >"$WORK/admin.pw")
    "$BIN" init --home "$H" --port "$PORT" --http-port "$HTTP_PORT" --name "$FP_LABEL" \
        --admin "$ADMIN_USER" --admin-password-file "$WORK/admin.pw" --access private --non-interactive \
        >"$WORK/init.log" 2>&1 || why "fileparcel init failed: $(tail -n 5 "$WORK/init.log" | tr '\n' ' ')" || return 1
    [ -f "$H/fileparcel.toml" ] || why "no fileparcel.toml after init" || return 1
    [ -f "$CA" ] || why "no CA certificate at $CA" || return 1
    # file modes of the self-contained layout (DESIGN §3)
    for d in data keys certs; do
        m=$(python3 -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$H/$d" 2>/dev/null)
        [ "$m" = 0o700 ] || why "$d/ has mode $m, want 0700" || return 1
    done
    m=$(python3 -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$H/keys/master.key" 2>/dev/null)
    [ "$m" = 0o600 ] || why "keys/master.key has mode $m, want 0600" || return 1
    # keep the test off the LAN: no mDNS publishing; make sure the leaf names NAME.local
    "$BIN" --home "$H" --offline config set mdns.mode off >>"$WORK/init.log" 2>&1 || note "config set mdns.mode off failed"
    "$BIN" --home "$H" --offline config set tls.extra_sans "$FP_NAME" >>"$WORK/init.log" 2>&1 || note "config set tls.extra_sans failed"
    return 0
}

t_start() {
    [ -f "$H/fileparcel.toml" ] || skip_because "no home" || return
    start_server
}

t_health() {
    server_alive || skip_because "server not running" || return
    EXPECT_CTX="GET /healthz via $FP_NAME"
    api GET /healthz
    if [ "$STATUS" = 000 ] && [ "$(curl -s --cacert "$CA" --max-time 3 "https://127.0.0.1:$PORT/healthz")" = ok ]; then
        # carry on by IP so the remaining steps still run, but report the problem
        BASE="https://127.0.0.1:$PORT"
        why "the certificate does not verify for $FP_NAME (the remaining steps use $BASE)"
        return 1
    fi
    expect 200 || return 1
    [ "$(cat "$BODY")" = ok ] || why "/healthz body is not 'ok'" || return 1
    EXPECT_CTX="GET /readyz"
    api GET /readyz
    expect 200 || return 1
    # the CA served on /trust matches the file (compare fingerprints)
    anon GET /trust/ca.pem
    EXPECT_CTX="GET /trust/ca.pem"
    expect 200 || return 1
    f1=$(openssl x509 -in "$BODY" -noout -fingerprint -sha256 2>/dev/null)
    f2=$(openssl x509 -in "$CA" -noout -fingerprint -sha256 2>/dev/null)
    [ -n "$f1" ] && [ "$f1" = "$f2" ] || why "/trust/ca.pem differs from certs/ca/ca.crt" || return 1
}

t_headers() {
    server_alive || skip_because "server not running" || return
    anon GET /login
    EXPECT_CTX="GET /login"
    expect 200 || return 1
    csp=$(header content-security-policy)
    case $csp in *"require-trusted-types-for 'script'"*) ;; *) why "page CSP lacks require-trusted-types-for: $csp"; return 1 ;; esac
    case $csp in *"trusted-types fp"*) ;; *) why "page CSP lacks 'trusted-types fp': $csp"; return 1 ;; esac
    case $csp in *"frame-ancestors 'none'"*) ;; *) why "page CSP lacks frame-ancestors 'none'"; return 1 ;; esac
    case $csp in *"'unsafe-inline'"* | *"'unsafe-eval'"*) why "page CSP allows unsafe-inline/eval: $csp"; return 1 ;; esac
    [ "$(header x-frame-options)" = DENY ] || why "X-Frame-Options is '$(header x-frame-options)'" || return 1
    [ "$(header x-content-type-options)" = nosniff ] || why "X-Content-Type-Options missing" || return 1
    [ "$(header referrer-policy)" = no-referrer ] || why "Referrer-Policy is '$(header referrer-policy)'" || return 1
    [ -n "$(header cross-origin-opener-policy)" ] || why "Cross-Origin-Opener-Policy missing" || return 1
    [ -z "$(header strict-transport-security)" ] || why "HSTS is sent with a local-CA certificate (tls.hsts=auto)" || return 1
    anon GET /api/v1/auth/state
    EXPECT_CTX="GET /api/v1/auth/state"
    expect 200 || return 1
    case $(header cache-control) in *no-store*) ;; *) why "API Cache-Control is '$(header cache-control)'"; return 1 ;; esac
    [ "$(jget 'd["keys_state"]')" = unlocked ] || why "keys_state is not unlocked" || return 1
}

t_redirect_same_port() {
    server_alive || skip_because "server not running" || return
    plain_http "http://127.0.0.1:$PORT/files?x=1" -H "Host: $FP_NAME:$PORT"
    EXPECT_CTX="plain HTTP on the HTTPS port"
    expect 308 || return 1
    loc=$(header location)
    [ "$loc" = "https://$FP_NAME:$PORT/files?x=1" ] || why "Location is '$loc'" || return 1
}

t_redirect_http_port() {
    server_alive || skip_because "server not running" || return
    plain_http "http://127.0.0.1:$HTTP_PORT/files" -H "Host: $FP_NAME:$HTTP_PORT"
    EXPECT_CTX="HTTP redirect port"
    expect 308 || return 1
    loc=$(header location)
    [ "$loc" = "https://$FP_NAME:$PORT/files" ] || why "Location is '$loc'" || return 1
}

t_tls_versions() {
    server_alive || skip_because "server not running" || return
    openssl s_client -connect "127.0.0.1:$PORT" -servername "$FP_NAME" -tls1_2 -CAfile "$CA" \
        -verify_return_error -verify_hostname "$FP_NAME" </dev/null >"$WORK/tls12.txt" 2>&1 ||
        why "TLS 1.2 handshake with certificate verification failed: $(grep -m1 -iE 'error|verify' "$WORK/tls12.txt")" || return 1
    openssl s_client -connect "127.0.0.1:$PORT" -servername "$FP_NAME" -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' \
        </dev/null >"$WORK/tls11.txt" 2>&1
    rc=$?
    if grep -qiE 'no protocols available|unknown option|invalid command' "$WORK/tls11.txt"; then
        skip_because "this openssl cannot speak TLS 1.1"
        return
    fi
    if [ "$rc" -eq 0 ] && grep -qE 'Protocol *: *TLSv1\.1|New, TLSv1\.1' "$WORK/tls11.txt"; then
        why "the server accepted a TLS 1.1 handshake"
        return 1
    fi
    return 0
}

t_anon_401() {
    server_alive || skip_because "server not running" || return
    for p in /api/v1/me /api/v1/spaces /api/v1/admin/users /api/v1/admin/settings /api/v1/shares; do
        anon GET "$p"
        EXPECT_CTX="anonymous GET $p"
        expect 401 || return 1
    done
    anon GET /api/v1/system/status
    EXPECT_CTX="GET /api/v1/system/status"
    expect 200 || return 1
}

t_login() {
    server_alive || skip_because "server not running" || return
    anon POST /api/v1/auth/login "{\"username\":\"$ADMIN_USER\",\"password\":\"wrong-$ADMIN_PW\"}"
    EXPECT_CTX="login with a wrong password"
    expect 401 || return 1
    api POST /api/v1/auth/login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}"
    EXPECT_CTX="login"
    expect 200 || return 1
    grep -q '__Host-fp_session' "$JAR" || why "no __Host-fp_session cookie was set" || return 1
    must=$(jget 'd.get("must_change_password")')
    refresh_csrf
    [ -n "$CSRF" ] || why "no CSRF token in the login response or GET /me" || return 1
    if [ "$must" = true ]; then
        new="E2e-$(rand_hex 12)"
        api POST /api/v1/me/password "{\"current_password\":\"$ADMIN_PW\",\"new_password\":\"$new\"}"
        EXPECT_CTX="change the initial password"
        expect 200 204 || return 1
        ADMIN_PW=$new
        refresh_csrf
    fi
    api GET /api/v1/me
    EXPECT_CTX="GET /me"
    expect 200 || return 1
    [ "$(jget 'd["user"]["username"]')" = "$ADMIN_USER" ] || why "GET /me returned another user" || return 1
}

t_csrf() {
    [ -n "$CSRF" ] || skip_because "not logged in" || return
    body='{"display_name":"E2E Admin"}'
    saved=$CSRF
    CSRF=""
    api PATCH /api/v1/me/profile "$body"
    CSRF=$saved
    EXPECT_CTX="PATCH without X-FP-CSRF"
    expect 403 || return 1
    api PATCH /api/v1/me/profile "$body" -H 'Sec-Fetch-Site: cross-site' -H 'Origin: https://evil.example'
    EXPECT_CTX="cross-site PATCH with a valid token"
    expect 403 || return 1
    CSRF="x$saved"
    api PATCH /api/v1/me/profile "$body"
    CSRF=$saved
    EXPECT_CTX="PATCH with a wrong token"
    expect 403 || return 1
    api PATCH /api/v1/me/profile "$body"
    EXPECT_CTX="same-origin PATCH with the token"
    expect 200 204 || return 1
}

t_totp_enroll() {
    [ -n "$CSRF" ] || skip_because "not logged in" || return
    # setting up a second factor needs step-up (DESIGN §9.3): the new factor satisfies it
    api POST /api/v1/me/totp/begin
    EXPECT_CTX="POST /me/totp/begin without step-up"
    expect 403 || return 1
    api POST /api/v1/auth/elevate "{\"password\":\"$ADMIN_PW\"}"
    EXPECT_CTX="elevate (the enrolling admin confirms with the password)"
    expect 200 || return 1
    refresh_csrf
    api POST /api/v1/me/totp/begin
    EXPECT_CTX="POST /me/totp/begin"
    expect 200 201 || return 1
    TOTP_SECRET=$(jget 'd["secret"]') || why "no secret in the enrollment response" || return 1
    TOTP_URI=$(jget 'd.get("otpauth_uri")')
    case $TOTP_URI in otpauth://totp/*) ;; *) why "bad otpauth_uri: $TOTP_URI"; return 1 ;; esac
    case $(jget 'd.get("qr_data_uri")') in data:image/svg+xml*) ;; *) why "qr_data_uri is not an SVG data URI"; return 1 ;; esac
    api POST /api/v1/me/totp/confirm '{"code":"000000"}'
    EXPECT_CTX="confirm with a wrong code"
    status_in 400 401 403 422 || { why "a wrong TOTP code was accepted (HTTP $STATUS)"; return 1; }
    api POST /api/v1/me/totp/confirm "{\"code\":\"$(totp_code)\"}"
    EXPECT_CTX="POST /me/totp/confirm"
    expect 200 201 || return 1
    n=$(jget 'len(d["recovery_codes"])') || why "no recovery codes returned" || return 1
    [ "$n" -ge 8 ] || why "only $n recovery codes" || return 1
    RECOVERY_CODE=$(jget 'd["recovery_codes"][0]')
    refresh_csrf
    api GET /api/v1/me/mfa
    [ "$(jget 'd["totp_enabled"]')" = true ] || why "GET /me/mfa: totp_enabled is not true" || return 1
}

t_relogin_totp() {
    [ -n "$TOTP_SECRET" ] || skip_because "TOTP not enrolled" || return
    api POST /api/v1/auth/logout
    EXPECT_CTX="logout"
    expect 200 204 || return 1
    api GET /api/v1/me
    EXPECT_CTX="GET /me after logout"
    expect 401 || return 1
    CSRF=""
    : >"$JAR"
    api POST /api/v1/auth/login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}"
    EXPECT_CTX="password step"
    expect 200 || return 1
    [ "$(jget 'd.get("mfa_required")')" = true ] || why "login did not ask for the second factor" || return 1
    refresh_csrf
    api GET /api/v1/spaces
    EXPECT_CTX="GET /spaces between the password and the TOTP step"
    status_in 401 403 || { why "a password-only session reached /spaces (HTTP $STATUS)"; return 1; }
    # the step used for the enrollment must not be accepted again
    replay=$(totp_code current)
    last=$(cat "$WORK/totp.step" 2>/dev/null || echo -1)
    if [ "$(python3 -c 'import time; print(int(time.time() // 30))')" = "$last" ]; then
        api POST /api/v1/auth/totp "{\"code\":\"$replay\"}"
        EXPECT_CTX="replayed TOTP code"
        # any client error is a rejection (401, or 422 "code not valid")
        status_in 400 401 403 422 429 || { why "a replayed TOTP code was accepted (HTTP $STATUS)"; return 1; }
    fi
    api POST /api/v1/auth/totp "{\"code\":\"$(totp_code)\"}"
    EXPECT_CTX="TOTP step"
    expect 200 || return 1
    refresh_csrf
    api GET /api/v1/me
    [ "$(jget 'd["mfa_pending"]')" = false ] || why "the session is still MFA-pending" || return 1
}

t_spaces() {
    [ -n "$CSRF" ] || skip_because "not logged in" || return
    ensure_login || return 1
    api GET /api/v1/spaces
    EXPECT_CTX="GET /spaces"
    expect 200 || return 1
    ROOT=$(jget '[s["root_id"] for s in d if s["kind"] == "user"][0]') || why "no personal space" || return 1
    [ -n "$ROOT" ] || why "empty root_id" || return 1
}

t_upload_big() {
    [ -n "$ROOT" ] || skip_because "no personal space" || return
    dd if=/dev/urandom of="$BIG" bs=1048576 count="$BIG_MB" 2>/dev/null || why "dd failed" || return 1
    head -c 12345 /dev/urandom >>"$BIG"
    size=$(file_size "$BIG")
    api POST /api/v1/upload-batches "{\"folder_id\":\"$ROOT\",\"mode\":\"files\",\"conflict\":\"rename\",\"files\":[{\"client_ref\":\"big\",\"rel_path\":\"big.bin\",\"size\":$size,\"mtime\":$(now_ms)}]}"
    EXPECT_CTX="create the upload batch"
    expect 200 201 || return 1
    batch=$(jget 'd["id"]')
    upf=$(jget 'd["files"][0]["id"]')
    pc=$(jget 'd["files"][0]["part_count"]')
    psize=$(jget 'd["part_size"]')
    [ -n "$upf" ] && [ -n "$pc" ] && [ "$psize" = 8388608 ] || why "unexpected batch response" || return 1
    want=$(((size + psize - 1) / psize))
    [ "$pc" -eq "$want" ] || why "part_count $pc, want $want" || return 1
    n=0
    while [ "$n" -lt "$pc" ]; do
        dd if="$BIG" of="$WORK/parts/p$n" bs="$psize" skip="$n" count=1 2>/dev/null
        n=$((n + 1))
    done
    # upload in reverse order, 4 parts in flight
    n=$((pc - 1))
    inflight=0
    pids=""
    while [ "$n" -ge 0 ]; do
        (
            curl -sS --cacert "$CA" --resolve "$FP_NAME:$PORT:127.0.0.1" --max-time 300 -b "$JAR" \
                -X PUT -H "X-FP-CSRF: $CSRF" -H "X-FP-SHA256: $(sha256 "$WORK/parts/p$n")" \
                -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/parts/p$n" \
                -o /dev/null -w '%{http_code}' "$BASE/api/v1/uploads/$upf/parts/$n" >"$WORK/parts/p$n.status" 2>/dev/null
        ) &
        pids="$pids $!"
        inflight=$((inflight + 1))
        if [ "$inflight" -ge 4 ]; then
            # shellcheck disable=SC2086 # a list of pids
            wait $pids
            pids=""
            inflight=0
        fi
        n=$((n - 1))
    done
    # never a bare "wait": it would also wait for the server process
    # shellcheck disable=SC2086
    [ -z "$pids" ] || wait $pids
    n=0
    while [ "$n" -lt "$pc" ]; do
        st=$(cat "$WORK/parts/p$n.status" 2>/dev/null)
        [ "$st" = 204 ] || [ "$st" = 200 ] || why "part $n: HTTP $st" || return 1
        n=$((n + 1))
    done
    # idempotent re-send, then a conflicting re-send of a finished part
    api PUT "/api/v1/uploads/$upf/parts/0" "" -H "X-FP-SHA256: $(sha256 "$WORK/parts/p0")" \
        -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/parts/p0"
    EXPECT_CTX="idempotent re-send of part 0"
    expect 200 204 || return 1
    head -c "$psize" /dev/urandom >"$WORK/parts/other"
    api PUT "/api/v1/uploads/$upf/parts/0" "" -H "X-FP-SHA256: $(sha256 "$WORK/parts/other")" \
        -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/parts/other"
    EXPECT_CTX="conflicting re-send of part 0"
    expect 409 || return 1
    api GET "/api/v1/uploads/$upf"
    EXPECT_CTX="GET /uploads/{id}"
    expect 200 || return 1
    [ "$(jget 'len(d["parts_done"])')" = "$pc" ] || why "parts_done: $(jget 'd["parts_done"]')" || return 1
    api POST "/api/v1/uploads/$upf/complete"
    EXPECT_CTX="complete the file"
    expect 200 || return 1
    BIG_NODE=$(jget 'd["node_id"]')
    [ -n "$BIG_NODE" ] || why "no node_id after completing the file" || return 1
    api POST "/api/v1/upload-batches/$batch/complete"
    EXPECT_CTX="complete the batch"
    expect 200 || return 1
    [ "$(jget 'd["state"]')" = "done" ] || why "batch state $(jget 'd["state"]')" || return 1
    rm -f "$WORK"/parts/p* "$WORK/parts/other"
}

check_big_download() { # full download + sha256
    api GET "/api/v1/nodes/$BIG_NODE/content"
    EXPECT_CTX="download the large file"
    expect 200 || return 1
    [ "$(sha256 "$BODY")" = "$(sha256 "$BIG")" ] || why "the downloaded file differs (sha256)" || return 1
}

t_download_big() {
    [ -n "$BIG_NODE" ] || skip_because "no large file" || return
    check_big_download || return 1
    case $(header content-disposition) in attachment*) ;; *) why "Content-Disposition is '$(header content-disposition)'"; return 1 ;; esac
    etag=$(header etag)
    [ -n "$etag" ] || why "no ETag" || return 1
    size=$(file_size "$BIG")
    for r in 0:1 65535:2 65536:65536 8388607:2 1000000:2000001 $((size - 100)):100 $((size - 1)):1; do
        start=${r%:*}
        len=${r#*:}
        api GET "/api/v1/nodes/$BIG_NODE/content" "" -r "$start-$((start + len - 1))"
        EXPECT_CTX="Range $start+$len"
        expect 206 || return 1
        slice "$BIG" "$start" "$len" "$WORK/slice"
        cmp -s "$BODY" "$WORK/slice" || why "Range $start-$((start + len - 1)) returned different bytes" || return 1
    done
    api GET "/api/v1/nodes/$BIG_NODE/content" "" -r "-500"
    EXPECT_CTX="suffix Range -500"
    expect 206 || return 1
    slice "$BIG" $((size - 500)) 500 "$WORK/slice"
    cmp -s "$BODY" "$WORK/slice" || why "suffix range returned different bytes" || return 1
    api GET "/api/v1/nodes/$BIG_NODE/content" "" -r "0-9,65530-65545"
    EXPECT_CTX="multi-range"
    expect 206 || return 1
    case $(header content-type) in multipart/byteranges*) ;; *) why "multi-range Content-Type '$(header content-type)'"; return 1 ;; esac
    api GET "/api/v1/nodes/$BIG_NODE/content" "" -H "If-None-Match: $etag"
    EXPECT_CTX="If-None-Match"
    expect 304 || return 1
    head_req "/api/v1/nodes/$BIG_NODE/content"
    EXPECT_CTX="HEAD"
    expect 200 || return 1
    [ "$(header content-length)" = "$size" ] || why "HEAD Content-Length $(header content-length), want $size" || return 1
}

t_upload_folder() {
    [ -n "$ROOT" ] || skip_because "no personal space" || return
    mkdir -p "$FILES/tree"
    printf 'alpha\n' >"$FILES/tree/a.txt"
    printf 'bravo\n' >"$FILES/tree/b.txt"
    printf 'deep file\n' >"$FILES/tree/z.txt"
    printf 'unicode\n' >"$FILES/tree/u.txt"
    : >"$FILES/tree/empty.txt"
    uname_nfc=$(python3 -c 'import unicodedata; print(unicodedata.normalize("NFC", "Grüße ☃.txt"))')
    files="{\"client_ref\":\"a\",\"rel_path\":\"Trip/day1/a.txt\",\"size\":6,\"mtime\":$(now_ms)},"
    files="$files{\"client_ref\":\"b\",\"rel_path\":\"Trip/day1/b.txt\",\"size\":6},"
    files="$files{\"client_ref\":\"z\",\"rel_path\":\"Trip/day2/deep/x/y/z.txt\",\"size\":10},"
    files="$files{\"client_ref\":\"u\",\"rel_path\":\"Trip/$uname_nfc\",\"size\":8},"
    files="$files{\"client_ref\":\"e\",\"rel_path\":\"Trip/zero.txt\",\"size\":0},"
    files="$files{\"client_ref\":\"d\",\"rel_path\":\"Trip/empty\",\"size\":0,\"kind\":\"dir\"}"
    api POST /api/v1/upload-batches "{\"folder_id\":\"$ROOT\",\"mode\":\"files\",\"conflict\":\"rename\",\"files\":[$files]}"
    EXPECT_CTX="create the folder batch"
    expect 200 201 || return 1
    batch=$(jget 'd["id"]')
    for x in a:a.txt b:b.txt z:z.txt u:u.txt e:empty.txt; do
        upload_small "$batch" "${x%%:*}" "$FILES/tree/${x#*:}"
        EXPECT_CTX="small upload ${x%%:*}"
        expect 200 201 || return 1
    done
    api POST "/api/v1/upload-batches/$batch/complete"
    EXPECT_CTX="complete the folder batch"
    expect 200 || return 1
    [ "$(jget 'd["state"]')" = "done" ] || why "batch state $(jget 'd["state"]')" || return 1
    api GET "/api/v1/nodes/$ROOT/children?limit=500"
    TRIP=$(find_child Trip) || why "no Trip folder in the root" || return 1
    api GET "/api/v1/nodes/$TRIP/children?limit=500"
    for nm in day1 day2 empty zero.txt "$uname_nfc"; do
        find_child "$nm" >/dev/null || why "Trip/ lacks '$nm'" || return 1
    done
    empty=$(find_child empty)
    day1=$(find_child day1)
    api GET "/api/v1/nodes/$empty/children"
    [ "$(jget 'len(d["items"])')" = 0 ] || why "Trip/empty is not empty" || return 1
    api GET "/api/v1/nodes/$day1/children"
    A_NODE=$(find_child a.txt) || why "no Trip/day1/a.txt" || return 1
    api GET "/api/v1/nodes/$A_NODE/content"
    cmp -s "$BODY" "$FILES/tree/a.txt" || why "a.txt content differs" || return 1
    # the upload path must not escape the folder
    api POST /api/v1/upload-batches "{\"folder_id\":\"$ROOT\",\"mode\":\"files\",\"files\":[{\"client_ref\":\"x\",\"rel_path\":\"../escape.txt\",\"size\":1}]}"
    EXPECT_CTX="rel_path with .."
    status_in 400 422 || { why "a rel_path with .. was accepted (HTTP $STATUS)"; return 1; }
}

t_zip_download() {
    [ -n "$TRIP" ] || skip_because "no folder" || return
    api POST /api/v1/archives "{\"node_ids\":[\"$TRIP\"],\"format\":\"zip\",\"name\":\"Trip\"}"
    EXPECT_CTX="POST /archives"
    expect 200 201 || return 1
    url=$(jget 'd["url"]')
    case $url in https://*) url=/${url#https://*/} ;; esac
    anon GET "$url"
    EXPECT_CTX="GET the archive ticket"
    expect 200 || return 1
    cp "$BODY" "$WORK/trip.zip"
    unzip -tq "$WORK/trip.zip" >"$WORK/unzip.txt" 2>&1 || why "unzip -t failed: $(head -c 200 "$WORK/unzip.txt")" || return 1
    list=$(unzip -Z1 "$WORK/trip.zip")
    for e in Trip/empty/ Trip/day2/deep/x/y/z.txt Trip/day1/a.txt; do
        printf '%s\n' "$list" | grep -qx "$e" || why "the zip lacks $e" || return 1
    done
    anon GET "$url"
    EXPECT_CTX="second use of the archive ticket"
    status_in 404 410 403 || { why "the archive ticket worked twice (HTTP $STATUS)"; return 1; }
    api POST /api/v1/archives "{\"node_ids\":[\"$TRIP\"],\"format\":\"tar\"}"
    EXPECT_CTX="POST /archives (tar)"
    expect 200 201 || return 1
    url=$(jget 'd["url"]')
    case $url in https://*) url=/${url#https://*/} ;; esac
    anon GET "$url"
    EXPECT_CTX="GET the tar archive"
    expect 200 || return 1
    tar -tf "$BODY" 2>/dev/null | grep -q 'day2/deep/x/y/z.txt' || why "the tar lacks day2/deep/x/y/z.txt" || return 1
}

t_zip_on_upload() {
    [ -n "$ROOT" ] || skip_because "no personal space" || return
    printf 'one\n' >"$FILES/one.txt"
    printf 'two two\n' >"$FILES/two.txt"
    files="{\"client_ref\":\"1\",\"rel_path\":\"Bundle/one.txt\",\"size\":4},"
    files="$files{\"client_ref\":\"2\",\"rel_path\":\"Bundle/sub/two.txt\",\"size\":8},"
    files="$files{\"client_ref\":\"3\",\"rel_path\":\"Bundle/emptydir\",\"size\":0,\"kind\":\"dir\"}"
    api POST /api/v1/upload-batches "{\"folder_id\":\"$ROOT\",\"mode\":\"zip\",\"zip_name\":\"Bundle.zip\",\"conflict\":\"rename\",\"files\":[$files]}"
    EXPECT_CTX="create the zip batch"
    expect 200 201 || return 1
    batch=$(jget 'd["id"]')
    upload_small "$batch" 1 "$FILES/one.txt"
    EXPECT_CTX="small upload 1"
    expect 200 201 || return 1
    upload_small "$batch" 2 "$FILES/two.txt"
    EXPECT_CTX="small upload 2"
    expect 200 201 || return 1
    api POST "/api/v1/upload-batches/$batch/complete"
    EXPECT_CTX="complete the zip batch"
    expect 200 202 || return 1
    job=$(jget 'd.get("job_id")')
    [ -n "$job" ] || why "no job_id for the zip batch (state $(jget 'd.get("state")'))" || return 1
    poll_job "$job" 120 || return 1
    api GET "/api/v1/upload-batches/$batch"
    zipnode=$(jget 'd.get("result_node_id")')
    if [ -z "$zipnode" ]; then
        api GET "/api/v1/nodes/$ROOT/children?limit=500"
        zipnode=$(find_child Bundle.zip) || why "no Bundle.zip in the root" || return 1
    fi
    api GET "/api/v1/nodes/$zipnode/content"
    EXPECT_CTX="download Bundle.zip"
    expect 200 || return 1
    cp "$BODY" "$WORK/bundle.zip"
    unzip -tq "$WORK/bundle.zip" >/dev/null 2>&1 || why "Bundle.zip is not a valid zip" || return 1
    list=$(unzip -Z1 "$WORK/bundle.zip")
    printf '%s\n' "$list" | grep -q 'one.txt$' || why "Bundle.zip lacks one.txt" || return 1
    printf '%s\n' "$list" | grep -q 'sub/two.txt$' || why "Bundle.zip lacks sub/two.txt (paths not preserved)" || return 1
    printf '%s\n' "$list" | grep -q 'emptydir/$' || why "Bundle.zip lacks the empty directory" || return 1
    unzip -p "$WORK/bundle.zip" "$(printf '%s\n' "$list" | grep 'sub/two.txt$')" | cmp -s - "$FILES/two.txt" ||
        why "two.txt inside the zip differs" || return 1
}

# zip_protected ENC PASSWORD NAME: uploads Vault/one.txt, Vault/sub/two.txt
# and an empty directory as a password-protected zip NAME (ENC: aes256 or
# zipcrypto) and downloads it to $WORK/NAME. Checks on the way that no answer
# carries the password and that the job's params are the batch id only.
zip_protected() {
    zp_files="{\"client_ref\":\"1\",\"rel_path\":\"Vault/one.txt\",\"size\":$(file_size "$FILES/one.txt")},"
    zp_files="$zp_files{\"client_ref\":\"2\",\"rel_path\":\"Vault/sub/two.txt\",\"size\":$(file_size "$FILES/two.txt")},"
    zp_files="$zp_files{\"client_ref\":\"3\",\"rel_path\":\"Vault/emptydir\",\"size\":0,\"kind\":\"dir\"}"
    api POST /api/v1/upload-batches "{\"folder_id\":\"$ROOT\",\"mode\":\"zip\",\"zip_name\":\"$3\",\"conflict\":\"rename\",\"zip_encryption\":\"$1\",\"zip_password\":\"$2\",\"files\":[$zp_files]}"
    EXPECT_CTX="create the $1 zip batch"
    expect 201 || return 1
    ! grep -F -q -- "$2" "$BODY" || why "the batch answer carries the password" || return 1
    zp_batch=$(jget 'd["id"]')
    upload_small "$zp_batch" 1 "$FILES/one.txt"
    EXPECT_CTX="small upload 1"
    expect 200 201 || return 1
    upload_small "$zp_batch" 2 "$FILES/two.txt"
    EXPECT_CTX="small upload 2"
    expect 200 201 || return 1
    api GET "/api/v1/upload-batches/$zp_batch"
    EXPECT_CTX="get the $1 zip batch"
    expect 200 || return 1
    [ "$(jget 'd.get("zip_encryption")')" = "$1" ] || why "the batch has zip_encryption '$(jget 'd.get("zip_encryption")')'" || return 1
    ! grep -F -q -- "$2" "$BODY" || why "the batch carries the password" || return 1
    api POST "/api/v1/upload-batches/$zp_batch/complete"
    EXPECT_CTX="complete the $1 zip batch"
    expect 200 202 || return 1
    zp_job=$(jget 'd.get("job_id")')
    [ -n "$zp_job" ] || why "no job_id for the $1 zip batch" || return 1
    poll_job "$zp_job" 120 || return 1
    ! grep -F -q -- "$2" "$BODY" || why "the job carries the password" || return 1
    [ "$(jget 'sorted(d["params"].keys())')" = '["batch_id"]' ] || why "job params $(jget 'd["params"]')" || return 1
    [ "$(jget 'd["result"].get("encryption")')" = "$1" ] || why "job result $(jget 'd["result"]')" || return 1
    zp_node=$(jget 'd["result"]["node_id"]')
    api GET "/api/v1/nodes/$zp_node"
    EXPECT_CTX="get the $1 zip node"
    expect 200 || return 1
    [ "$(jget 'd.get("zip_encryption")')" = "$1" ] || why "the node has zip_encryption '$(jget 'd.get("zip_encryption")')'" || return 1
    api GET "/api/v1/nodes/$zp_node/content"
    EXPECT_CTX="download $3"
    expect 200 || return 1
    cp "$BODY" "$WORK/$3"
}

t_zip_on_upload_password() {
    [ -n "$ROOT" ] || skip_because "no personal space" || return
    printf 'one\n' >"$FILES/one.txt"
    printf 'two two\n' >"$FILES/two.txt"
    zp_pw="e2e $(rand_hex 8) zip"

    # ZipCrypto: the unzip everyone has opens it, and only with the password.
    zip_protected zipcrypto "$zp_pw" Vault-zipcrypto.zip || return 1
    unzip -P "$zp_pw" -tq "$WORK/Vault-zipcrypto.zip" >/dev/null 2>&1 || why "unzip -P cannot test the ZipCrypto zip" || return 1
    ! unzip -P "wrong password" -tq "$WORK/Vault-zipcrypto.zip" >/dev/null 2>&1 || why "unzip accepted a wrong password" || return 1
    unzip -P "$zp_pw" -p "$WORK/Vault-zipcrypto.zip" Vault/sub/two.txt | cmp -s - "$FILES/two.txt" ||
        why "two.txt inside the ZipCrypto zip differs" || return 1

    # AES-256: WinZip AE-2 entries (method 99, extra 0x9901) in the local and
    # the central headers; folders stay unencrypted.
    zip_protected aes256 "$zp_pw" Vault-aes256.zip || return 1
    python3 - "$WORK/Vault-aes256.zip" <<'PY' || why "Vault-aes256.zip is not a WinZip AES archive" || return 1
import struct, sys, zipfile
path = sys.argv[1]
z = zipfile.ZipFile(path)
data = open(path, "rb").read()
files = [i for i in z.infolist() if not i.is_dir()]
assert len(files) == 2, files
for i in z.infolist():
    sig, _, flags, method = struct.unpack_from("<IHHH", data, i.header_offset)
    n, e = struct.unpack_from("<HH", data, i.header_offset + 26)
    extra = data[i.header_offset + 30 + n:i.header_offset + 30 + n + e]
    assert sig == 0x04034B50
    if i.is_dir():
        assert not flags & 1 and method == 0 and b"\x01\x99" not in extra, i.filename
        continue
    assert flags & 1 and not flags & 8 and method == 99 and i.compress_type == 99 and i.CRC == 0, i.filename
    for ex in (extra, i.extra):
        assert b"\x01\x99\x07\x00\x02\x00AE\x03" in ex, (i.filename, ex)
PY
    zp_7z=""
    for c in 7zz 7z 7za; do
        if have "$c"; then zp_7z=$c; break; fi
    done
    if [ -n "$zp_7z" ]; then
        "$zp_7z" t -p"$zp_pw" "$WORK/Vault-aes256.zip" >/dev/null 2>&1 || why "7-Zip cannot test the AES zip" || return 1
        ! "$zp_7z" t -p"wrong password" "$WORK/Vault-aes256.zip" >/dev/null 2>&1 || why "7-Zip accepted a wrong password" || return 1
        rm -rf "$WORK/vault7z"
        "$zp_7z" x -y -p"$zp_pw" -o"$WORK/vault7z" "$WORK/Vault-aes256.zip" >/dev/null 2>&1 || why "7-Zip cannot extract the AES zip" || return 1
        cmp -s "$WORK/vault7z/Vault/one.txt" "$FILES/one.txt" && cmp -s "$WORK/vault7z/Vault/sub/two.txt" "$FILES/two.txt" ||
            why "the files 7-Zip extracted differ" || return 1
        [ -d "$WORK/vault7z/Vault/emptydir" ] || why "7-Zip extracted no empty directory" || return 1
    else
        note "7-Zip is not installed: AES extraction not checked"
    fi

    # The password never reached a log.
    for f in "$WORK/server.log" "$H"/logs/*.log; do
        [ -f "$f" ] || continue
        ! grep -F -q -- "$zp_pw" "$f" || why "the zip password appears in $(basename "$f")" || return 1
    done
}

t_evil_files() {
    [ -n "$ROOT" ] || skip_because "no personal space" || return
    printf '<html><body><script>alert(document.cookie)</script></body></html>\n' >"$FILES/evil.html"
    printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>\n' >"$FILES/evil.svg"
    printf 'just text\n' >"$FILES/note.txt"
    files=""
    for f in evil.html evil.svg note.txt; do
        files="$files{\"client_ref\":\"$f\",\"rel_path\":\"$f\",\"size\":$(file_size "$FILES/$f")},"
    done
    api POST /api/v1/upload-batches "{\"folder_id\":\"$ROOT\",\"mode\":\"files\",\"conflict\":\"replace\",\"files\":[${files%,}]}"
    EXPECT_CTX="create the batch"
    expect 200 201 || return 1
    batch=$(jget 'd["id"]')
    for f in evil.html evil.svg note.txt; do
        upload_small "$batch" "$f" "$FILES/$f"
        EXPECT_CTX="upload $f"
        expect 200 201 || return 1
    done
    api POST "/api/v1/upload-batches/$batch/complete"
    api GET "/api/v1/nodes/$ROOT/children?limit=500"
    cp "$BODY" "$WORK/root.json"
    for f in evil.html evil.svg; do
        id=$(find_child "$f" "$WORK/root.json") || why "$f not found" || return 1
        api GET "/api/v1/nodes/$id/content?inline=1"
        EXPECT_CTX="GET $f inline"
        expect 200 || return 1
        case $(header content-disposition) in attachment*) ;; *) why "$f served with Content-Disposition '$(header content-disposition)'"; return 1 ;; esac
        ct=$(header content-type)
        case $ct in *html* | *svg* | *xml* | *javascript*) why "$f served as $ct"; return 1 ;; esac
        [ "$(header x-content-type-options)" = nosniff ] || why "$f without nosniff" || return 1
        case $(header content-security-policy) in *sandbox*) ;; *) why "$f without a sandbox CSP"; return 1 ;; esac
    done
    id=$(find_child note.txt "$WORK/root.json")
    api GET "/api/v1/nodes/$id/content?inline=1"
    case $(header content-disposition) in inline*) ;; *) why "note.txt not served inline"; return 1 ;; esac
    case $(header content-type) in text/plain*) ;; *) why "note.txt served as $(header content-type)"; return 1 ;; esac
}

t_share_link() {
    [ -n "$A_NODE" ] || skip_because "no file to share" || return
    api POST /api/v1/shares "{\"kind\":\"link\",\"node_id\":\"$A_NODE\",\"password\":\"$SHARE_PW\",\"max_downloads\":2}"
    EXPECT_CTX="create the share link"
    expect 200 201 || return 1
    share_id=$(jget 'd.get("id") or d["share"]["id"]')
    url=$(jget 'd.get("url") or d["share"]["url"]')
    SHARE_TOKEN=${url##*/s/}
    SHARE_TOKEN=${SHARE_TOKEN%%/*}
    [ -n "$SHARE_TOKEN" ] || why "no share URL in the response" || return 1
    : >"$ANON_JAR"
    anon GET "/s/$SHARE_TOKEN"
    EXPECT_CTX="share page"
    expect 200 || return 1
    anon GET "/s/$SHARE_TOKEN/api"
    EXPECT_CTX="share info without the password"
    expect 200 401 || return 1
    if [ "$STATUS" = 200 ]; then
        [ "$(jget 'd.get("password_required")')" = true ] || why "password_required is not true" || return 1
        [ -z "$(jget 'd.get("node")')" ] || why "the node is revealed before the password" || return 1
    fi
    anon GET "/s/$SHARE_TOKEN/dl/$A_NODE"
    EXPECT_CTX="download without the password"
    status_in 401 403 || { why "downloaded without the password (HTTP $STATUS)"; return 1; }
    anon POST "/s/$SHARE_TOKEN/api/password" '{"password":"wrong"}'
    EXPECT_CTX="wrong share password"
    status_in 401 403 422 429 || { why "a wrong share password was accepted (HTTP $STATUS)"; return 1; }
    anon POST "/s/$SHARE_TOKEN/api/password" "{\"password\":\"$SHARE_PW\"}" -H 'Sec-Fetch-Site: cross-site' -H 'Origin: https://evil.example'
    EXPECT_CTX="cross-site share password POST"
    expect 403 || return 1
    anon POST "/s/$SHARE_TOKEN/api/password" "{\"password\":\"$SHARE_PW\"}"
    EXPECT_CTX="share password"
    expect 200 204 || return 1
    grep -q '__Host-fp_s_' "$ANON_JAR" || why "no share access cookie" || return 1
    head_req "/s/$SHARE_TOKEN/dl/$A_NODE" "$ANON_JAR"
    EXPECT_CTX="HEAD share download"
    expect 200 || return 1
    for i in 1 2; do
        anon GET "/s/$SHARE_TOKEN/dl/$A_NODE"
        EXPECT_CTX="share download $i of 2"
        expect 200 || return 1
        cmp -s "$BODY" "$FILES/tree/a.txt" || why "share download $i differs" || return 1
    done
    anon GET "/s/$SHARE_TOKEN/dl/$A_NODE"
    EXPECT_CTX="download beyond max_downloads"
    status_in 403 404 410 || { why "download 3 of max 2 succeeded (HTTP $STATUS)"; return 1; }
    api GET "/api/v1/shares/$share_id"
    [ "$(jget 'd["download_count"]')" = 2 ] || why "download_count is $(jget 'd["download_count"]'), want 2 (HEAD must not count)" || return 1
    anon GET "/s/${SHARE_TOKEN}x/api"
    EXPECT_CTX="unknown share token"
    expect 404 || return 1
}

t_cli_config_socket() {
    server_alive || skip_because "server not running" || return
    "$BIN" --home "$H" status >"$WORK/cli.txt" 2>&1 || why "fileparcel status failed: $(head -c 300 "$WORK/cli.txt")" || return 1
    "$BIN" --home "$H" config set ui.instance_name "E2E Parcel" >"$WORK/cli.txt" 2>&1 ||
        why "fileparcel config set failed: $(head -c 300 "$WORK/cli.txt")" || return 1
    anon GET /api/v1/auth/state
    [ "$(jget 'd["instance"]')" = "E2E Parcel" ] || why "the new instance name is not live (got '$(jget 'd["instance"]')')" || return 1
    "$BIN" --home "$H" --json config get ui.instance_name >"$WORK/cli.txt" 2>&1 || why "config get failed" || return 1
    grep -q 'E2E Parcel' "$WORK/cli.txt" || why "config get does not show the value" || return 1
}

t_backup() {
    [ -n "$CSRF" ] || skip_because "not logged in" || return
    ensure_login || return 1
    api POST /api/v1/admin/backups '{"scope":"full","note":"e2e"}'
    EXPECT_CTX="POST /admin/backups"
    expect 200 201 202 || return 1
    job=$(jget 'd["job_id"]') || why "no job_id" || return 1
    poll_job "$job" 300 || return 1
    api GET "/api/v1/admin/backups?limit=10"
    bid=$(jget '[b["id"] for b in d["items"] if b.get("note") == "e2e"][0]') || why "the backup is not listed" || return 1
    [ "$(jget "[b['state'] for b in d['items'] if b['id'] == '$bid'][0]")" = ready ] || why "backup state is not ready" || return 1
    f=""
    for x in "$H"/backups/*.fpbak; do
        if [ -f "$x" ]; then f=$x; break; fi
    done
    [ -n "$f" ] || why "no .fpbak file in backups/" || return 1
    head -c 21 "$f" | grep -q 'age-encryption.org/v1' || why "the backup file is not age-encrypted" || return 1
    api POST "/api/v1/admin/backups/$bid/verify?deep=1"
    if status_in 400 415 422; then api POST "/api/v1/admin/backups/$bid/verify" '{"deep":true}'; fi
    EXPECT_CTX="verify the backup"
    expect 200 201 202 || return 1
    vjob=$(jget 'd.get("job_id")')
    if [ -n "$vjob" ]; then poll_job "$vjob" 300 || return 1; fi
    api GET "/api/v1/admin/backups/$bid"
    [ "$(jget 'd.get("verify_ok")')" = true ] || why "verify_ok is not true" || return 1
    "$BIN" --home "$H" backup list >"$WORK/cli.txt" 2>&1 || why "fileparcel backup list failed" || return 1
    # "fileparcel backup restore" needs the server stopped; a dry run decrypts
    # and checks the archive without changing anything.
    stop_server || return 1
    restore_rc=0
    "$BIN" --home "$H" backup restore "$bid" --dry-run -y >"$WORK/cli.txt" 2>&1 || restore_rc=$?
    start_server || return 1
    [ "$restore_rc" -eq 0 ] || why "fileparcel backup restore --dry-run failed: $(tail -n 3 "$WORK/cli.txt" | tr '\n' ' ')" || return 1
}

t_keys_rotate_kek() {
    server_alive || skip_because "server not running" || return
    [ -n "$BIG_NODE" ] || skip_because "no large file to re-check" || return
    ensure_login || return 1
    api GET /api/v1/admin/keys
    EXPECT_CTX="GET /admin/keys"
    expect 200 || return 1
    before=$(jget '[k["id"] for k in d["keks"] if k["purpose"] == "blob" and k["state"] == "active"][0]') ||
        why "no active blob KEK" || return 1
    "$BIN" --home "$H" -y keys rotate --kek --purpose blob >"$WORK/cli.txt" 2>&1 ||
        why "fileparcel keys rotate --kek failed: $(head -c 300 "$WORK/cli.txt")" || return 1
    after=""
    end=$(($(date +%s) + 120))
    while [ "$(date +%s)" -lt "$end" ]; do
        api GET /api/v1/admin/keys
        after=$(jget '[k["id"] for k in d["keks"] if k["purpose"] == "blob" and k["state"] == "active"][0]')
        refs=$(jget "[k['refs'] for k in d['keks'] if k['id'] == '$before'][0]")
        if [ -n "$after" ] && [ "$after" != "$before" ] && { [ "$refs" = 0 ] || [ -z "$refs" ]; }; then break; fi
        sleep 1
    done
    [ -n "$after" ] && [ "$after" != "$before" ] || why "the active blob KEK did not change" || return 1
    [ "$refs" = 0 ] || [ -z "$refs" ] || why "the old KEK is still referenced by $refs blobs" || return 1
    check_big_download || return 1
}

t_audit() {
    [ -n "$CSRF" ] || skip_because "not logged in" || return
    ensure_login || return 1
    api GET /api/v1/admin/audit/verify
    EXPECT_CTX="GET /admin/audit/verify"
    expect 200 || return 1
    [ "$(jget 'd["ok"]')" = true ] || why "audit chain broken: $(jget 'd.get("message")')" || return 1
    api GET "/api/v1/admin/audit?action=auth.login&limit=50"
    EXPECT_CTX="GET /admin/audit"
    expect 200 || return 1
    [ "$(jget 'len(d["items"]) > 0')" = true ] || why "no auth.login entries" || return 1
    [ "$(jget 'any(i["outcome"] == "failure" for i in d["items"])')" = true ] || why "the failed login is not audited" || return 1
}

t_seal_restart_unlock() {
    [ -n "$BIG_NODE" ] || skip_because "no large file" || return
    ensure_login || return 1
    api POST /api/v1/auth/elevate "{\"password\":\"$ADMIN_PW\"}"
    EXPECT_CTX="elevate"
    expect 200 || return 1
    refresh_csrf
    api POST /api/v1/admin/keys/seal "{\"passphrase\":\"$SEAL_PW\"}"
    EXPECT_CTX="seal the master key"
    expect 200 204 || return 1
    api GET /api/v1/admin/keys
    [ "$(jget 'd["mode"]')" = sealed ] || why "key mode is '$(jget 'd["mode"]')' after sealing" || return 1
    grep -q '"sealed"' "$H/keys/master.key" || why "keys/master.key is not in sealed mode" || return 1
    stop_server || return 1
    start_server || return 1
    anon GET /api/v1/system/status
    [ "$(jget 'd["state"]')" = locked ] || why "the server did not start locked (state '$(jget 'd["state"]')')" || return 1
    api GET /readyz
    EXPECT_CTX="readyz while locked"
    expect 503 || return 1
    api GET "/api/v1/nodes/$BIG_NODE/content"
    EXPECT_CTX="download while locked"
    expect 503 || return 1
    [ "$(jget 'd["error"]["code"]')" = keys_locked ] || why "error code is not keys_locked" || return 1
    anon POST /api/v1/system/unlock '{"passphrase":"wrong passphrase"}'
    EXPECT_CTX="unlock with a wrong passphrase"
    status_in 401 403 422 || { why "a wrong passphrase unlocked the server (HTTP $STATUS)"; return 1; }
    anon POST /api/v1/system/unlock "{\"passphrase\":\"$SEAL_PW\"}"
    EXPECT_CTX="unlock"
    expect 200 204 || return 1
    anon GET /api/v1/system/status
    [ "$(jget 'd["state"]')" = unlocked ] || why "still locked after unlock" || return 1
    api GET /api/v1/me
    if [ "$STATUS" = 401 ]; then login_full || return 1; fi
    check_big_download || return 1
}

t_secrets_not_logged() {
    [ -f "$WORK/server.log" ] || skip_because "no server log" || return
    for s in "$ADMIN_PW" "$SEAL_PW" "$SHARE_PW" "$TOTP_SECRET" "$RECOVERY_CODE"; do
        [ -n "$s" ] || continue
        for f in "$WORK/server.log" "$H"/logs/*.log; do
            [ -f "$f" ] || continue
            if grep -F -q -- "$s" "$f"; then
                why "a secret appears in $(basename "$f")"
                return 1
            fi
        done
    done
}

t_logout() {
    [ -n "$CSRF" ] || skip_because "not logged in" || return
    api POST /api/v1/auth/logout
    EXPECT_CTX="logout"
    expect 200 204 || return 1
    api GET /api/v1/me
    EXPECT_CTX="GET /me after logout"
    expect 401 || return 1
}

# ======================================================================
run_step build "build the binary"
run_step init "fileparcel init (scratch home, file modes)"
run_step start "start the server"
run_step health "healthz, readyz, CA download"
run_step headers "security headers (CSP + Trusted Types)"
run_step redirect_same_port "plain HTTP on the HTTPS port -> 308"
run_step redirect_http_port "HTTP port -> 308 to HTTPS"
run_step tls_versions "TLS 1.2 verifies, TLS 1.1 rejected"
run_step anon_401 "anonymous API access is refused"
run_step login "password login, CSRF token"
run_step csrf "CSRF: missing/wrong token and cross-site requests"
run_step totp_enroll "enroll TOTP (QR, recovery codes)"
run_step relogin_totp "re-login with TOTP (replay refused)"
run_step spaces "personal space"
run_step upload_big "${BIG_MB} MiB parted upload (parallel, out of order)"
run_step download_big "download, sha256, Range slices, HEAD"
run_step upload_folder "folder upload with nested and empty dirs"
run_step zip_download "folder as zip (unzip -t) and tar"
run_step zip_on_upload "bundle an upload into a zip"
run_step zip_on_upload_password "password-protected zip on upload (ZipCrypto, AES-256)"
run_step evil_files "evil.html / evil.svg served as attachments"
run_step share_link "share link: password, max downloads"
run_step cli_config_socket "CLI config set over the admin socket"
run_step backup "backup create + deep verify"
run_step keys_rotate_kek "keys rotate --kek, data still readable"
run_step audit "audit chain verifies"
run_step seal_restart_unlock "seal -> restart -> 503 -> unlock -> download"
run_step secrets_not_logged "no secrets in the logs"
run_step logout "logout"

summary
[ "$N_FAIL" -eq 0 ]
