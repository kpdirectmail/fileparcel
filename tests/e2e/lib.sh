# shellcheck shell=sh
# shellcheck disable=SC2154 # CA, FP_NAME, PORT, BASE, JAR, ANON_JAR, BODY, HDRS, WORK are set by e2e.sh
# Helpers for tests/e2e/e2e.sh (sourced, not executed). POSIX sh + curl +
# python3 (standard library only). Conventions:
#   - every test step is a function t_<name>; run_step calls it and records
#     PASS / FAIL / SKIP. A step returns 0 (pass), 1 (fail; the reason is in
#     $WHY) or 2 (skip; reason in $WHY).
#   - api METHOD PATH [JSON] [extra curl args...] talks to the server with the
#     test user's cookie jar and CSRF token; the status code lands in $STATUS,
#     the body in $BODY (a file), the response headers in $HDRS (a file).

# ---------- output ----------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_OK=$(printf '\033[32m')
    C_BAD=$(printf '\033[31m')
    C_SKIP=$(printf '\033[33m')
    C_DIM=$(printf '\033[2m')
    C_OFF=$(printf '\033[0m')
else
    C_OK="" C_BAD="" C_SKIP="" C_DIM="" C_OFF=""
fi

N_PASS=0
N_FAIL=0
N_SKIP=0
FAILED_STEPS=""
WHY=""

note() { printf '%s      %s%s\n' "$C_DIM" "$*" "$C_OFF"; }
info() { printf '%s\n' "$*"; }
die() {
    printf '%sFATAL%s %s\n' "$C_BAD" "$C_OFF" "$*" >&2
    exit 2
}
have() { command -v "$1" >/dev/null 2>&1; }

# why MSG: record the failure reason and return 1 (use: cond || why "msg"; or `why "..."; return 1`).
why() {
    WHY=$*
    return 1
}
skip_because() {
    WHY=$*
    return 2
}

# run_step NAME DESCRIPTION: runs t_NAME unless listed in $E2E_SKIP.
run_step() {
    rs_name=$1
    rs_desc=$2
    case " ${E2E_SKIP:-} " in
        *" $rs_name "*)
            N_SKIP=$((N_SKIP + 1))
            printf '%sSKIP%s  %-24s %s (E2E_SKIP)\n' "$C_SKIP" "$C_OFF" "$rs_name" "$rs_desc"
            return 0
            ;;
    esac
    if [ -n "${E2E_ONLY:-}" ]; then
        case " $E2E_ONLY " in
            *" $rs_name "*) ;;
            *) return 0 ;;
        esac
    fi
    WHY=""
    rs_t0=$(date +%s)
    rs_rc=0
    "t_$rs_name" || rs_rc=$?
    rs_dt=$(($(date +%s) - rs_t0))
    case $rs_rc in
        0)
            N_PASS=$((N_PASS + 1))
            printf '%sPASS%s  %-24s %s %s(%ss)%s\n' "$C_OK" "$C_OFF" "$rs_name" "$rs_desc" "$C_DIM" "$rs_dt" "$C_OFF"
            ;;
        2)
            N_SKIP=$((N_SKIP + 1))
            printf '%sSKIP%s  %-24s %s: %s\n' "$C_SKIP" "$C_OFF" "$rs_name" "$rs_desc" "$WHY"
            ;;
        *)
            N_FAIL=$((N_FAIL + 1))
            FAILED_STEPS="$FAILED_STEPS $rs_name"
            printf '%sFAIL%s  %-24s %s %s(%ss)%s\n' "$C_BAD" "$C_OFF" "$rs_name" "$rs_desc" "$C_DIM" "$rs_dt" "$C_OFF"
            printf '        reason: %s\n' "${WHY:-unknown}"
            if [ -n "${STATUS:-}" ] && [ -s "${BODY:-/nonexistent}" ]; then
                printf '        last response: HTTP %s %s\n' "$STATUS" "$(head -c 300 "$BODY" | tr '\n' ' ')"
            fi
            ;;
    esac
    return 0
}

summary() {
    info ""
    info "E2E summary: $N_PASS passed, $N_FAIL failed, $N_SKIP skipped"
    if [ "$N_FAIL" -gt 0 ]; then
        info "Failed steps:$FAILED_STEPS"
    fi
}

# ---------- small utilities ----------
sha256() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        openssl dgst -sha256 -r "$1" | cut -d' ' -f1
    fi
}

file_size() { wc -c <"$1" | tr -d ' '; }

now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }

# free_port: prints a TCP port that is free on 127.0.0.1 right now.
free_port() {
    python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

# rand_hex N: N random bytes as hex.
rand_hex() { python3 -c "import secrets; print(secrets.token_hex($1))"; }

# slice FILE START LEN OUT: copy a byte range (dd when it can address bytes).
slice() {
    if dd if=/dev/null of=/dev/null iflag=skip_bytes,count_bytes 2>/dev/null; then
        dd if="$1" of="$4" bs=65536 iflag=skip_bytes,count_bytes skip="$2" count="$3" 2>/dev/null
    else
        python3 -c 'import sys
f = open(sys.argv[1], "rb"); f.seek(int(sys.argv[2]))
open(sys.argv[4], "wb").write(f.read(int(sys.argv[3])))' "$1" "$2" "$3" "$4"
    fi
}

# jget EXPR [FILE]: evaluates a Python expression over the JSON document d
# (default file: $BODY) and prints the result: strings raw, booleans as
# true/false, null as nothing, lists/objects as JSON. Returns 1 on error.
#   jget 'd["user"]["id"]'      jget 'len(d["items"])'
jget() {
    python3 - "$1" "${2:-$BODY}" <<'PY' 2>/dev/null
import json, sys
expr, path = sys.argv[1], sys.argv[2]
try:
    with open(path, "rb") as f:
        d = json.load(f)
    v = eval(expr, {"__builtins__": {"len": len, "any": any, "all": all, "sorted": sorted, "str": str,
                                      "isinstance": isinstance, "list": list, "dict": dict, "set": set}},
             {"d": d})
except Exception:
    sys.exit(1)
if v is None:
    print("")
elif isinstance(v, bool):
    print("true" if v else "false")
elif isinstance(v, (dict, list)):
    print(json.dumps(v))
else:
    print(v)
PY
}

# find_child NAME [FILE]: id of the item called NAME in a Page[Node] body.
find_child() {
    jget "[i['id'] for i in d['items'] if i['name'] == '$1'][0]" "${2:-$BODY}"
}

# header NAME [FILE]: value of the last response header NAME (case-insensitive).
header() {
    tr -d '\r' <"${2:-$HDRS}" | awk -v n="$1" 'BEGIN { n = tolower(n) }
        { i = index($0, ":"); if (i > 0 && tolower(substr($0, 1, i - 1)) == n) { v = substr($0, i + 1); sub(/^[ \t]+/, "", v); last = v } }
        END { if (last != "") print last }'
}

# status_in CODE...: $STATUS is one of the codes.
status_in() {
    for si_c in "$@"; do
        [ "$STATUS" = "$si_c" ] && return 0
    done
    return 1
}

# expect CODE...: like status_in but records the failure reason.
expect() {
    status_in "$@" && return 0
    WHY="${EXPECT_CTX:-request}: expected HTTP $*, got $STATUS"
    return 1
}

# ---------- HTTP ----------
# These globals are set by the test script: CA, FP_NAME, PORT, BASE, JAR,
# BODY, HDRS, CSRF.

# api METHOD PATH [JSON] [extra curl args...]
api() {
    a_m=$1
    a_p=$2
    shift 2
    a_b=""
    if [ $# -gt 0 ]; then
        a_b=$1
        shift
    fi
    if [ -n "${CSRF:-}" ]; then set -- -H "X-FP-CSRF: $CSRF" "$@"; fi
    if [ -n "$a_b" ]; then set -- -H 'Content-Type: application/json' --data-binary "$a_b" "$@"; fi
    : >"$HDRS"
    : >"$BODY"
    STATUS=$(curl -sS --cacert "$CA" --resolve "$FP_NAME:$PORT:127.0.0.1" --connect-timeout 5 --max-time 600 \
        -b "$JAR" -c "$JAR" -X "$a_m" -o "$BODY" -D "$HDRS" -w '%{http_code}' "$@" "$BASE$a_p" 2>"$WORK/curl.err") || STATUS=000
    [ "$STATUS" != 000 ] || WHY="curl: $(head -c 200 "$WORK/curl.err")"
    return 0
}

# anon METHOD PATH [JSON] [extra curl args...]: like api, but with the
# anonymous visitor's cookie jar ($ANON_JAR) and no CSRF token.
anon() {
    an_m=$1
    an_p=$2
    shift 2
    an_b=""
    if [ $# -gt 0 ]; then
        an_b=$1
        shift
    fi
    if [ -n "$an_b" ]; then set -- -H 'Content-Type: application/json' --data-binary "$an_b" "$@"; fi
    : >"$HDRS"
    : >"$BODY"
    STATUS=$(curl -sS --cacert "$CA" --resolve "$FP_NAME:$PORT:127.0.0.1" --connect-timeout 5 --max-time 600 \
        -b "$ANON_JAR" -c "$ANON_JAR" -X "$an_m" -o "$BODY" -D "$HDRS" -w '%{http_code}' "$@" "$BASE$an_p" 2>"$WORK/curl.err") || STATUS=000
    return 0
}

# head_req PATH [jar]: HEAD request (curl -I) with the user's jar.
head_req() {
    : >"$HDRS"
    : >"$BODY"
    STATUS=$(curl -sS -I --cacert "$CA" --resolve "$FP_NAME:$PORT:127.0.0.1" --connect-timeout 5 --max-time 60 \
        -b "${2:-$JAR}" -c "${2:-$JAR}" -o "$HDRS" -w '%{http_code}' "$BASE$1" 2>"$WORK/curl.err") || STATUS=000
    return 0
}

# plain_http URL [extra curl args...]: plain-HTTP request, no redirects followed.
plain_http() {
    ph_u=$1
    shift
    : >"$HDRS"
    STATUS=$(curl -sS --connect-timeout 5 --max-time 30 -o /dev/null -D "$HDRS" -w '%{http_code}' "$@" "$ph_u" 2>"$WORK/curl.err") || STATUS=000
    return 0
}

# wait_until TIMEOUT_S CMD...: retries CMD every 0.5 s until it succeeds.
wait_until() {
    wu_end=$(($(date +%s) + $1))
    shift
    while :; do
        if "$@"; then return 0; fi
        [ "$(date +%s)" -lt "$wu_end" ] || return 1
        sleep 0.5 2>/dev/null || sleep 1
    done
}

# ---------- TOTP (RFC 6238, python3 stdlib) ----------
# totp_code: prints a code for $TOTP_URI (otpauth://…) or $TOTP_SECRET for a
# time step that has not been used yet in this run (a server rejects a replay
# of the same step), waiting for the next step when necessary. The step is
# remembered in $WORK/totp.step.
totp_code() {
    python3 - "${TOTP_URI:-}" "${TOTP_SECRET:-}" "$WORK/totp.step" "${1:-fresh}" <<'PY'
import base64, hashlib, hmac, struct, sys, time, urllib.parse
uri, secret, state, mode = sys.argv[1:5]
period, digits, algo = 30, 6, "SHA1"
if uri:
    q = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
    secret = q.get("secret", [secret])[0]
    period = int(q.get("period", ["30"])[0])
    digits = int(q.get("digits", ["6"])[0])
    algo = q.get("algorithm", ["SHA1"])[0].upper()
key = base64.b32decode(secret.upper().replace(" ", "") + "=" * (-len(secret.replace(" ", "")) % 8))
try:
    last = int(open(state).read().strip())
except Exception:
    last = -1
if mode == "fresh":
    while True:
        now = time.time()
        step = int(now // period)
        # a step not used before, with at least 2 s left so the request lands in it
        if step > last and (step + 1) * period - now >= 2:
            break
        time.sleep(0.25)
else:  # "current": the current step even if used (for replay tests)
    step = int(time.time() // period)
mac = hmac.new(key, struct.pack(">Q", step), getattr(hashlib, algo.lower())).digest()
off = mac[-1] & 0x0F
code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
if mode == "fresh":
    open(state, "w").write(str(step))
print(str(code).zfill(digits))
PY
}
