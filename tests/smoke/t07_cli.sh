#!/bin/bash
# Phase 7: the CLI over the admin socket.
D="${FP_SMOKE_DIR:-${TMPDIR:-/tmp}/fileparcel-smoke}"
PORT="${FP_PORT:-18443}"
HOST="${FP_HOST:-fileparcel.local}"
FP="$D/fileparcel --home $D/h1"
PASS=0; FAIL=0
declare -a FAILED
chk() { # chk "name" <exit> [expected-exit]
  local name="$1" got="$2" want="${3:-0}"
  if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "[PASS] $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name (exit $got, want $want)"); echo "[FAIL] $name (exit $got, want $want)"; fi
}
chkout() { # chkout "name" "needle" <<< output
  local name="$1" needle="$2" out; out=$(cat)
  if grep -qF -- "$needle" <<<"$out"; then PASS=$((PASS+1)); echo "[PASS] $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name (missing '$needle')"); echo "[FAIL] $name -- want '$needle' in: $(head -c 300 <<<"$out")"; fi
}

echo "=== status ==="
out=$($FP status 2>&1); chk "fileparcel status" $?
chkout "status reports the server is running" "running" <<<"$out"
$FP status --json > "$D/st.json" 2>&1; chk "fileparcel status --json" $?
python3 -c "import json,sys; d=json.load(open(\"$D/st.json\")); assert d.get('running') is True, d; print('ok')" >/dev/null 2>&1
chk "status --json is valid JSON with running=true" $?

echo "=== healthcheck / version ==="
$FP healthcheck >/dev/null 2>&1; chk "fileparcel healthcheck" $?
$FP version >/dev/null 2>&1; chk "fileparcel version" $?

echo "=== user ==="
out=$($FP user list 2>&1); chk "fileparcel user list" $?
chkout "user list shows admin" "admin" <<<"$out"
chkout "user list shows bob" "bob" <<<"$out"
out=$($FP user list --json 2>&1); chk "user list --json" $?
python3 -c "
import json,sys
d=json.loads(sys.stdin.read())
items = d['items'] if isinstance(d,dict) else d
assert any(u['username']=='admin' for u in items), items
print('ok')" <<<"$out" >/dev/null 2>&1
chk "user list --json parses" $?
$FP user show admin >/dev/null 2>&1; chk "fileparcel user show admin" $?

echo "=== config ==="
out=$($FP config get ratelimit.api_rps 2>&1); chk "config get" $?
chkout "config get prints the value" "50" <<<"$out"
$FP config set ui.login_message "cli smoke" >/dev/null 2>&1; chk "config set" $?
out=$($FP config get ui.login_message 2>&1)
chkout "config set took effect" "cli smoke" <<<"$out"
curl -s --cacert "$D/h1/certs/ca/ca.crt" --resolve "$HOST:$PORT:127.0.0.1" \
  "https://$HOST:$PORT/api/v1/auth/state" | grep -q "cli smoke"
chk "config set is visible over HTTPS" $?
$FP config unset ui.login_message >/dev/null 2>&1; chk "config unset" $?
$FP config list >/dev/null 2>&1; chk "config list" $?
$FP config get no.such.key >/dev/null 2>&1; chk "config get unknown key fails" $? 1
if $FP config set ratelimit.api_rps notanumber >/dev/null 2>&1; then chk "config set wrong type fails" 0 1; else chk "config set wrong type fails" 1 1; fi

echo "=== network ==="
out=$($FP network urls 2>&1); chk "network urls" $?
chkout "network urls lists an https URL" "https://" <<<"$out"
out=$($FP network urls --qr 2>&1); chk "network urls --qr" $?
chkout "network urls --qr draws a QR code" "█" <<<"$out"
$FP network policy >/dev/null 2>&1; chk "network policy" $?

echo "=== backup ==="
out=$($FP backup list 2>&1); chk "backup list" $?
chkout "backup list shows a backup" "full" <<<"$out"
out=$($FP backup list --json 2>&1); chk "backup list --json" $?

echo "=== audit ==="
out=$($FP audit verify 2>&1); chk "audit verify" $?
chkout "audit verify reports the chain is intact" "audit log intact" <<<"$out"
$FP audit list --limit 5 >/dev/null 2>&1; chk "audit list" $?
$FP audit export --format jsonl -o "$D/cli-audit.jsonl" --force >/dev/null 2>&1; chk "audit export --format jsonl" $?
python3 -c "import json,sys;[json.loads(l) for l in open('$D/cli-audit.jsonl') if l.strip()];print('ok')" >/dev/null 2>&1; chk "audit export produces valid JSON lines" $?

echo "=== jobs / doctor / logs ==="
$FP jobs list >/dev/null 2>&1; chk "jobs list" $?
$FP jobs list --json >/dev/null 2>&1; chk "jobs list --json" $?
out=$($FP doctor 2>&1); chk "fileparcel doctor" $?
chkout "doctor does not report database damage" "Database integrity" <<<"$out"
if grep -qi "Damaged" <<<"$out"; then FAIL=$((FAIL+1)); FAILED+=("doctor reports Damaged"); echo "[FAIL] doctor reports Damaged: $(grep -i Damaged <<<"$out")"; else PASS=$((PASS+1)); echo "[PASS] doctor reports no damage"; fi
$FP logs --lines 5 >/dev/null 2>&1; chk "fileparcel logs" $?

echo "=== db check ==="
out=$($FP db check 2>&1); chk "db check" $?
chkout "db check integrity ok" "ok" <<<"$out"
if grep -qi "fts5: corruption" <<<"$out"; then FAIL=$((FAIL+1)); FAILED+=("db check reports fts5 corruption"); echo "[FAIL] db check: $(grep -i corruption <<<"$out")"; else PASS=$((PASS+1)); echo "[PASS] db check reports no fts5 corruption"; fi

echo "=== files ls/put/get ==="
rm -rf "$D/cli" && mkdir -p "$D/cli"
printf 'cli upload payload %s\n' "$(date +%s)" > "$D/cli/up.txt"
out=$($FP files ls / 2>&1); chk "files ls / (spaces)" $?
chkout "files ls / lists the personal space" "My files" <<<"$out"
out=$($FP files ls "/My files" 2>&1); chk "files ls /My files" $?
chkout "files ls shows the Smoke folder" "Smoke" <<<"$out"
$FP files mkdir "/My files/CLI" >/dev/null 2>&1; chk "files mkdir" $?
$FP files put "$D/cli/up.txt" "/My files/CLI/" >/dev/null 2>&1; chk "files put" $?
out=$($FP files ls "/My files/CLI" 2>&1); chk "files ls /My files/CLI" $?
chkout "files ls shows the uploaded file" "up.txt" <<<"$out"
$FP files get "/My files/CLI/up.txt" "$D/cli/down.txt" >/dev/null 2>&1; chk "files get" $?
cmp -s "$D/cli/up.txt" "$D/cli/down.txt"; chk "downloaded bytes match the uploaded file" $?
# the file the CLI uploaded must also be visible over the API
curl -s --cacert "$D/h1/certs/ca/ca.crt" --resolve "$HOST:$PORT:127.0.0.1" \
  "https://$HOST:$PORT/api/v1/search?q=up.txt" -H "Authorization: Bearer $FP_PAT" | grep -q "up.txt"
chk "CLI upload is visible through the API" $?
$FP files rm "/My files/CLI/up.txt" >/dev/null 2>&1; chk "files rm" $?
if $FP files get "/My files/CLI/up.txt" "$D/cli/x.txt" >/dev/null 2>&1; then chk "files get after rm fails" 0 1; else chk "files get after rm fails" 1 1; fi

echo "=== share / token / group / invite ==="
out=$($FP share list 2>&1); chk "share list" $?
out=$($FP token list 2>&1); chk "token list" $?
out=$($FP group list 2>&1); chk "group list" $?
chkout "group list shows Team Smoke" "Team Smoke" <<<"$out"
out=$($FP invite list 2>&1); chk "invite list" $?
out=$($FP mdns status 2>&1); chk "mdns status" $?
out=$($FP cert status 2>&1); chk "cert status" $?
out=$($FP ca show 2>&1); chk "ca show" $?
out=$($FP keys status 2>&1); chk "keys status" $?
out=$($FP maintenance status 2>&1); chk "maintenance status" $?
chkout "maintenance status reports a real mode" "Maintenance mode" <<<"$out"

# The tidied-up command line (docs/DESIGN.md §12): canonical names next to the
# legacy ones above (mdns status, …), which keep working.
echo "=== help, suggestions, canonical names ==="
out=$($FP help paths 2>&1); chk "help paths" $?
chkout "help paths explains /My files" "/My files" <<<"$out"
out=$($FP --help 2>&1); chk "root help" $?
chkout "root help is grouped" "People & access:" <<<"$out"
out=$($FP user lsit 2>&1); chk "user lsit is a usage error" $? 2
chkout "user lsit suggests list" "Did you mean" <<<"$out"
$FP service frobnicate >/dev/null 2>&1; chk "service frobnicate is a usage error" $? 2
out=$($FP network status --json 2>&1); chk "network status --json" $?
python3 -c "import json,sys; d=json.loads(sys.stdin.read()); assert 'interfaces' in d, d; print('ok')" <<<"$out" >/dev/null 2>&1
chk "network status --json is the overview" $?
out=$($FP network mdns status 2>&1); chk "network mdns status" $?
out=$($FP share list --all-users 2>&1); chk "share list --all-users" $?
out=$($FP user create smoke-cli-new --generate-password 2>&1); chk "user create --generate-password" $?
chkout "user create prints the password once" "Password:" <<<"$out"
out=$($FP user add smoke-cli-old --generate-password 2>&1); chk "user add (legacy name) --generate-password" $?
$FP -y user delete smoke-cli-new >/dev/null 2>&1; chk "user delete (canonical)" $?
$FP -y user rm smoke-cli-old >/dev/null 2>&1; chk "user rm (alias)" $?
out=$($FP whoami 2>&1); chk "whoami" $?
chkout "whoami over the socket has full rights" "admin socket (system): full rights" <<<"$out"
out=$($FP --as admin whoami 2>&1); chk "whoami --as admin" $?
chkout "whoami --as admin names the account" "admin" <<<"$out"
out=$($FP __complete user show "" 2>&1); chk "completion of user names" $?
chkout "completion lists admin from the server" "admin" <<<"$out"

echo "=== roles, access, VPN, Funnel, zip password ==="
out=$($FP role list 2>&1); chk "role list" $?
chkout "role list shows the built-in member role" "member" <<<"$out"
out=$($FP role permissions 2>&1); chk "role permissions" $?
out=$($FP --as admin access list "/My files" 2>&1); chk "access list /My files (--as admin)" $?
out=$($FP access check admin "/My files" --as admin 2>&1); chk "access check" $?
out=$($FP network vpn list 2>&1); chk "network vpn list" $?
# Without Tailscale the status is "unavailable", which is not an error.
out=$($FP network funnel status 2>&1); chk "network funnel status" $?
out=$($FP network funnel status --json 2>&1); chk "network funnel status --json" $?
python3 -c "import json,sys; d=json.loads(sys.stdin.read()); assert 'funnel' in d, d; print('ok')" <<<"$out" >/dev/null 2>&1
chk "network funnel status --json is the ingress status" $?
printf 'protected by the cli smoke %s\n' "$(date +%s)" > "$D/cli/secret.txt"
$FP files mkdir "/My files/CLI" >/dev/null 2>&1
out=$($FP --json files put "$D/cli/secret.txt" "/My files/CLI" --zip cli-protected.zip --zip-generate-password 2>&1)
chk "files put --zip --zip-generate-password" $?
python3 -c "import json,sys; d=json.loads(sys.stdin.read()); assert len(d.get('zip_password',''))>=12, d; print('ok')" <<<"$out" >/dev/null 2>&1
chk "the generated zip password is in the --json result" $?
out=$($FP files info "/My files/CLI/cli-protected.zip" 2>&1); chk "files info of the protected zip" $?
chkout "files info shows the protection" "AES-256" <<<"$out"
$FP files rm "/My files/CLI/cli-protected.zip" >/dev/null 2>&1; chk "files rm of the protected zip" $?

# A custom role from start to end (docs/DESIGN.md §6a): made from member,
# given to an account, member of a group through the role, holder of an
# access grant, and deleted with its people moved back to member.
echo "=== custom role lifecycle ==="
$FP group create smoke-cli-crew >/dev/null 2>&1; chk "group create smoke-cli-crew" $?
$FP group create smoke-cli-vault >/dev/null 2>&1; chk "group create smoke-cli-vault" $?
out=$($FP role create smoke-contractors --from member --remove shares.links --description "CLI smoke role" 2>&1)
chk "role create --from member --remove" $?
chkout "role create names the base" "custom, based on member" <<<"$out"
out=$($FP role show smoke-contractors 2>&1); chk "role show" $?
chkout "role show lists what is left" "shares.requests" <<<"$out"
out=$($FP role edit smoke-contractors --add shares.links 2>&1); chk "role edit --add" $?
chkout "role edit adds the permission" "shares.links" <<<"$out"
out=$($FP role add-group smoke-contractors smoke-cli-crew 2>&1); chk "role add-group" $?
$FP user create smoke-cli-temp --generate-password >/dev/null 2>&1; chk "user create smoke-cli-temp" $?
out=$($FP user set-role smoke-cli-temp smoke-contractors 2>&1); chk "user set-role with a custom role" $?
out=$($FP user show smoke-cli-temp 2>&1); chk "user show of the role's holder" $?
chkout "user show names the custom role" "smoke-contractors (rol_" <<<"$out"
out=$($FP role members smoke-contractors 2>&1); chk "role members" $?
chkout "role members lists the holder" "smoke-cli-temp" <<<"$out"
out=$($FP group members smoke-cli-crew 2>&1); chk "group members of the role's group" $?
chkout "group members says the role made them a member" "role:smoke-contractors" <<<"$out"
out=$($FP access grant /Team/smoke-cli-vault --role smoke-contractors 2>&1); chk "access grant --role" $?
out=$($FP access check smoke-cli-temp /Team/smoke-cli-vault 2>&1); chk "access check of a role grant" $?
chkout "access check names the role grant" "smoke-cli-temp can VIEW /Team/smoke-cli-vault" <<<"$out"
out=$($FP --as smoke-cli-temp files ls /Team/smoke-cli-vault 2>&1)
chk "a team folder shared with the role opens by its /Team path" $?
out=$($FP role remove-group smoke-contractors smoke-cli-crew 2>&1); chk "role remove-group" $?
out=$($FP group members smoke-cli-crew 2>&1); chk "group members after role remove-group" $?
! grep -q "smoke-cli-temp" <<<"$out"; chk "the role's holder left the group with the role" $?
out=$($FP -y role delete smoke-contractors 2>&1); chk "role delete without --reassign-to is a usage error" $? 2
out=$($FP -y role delete smoke-contractors --reassign-to member 2>&1); chk "role delete --reassign-to member" $?
out=$($FP user show smoke-cli-temp 2>&1)
chkout "the holder is a member again" "member" <<<"$out"
$FP -y user delete smoke-cli-temp >/dev/null 2>&1; chk "user delete smoke-cli-temp" $?
$FP -y group delete smoke-cli-crew >/dev/null 2>&1; chk "group delete smoke-cli-crew" $?
$FP -y group delete smoke-cli-vault >/dev/null 2>&1; chk "group delete smoke-cli-vault" $?

echo
echo "======================================================================"
echo "CLI TOTAL $((PASS+FAIL))  PASS $PASS  FAIL $FAIL"
if [ $FAIL -gt 0 ]; then printf 'FAILURES:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
echo "======================================================================"
[ $FAIL -eq 0 ]
