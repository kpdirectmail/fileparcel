#!/usr/bin/env python3
"""Phase 1: auth state, login, password change, /me, TOTP, passkey begin."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

INIT_PW = sys.argv[1] if len(sys.argv) > 1 else "BPeB8-cwAE7-TdiWs-ga4Ws"
NEW_PW = "Integr8-Smoke-Test-Pw!2026"
STATE = {}

c = Client()

# --- auth state ---
r = c.api("GET", "/auth/state")
check("auth.state 200", r.status == 200, r.status)
st = r.json()
check("auth.state setup_needed=false", st.get("setup_needed") is False, st)
check("auth.state keys_state=unlocked", st.get("keys_state") == "unlocked", st)
check("auth.state rp_id", st.get("rp_id") == HOST, st)

# --- CSRF enforcement: POST without token must be rejected ---
r = c.api("POST", "/auth/logout", json_body={})
check("CSRF: logout w/o session rejected", r.status in (401, 403), "%d %s" % (r.status, r.text()[:200]))

# --- bad login ---
r = c.api("POST", "/auth/login", json_body={"username": "admin", "password": "wrong-password-xyz"})
check("login wrong password 401", r.status == 401, "%d %s" % (r.status, r.text()[:200]))

# --- login ---
r = c.api("POST", "/auth/login", json_body={"username": "admin", "password": INIT_PW})
check("login 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
lr = r.json()
check("login must_change_password", lr.get("must_change_password") is True, lr)
check("login set session cookie", bool(c.cookies), c.cookies)
c.csrf = lr.get("csrf")
check("login returns csrf", bool(c.csrf), lr)

# --- wrong CSRF must fail ---
old = c.csrf
c.csrf = "bogus"
r = c.api("POST", "/me/password", json_body={"current_password": INIT_PW, "new_password": NEW_PW})
check("CSRF: wrong token 403", r.status == 403, "%d %s" % (r.status, r.text()[:200]))
c.csrf = old

# --- /me while must_change_password ---
r = c.api("GET", "/me")
check("GET /me 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
me = r.json()
check("/me username=admin", (me.get("user") or {}).get("username") == "admin", me)

# --- change password ---
r = c.api("POST", "/me/password", json_body={"current_password": INIT_PW, "new_password": NEW_PW})
check("POST /me/password", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))
if r.status in (200, 204) and r.body:
    try:
        b = r.json()
        if b.get("csrf"):
            c.csrf = b["csrf"]
    except Exception:
        pass

r = c.api("GET", "/me")
me = r.json() if r.status == 200 else {}
check("/me must_change_password cleared",
      (me.get("user") or {}).get("must_change_password") in (False, None), me.get("user"))

# --- weak password rejected ---
r = c.api("POST", "/me/password", json_body={"current_password": NEW_PW, "new_password": "password"})
check("weak password rejected 422", r.status == 422, "%d %s" % (r.status, r.text()[:200]))

# --- auth.require_2fa=admins: an administrator must enrol before acting ---
r = c.api("PATCH", "/admin/settings", json_body={"ratelimit.login_per_min": 2000})
check("admin without 2FA is refused admin actions (mfa_enroll_required)",
      r.status == 403 and "mfa_enroll" in r.text(), "%d %s" % (r.status, r.text()[:250]))

# --- /me/mfa ---
r = c.api("GET", "/me/mfa")
check("GET /me/mfa 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("/me/mfa totp disabled", r.json().get("totp_enabled") is False, r.text()[:200])

# --- /me/sessions, tokens, usage ---
for p, name in [("/me/sessions", "sessions"), ("/me/tokens", "tokens"),
                ("/me/usage", "usage"), ("/me/passkeys", "passkeys"),
                ("/me/client-certs", "client-certs")]:
    r = c.api("GET", p)
    check("GET %s 200" % p, r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# --- passkey begin: discoverable (anonymous client, conditional mediation) ---
anon = Client()
flows = []
for label, body in [("no username", {}), ("username=admin", {"username": "admin"}),
                    ("unknown username", {"username": "nosuchuser"})]:
    r = anon.api("POST", "/auth/passkey/begin", json_body=body)
    check("POST /auth/passkey/begin (%s) 200" % label, r.status == 200, "%d %s" % (r.status, r.text()[:300]))
    if r.status != 200:
        continue
    pb = r.json()
    check("passkey/begin (%s) options+flow_id" % label,
          bool(pb.get("options")) and bool(pb.get("flow_id")), list(pb))
    opts = json.loads(pb["options"]) if isinstance(pb["options"], str) else pb["options"]
    pk = opts.get("publicKey", {})
    check("passkey/begin (%s) challenge + discoverable" % label,
          bool(pk.get("challenge")) and not pk.get("allowCredentials"), str(pk)[:200])
    flows.append(json.dumps(pk, sort_keys=True))
check("passkey/begin does not reveal account existence",
      len(flows) == 3 and len({f.replace(json.loads(f).get("challenge", ""), "") for f in flows}) == 1,
      fail_detail="options differ between known and unknown usernames")

# signed-in branch: admin has no passkey yet -> 404
r = c.api("POST", "/auth/passkey/begin", json_body={})
check("passkey/begin signed-in w/o passkey 404", r.status == 404, "%d %s" % (r.status, r.text()[:200]))

# adding a passkey or an authenticator app needs step-up (a new factor satisfies step-up
# itself); an administrator who still has to enrol confirms with the password
r = c.api("POST", "/me/passkeys/begin", json_body={})
check("POST /me/passkeys/begin needs step-up", r.status == 403 and "elevation_required" in r.text(),
      "%d %s" % (r.status, r.text()[:300]))
r = c.api("POST", "/auth/elevate", json_body={"password": NEW_PW})
check("enrolling admin elevates with the password", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
if r.status == 200 and r.json().get("csrf"):
    c.csrf = r.json()["csrf"]
r = c.api("POST", "/me/passkeys/begin", json_body={})
check("POST /me/passkeys/begin 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
if r.status == 200:
    pb = r.json()
    opts = json.loads(pb["options"]) if isinstance(pb.get("options"), str) else pb.get("options", {})
    check("me/passkeys/begin has user id",
          bool(opts.get("publicKey", {}).get("user", {}).get("id")), str(opts)[:300])

# --- passkey finish with garbage must not 500 ---
r = c.api("POST", "/auth/passkey/finish", json_body={"flow_id": "nope", "credential": {"x": 1}})
check("passkey/finish bad flow != 500", r.status < 500, "%d %s" % (r.status, r.text()[:200]))

# --- TOTP enroll ---
r = c.api("POST", "/me/totp/begin", json_body={})
check("POST /me/totp/begin 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
enr = r.json() if r.status == 200 else {}
secret = enr.get("secret", "")
check("totp/begin secret", bool(secret), enr)
check("totp/begin otpauth_uri", enr.get("otpauth_uri", "").startswith("otpauth://totp/"), enr.get("otpauth_uri"))
check("totp/begin qr data uri", enr.get("qr_data_uri", "").startswith("data:image/svg+xml"), (enr.get("qr_data_uri") or "")[:60])

# wrong code
r = c.api("POST", "/me/totp/confirm", json_body={"code": "000000"})
check("totp/confirm wrong code rejected", r.status in (401, 403, 422), "%d %s" % (r.status, r.text()[:200]))

code = totp_code(secret)
r = c.api("POST", "/me/totp/confirm", json_body={"code": code})
check("POST /me/totp/confirm 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
rc = r.json() if r.status in (200, 201) and r.body else {}
codes = rc.get("recovery_codes") or []
check("totp/confirm returns recovery codes", len(codes) >= 5, len(codes))
STATE["recovery_codes"] = codes
STATE["totp_secret"] = secret

r = c.api("GET", "/me/mfa")
check("/me/mfa totp enabled after confirm", r.json().get("totp_enabled") is True, r.text()[:200])

# The same admin action now goes through, and the new limit applies live.
r = c.api("PATCH", "/admin/settings", json_body={"ratelimit.login_per_min": 2000})
check("admin actions work once 2FA is enrolled", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
r = Client().api("POST", "/auth/login", json_body={"username": "admin", "password": "still-wrong"})
check("the raised rate limit applies live without a restart", r.status == 401,
      "%d %s" % (r.status, r.text()[:200]))

# --- logout ---
r = c.api("POST", "/auth/logout", json_body={})
check("POST /auth/logout", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/me")
check("/me after logout 401", r.status == 401, "%d %s" % (r.status, r.text()[:200]))

# --- re-login with MFA ---
c2 = Client()
r = c2.api("POST", "/auth/login", json_body={"username": "admin", "password": NEW_PW})
check("re-login 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
lr = r.json()
check("re-login mfa_required", lr.get("mfa_required") is True, lr)
check("re-login methods has totp", "totp" in (lr.get("methods") or []), lr)
c2.csrf = lr.get("csrf")
check("re-login gives csrf at level 1", bool(c2.csrf), lr)

# /me at AuthLevel 1 must not give full access
r = c2.api("GET", "/spaces")
check("level-1 session blocked from /spaces", r.status in (401, 403), "%d %s" % (r.status, r.text()[:200]))

# wrong TOTP
r = c2.api("POST", "/auth/totp", json_body={"code": "000000"})
check("auth/totp wrong code rejected", r.status in (401, 403, 422), "%d %s" % (r.status, r.text()[:200]))

# right TOTP -- wait for a fresh window if the previous code was consumed
code = totp_code(STATE["totp_secret"])
r = c2.api("POST", "/auth/totp", json_body={"code": code})
if r.status != 200:
    time.sleep(31)
    code = totp_code(STATE["totp_secret"])
    r = c2.api("POST", "/auth/totp", json_body={"code": code})
check("POST /auth/totp 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
lr = r.json() if r.status == 200 else {}
if lr.get("csrf"):
    c2.csrf = lr["csrf"]
r = c2.api("GET", "/spaces")
check("full access after TOTP", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# --- recovery code login ---
c3 = Client()
r = c3.api("POST", "/auth/login", json_body={"username": "admin", "password": NEW_PW})
c3.csrf = r.json().get("csrf")
r = c3.api("POST", "/auth/recovery", json_body={"code": codes[0] if codes else "x"})
check("POST /auth/recovery 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
if r.status == 200 and r.json().get("csrf"):
    c3.csrf = r.json()["csrf"]
r = c3.api("POST", "/auth/recovery", json_body={"code": codes[0] if codes else "x"})
check("recovery code single use", r.status != 200, "%d %s" % (r.status, r.text()[:200]))

# --- elevate ---
r = c2.api("POST", "/auth/elevate", json_body={"password": NEW_PW})
check("POST /auth/elevate 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
if r.status == 200:
    el = r.json()
    if el.get("csrf"):
        c2.csrf = el["csrf"]
    check("elevate returns elevated_until", bool(el.get("elevated_until")), el)

# --- API token (PAT) ---
r = c2.api("POST", "/me/tokens", json_body={"name": "smoke", "scopes": ["files:read", "files:write", "admin"]})
check("POST /me/tokens", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
tok = r.json() if r.status in (200, 201) else {}
STATE["pat"] = tok.get("secret") or ""
check("token secret returned once", bool(STATE["pat"]), list(tok))

if STATE["pat"]:
    ct = Client(token=STATE["pat"])
    r = ct.api("GET", "/me")
    check("PAT works on /me", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    r = ct.api("GET", "/spaces")
    check("PAT works on /spaces", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# --- the login rate limit really fires (set low on purpose, then restored) ---
r = c2.api("PATCH", "/admin/settings", json_body={"ratelimit.login_per_min": 3})
check("lower ratelimit.login_per_min to 3", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
# Use a username that does not exist: this exercises the per-IP limiter
# without tripping the per-account lockout (auth.lockout_threshold) on the
# only administrator.
codes = []
for i in range(8):
    codes.append(Client().api("POST", "/auth/login",
                              json_body={"username": "nobody-%d" % i, "password": "wrong-%d" % i}).status)
check("login attempts are rate limited", 429 in codes, codes)
check("the limiter answers 401 before 429", codes[0] == 401, codes[:3])
rl = [x for x in codes if x == 429]
check("the limiter keeps refusing once tripped", len(rl) >= 3, codes)
r = c2.api("PATCH", "/admin/settings", json_body={"ratelimit.login_per_min": 2000})
check("restore ratelimit.login_per_min", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
ok_again = False
for _ in range(12):
    r = Client().api("POST", "/auth/login", json_body={"username": "admin", "password": NEW_PW})
    if r.status == 200:
        ok_again = True
        break
    time.sleep(5)
check("real logins work again once the limit is restored", ok_again, "%d %s" % (r.status, r.text()[:250]))

# The owner must not be left locked out by the bad attempts above.
me = c2.api("GET", "/me").json()
c2.api("POST", "/admin/users/%s/unlock" % me["user"]["id"])
r = c2.api("GET", "/admin/users/%s" % me["user"]["id"])
check("the owner account is not locked", (r.json().get("lock_level") or 0) == 0, r.text()[:250])

STATE["cookies"] = c2.cookies
STATE["csrf"] = c2.csrf
STATE["password"] = NEW_PW
save_state(STATE)

sys.exit(1 if summary() else 0)
