#!/usr/bin/env python3
"""Phase 8: sealed mode - seal, restart, locked 503 + /unlock page, unlock, unseal."""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
st = load_state()
PASSPHRASE = "smoke-master-passphrase-2026!"


def srv(action):
    r = subprocess.run([SRV, action], capture_output=True, text=True, timeout=180)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def cli(*args, timeout=120, stdin=None):
    r = subprocess.run([BIN, "--home", HOME] + list(args),
                       capture_output=True, text=True, timeout=timeout, input=stdin)
    return r.returncode, (r.stdout + r.stderr)


def wait_state(want, tries=60):
    for _ in range(tries):
        try:
            r = Client().api("GET", "/system/status")
            if r.status == 200 and r.json().get("state") == want:
                return True, r.json()
        except Exception:
            pass
        time.sleep(0.5)
    try:
        return False, Client().api("GET", "/system/status").text()[:200]
    except Exception as e:
        return False, repr(e)


c = admin_client()

# ---------- seal ----------
r = c.api("GET", "/admin/keys")
check("keys start in plain mode", r.json().get("mode") in ("plain", None) and r.json().get("state") == "unlocked",
      r.text()[:250])

r = c.api("POST", "/admin/keys/seal", json_body={"passphrase": ""})
check("seal without a passphrase is refused", r.status in (400, 422), "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/admin/keys/seal", json_body={"passphrase": PASSPHRASE})
check("POST /admin/keys/seal 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
check("keys are now sealed but still unlocked",
      r.json().get("mode") == "sealed" and r.json().get("state") == "unlocked", r.text()[:250])

mk = os.path.join(HOME, "keys", "master.key")
with open(mk) as f:
    mkj = json.load(f)
check("master.key on disk says mode=sealed", mkj.get("mode") == "sealed", list(mkj))
check("master.key holds no plaintext key material",
      "key" not in mkj and bool(mkj.get("ct")), list(mkj))

# still fully working while sealed-and-unlocked
r = c.api("GET", "/nodes/%s/content" % st["small_node"])
check("files still readable while sealed+unlocked", r.status == 200, "%d" % r.status)

# ---------- restart -> locked ----------
ok, out = srv("stop")
check("server stopped", ok, out)
ok, out = srv("start")
check("server restarted (serves /healthz while locked)", ok, out)

ok, ss = wait_state("locked")
check("GET /system/status state=locked", ok, ss)

r = Client().get("/healthz")
check("/healthz 200 while locked", r.status == 200, "%d %s" % (r.status, r.text()[:120]))
r = Client().get("/readyz")
check("/readyz 503 while locked", r.status == 503, "%d %s" % (r.status, r.text()[:150]))

# API is gated
locked_codes = {}
for p in ["/auth/state", "/me", "/spaces", "/admin/users", "/admin/settings", "/search?q=x"]:
    r = Client().api("GET", p)
    locked_codes[p] = r.status
check("/auth/state answers while locked (the login page needs it)",
      locked_codes["/auth/state"] == 200, locked_codes)
r = Client().api("GET", "/auth/state")
check("/auth/state reports keys_state=locked", r.json().get("keys_state") == "locked", r.text()[:200])
gated = [p for p in ["/me", "/spaces", "/admin/users", "/admin/settings", "/search?q=x"]
         if locked_codes[p] != 503]
check("every data route is 503 while locked", not gated,
      {p: locked_codes[p] for p in gated})

r = Client().api("POST", "/auth/login", json_body={"username": "admin", "password": st["password"]})
check("login is refused while locked (503)", r.status == 503, "%d %s" % (r.status, r.text()[:200]))

# public share must not serve data while locked (it points the visitor at
# /unlock, which leaks nothing /system/status does not already say)
r = Client().get("/s/%s/dl/%s" % (st["share_token"], st["small_node"]))
check("share download serves no data while locked",
      r.status != 200 and b"hello fileparcel" not in r.body, "%d %s" % (r.status, r.text()[:150]))
check("share download points at /unlock while locked",
      r.status == 303 and r.header("Location") == "/unlock", "%d %s" % (r.status, r.header("Location")))
r = Client().get("/s/%s/api" % st["share_token"])
check("share API serves no data while locked", r.status != 200 or "node" not in r.text(),
      "%d %s" % (r.status, r.text()[:150]))

# ---------- /unlock page ----------
r = Client().get("/unlock")
check("GET /unlock 200 while locked", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
body = r.text()
check("/unlock is a complete HTML page", body.lstrip()[:15].lower().startswith("<!doctype html")
      and "</html>" in body.lower(), body[:100])
check("/unlock has no template error", not re.search(r"\{\{|<no value>|ZgotmplZ", body), body[:200])
check("/unlock CSP", (r.header("Content-Security-Policy") or "").startswith("default-src 'self'"),
      r.header("Content-Security-Policy"))
check("/unlock reveals no passphrase hint", PASSPHRASE not in body,
      fail_detail="the passphrase is in the page")

# other pages redirect to /unlock while locked
for p in ["/", "/files", "/login", "/admin"]:
    r = Client().get(p)
    check("%s points at /unlock while locked" % p,
          (r.status in (302, 303, 307) and "/unlock" in (r.header("Location") or ""))
          or (r.status == 200 and "unlock" in r.text().lower()),
          "%d %s" % (r.status, r.header("Location")))

# ---------- unlock ----------
r = Client().api("POST", "/system/unlock", json_body={"passphrase": "wrong-passphrase"})
check("wrong passphrase rejected", r.status in (401, 403, 422), "%d %s" % (r.status, r.text()[:200]))
r = Client().api("GET", "/system/status")
check("still locked after a wrong passphrase", r.json().get("state") == "locked", r.text()[:150])

# rate limit (ratelimit.unlock_per_min = 5)
codes = [Client().api("POST", "/system/unlock", json_body={"passphrase": "nope-%d" % i}).status
         for i in range(8)]
check("unlock attempts are rate limited", 429 in codes, codes)

time.sleep(61)
r = Client().api("POST", "/system/unlock", json_body={"passphrase": PASSPHRASE})
check("POST /system/unlock 200", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))

ok, ss = wait_state("unlocked")
check("server reports unlocked", ok, ss)
r = Client().get("/readyz")
check("/readyz 200 after unlock", r.status == 200, "%d %s" % (r.status, r.text()[:150]))

c2 = admin_client()
r = c2.api("GET", "/nodes/%s/content" % st["small_node"])
check("files readable again after unlock", r.status == 200, "%d" % r.status)
check("content survived the seal/restart/unlock cycle",
      r.body == b"hello fileparcel small path\n" * 4, r.body[:60])
r = c2.api("GET", "/search?q=small")
check("search works after unlock", r.status == 200, "%d" % r.status)
r = Client().get("/s/%s/dl/%s" % (st["share_token"], st["small_node"]))
check("share download works again", r.status == 200, "%d" % r.status)

# ---------- keys lock / CLI unlock ----------
r = c2.api("POST", "/admin/keys/lock")
check("POST /admin/keys/lock 200", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
ok, ss = wait_state("locked")
check("server locked again without a restart", ok, ss)
r = Client().api("GET", "/spaces")
check("data routes 503 after lock", r.status == 503, "%d" % r.status)

rc, out = cli("keys", "unlock", "--passphrase-stdin", stdin=PASSPHRASE + "\n")
check("fileparcel keys unlock (admin socket)", rc == 0, "%d %s" % (rc, out[:300]))
ok, ss = wait_state("unlocked")
check("unlocked over the admin socket", ok, ss)

# ---------- unseal back to plain ----------
c3 = admin_client()
r = c3.api("POST", "/admin/keys/unseal", json_body={"passphrase": "wrong"})
check("unseal with the wrong passphrase is refused", r.status in (401, 403, 422),
      "%d %s" % (r.status, r.text()[:200]))
r = c3.api("POST", "/admin/keys/unseal", json_body={"passphrase": PASSPHRASE})
check("POST /admin/keys/unseal 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
check("keys back to plain + unlocked",
      r.json().get("mode") == "plain" and r.json().get("state") == "unlocked", r.text()[:250])

ok, out = srv("stop")
check("server stopped after unseal", ok, out)
ok, out = srv("start")
check("server starts unlocked again", ok, out)
ok, ss = wait_state("unlocked")
check("plain mode starts unlocked without a passphrase", ok, ss)
r = admin_client().api("GET", "/nodes/%s/content" % st["small_node"])
check("files intact after the whole cycle", r.status == 200 and len(r.body) == 112,
      "%d %d" % (r.status, len(r.body)))

sys.exit(1 if summary() else 0)
