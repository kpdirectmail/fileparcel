#!/usr/bin/env python3
"""Phase 11: maintenance mode (DESIGN §20 gap 1, closed by this run)."""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
st = load_state()
MSG = "Back at 09:00 UTC. Sorry for the noise."


def cli(*args, timeout=120):
    r = subprocess.run([BIN, "--home", HOME] + list(args),
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr)


c = admin_client()
cbob = login("bob", st["bob_pw"])
anon = Client()

# ---------- the settings exist now ----------
r = c.api("GET", "/admin/settings")
_sl = r.json()
_sl = _sl["items"] if isinstance(_sl, dict) else _sl
keys = {s["key"]: s for s in _sl}
check("maintenance.enabled is registered", "maintenance.enabled" in keys, len(keys))
check("maintenance.message is registered", "maintenance.message" in keys, len(keys))
check("both live in the general section",
      keys["maintenance.enabled"]["section"] == "general" and keys["maintenance.message"]["section"] == "general",
      [keys["maintenance.enabled"]["section"], keys["maintenance.message"]["section"]])
check("maintenance.enabled defaults to false", keys["maintenance.enabled"]["default"] is False,
      keys["maintenance.enabled"])
check("neither needs a restart", not keys["maintenance.enabled"]["restart"] and not keys["maintenance.message"]["restart"],
      fail_detail="one of them is marked restart-required")

# ---------- CLI status / on / off ----------
rc, out = cli("maintenance", "status")
check("fileparcel maintenance status works now", rc == 0, "%d %s" % (rc, out[:250]))
check("status reports it is off", "off" in out.lower(), out[:200])

rc, out = cli("maintenance", "on", "--message", MSG)
check("fileparcel maintenance on", rc == 0, "%d %s" % (rc, out[:250]))
rc, out = cli("maintenance", "status")
check("status reports it is on", rc == 0 and "on" in out.lower(), "%d %s" % (rc, out[:250]))
check("status shows the message", MSG in out, out[:300])
rc, out = cli("--json", "maintenance", "status")
try:
    js = json.loads(out)
    check("maintenance status --json", js.get("enabled") is True and js.get("message") == MSG, js)
except Exception as e:
    check("maintenance status --json", False, "%s %s" % (e, out[:200]))

# ---------- enforcement ----------
r = cbob.api("GET", "/spaces")
check("member API request -> 503", r.status == 503, "%d %s" % (r.status, r.text()[:250]))
check("503 carries the operator's message", MSG in r.text(), r.text()[:250])
check("503 carries Retry-After", bool(r.header("Retry-After")), dict(r.headers))
r = cbob.api("POST", "/nodes/%s/folders" % st["root"], json_body={"name": "nope"})
check("member write -> 503", r.status == 503, "%d %s" % (r.status, r.text()[:200]))

r = anon.api("GET", "/nodes/%s/content" % st["small_node"])
check("anonymous API -> 503", r.status == 503, "%d %s" % (r.status, r.text()[:200]))

r = anon.get("/s/%s" % st["share_token"])
check("public share page -> 503", r.status == 503, "%d %s" % (r.status, r.text()[:200]))
r = anon.get("/s/%s/dl/%s" % (st["share_token"], st["small_node"]))
check("public share download -> 503 (no data)",
      r.status == 503 and b"hello fileparcel" not in r.body, "%d %s" % (r.status, r.text()[:200]))

# pages show the notice
r = cbob.get("/files")
check("page navigation -> 503 notice", r.status == 503, "%d %s" % (r.status, r.text()[:200]))
check("the notice is an HTML page", "text/html" in (r.header("Content-Type") or ""), r.header("Content-Type"))
check("the notice carries the message", MSG in r.text(), r.text()[:400])
check("the notice has no template error", not re.search(r"\{\{|<no value>|ZgotmplZ", r.text()), r.text()[:200])
check("the notice keeps the app CSP",
      (r.header("Content-Security-Policy") or "").startswith("default-src 'self'"),
      r.header("Content-Security-Policy"))
check("the notice is a complete document",
      r.text().lstrip()[:15].lower().startswith("<!doctype html") and "</html>" in r.text().lower(),
      r.text()[:100])

# ---------- what must stay reachable ----------
for p, cl in [("/healthz", anon), ("/readyz", anon), ("/login", anon), ("/trust", anon),
              ("/favicon.ico", anon), ("/robots.txt", anon), ("/theme.css", anon),
              ("/manifest.webmanifest", anon), ("/sw.js", anon), ("/trust/ca.crt", anon)]:
    r = cl.get(p)
    check("%s stays reachable" % p, r.status == 200, "%d" % r.status)

for p in ["/auth/state", "/system/status"]:
    r = anon.api("GET", p)
    check("%s stays reachable" % p, r.status == 200, "%d %s" % (r.status, r.text()[:150]))

r = cbob.api("GET", "/me")
check("/me stays reachable for a member", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = cbob.get("/admin")
check("the admin SPA shell still loads", r.status == 200, "%d" % r.status)

# a member can still sign in (so an admin can take over on a shared device)
cb2 = Client()
r = cb2.api("POST", "/auth/login", json_body={"username": "bob", "password": st["bob_pw"]})
check("sign-in still works during maintenance", r.status == 200, "%d %s" % (r.status, r.text()[:250]))

# ---------- admins are unaffected ----------
r = c.api("GET", "/spaces")
check("admin API request passes", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/nodes/%s/content" % st["small_node"])
check("admin can still read files", r.status == 200, "%d" % r.status)
r = c.get("/files")
check("admin page navigation passes", r.status == 200, "%d" % r.status)
r = c.api("GET", "/admin/settings")
check("admin settings pass", r.status == 200, "%d" % r.status)
r = c.api("POST", "/nodes/%s/folders" % st["root"], json_body={"name": "maint-%d" % int(time.time())})
check("admin can still write", r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))
if r.status in (200, 201):
    c.api("POST", "/nodes/trash", json_body={"ids": [r.json()["id"]]})
    c.api("DELETE", "/trash")

# an admin PAT works too
if st.get("pat"):
    r = Client(token=st["pat"]).api("GET", "/spaces")
    check("an admin API token passes", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# the CLI keeps working over the admin socket
rc, out = cli("status")
check("fileparcel status works during maintenance", rc == 0, "%d %s" % (rc, out[:200]))
rc, out = cli("user", "list")
check("fileparcel user list works during maintenance", rc == 0, "%d %s" % (rc, out[:200]))
rc, out = cli("files", "ls", "/My files")
check("fileparcel files ls works during maintenance", rc == 0, "%d %s" % (rc, out[:200]))

# health checks keep the service "up" for a supervisor
rc, out = cli("healthcheck")
check("fileparcel healthcheck passes during maintenance", rc == 0, "%d %s" % (rc, out[:200]))

# ---------- message changes apply live ----------
rc, out = cli("maintenance", "on", "--message", "Second message.")
check("changing the message", rc == 0, "%d %s" % (rc, out[:200]))
r = cbob.api("GET", "/spaces")
check("the new message is served immediately", "Second message." in r.text(), r.text()[:250])

# empty message falls back to a default
r = c.api("PATCH", "/admin/settings", json_body={"maintenance.message": ""})
check("clearing the message", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = cbob.api("GET", "/spaces")
check("a default notice is used when the message is empty",
      r.status == 503 and "maintenance" in r.text().lower(), r.text()[:250])

# ---------- switch it off ----------
rc, out = cli("maintenance", "off")
check("fileparcel maintenance off", rc == 0, "%d %s" % (rc, out[:250]))
rc, out = cli("maintenance", "status")
check("status reports it is off again", rc == 0 and "off" in out.lower(), "%d %s" % (rc, out[:200]))

r = cbob.api("GET", "/spaces")
check("member API works again", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = anon.get("/s/%s" % st["share_token"])
check("public share works again", r.status == 200, "%d" % r.status)
r = cbob.get("/files")
check("pages work again", r.status == 200, "%d" % r.status)

# ---------- the API can switch it on as well ----------
r = c.api("PATCH", "/admin/settings", json_body={"maintenance.enabled": True, "maintenance.message": "via API"})
check("PATCH /admin/settings turns maintenance on", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
r = cbob.api("GET", "/spaces")
check("the API switch takes effect", r.status == 503 and "via API" in r.text(), "%d %s" % (r.status, r.text()[:200]))
r = c.api("DELETE", "/admin/settings/maintenance.enabled")
check("resetting the setting turns it off", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = cbob.api("GET", "/spaces")
check("everything is back to normal", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
c.api("DELETE", "/admin/settings/maintenance.message")

# ---------- it survives a restart ----------
cli("maintenance", "on", "--message", "persisted")
subprocess.run([SRV, "restart"], capture_output=True, timeout=180)
for _ in range(60):
    try:
        if Client().get("/healthz").status == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)
r = Client().api("GET", "/nodes/%s/content" % st["small_node"])
check("maintenance mode survives a restart", r.status == 503 and "persisted" in r.text(),
      "%d %s" % (r.status, r.text()[:250]))
rc, out = cli("maintenance", "off")
check("switched off after the restart", rc == 0, "%d %s" % (rc, out[:200]))
c.api("DELETE", "/admin/settings/maintenance.message")
r = login("bob", st["bob_pw"]).api("GET", "/spaces")
check("normal service restored", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

sys.exit(1 if summary() else 0)
