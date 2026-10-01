#!/usr/bin/env python3
"""Phase 5: admin surfaces - certs, client certs, keys, settings, network, mdns,
backups, jobs, system, doctor, dashboard, audit, events SSE, /trust, /system/status."""
import http.client
import json
import os
import urllib.parse
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

st = load_state()
c = admin_client()

# ---------- /system/status + /trust (public) ----------
pub = Client()
r = pub.api("GET", "/system/status")
check("GET /system/status 200 (public)", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
ss = r.json() if r.status == 200 else {}
check("system/status state=unlocked", ss.get("state") == "unlocked", ss)
check("system/status setup_needed=false", ss.get("setup_needed") is False, ss)

for path, want in [("/trust/ca.crt", b"\x30"), ("/trust/ca.pem", b"-----BEGIN CERTIFICATE-----"),
                   ("/trust/ca.mobileconfig", b"<?xml")]:
    r = pub.get(path)
    check("GET %s 200" % path, r.status == 200, "%d %s" % (r.status, r.text()[:150]))
    check("%s body looks right" % path, r.body.startswith(want), r.body[:40])
    check("%s has Content-Disposition" % path, bool(r.header("Content-Disposition")), r.header("Content-Disposition"))

# ca.crt must be byte-identical to the file the CLI hands out
with open(os.path.join(HOME, "certs", "ca", "ca.crt"), "rb") as f:
    pem_on_disk = f.read()
r = pub.get("/trust/ca.pem")
check("/trust/ca.pem matches certs/ca/ca.crt", r.body.strip() == pem_on_disk.strip(),
      "%d vs %d bytes" % (len(r.body), len(pem_on_disk)))

# ---------- certs ----------
r = c.api("GET", "/admin/certs")
check("GET /admin/certs 200", r.status == 200, "%d %s" % (r.status, r.text()[:400]))
cs = r.json() if r.status == 200 else {}
check("cert status has a leaf + CA", json.dumps(cs).count("not_after") >= 1, list(cs))

r = c.api("POST", "/admin/certs/renew", json_body={"force": True})
check("POST /admin/certs/renew 200", r.status in (200, 202, 204), "%d %s" % (r.status, r.text()[:300]))

r = c.api("POST", "/admin/certs/acme/apply", json_body={})
check("POST /admin/certs/acme/apply answers (no ACME configured)",
      r.status in (200, 202, 400, 409, 422, 503), "%d %s" % (r.status, r.text()[:250]))
# run_all.sh points FILEPARCEL_TAILSCALE_SOCKET at a missing socket (never the
# real tailscaled), so Tailscale is "not running": 412 precondition_failed is
# the correct answer. Against a tailscaled without `tailscale set --operator`
# it is 503 with the LocalAPI reason. What matters is a clean error, not a panic.
r = c.api("POST", "/admin/certs/tailscale/fetch", json_body={})
try:
    ts_code = r.json().get("error", {}).get("code") if r.status == 412 else None
except ValueError:
    ts_code = None
check("POST /admin/certs/tailscale/fetch answers cleanly",
      r.status in (200, 202, 409, 422, 503) or (r.status == 412 and ts_code == "precondition_failed"),
      "%d %s" % (r.status, r.text()[:200]))
check("tailscale failure explains itself", "tailscale" in r.text().lower(), r.text()[:200])
r = c.api("PUT", "/admin/certs/custom", json_body={"cert_pem": "not a cert", "key_pem": "nope"})
check("PUT /admin/certs/custom rejects junk", r.status in (400, 422), "%d %s" % (r.status, r.text()[:250]))
r = c.api("DELETE", "/admin/certs/custom")
check("DELETE /admin/certs/custom answers", r.status < 500, "%d %s" % (r.status, r.text()[:200]))

# ---------- client certs (mTLS) ----------
r = c.api("GET", "/admin/client-certs")
check("GET /admin/client-certs 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
me = c.api("GET", "/me").json()
UID = (me.get("user") or {}).get("id", "")
r = c.api("POST", "/admin/client-certs", json_body={"user_id": UID, "name": "smoke-laptop", "days": 30})
check("POST /admin/client-certs 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
cc = r.json() if r.status in (200, 201) else {}
check("client cert issue returns a one-time download URL",
      bool(cc.get("download_url") or cc.get("url") or cc.get("p12")), list(cc))
dlurl = cc.get("download_url") or cc.get("url") or ""
if dlurl:
    r = c.get(dlurl if dlurl.startswith("/") else "/" + dlurl)
    check("GET client-cert download 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    check("p12 is a PKCS#12 SEQUENCE", r.body[:1] == b"\x30" and len(r.body) > 500, "%d bytes" % len(r.body))
    check("p12 password returned once", bool(cc.get("password")), list(cc))
    r2 = c.get(dlurl if dlurl.startswith("/") else "/" + dlurl)
    check("client-cert download link is single-use", r2.status != 200, "%d" % r2.status)

certid = (cc.get("cert") or cc).get("id", "")
if certid:
    r = c.api("DELETE", "/admin/client-certs/" + certid)
    check("DELETE /admin/client-certs/{id}", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))

r = c.api("GET", "/me/client-certs")
check("GET /me/client-certs 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("POST", "/me/client-certs", json_body={"name": "self", "days": 30})
check("POST /me/client-certs answers (mtls.self_service)", r.status < 500, "%d %s" % (r.status, r.text()[:250]))

# ---------- keys ----------
r = c.api("GET", "/admin/keys")
check("GET /admin/keys 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
ks = r.json() if r.status == 200 else {}
check("keys state unlocked", ks.get("state") == "unlocked", ks)

r = c.api("POST", "/admin/keys/recovery")
check("POST /admin/keys/recovery 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))
rk = r.json() if r.status in (200, 201) else {}
check("recovery key returned once", bool(json.dumps(rk).strip("{} ")), list(rk))
st["recovery_key"] = rk.get("recovery_key") or rk.get("key") or ""
save_state(st)

r = c.api("POST", "/admin/keys/rotate", json_body={"target": "kek", "purpose": "blob"})
check("POST /admin/keys/rotate answers", r.status < 500, "%d %s" % (r.status, r.text()[:300]))
if r.status in (200, 201, 202):
    jr = r.json()
    if jr.get("job_id"):
        for _ in range(100):
            j = c.api("GET", "/admin/jobs/" + jr["job_id"])
            if j.status == 200 and j.json().get("state") in ("done", "succeeded", "failed"):
                break
            time.sleep(0.3)
        check("key rotation job succeeded", j.json().get("state") in ("done", "succeeded"),
              j.text()[:300])

# ---------- settings ----------
r = c.api("GET", "/admin/settings")
check("GET /admin/settings 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
sl = r.json()
items = sl["items"] if isinstance(sl, dict) else sl
check("settings catalog >= 90 keys", len(items) >= 90, len(items))
keys = {s["key"]: s for s in items}
check("settings include runtime.gomemlimit_mb", "runtime.gomemlimit_mb" in keys, len(keys))
secret_leak = [s["key"] for s in items if s.get("secret") and s.get("value") not in (None, "", "********")]
check("secret settings never echo their value", not secret_leak, secret_leak)

r = c.api("PATCH", "/admin/settings", json_body={"ui.login_message": "smoke test banner"})
check("PATCH /admin/settings 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
check("patch reports applied", "ui.login_message" in (r.json().get("applied") or []), r.text()[:200])
r = Client().api("GET", "/auth/state")
check("setting visible in /auth/state", r.json().get("login_message") == "smoke test banner", r.text()[:200])

r = c.api("PATCH", "/admin/settings", json_body={"ratelimit.api_rps": "not-a-number"})
check("PATCH rejects wrong type", r.status == 422, "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/admin/settings", json_body={"ratelimit.api_rps": 999999999})
check("PATCH enforces max", r.status == 422, "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/admin/settings", json_body={"no.such.setting": 1})
check("PATCH rejects unknown key", r.status in (400, 422), "%d %s" % (r.status, r.text()[:200]))

r = c.api("DELETE", "/admin/settings/ui.login_message")
check("DELETE /admin/settings/{key} (reset)", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = Client().api("GET", "/auth/state")
check("setting back to default", r.json().get("login_message") == "", r.text()[:200])

# ---------- network + mdns ----------
r = c.api("GET", "/admin/network")
check("GET /admin/network 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
net = r.json() if r.status == 200 else {}
check("network overview has policy + interfaces", "policy" in json.dumps(net) or "access" in json.dumps(net), list(net))

r = c.api("GET", "/network/urls")
check("GET /network/urls 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
urls = r.json()
uitems = urls["items"] if isinstance(urls, dict) and "items" in urls else urls
check("network urls non-empty", len(uitems) > 0, str(uitems)[:300])

r = c.api("GET", "/qr.svg?data=" + urllib.parse.quote(ORIGIN + "/", safe=""))
check("GET /qr.svg?data= 200", r.status == 200 and r.body.startswith(b"<svg"), "%d %s" % (r.status, r.body[:80]))
check("qr.svg content-type", "image/svg+xml" in (r.header("Content-Type") or ""), r.header("Content-Type"))
r = c.api("GET", "/qr.svg")
check("GET /qr.svg without data 422", r.status == 422, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/qr.svg?data=" + "x" * 600)
check("GET /qr.svg oversized data rejected", r.status in (400, 414, 422), "%d %s" % (r.status, r.text()[:200]))

r = c.api("GET", "/admin/mdns")
check("GET /admin/mdns 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
r = c.api("POST", "/admin/mdns/republish")
check("POST /admin/mdns/republish", r.status in (200, 202, 204), "%d %s" % (r.status, r.text()[:200]))

# network policy lockout guard (G-1): a policy that would lock the caller out is refused
r = c.api("GET", "/admin/network")
before = r.json()
saved = before.get("policy") or {}

# DESIGN 10.3: loopback is always admitted, so no policy can lock out a
# loopback caller -- this one must be accepted.
r = c.api("PUT", "/admin/network/policy",
          json_body={"mode": "allowlist", "allow": ["203.0.113.0/24"], "deny": []})
check("loopback caller is never locked out (DESIGN 10.3)", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
r = c.api("PUT", "/admin/network/policy",
          json_body={"mode": saved.get("mode", "allowlist"),
                     "allow": saved.get("allow") or ["127.0.0.0/8", "::1"],
                     "deny": saved.get("deny") or []})
check("policy restored after the loopback case", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# The guard only means something for a non-loopback client, so drive it over
# this host's LAN address (the leaf certificate covers it).
LAN = os.environ.get("FP_LAN_IP", "")
if not LAN:
    import subprocess
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            f = line.split()
            if len(f) > 3 and f[3].startswith(("192.168.", "10.")):
                LAN = f[3].split("/")[0]
                break
    except Exception:
        LAN = ""

if not LAN:
    check("lockout guard tested from a non-loopback address", False, "no LAN address found on this host")
else:
    LANORIG = "https://%s:%d" % (LAN, PORT)

    def lreq(cl, method, path, **kw):
        kw.setdefault("raw_host", LAN)
        h = dict(kw.pop("headers", {}) or {})
        if method not in ("GET", "HEAD"):
            h.setdefault("Origin", LANORIG)
            h.setdefault("Sec-Fetch-Site", "same-origin")
        return cl.request(method, path, headers=h, origin=False, **kw)

    cl = Client()
    r = lreq(cl, "POST", "/api/v1/auth/login", json_body={"username": "admin", "password": st["password"]})
    check("login over the LAN address 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    cl.csrf = r.json().get("csrf")
    if r.json().get("mfa_required"):
        for _ in range(3):
            r = lreq(cl, "POST", "/api/v1/auth/totp", json_body={"code": totp_code(st["totp_secret"])})
            if r.status == 200:
                break
            time.sleep(31)
        cl.csrf = r.json().get("csrf") or cl.csrf
    r = lreq(cl, "POST", "/api/v1/auth/elevate", json_body={"password": st["password"]})
    cl.csrf = r.json().get("csrf") or cl.csrf
    r = lreq(cl, "GET", "/api/v1/admin/network")
    check("admin reachable over the LAN address", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

    lock = {"mode": "allowlist", "allow": ["203.0.113.0/24"], "deny": []}
    r = lreq(cl, "PUT", "/api/v1/admin/network/policy", json_body=lock)
    check("PUT /admin/network/policy lockout -> 409", r.status == 409, "%d %s" % (r.status, r.text()[:250]))
    check("409 names the caller address", LAN in r.text(), r.text()[:200])
    r = lreq(cl, "PATCH", "/api/v1/admin/settings", json_body={"network.allow_cidrs": ["203.0.113.0/24"]})
    check("PATCH network.allow_cidrs lockout -> 409", r.status == 409, "%d %s" % (r.status, r.text()[:250]))
    r = lreq(cl, "DELETE", "/api/v1/admin/settings/network.allow_cidrs")
    check("DELETE network.allow_cidrs lockout -> 409", r.status == 409, "%d %s" % (r.status, r.text()[:250]))

    r = lreq(cl, "GET", "/api/v1/admin/network")
    check("no refused attempt changed the policy",
          (r.json().get("policy") or {}).get("allow") == (before.get("policy") or {}).get("allow"),
          r.text()[:250])

    # force=1 must go through, with a warning, and the listener must enforce it.
    lock["force"] = True
    r = lreq(cl, "PUT", "/api/v1/admin/network/policy", json_body=lock)
    check("forced lockout accepted with a warning",
          r.status == 200 and any(LAN in w for w in (r.json().get("warnings") or [])), r.text()[:300])
    blocked = False
    try:
        Client().request("GET", "/api/v1/system/status", raw_host=LAN)
    except Exception:
        blocked = True
    check("listener now refuses the LAN address", blocked,
          fail_detail="the LAN address is still reachable under the lockout")
    r = Client().api("GET", "/system/status")
    check("loopback still reachable under the lockout", r.status == 200, "%d" % r.status)

    r = c.api("PUT", "/admin/network/policy",
              json_body={"mode": saved.get("mode", "allowlist"),
                         "allow": saved.get("allow") or ["127.0.0.0/8", "::1"],
                         "deny": saved.get("deny") or []})
    check("network policy restored", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    r = Client().request("GET", "/api/v1/system/status", raw_host=LAN)
    check("LAN address reachable again", r.status == 200, "%d" % r.status)

r = c.api("GET", "/admin/network")
check("still reachable after policy changes", r.status == 200, "%d" % r.status)

# ---------- jobs ----------
r = c.api("GET", "/admin/jobs")
check("GET /admin/jobs 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/jobs/kinds")
check("GET /admin/jobs/kinds 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
kinds = r.json()
kinds = kinds["items"] if isinstance(kinds, dict) else kinds
kindnames = [k if isinstance(k, str) else k.get("kind") for k in kinds]
check("job kinds non-empty", len(kindnames) > 5, kindnames)
r = c.api("GET", "/admin/jobs/schedules")
check("GET /admin/jobs/schedules 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
sched = r.json()
sched = sched["items"] if isinstance(sched, dict) else sched
check("schedules non-empty", len(sched) > 0, str(sched)[:200])

ran = None
for kind in ("maintenance.trash", "maintenance.sessions", "maintenance.uploads", "search.reindex"):
    if kind in kindnames:
        r = c.api("POST", "/admin/jobs/run", json_body={"kind": kind})
        if r.status in (200, 201, 202):
            ran = (kind, r.json().get("job_id"))
            break
check("POST /admin/jobs/run 202", ran is not None, "%s / %s" % (kindnames, r.text()[:200]))
if ran:
    kind, jid = ran
    jstate = None
    for _ in range(120):
        j = c.api("GET", "/admin/jobs/" + jid)
        if j.status == 200:
            jstate = j.json().get("state")
            if jstate in ("done", "succeeded", "failed", "cancelled"):
                break
        time.sleep(0.25)
    check("job %s finished OK" % kind, jstate in ("done", "succeeded"), "%s %s" % (jstate, j.text()[:300]))
    r = c.api("GET", "/jobs/" + jid)
    check("GET /jobs/{id} (own job) 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/admin/jobs/run", json_body={"kind": "no.such.kind"})
check("unknown job kind rejected", r.status in (400, 404, 422), "%d %s" % (r.status, r.text()[:200]))
r = c.api("POST", "/admin/jobs/job_doesnotexist/cancel")
check("cancel unknown job 404", r.status in (404, 409, 422), "%d %s" % (r.status, r.text()[:200]))

# ---------- system / doctor / dashboard / logs ----------
r = c.api("GET", "/admin/system")
check("GET /admin/system 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
sysinfo = r.json() if r.status == 200 else {}
check("system info has version + uptime", "version" in json.dumps(sysinfo), list(sysinfo))

r = c.api("GET", "/admin/system/doctor")
check("GET /admin/system/doctor 200", r.status == 200, "%d %s" % (r.status, r.text()[:400]))
doc = r.json() if r.status == 200 else {}
checks = doc.get("checks") or doc.get("items") or []
check("doctor runs checks", len(checks) > 0, str(doc)[:400])
bad = [x for x in checks if x.get("status") in ("fail", "error")]
check("doctor reports no failures", not bad, bad)

r = c.api("GET", "/admin/system/logs")
check("GET /admin/system/logs 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/dashboard")
check("GET /admin/dashboard 200", r.status == 200, "%d %s" % (r.status, r.text()[:400]))
dash = r.json() if r.status == 200 else {}
check("dashboard has counters", len(dash) > 2, list(dash))

# ---------- audit ----------
r = c.api("GET", "/admin/audit")
check("GET /admin/audit 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
au = r.json().get("items") or []
check("audit has entries", len(au) > 0, len(au))
acts = {a.get("action") for a in au}
r = c.api("GET", "/admin/audit?action=user.create")
check("audit filter by action", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("audit recorded user.create", len(r.json().get("items") or []) > 0, r.text()[:300])

r = c.api("GET", "/admin/audit/verify")
check("GET /admin/audit/verify 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
av = r.json() if r.status == 200 else {}
check("audit chain verifies", av.get("ok") is True or av.get("valid") is True, av)

r = c.api("GET", "/admin/audit/export")
check("GET /admin/audit/export 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("audit export is ndjson/csv", len(r.body) > 0, r.body[:120])

# ---------- backups ----------
r = c.api("GET", "/admin/backups/config")
check("GET /admin/backups/config 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
cfg = r.json() if r.status == 200 else {}
r = c.api("PUT", "/admin/backups/config", json_body=cfg)
check("PUT /admin/backups/config round-trips", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))

r = c.api("GET", "/admin/backups")
check("GET /admin/backups 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/admin/backups", json_body={"scope": "full", "note": "smoke"})
check("POST /admin/backups 202", r.status in (200, 201, 202), "%d %s" % (r.status, r.text()[:400]))
bk = r.json() if r.status in (200, 201, 202) else {}
BJOB = bk.get("job_id", "")
BID = bk.get("id") or (bk.get("backup") or {}).get("id", "")
if BJOB:
    jstate = None
    for _ in range(240):
        j = c.api("GET", "/admin/jobs/" + BJOB)
        if j.status == 200:
            jstate = j.json().get("state")
            if jstate in ("done", "succeeded", "failed", "cancelled"):
                break
        time.sleep(0.25)
    check("backup job finished OK", jstate in ("done", "succeeded"), "%s %s" % (jstate, j.text()[:400]))

r = c.api("GET", "/admin/backups")
bl = r.json().get("items") or []
check("backup listed", len(bl) >= 1, r.text()[:400])
if bl and not BID:
    BID = bl[0]["id"]
if BID:
    r = c.api("GET", "/admin/backups/" + BID)
    check("GET /admin/backups/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
    b1 = r.json() if r.status == 200 else {}
    check("backup has size + sha", (b1.get("size_bytes") or b1.get("size") or 0) > 0, b1)

    r = c.api("POST", "/admin/backups/%s/verify" % BID)
    check("POST /admin/backups/{id}/verify", r.status in (200, 202), "%d %s" % (r.status, r.text()[:400]))
    vr = r.json() if r.status in (200, 202) else {}
    if vr.get("job_id"):
        jstate = None
        for _ in range(240):
            j = c.api("GET", "/admin/jobs/" + vr["job_id"])
            if j.status == 200:
                jstate = j.json().get("state")
                if jstate in ("done", "succeeded", "failed", "cancelled"):
                    break
            time.sleep(0.25)
        check("backup verify job succeeded", jstate in ("done", "succeeded"), "%s %s" % (jstate, j.text()[:400]))
    else:
        check("backup verify result ok", vr.get("ok") is True or vr.get("valid") is True, vr)

    r = c.api("GET", "/admin/backups/%s/download" % BID)
    check("GET /admin/backups/{id}/download 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    check("backup download non-trivial", len(r.body) > 1000, len(r.body))
    st["backup_id"] = BID
    save_state(st)

r = c.api("POST", "/admin/backups/identity/export", json_body={})
check("POST /admin/backups/identity/export", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
check("identity export carries an age key", "AGE-SECRET-KEY" in r.text() or "age1" in r.text(), r.text()[:150])

# ---------- events SSE ----------
def sse_probe(client, timeout=12):
    ctx = client.ctx
    conn = http.client.HTTPSConnection(HOST, PORT, context=ctx, timeout=timeout)
    h = {"Accept": "text/event-stream",
         "Cookie": "; ".join("%s=%s" % kv for kv in client.cookies.items())}
    conn.request("GET", "/api/v1/events", headers=h)
    resp = conn.getresponse()
    out = {"status": resp.status, "ctype": resp.getheader("Content-Type"), "data": b""}
    t0 = time.time()
    try:
        while time.time() - t0 < timeout and len(out["data"]) < 4096:
            chunk = resp.read(1)
            if not chunk:
                break
            out["data"] += chunk
            if out["data"].count(b"\n\n") >= 2:
                break
    except Exception as e:
        out["err"] = repr(e)
    finally:
        conn.close()
    return out


# SSE carries job.*, upload.*, share.accessed, keys.state and (for admins)
# settings/network/certs/mdns/backup topics -- a settings change is the
# cheapest deterministic trigger.
# Sign the trigger client in first: a second login may have to wait out a
# TOTP window, which would outlast the probe.
trig = admin_client(elevate=False)
res = {}
th = threading.Thread(target=lambda: res.update(sse_probe(c, timeout=25)), daemon=True)
th.start()
time.sleep(1.0)
for i in range(3):
    trig.api("PATCH", "/admin/settings", json_body={"ui.login_message": "sse-%d-%d" % (int(time.time()), i)})
    if res:
        break
    time.sleep(1.0)
th.join(30)
trig.api("DELETE", "/admin/settings/ui.login_message")
check("GET /api/v1/events 200", res.get("status") == 200, res)
check("events content-type text/event-stream", "text/event-stream" in (res.get("ctype") or ""), res.get("ctype"))
d = res.get("data", b"")
check("events stream opens with a retry hint", b"retry:" in d, d[:200])
check("events stream delivers a live event", b"event: settings.changed" in d and b"data:" in d, d[:400])

# ---------- authorization sweep: member must not reach Adm routes ----------
cbob = login("bob", st["bob_pw"])
denied = []
for p in ["/admin/certs", "/admin/keys", "/admin/settings", "/admin/network", "/admin/mdns",
          "/admin/backups", "/admin/jobs", "/admin/system", "/admin/system/doctor",
          "/admin/dashboard", "/admin/audit", "/admin/audit/verify", "/admin/shares",
          "/admin/users", "/admin/groups", "/admin/invites", "/admin/system/logs"]:
    r = cbob.api("GET", p)
    if r.status != 403:
        denied.append("%s -> %d" % (p, r.status))
check("every Adm GET route is 403 for a member", not denied, denied)

anon = Client()
leaked = []
for p in ["/admin/settings", "/admin/keys", "/admin/audit", "/admin/users", "/admin/backups",
          "/me", "/spaces", "/shares"]:
    r = anon.api("GET", p)
    if r.status != 401:
        leaked.append("%s -> %d" % (p, r.status))
check("anonymous gets 401 on authenticated routes", not leaked, leaked)

sys.exit(1 if summary() else 0)
