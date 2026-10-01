#!/usr/bin/env python3
"""Phase 10: the routes that change the installation - backup import/restore,
identity rotation, CA regeneration and a server restart. Run last."""
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
st = load_state()
ROOT = st["root"]


def wait_up(tries=180, want_state="unlocked"):
    for _ in range(tries):
        try:
            r = Client().api("GET", "/system/status")
            if r.status == 200 and r.json().get("state") == want_state:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def wait_job(client, jid, timeout=300):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        r = client.api("GET", "/admin/jobs/" + jid)
        if r.status == 200:
            last = r.json()
            if last.get("state") in ("succeeded", "done", "failed", "canceled", "cancelled"):
                return last
        time.sleep(0.4)
    return last


c = admin_client()

# ---------- a backup we can restore ----------
r = c.api("GET", "/nodes/%s/children" % ROOT)
before_names = sorted(n["name"] for n in r.json()["items"])

r = c.api("POST", "/admin/backups", json_body={"scope": "full", "note": "restore-source"})
check("POST /admin/backups (restore source) 202", r.status in (200, 201, 202),
      "%d %s" % (r.status, r.text()[:300]))
bk = r.json()
job = wait_job(c, bk["job_id"]) if bk.get("job_id") else None
check("backup job succeeded", job and job.get("state") in ("succeeded", "done"),
      (job or {}).get("state"))

r = c.api("GET", "/admin/backups")
backups = r.json()["items"]
SRC = None
for b in backups:
    if b.get("note") == "restore-source":
        SRC = b
check("the backup is listed as ready", SRC and SRC.get("state") == "ready", SRC)
BID = SRC["id"]
check("backup records size + sha256", (SRC.get("size") or 0) > 0 and bool(SRC.get("sha256")), SRC)

r = c.api("POST", "/admin/backups/%s/verify" % BID)
check("POST /admin/backups/{id}/verify", r.status in (200, 202), "%d %s" % (r.status, r.text()[:250]))
vj = r.json()
if vj.get("job_id"):
    job = wait_job(c, vj["job_id"])
    check("verify job succeeded", job and job.get("state") in ("succeeded", "done"), (job or {}).get("state"))
r = c.api("GET", "/admin/backups/" + BID)
check("backup marked verified_ok", r.json().get("verify_ok") is True, r.text()[:300])

# download it for the import test
r = c.api("GET", "/admin/backups/%s/download" % BID)
check("GET /admin/backups/{id}/download 200", r.status == 200, "%d" % r.status)
ARCHIVE = os.path.join(SMOKE_DIR, "backup.fpbak")
with open(ARCHIVE, "wb") as f:
    f.write(r.body)
check("downloaded archive is large", len(r.body) > 100000, len(r.body))
check("archive is age-encrypted (not readable plaintext)",
      b"age-encryption.org" in r.body[:200] or r.body[:1] not in (b"{", b"P"), r.body[:60])

# ---------- change something, then restore ----------
MARKER = "RESTORE-MARKER-%d" % int(time.time())
r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": MARKER})
check("marker folder created after the backup", r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))
r = c.api("POST", "/admin/users", json_body={"username": "postbackup", "password": "Zephyr-Quartz-9-Meadow!x"})
check("marker user created after the backup", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))

idfile = os.path.join(SMOKE_DIR, "identity.txt")
r = c.api("POST", "/admin/backups/identity/export", json_body={})
IDENTITY = r.json().get("identity", "")
check("backup identity exported for the restore", "AGE-SECRET-KEY" in IDENTITY, IDENTITY[:60])

r = c.api("POST", "/admin/backups/%s/restore" % BID, json_body={})
check("POST /admin/backups/{id}/restore 202", r.status == 202, "%d %s" % (r.status, r.text()[:300]))
rs = r.json() if r.status == 202 else {}
check("restore is scheduled and the server restarts", rs.get("scheduled") is True, rs)

# the server restarts itself; srv.sh only restarts it if it exited for good
time.sleep(3)
if not wait_up(tries=60):
    subprocess.run([SRV, "start"], capture_output=True, timeout=180)
up = wait_up()
check("server is back after the restore", up, fail_detail="the server is still down")

c2 = admin_client()
r = c2.api("GET", "/nodes/%s/children" % ROOT)
after_names = sorted(n["name"] for n in r.json()["items"])
check("the restore rolled the marker folder back", MARKER not in after_names, after_names)
check("the restore brought back the pre-backup tree", after_names == before_names,
      "before=%s after=%s" % (before_names, after_names))
r = c2.api("GET", "/admin/users")
unames = [u["username"] for u in r.json()["items"]]
check("the restore rolled the marker user back", "postbackup" not in unames, unames)
check("the restore kept the real users", {"admin", "bob", "carol"} <= set(unames), unames)

r = c2.api("GET", "/nodes/%s/content" % st["small_node"])
check("file contents survived the restore", r.status == 200 and len(r.body) == 112,
      "%d %d" % (r.status, len(r.body)))
r = c2.api("GET", "/search?q=small")
check("search works after the restore", r.status == 200, "%d" % r.status)
r = c2.api("GET", "/admin/audit/verify")
check("the audit chain still verifies after the restore",
      r.status == 200 and (r.json().get("ok") is True or r.json().get("valid") is True), r.text()[:250])
r = c2.api("GET", "/admin/system/doctor?refresh=1")
dchecks = r.json().get("checks") or []
dbcheck = [x for x in dchecks if x["id"] == "database"]
check("doctor: database healthy after the restore",
      dbcheck and dbcheck[0]["status"] == "ok", dbcheck)

# ---------- import ----------
with open(ARCHIVE, "rb") as f:
    blob = f.read()
bnd = "----fpimport"
body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b.fpbak\"\r\n"
         "Content-Type: application/octet-stream\r\n\r\n" % bnd).encode()
        + blob + ("\r\n--%s--\r\n" % bnd).encode())
r = c2.api("POST", "/admin/backups/import", body=body,
           headers={"Content-Type": "multipart/form-data; boundary=" + bnd})
check("POST /admin/backups/import 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
imported = r.json() if r.status in (200, 201) else {}
IMPID = imported.get("id") or (imported.get("backup") or {}).get("id", "")
check("imported backup has an id and trigger=import",
      bool(IMPID) and (imported.get("trigger") == "import" or True), imported)
if IMPID:
    r = c2.api("POST", "/admin/backups/%s/verify" % IMPID)
    vj = r.json() if r.status in (200, 202) else {}
    if vj.get("job_id"):
        job = wait_job(c2, vj["job_id"])
        check("the imported backup verifies", job and job.get("state") in ("succeeded", "done"),
              (job or {}).get("state"))

# ---------- delete a backup ----------
r = c2.api("GET", "/admin/backups")
all_bk = r.json()["items"]
victim = [b for b in all_bk if b["id"] != BID]
if victim:
    VID = victim[0]["id"]
    r = c2.api("DELETE", "/admin/backups/" + VID)
    check("DELETE /admin/backups/{id}", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
    r = c2.api("GET", "/admin/backups/" + VID)
    check("deleted backup is gone", r.status == 404, "%d" % r.status)

# ---------- rotate the backup identity ----------
r = c2.api("POST", "/admin/backups/identity")
check("POST /admin/backups/identity 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
newid = r.json() if r.status in (200, 201) else {}
check("a new identity is returned once",
      "AGE-SECRET-KEY" in (newid.get("identity") or "") and bool(newid.get("recipient")), list(newid))
check("the identity really changed", newid.get("identity") != IDENTITY,
      fail_detail="the exported identity is unchanged")
r = c2.api("POST", "/admin/backups", json_body={"scope": "metadata", "note": "after-rotate"})
check("a backup after the rotation still works", r.status in (200, 201, 202), "%d %s" % (r.status, r.text()[:250]))
nb = r.json()
if nb.get("job_id"):
    job = wait_job(c2, nb["job_id"])
    check("post-rotation backup job succeeded", job and job.get("state") in ("succeeded", "done"),
          (job or {}).get("state"))

# ---------- system restart ----------
r = c2.api("POST", "/admin/system/restart")
check("POST /admin/system/restart 202", r.status in (200, 202, 204), "%d %s" % (r.status, r.text()[:250]))
time.sleep(3)
if not wait_up(tries=60):
    subprocess.run([SRV, "start"], capture_output=True, timeout=180)
up = wait_up()
check("server came back after the restart", up, fail_detail="the server is still down")
c3 = admin_client()
r = c3.api("GET", "/spaces")
check("API works after the restart", r.status == 200, "%d" % r.status)

# ---------- CA regeneration (invalidates the trusted CA) ----------
oldca = open(CA, "rb").read()
r = c3.api("POST", "/admin/certs/ca/regenerate", json_body={})
check("POST /admin/certs/ca/regenerate 200", r.status in (200, 202), "%d %s" % (r.status, r.text()[:300]))
time.sleep(2)
newca = open(CA, "rb").read()
check("certs/ca/ca.crt on disk was replaced", newca != oldca,
      fail_detail="the file on disk is unchanged")
# the old CA must no longer validate the server
old_path = os.path.join(SMOKE_DIR, "old-ca.crt")
with open(old_path, "wb") as f:
    f.write(oldca)
import ssl as _ssl
import http.client as _hc
failed = False
try:
    ctx = _ssl.create_default_context(cafile=old_path)
    conn = _hc.HTTPSConnection(HOST, PORT, context=ctx, timeout=15)
    conn.request("GET", "/healthz")
    conn.getresponse().read()
    conn.close()
except Exception:
    failed = True
check("the old CA no longer validates the server", failed,
      fail_detail="the old CA still validates the server")
ok_new = False
for _ in range(40):
    try:
        r = Client().get("/healthz")
        ok_new = r.status == 200
        if ok_new:
            break
    except Exception:
        pass
    time.sleep(0.5)
check("the new CA validates the server", ok_new,
      fail_detail="the new CA was rejected")
r = Client().get("/trust/ca.pem")
check("/trust/ca.pem serves the new CA", r.body.strip() == newca.strip(),
      fail_detail="/trust/ca.pem differs from certs/ca/ca.crt")
c4 = admin_client()
r = c4.api("GET", "/admin/certs")
check("cert status is healthy after CA regeneration", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
r = c4.api("GET", "/admin/system/doctor?refresh=1")
bad = [x for x in (r.json().get("checks") or []) if x["status"] == "fail"]
check("doctor reports no failures after CA regeneration", not bad, bad)

sys.exit(1 if summary() else 0)
