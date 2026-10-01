#!/usr/bin/env python3
"""Phase 9: the §9.4 routes the earlier phases had not reached."""
import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

st = load_state()
c = admin_client()
ROOT = st["root"]
me = c.api("GET", "/me").json()
UID = me["user"]["id"]

# ---------- /me: profile, tokens, sessions, recovery codes ----------
r = c.api("PATCH", "/me/profile", json_body={"display_name": "Admin (smoke)"})
check("PATCH /me/profile 200", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
r = c.api("GET", "/me")
check("profile change applied", (r.json().get("user") or {}).get("display_name") == "Admin (smoke)",
      r.text()[:200])
# a profile update must not be able to smuggle a role or quota change
r = c.api("PATCH", "/me/profile", json_body={"role": "owner"})
check("PATCH /me/profile rejects unknown fields (no role smuggling)",
      r.status == 422, "%d %s" % (r.status, r.text()[:200]))
c.api("PATCH", "/me/profile", json_body={"display_name": "admin"})

r = c.api("POST", "/me/tokens", json_body={"name": "to-revoke", "scopes": ["files:read"]})
check("POST /me/tokens (scoped) 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
tb = r.json()
TID = tb["token"]["id"]
TSEC = tb["secret"]
ct = Client(token=TSEC)
r = ct.api("GET", "/spaces")
check("files:read token can read", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = ct.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "scope-test"})
check("files:read token cannot write", r.status == 403, "%d %s" % (r.status, r.text()[:200]))
r = ct.api("GET", "/admin/users")
check("files:read token cannot reach admin", r.status == 403, "%d %s" % (r.status, r.text()[:200]))

r = c.api("DELETE", "/me/tokens/" + TID)
check("DELETE /me/tokens/{id} 204", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = ct.api("GET", "/spaces")
check("revoked token stops working", r.status == 401, "%d %s" % (r.status, r.text()[:200]))

# sessions
extra = login("admin", st["password"], st.get("totp_secret"), elevate=False)
r = c.api("GET", "/me/sessions")
check("GET /me/sessions lists more than one", len(r.json().get("items") or []) >= 2,
      len(r.json().get("items") or []))
sess = r.json()["items"]
mine = [s for s in sess if s.get("current")]
other = [s for s in sess if not s.get("current")]
check("one session is marked current", len(mine) == 1, [s.get("current") for s in sess])
if other:
    r = c.api("DELETE", "/me/sessions/" + other[0]["id"])
    check("DELETE /me/sessions/{id} 204", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))

extra2 = login("admin", st["password"], st.get("totp_secret"), elevate=False)
r = c.api("POST", "/me/sessions/revoke-others")
check("POST /me/sessions/revoke-others", r.status in (200, 204), "%d %s" % (r.status, r.text()[:250]))
r = extra2.api("GET", "/me")
check("the other session is gone", r.status == 401, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/me")
check("my own session survived revoke-others", r.status == 200, "%d" % r.status)

r = c.api("POST", "/me/recovery-codes")
check("POST /me/recovery-codes 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
first = r.json().get("recovery_codes") or []
check("a fresh set of recovery codes", len(first) >= 5, len(first))
r = c.api("POST", "/me/recovery-codes")
newcodes = r.json().get("recovery_codes") or []
check("regenerating gives a different set", set(newcodes) & set(first) == set(), (first[:2], newcodes[:2]))
old = first[0]
cx = Client()
r = cx.api("POST", "/auth/login", json_body={"username": "admin", "password": st["password"]})
cx.csrf = r.json().get("csrf")
r = cx.api("POST", "/auth/recovery", json_body={"code": old})
check("regenerating invalidates the old recovery codes", r.status != 200, "%d %s" % (r.status, r.text()[:200]))
r = cx.api("POST", "/auth/recovery", json_body={"code": newcodes[0]})
check("a new recovery code works", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
st["recovery_codes"] = newcodes
save_state(st)

# passkeys: no real authenticator here (no ECDSA in the stdlib), so pin the
# error paths of the routes instead of a successful registration.
r = c.api("POST", "/me/passkeys/finish", json_body={"flow_id": "bogus", "credential": {"id": "x"}})
check("POST /me/passkeys/finish bad flow is a clean 4xx", 400 <= r.status < 500,
      "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/me/passkeys/pky_nosuchpasskey", json_body={"name": "x"})
check("PATCH /me/passkeys/{id} unknown 404", r.status == 404, "%d %s" % (r.status, r.text()[:200]))
r = c.api("DELETE", "/me/passkeys/pky_nosuchpasskey")
check("DELETE /me/passkeys/{id} unknown 404", r.status == 404, "%d %s" % (r.status, r.text()[:200]))

# ---------- client certs: admin + self-service ----------
r = c.api("POST", "/admin/client-certs", json_body={"user_id": UID, "name": "smoke-p12", "days": 30})
check("POST /admin/client-certs 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
cc = r.json()
check("issue response is ClientCertIssued",
      set(["client_cert", "p12", "password", "filename", "download_url"]) <= set(cc), list(cc))
p12 = base64.b64decode(cc["p12"])
check("inline p12 is a PKCS#12 SEQUENCE", p12[:1] == b"\x30" and len(p12) > 500, len(p12))
check("filename ends .p12", cc["filename"].endswith(".p12"), cc["filename"])
r = c.get(cc["download_url"])
check("GET /admin/client-certs/download?ticket= 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("downloaded p12 matches the inline one", r.body == p12, "%d vs %d" % (len(r.body), len(p12)))
r = c.get(cc["download_url"])
check("client-cert ticket is single use", r.status != 200, "%d" % r.status)
r = c.get("/api/v1/admin/client-certs/download?ticket=deadbeef")
check("unknown client-cert ticket 404", r.status in (403, 404), "%d" % r.status)

CID = cc["client_cert"]["id"]
r = c.api("GET", "/admin/client-certs")
check("issued cert is listed", any(x["id"] == CID for x in r.json()["items"]), r.text()[:250])

# self-service, gated by mtls.self_service
r = c.api("POST", "/me/client-certs", json_body={"name": "self", "days": 30})
check("self-service off -> POST /me/client-certs refused", r.status == 403, "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/admin/settings", json_body={"mtls.self_service": True})
check("enable mtls.self_service", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("POST", "/me/client-certs", json_body={"name": "self", "days": 30})
check("self-service on -> POST /me/client-certs 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
sc = r.json() if r.status in (200, 201) else {}
if sc.get("download_url"):
    r = c.get(sc["download_url"])
    check("GET /me/client-certs/download?ticket= 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    check("self-service p12 is a PKCS#12", r.body[:1] == b"\x30", r.body[:8])
    r = c.api("DELETE", "/me/client-certs/" + sc["client_cert"]["id"])
    check("DELETE /me/client-certs/{id}", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
c.api("PATCH", "/admin/settings", json_body={"mtls.self_service": False})

r = c.api("DELETE", "/admin/client-certs/" + CID)
check("DELETE /admin/client-certs/{id}", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/client-certs")
revoked = [x for x in r.json()["items"] if x["id"] == CID]
check("revoked cert is gone or marked revoked",
      not revoked or revoked[0].get("revoked_at"), r.text()[:250])

# ---------- upload: add files to an open batch, abort one file ----------
r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "Phase9-%d" % int(time.time())})
P9 = r.json()["id"]
A = b"batch add file A\n"
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": P9, "mode": "files",
    "files": [{"client_ref": "a", "rel_path": "a.txt", "size": len(A)}]})
bid = r.json()["id"]
B = b"batch add file B, added later\n"
r = c.api("POST", "/upload-batches/%s/files" % bid,
          json_body=[{"client_ref": "b", "rel_path": "b.txt", "size": len(B)},
                     {"client_ref": "d", "rel_path": "sub/dir", "size": 0, "kind": "dir"}])
check("POST /upload-batches/{id}/files 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
added = r.json()
added = added["items"] if isinstance(added, dict) else added
check("added files come back as states", len(added) == 2, added)

for ref, data in [("a", A), ("b", B)]:
    r = c.api("PUT", "/upload-batches/%s/small?ref=%s" % (bid, ref), body=data,
              headers={"X-FP-SHA256": sha256hex(data), "Content-Type": "application/octet-stream"})
    check("small upload %s" % ref, r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))
r = c.api("POST", "/upload-batches/%s/complete" % bid)
check("batch with added files completes", r.status in (200, 202), "%d %s" % (r.status, r.text()[:250]))
r = c.api("GET", "/nodes/%s/children" % P9)
names = {n["name"] for n in r.json()["items"]}
check("both files and the declared directory exist", {"a.txt", "b.txt", "sub"} <= names, names)

# abort a single file of a batch
BIGGER = b"x" * (12 << 20)
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": P9, "mode": "files",
    "files": [{"client_ref": "big", "rel_path": "abortme.bin", "size": len(BIGGER)}]})
ab = r.json()
upid = ab["files"][0]["id"]
part = BIGGER[:ab["part_size"]]
r = c.api("PUT", "/uploads/%s/parts/0" % upid, body=part,
          headers={"X-FP-SHA256": sha256hex(part), "Content-Type": "application/octet-stream"})
check("part uploaded before abort", r.status == 204, "%d %s" % (r.status, r.text()[:200]))
r = c.api("DELETE", "/uploads/" + upid)
check("DELETE /uploads/{id} 204", r.status == 204, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/uploads/" + upid)
check("aborted upload reports aborted", r.status != 200 or r.json().get("state") == "aborted",
      "%d %s" % (r.status, r.text()[:200]))
c.api("DELETE", "/upload-batches/" + ab["id"])

# ---------- file-request multipart upload (the /s/ upload routes) ----------
FTOK = st["request_token"]
DROP = st["drop"]
# phase 4 capped this request at 1 MiB (and proved the cap); raise it so the
# multipart path can be exercised, then put it back.
r = c.api("GET", "/shares")
reqs = [x for x in (r.json().get("items") or []) if x.get("kind") == "request"]
FSID = reqs[0]["id"] if reqs else ""
r = c.api("PATCH", "/shares/" + FSID, json_body={"upload_max_file_bytes": 64 << 20})
check("raise the file request upload limit", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
pu = Client()
DATA = bytes((i * 17 + 3) & 0xFF for i in range(int(9 << 20)))
r = pu.post("/s/%s/api/upload-batches" % FTOK, json_body={
    "folder_id": DROP, "mode": "files", "uploader": "Multipart Tester",
    "files": [{"client_ref": "m0", "rel_path": "seed.txt", "size": 4}]})
check("POST /s/{token}/api/upload-batches 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
sb = r.json()
SBID = sb["id"]
r = pu.post("/s/%s/api/upload-batches/%s/files" % (FTOK, SBID),
            json_body=[{"client_ref": "m1", "rel_path": "multipart.bin", "size": len(DATA)}])
check("POST /s/{token}/api/upload-batches/{id}/files", r.status in (200, 201),
      "%d %s" % (r.status, r.text()[:300]))
adds = r.json()
adds = adds["items"] if isinstance(adds, dict) else adds
SUID = adds[0]["id"]
nparts = adds[0]["part_count"]
PS = sb["part_size"]
check("share upload declares parts", nparts == (len(DATA) + PS - 1) // PS, "%d" % nparts)

for n in range(nparts):
    chunk = DATA[n * PS:(n + 1) * PS]
    r = pu.put("/s/%s/api/uploads/%s/parts/%d" % (FTOK, SUID, n), body=chunk,
               headers={"X-FP-SHA256": sha256hex(chunk), "Content-Type": "application/octet-stream"})
    if r.status != 204:
        check("PUT /s/{token}/api/uploads/{id}/parts/%d" % n, False, "%d %s" % (r.status, r.text()[:250]))
        break
else:
    check("PUT /s/{token}/api/uploads/{id}/parts/{n} (all %d)" % nparts, True)

r = pu.get("/s/%s/api/uploads/%s" % (FTOK, SUID))
check("GET /s/{token}/api/uploads/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
check("share upload parts_done complete", sorted(r.json().get("parts_done") or []) == list(range(nparts)),
      r.text()[:250])
r = pu.post("/s/%s/api/uploads/%s/complete" % (FTOK, SUID))
check("POST /s/{token}/api/uploads/{id}/complete", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
seed = b"seed"
r = pu.put("/s/%s/api/upload-batches/%s/small?ref=m0" % (FTOK, SBID), body=seed,
           headers={"X-FP-SHA256": sha256hex(seed), "Content-Type": "application/octet-stream"})
r = pu.post("/s/%s/api/upload-batches/%s/complete" % (FTOK, SBID))
check("public multipart batch completes", r.status in (200, 202), "%d %s" % (r.status, r.text()[:250]))

r = c.api("GET", "/nodes/%s/children" % DROP)
kids = {n["name"]: n for n in r.json()["items"]}
check("multipart file landed through the share", "multipart.bin" in kids, list(kids))
if "multipart.bin" in kids:
    r = c.api("GET", "/nodes/%s/content" % kids["multipart.bin"]["id"])
    check("multipart share upload bytes match", sha256hex(r.body) == sha256hex(DATA),
          "%d %d bytes" % (r.status, len(r.body)))

# abort paths on the share routes
r = pu.post("/s/%s/api/upload-batches" % FTOK, json_body={
    "folder_id": DROP, "mode": "files", "uploader": "T",
    "files": [{"client_ref": "z", "rel_path": "abort2.bin", "size": (9 << 20)}]})
ab2 = r.json()
r = pu.delete("/s/%s/api/uploads/%s" % (FTOK, ab2["files"][0]["id"]))
check("DELETE /s/{token}/api/uploads/{id} 204", r.status == 204, "%d %s" % (r.status, r.text()[:200]))
r = pu.delete("/s/%s/api/upload-batches/%s" % (FTOK, ab2["id"]))
check("DELETE /s/{token}/api/upload-batches/{id} 204", r.status == 204, "%d %s" % (r.status, r.text()[:200]))

r = c.api("PATCH", "/shares/" + FSID, json_body={"upload_max_file_bytes": 1 << 20})
check("file request upload limit restored", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# ---------- email test endpoint (C-3) ----------
import socket as _socket
import subprocess as _sub

# With no smtp.host at all every input is 503 "not configured" -- the
# availability answer is the useful one, and it comes before validation.
r = c.api("POST", "/admin/settings/email/test", json_body={"to": "not-an-address"})
check("email test with no SMTP -> 503 not configured",
      r.status == 503 and "not configured" in r.text(), "%d %s" % (r.status, r.text()[:250]))
r = c.api("POST", "/admin/settings/email/test", json_body={"to": ""})
check("email test with an empty address -> 422", r.status == 422, "%d %s" % (r.status, r.text()[:250]))

# Point SMTP at a closed port: configured, but delivery fails -> 503 with the
# SMTP error; and now a bad address is a 422 as documented.
sk = _socket.socket()
sk.bind(("127.0.0.1", 0))
DEADPORT = sk.getsockname()[1]
sk.close()
r = c.api("PATCH", "/admin/settings", json_body={
    "smtp.host": "127.0.0.1", "smtp.port": DEADPORT, "smtp.tls": "none",
    "smtp.from": "fileparcel@example.org"})
check("configure SMTP (dead port)", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
r = c.api("POST", "/admin/settings/email/test", json_body={"to": "not-an-address"})
check("configured SMTP + bad address -> 422", r.status == 422, "%d %s" % (r.status, r.text()[:250]))
r = c.api("POST", "/admin/settings/email/test", json_body={"to": "someone@example.org"})
check("configured SMTP + dead server -> 503 carrying the SMTP error",
      r.status == 503 and "test e-mail" in r.text(), "%d %s" % (r.status, r.text()[:250]))

# Now a real sink: the test message must actually arrive.
sk = _socket.socket()
sk.bind(("127.0.0.1", 0))
SMTPPORT = sk.getsockname()[1]
sk.close()
# The mailbox is scratch output: it belongs in FP_SMOKE_DIR, not in the repo.
MBOX = os.path.join(SMOKE_DIR, "mbox.txt")
if os.path.exists(MBOX):
    os.remove(MBOX)
sink = _sub.Popen([sys.executable, os.path.join(SCRIPTS, "smtpsink.py"), str(SMTPPORT), MBOX],
                  stdout=_sub.DEVNULL, stderr=_sub.DEVNULL)
try:
    time.sleep(1.0)
    r = c.api("PATCH", "/admin/settings", json_body={"smtp.port": SMTPPORT})
    check("point SMTP at the sink", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    r = c.api("POST", "/admin/settings/email/test", json_body={"to": "admin@example.org"})
    check("POST /admin/settings/email/test 204", r.status == 204, "%d %s" % (r.status, r.text()[:300]))
    got = ""
    for _ in range(40):
        if os.path.exists(MBOX):
            got = open(MBOX, errors="replace").read()
            if "--- END ---" in got:
                break
        time.sleep(0.25)
    check("the test e-mail really arrived at the SMTP server", "--- END ---" in got, got[:200])
    check("it is addressed to the given recipient", "admin@example.org" in got, got[:400])
    check("it carries a Subject", "Subject:" in got, got[:400])

    # an invite with send=true must reach the same sink
    before = len(got)
    r = c.api("POST", "/admin/invites",
              json_body={"email": "invitee@example.org", "role": "member", "send": True})
    check("POST /admin/invites with send=true", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
    got2 = ""
    for _ in range(40):
        got2 = open(MBOX, errors="replace").read() if os.path.exists(MBOX) else ""
        if "invitee@example.org" in got2:
            break
        time.sleep(0.25)
    check("the invitation e-mail was delivered", "invitee@example.org" in got2, got2[-400:])
finally:
    sink.terminate()
    try:
        sink.wait(timeout=10)
    except Exception:
        sink.kill()
    for k in ("smtp.host", "smtp.port", "smtp.tls", "smtp.from"):
        c.api("DELETE", "/admin/settings/" + k)
r = c.api("POST", "/admin/settings/email/test", json_body={"to": "a@b.example"})
check("SMTP settings reset -> 503 again", r.status == 503, "%d %s" % (r.status, r.text()[:200]))

# ---------- setup is closed ----------
r = Client().api("POST", "/auth/setup",
                 json_body={"setup_token": "x", "username": "intruder", "password": "Whatever-12345!"})
check("POST /auth/setup is closed after the owner exists", r.status in (403, 404, 409),
      "%d %s" % (r.status, r.text()[:250]))
r = Client().api("GET", "/auth/state")
check("auth state still says setup_needed=false", r.json().get("setup_needed") is False, r.text()[:200])

# ---------- keys passphrase change (sealed mode only) ----------
r = c.api("POST", "/admin/keys/passphrase",
          json_body={"current_passphrase": "a", "new_passphrase": "b-long-enough-passphrase"})
check("passphrase change refused in plain mode (412)", r.status == 412,
      "%d %s" % (r.status, r.text()[:250]))

# ---------- DELETE /me/totp: disable the second factor, then re-enrol ----------
r = c.api("GET", "/me/mfa")
check("TOTP is enabled before the disable test", r.json().get("totp_enabled") is True, r.text()[:200])
r = c.api("DELETE", "/me/totp")
check("DELETE /me/totp", r.status in (200, 204), "%d %s" % (r.status, r.text()[:250]))
r = c.api("GET", "/me/mfa")
check("TOTP is disabled", r.json().get("totp_enabled") is False, r.text()[:250])

cnf = Client()
r = cnf.api("POST", "/auth/login", json_body={"username": "admin", "password": st["password"]})
check("login no longer asks for TOTP", r.status == 200 and not r.json().get("mfa_required"),
      "%d %s" % (r.status, r.text()[:250]))
cnf.csrf = r.json().get("csrf")
enroll_required = r.json().get("enroll_required")
check("but auth.require_2fa still asks the owner to enrol",
      enroll_required is True, r.json())

# re-enrol so the rest of the suite (and the operator) keeps a second factor
# (setting up an authenticator app needs step-up)
r = c.api("POST", "/auth/elevate", json_body={"password": st["password"]})
if r.status == 200 and r.json().get("csrf"):
    c.csrf = r.json()["csrf"]
r = c.api("POST", "/me/totp/begin", json_body={})
check("re-enrolment begins", r.status == 200, "%d %s" % (r.status, r.text()[:250]))
secret = r.json()["secret"]
check("re-enrolment issues a new secret", secret != st.get("totp_secret"),
      fail_detail="the same secret was handed out again")
for _ in range(3):
    r = c.api("POST", "/me/totp/confirm", json_body={"code": totp_code(secret)})
    if r.status in (200, 201):
        break
    time.sleep(31)
check("re-enrolment confirmed", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
st["totp_secret"] = secret
st["recovery_codes"] = r.json().get("recovery_codes") or st.get("recovery_codes")
save_state(st)
r = admin_client().api("GET", "/me/mfa")
check("TOTP is back on and login still works", r.json().get("totp_enabled") is True, r.text()[:250])

sys.exit(1 if summary() else 0)
