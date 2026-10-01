#!/usr/bin/env python3
"""Phase 4: shares - link shares, passwords, max downloads, public pages, file requests."""
import io
import json
import os
import sys
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

st = load_state()
c = admin_client()
SMOKE = st["smoke"]
SMALL_NODE = st["small_node"]
PNG_NODE = st["png_node"]
ROOT = st["root"]

# ---------- create a link share on a folder ----------
r = c.api("POST", "/shares", json_body={"kind": "link", "node_id": SMOKE, "title": "Smoke share"})
check("POST /shares (folder link) 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
sh = r.json() if r.status in (200, 201) else {}
sh = sh.get("share", sh)
SID = sh.get("id", "")
url = sh.get("url", "")
TOK = url.rstrip("/").rsplit("/", 1)[-1] if url else ""
check("share has id + url", bool(SID) and bool(TOK), sh)
check("share defaults allow_download/preview", sh.get("allow_download") and sh.get("allow_preview"), sh)
check("share status active", sh.get("status") == "active", sh.get("status"))

r = c.api("GET", "/shares")
check("GET /shares 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/shares/" + SID)
check("GET /shares/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/shares/%s/qr.svg" % SID)
check("GET /shares/{id}/qr.svg 200", r.status == 200 and r.body.startswith(b"<svg"),
      "%d %s" % (r.status, r.body[:60]))
check("qr.svg content-type", "svg" in (r.header("Content-Type") or ""), r.header("Content-Type"))

# ---------- public access, anonymous ----------
p = Client()
r = p.get("/s/" + TOK)
check("GET /s/{token} page 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("share page is HTML", "text/html" in (r.header("Content-Type") or ""), r.header("Content-Type"))
check("share page has CSP", bool(r.header("Content-Security-Policy")), dict(r.headers))
check("share page X-Frame-Options DENY", r.header("X-Frame-Options") == "DENY", r.header("X-Frame-Options"))
check("share page no template error", "{{" not in r.text() and "<no value>" not in r.text(), r.text()[:200])

r = p.get("/s/" + TOK + "/api")
check("GET /s/{token}/api 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
info = r.json() if r.status == 200 else {}
check("share info hides token hash + password hash",
      "token_hash" not in json.dumps(info) and "password_hash" not in json.dumps(info), list(info))

r = p.get("/s/" + TOK + "/api/list")
check("GET /s/{token}/api/list 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
lst = r.json() if r.status == 200 else {}
entries = lst.get("items") or lst.get("nodes") or []
if isinstance(lst, dict) and not entries:
    for k in lst:
        if isinstance(lst[k], list):
            entries = lst[k]
            break
check("share list has small.txt", any(n.get("name") == "small.txt" for n in entries), str(entries)[:400])
node_id = [n["id"] for n in entries if n.get("name") == "small.txt"]
DL = node_id[0] if node_id else SMALL_NODE

r = p.get("/s/%s/dl/%s" % (TOK, DL))
check("GET /s/{token}/dl/{nodeId} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
SMALLBODY = r.body
check("anon download non-empty", len(SMALLBODY) > 0, len(SMALLBODY))
r = p.request("GET", "/s/%s/dl/%s" % (TOK, DL), headers={"Range": "bytes=0-5"})
check("share download supports Range", r.status == 206 and r.body == SMALLBODY[:6], "%d %r" % (r.status, r.body[:20]))

png_entries = [n["id"] for n in entries if n.get("name") == "pic.png"]
if png_entries:
    r = p.get("/s/%s/thumb/%s" % (TOK, png_entries[0]))
    check("GET /s/{token}/thumb/{nodeId} 200", r.status == 200 and (r.header("Content-Type") or "").startswith("image/"),
          "%d %s" % (r.status, r.header("Content-Type")))

# share zip
r = p.post("/s/%s/api/archive" % TOK, json_body={"node_ids": [DL], "format": "zip"})
check("POST /s/{token}/api/archive 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
at = r.json() if r.status in (200, 201) else {}
zt = at.get("ticket", "")
check("share archive url is /s/<token>/zip/<ticket>", (at.get("url") or "").startswith("/s/%s/zip/" % TOK), at)
r = p.get("/s/%s/zip/%s" % (TOK, zt))
check("GET /s/{token}/zip/{ticket} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
try:
    z = zipfile.ZipFile(io.BytesIO(r.body))
    check("share zip valid", z.testzip() is None, z.namelist())
except Exception as e:
    check("share zip valid", False, e)

# bad token -> generic 404, no oracle
r = Client().get("/s/thistokendoesnotexistatall")
check("unknown share token 404", r.status == 404, "%d" % r.status)
r = Client().get("/s/thistokendoesnotexistatall/api")
check("unknown share api 404", r.status == 404, "%d" % r.status)

# ---------- password protected share ----------
r = c.api("POST", "/shares", json_body={"kind": "link", "node_id": SMALL_NODE,
                                        "title": "pw", "password": "sharepass-xyz-123"})
check("POST /shares with password 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
sp = r.json()
sp = sp.get("share", sp)
PSID = sp["id"]
PTOK = sp["url"].rstrip("/").rsplit("/", 1)[-1]
check("share has_password", sp.get("has_password") is True, sp)

pp = Client()
r = pp.get("/s/" + PTOK)
check("password share page 200 (asks for password)", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = pp.get("/s/%s/api/list" % PTOK)
check("password share list blocked before password", r.status in (401, 403), "%d %s" % (r.status, r.text()[:200]))
r = pp.get("/s/%s/dl/%s" % (PTOK, SMALL_NODE))
check("password share download blocked", r.status in (401, 403, 404), "%d %s" % (r.status, r.text()[:200]))

r = pp.post("/s/%s/api/password" % PTOK, json_body={"password": "wrong"})
check("wrong share password rejected", r.status in (401, 403), "%d %s" % (r.status, r.text()[:200]))
r = pp.post("/s/%s/api/password" % PTOK, json_body={"password": "sharepass-xyz-123"})
check("correct share password 200", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))
cookie_set = any(k.startswith("__Host-fp_s_") for k in pp.cookies)
check("share access cookie __Host-fp_s_*", cookie_set, list(pp.cookies))

r = pp.get("/s/%s/api" % PTOK)
check("password share api after unlock 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = pp.get("/s/%s/dl/%s" % (PTOK, SMALL_NODE))
check("password share download after unlock 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# password change invalidates the cookie (password_version)
r = c.api("PATCH", "/shares/" + PSID, json_body={"password": "new-sharepass-456"})
check("PATCH share password", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
r = pp.get("/s/%s/api/list" % PTOK)
check("old share cookie invalid after password change", r.status in (401, 403), "%d %s" % (r.status, r.text()[:200]))

# remove the password entirely
r = c.api("PATCH", "/shares/" + PSID, json_body={"password": ""})
check("PATCH remove share password", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
check("has_password cleared", r.json().get("share", r.json()).get("has_password") is False, r.text()[:200])
r = Client().get("/s/%s/api" % PTOK)
check("share open after password removed", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# ---------- max downloads ----------
r = c.api("POST", "/shares", json_body={"kind": "link", "node_id": SMALL_NODE,
                                        "title": "limited", "max_downloads": 2})
md = r.json()
md = md.get("share", md)
MTOK = md["url"].rstrip("/").rsplit("/", 1)[-1]
MSID = md["id"]
check("share max_downloads set", md.get("max_downloads") == 2, md.get("max_downloads"))

pm = Client()
for i in (1, 2):
    r = pm.get("/s/%s/dl/%s" % (MTOK, SMALL_NODE))
    check("limited share download %d 200" % i, r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = pm.get("/s/%s/dl/%s" % (MTOK, SMALL_NODE))
check("limited share exhausted after 2", r.status in (403, 404, 410), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/shares/" + MSID)
sj = r.json().get("share", r.json())
check("download_count == 2", sj.get("download_count") == 2, sj.get("download_count"))
check("status exhausted", sj.get("status") == "exhausted", sj.get("status"))

# ---------- expiry / disable ----------
r = c.api("PATCH", "/shares/" + SID, json_body={"disabled": True})
check("PATCH share disabled", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
r = Client().get("/s/%s/api" % TOK)
check("disabled share 404", r.status == 404, "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/shares/" + SID, json_body={"disabled": False})
check("PATCH share re-enabled", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = Client().get("/s/%s/api" % TOK)
check("re-enabled share 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

past = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
r = c.api("PATCH", "/shares/" + SID, json_body={"expires_at": past})
if r.status == 200:
    r2 = Client().get("/s/%s/api" % TOK)
    check("expired share 404", r2.status == 404, "%d %s" % (r2.status, r2.text()[:200]))
    future = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400))
    c.api("PATCH", "/shares/" + SID, json_body={"expires_at": future})
else:
    check("PATCH share expiry in the past", r.status in (200, 422), "%d %s" % (r.status, r.text()[:200]))

# ---------- access log ----------
r = c.api("GET", "/shares/%s/log" % SID)
check("GET /shares/{id}/log 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
logs = r.json().get("items") or []
check("access log records view/download",
      any(l.get("action") in ("view", "download", "zip", "preview") for l in logs), str(logs)[:400])

# ---------- file request (public upload) ----------
r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "Dropbox"})
DROP = r.json()["id"] if r.status in (200, 201) else ""
if not DROP:
    r = c.api("GET", "/nodes/%s/children" % ROOT)
    DROP = [n["id"] for n in r.json()["items"] if n["name"] == "Dropbox"][0]

r = c.api("POST", "/shares", json_body={"kind": "request", "node_id": DROP, "title": "Send me files",
                                        "allow_upload": True, "require_uploader_name": True,
                                        "upload_max_file_bytes": 1 << 20})
check("POST /shares (file request) 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
fr = r.json()
fr = fr.get("share", fr)
FSID = fr["id"]
FTOK = fr["url"].rstrip("/").rsplit("/", 1)[-1]
check("request share kind=request", fr.get("kind") == "request", fr.get("kind"))
check("request share allow_upload", fr.get("allow_upload") is True, fr)

pu = Client()
r = pu.get("/s/" + FTOK)
check("file request page 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = pu.get("/s/%s/api" % FTOK)
check("file request api 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))

DATA = b"uploaded through a public file request\n"
r = pu.post("/s/%s/api/upload-batches" % FTOK, json_body={
    "folder_id": DROP, "mode": "files", "uploader": "Anonymous Tester",
    "files": [{"client_ref": "u1", "rel_path": "from-public.txt", "size": len(DATA), "mime": "text/plain"}]})
check("POST /s/{token}/api/upload-batches 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
ub = r.json() if r.status in (200, 201) else {}
UBID = ub.get("id", "")
check("public batch created", bool(UBID), ub)

r = pu.put("/s/%s/api/upload-batches/%s/small?ref=u1" % (FTOK, UBID), body=DATA,
           headers={"X-FP-SHA256": sha256hex(DATA), "Content-Type": "application/octet-stream"})
check("PUT /s/{token}/api/upload-batches/{id}/small", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
r = pu.post("/s/%s/api/upload-batches/%s/complete" % (FTOK, UBID))
check("POST public batch complete", r.status in (200, 202), "%d %s" % (r.status, r.text()[:300]))
r = pu.get("/s/%s/api/upload-batches/%s" % (FTOK, UBID))
check("GET public batch 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))

r = c.api("GET", "/nodes/%s/children" % DROP)
kids = {n["name"]: n for n in r.json()["items"]}
check("public upload landed in the folder", "from-public.txt" in kids, list(kids))
if "from-public.txt" in kids:
    r = c.api("GET", "/nodes/%s/content" % kids["from-public.txt"]["id"])
    check("public upload content matches", r.body == DATA, r.body[:80])

# a file request must not allow downloading
r = pu.get("/s/%s/api/list" % FTOK)
check("file request listing is not a download portal",
      r.status in (200, 403, 404), "%d %s" % (r.status, r.text()[:200]))

# upload_max_file_bytes enforced
r = pu.post("/s/%s/api/upload-batches" % FTOK, json_body={
    "folder_id": DROP, "mode": "files", "uploader": "T",
    "files": [{"client_ref": "big", "rel_path": "too-big.bin", "size": (2 << 20)}]})
check("file request enforces upload_max_file_bytes", r.status not in (200, 201), "%d %s" % (r.status, r.text()[:250]))

# uploading through a plain link share must be refused
r = Client().post("/s/%s/api/upload-batches" % TOK, json_body={
    "folder_id": SMOKE, "mode": "files",
    "files": [{"client_ref": "x", "rel_path": "evil.txt", "size": 4}]})
check("link share refuses uploads", r.status in (403, 404), "%d %s" % (r.status, r.text()[:200]))

# ---------- POST /share-target ----------
# PWA Web Share Target (DESIGN 13.7): the service worker normally intercepts
# this POST; without it the browser posts here and must land on the upload UI.
bnd = "----fpsmoke"
mp = ("--%s\r\nContent-Disposition: form-data; name=\"files\"; filename=\"a.txt\"\r\n"
      "Content-Type: text/plain\r\n\r\nhello\r\n--%s--\r\n" % (bnd, bnd)).encode()
r = c.post("/share-target", body=mp,
           headers={"Content-Type": "multipart/form-data; boundary=" + bnd})
check("POST /share-target 303", r.status == 303, "%d %s" % (r.status, r.text()[:200]))
check("/share-target redirects to the upload UI",
      (r.header("Location") or "") == "/files?upload=1", r.header("Location"))
r = Client().post("/share-target", body=mp,
                  headers={"Content-Type": "multipart/form-data; boundary=" + bnd,
                           "Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
check("/share-target blocks cross-site POST", r.status == 403, "%d %s" % (r.status, r.text()[:200]))

# ---------- admin view + revoke ----------
r = c.api("GET", "/admin/shares")
check("GET /admin/shares 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("admin sees shares", len(r.json().get("items") or []) >= 3, len(r.json().get("items") or []))

r = c.api("DELETE", "/shares/" + MSID)
check("DELETE /shares/{id} 204", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = Client().get("/s/%s/api" % MTOK)
check("revoked share 404", r.status == 404, "%d" % r.status)

# other users must not touch my share
cbob = login("bob", st["bob_pw"])
r = cbob.api("GET", "/shares/" + SID)
check("other user cannot read my share", r.status in (403, 404), "%d %s" % (r.status, r.text()[:200]))
r = cbob.api("DELETE", "/shares/" + SID)
check("other user cannot revoke my share", r.status in (403, 404), "%d %s" % (r.status, r.text()[:200]))

st.update({"share_id": SID, "share_token": TOK, "request_token": FTOK, "drop": DROP})
save_state(st)
sys.exit(1 if summary() else 0)
