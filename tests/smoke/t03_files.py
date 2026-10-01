#!/usr/bin/env python3
"""Phase 3: spaces, nodes, uploads, content, thumbs, archives, versions, grants."""
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import time
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

st = load_state()
c = admin_client()


def wait_job(client, job_id, timeout=60):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        r = client.api("GET", "/jobs/" + job_id)
        if r.status != 200:
            return None, "GET /jobs/%s -> %d %s" % (job_id, r.status, r.text()[:200])
        last = r.json()
        if last.get("state") in ("done", "failed", "cancelled", "succeeded"):
            return last, ""
        time.sleep(0.3)
    return last, "timeout"


# ---------- spaces ----------
r = c.api("GET", "/spaces")
check("GET /spaces 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
spaces = r.json()
spaces = spaces["items"] if isinstance(spaces, dict) else spaces
mine = [s for s in spaces if s.get("kind") == "user"]
check("personal space present", len(mine) == 1, str(spaces)[:400])
ROOT = mine[0]["root_id"] if mine else ""
SPACE = mine[0]["id"] if mine else ""
check("space has root_id", bool(ROOT), mine[0] if mine else None)

r = c.api("GET", "/nodes/" + ROOT)
check("GET /nodes/{root} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/nodes/%s/children" % ROOT)
check("GET /nodes/{id}/children 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/nodes/%s/breadcrumbs" % ROOT)
check("GET /nodes/{id}/breadcrumbs 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# ---------- clean the personal space (re-runnable) ----------
r = c.api("GET", "/nodes/%s/children" % ROOT)
ids = [n["id"] for n in (r.json().get("items") or [])]
if ids:
    c.api("POST", "/nodes/trash", json_body={"ids": ids})
c.api("DELETE", "/trash")

# ---------- mkdir ----------
r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "Smoke"})
check("POST mkdir 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
SMOKE = r.json().get("id", "") if r.status in (200, 201) else ""
check("mkdir returns node id", bool(SMOKE), r.text()[:200])

r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "Smoke"})
check("mkdir duplicate name conflict", r.status == 409, "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/nodes/%s/folders" % SMOKE, json_body={"name": "sub"})
SUB = r.json().get("id", "") if r.status in (200, 201) else ""
check("mkdir nested", bool(SUB), r.text()[:200])

for bad in ["", ".", "..", "a/b", "a\x00b"]:
    r = c.api("POST", "/nodes/%s/folders" % SMOKE, json_body={"name": bad})
    check("mkdir rejects name %r" % bad, r.status in (400, 422), "%d %s" % (r.status, r.text()[:150]))

# ---------- uploads: small path ----------
SMALL = b"hello fileparcel small path\n" * 4
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": SMOKE, "mode": "files",
    "files": [{"client_ref": "s1", "rel_path": "small.txt", "size": len(SMALL), "mime": "text/plain"}]})
check("POST /upload-batches (small) 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
b = r.json() if r.status in (200, 201) else {}
BID = b.get("id", "")
check("batch has protocol params", b.get("part_size", 0) > 0 and b.get("small_max", 0) > 0, b)

# bad sha rejected
r = c.api("PUT", "/upload-batches/%s/small?ref=s1" % BID, body=SMALL,
          headers={"X-FP-SHA256": "00" * 32, "Content-Type": "application/octet-stream"})
check("small upload wrong sha rejected", r.status in (400, 409, 422), "%d %s" % (r.status, r.text()[:200]))
r = c.api("PUT", "/upload-batches/%s/small?ref=s1" % BID, body=SMALL,
          headers={"X-FP-SHA256": "zz", "Content-Type": "application/octet-stream"})
check("small upload malformed sha 422", r.status == 422, "%d %s" % (r.status, r.text()[:200]))

r = c.api("PUT", "/upload-batches/%s/small?ref=s1" % BID, body=SMALL,
          headers={"X-FP-SHA256": sha256hex(SMALL), "Content-Type": "application/octet-stream"})
check("PUT small upload 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
check("small upload state uploaded", r.json().get("state") in ("uploaded", "committed"), r.text()[:200])

r = c.api("POST", "/upload-batches/%s/complete" % BID)
check("POST batch complete 200", r.status in (200, 202), "%d %s" % (r.status, r.text()[:300]))
bb = r.json()
check("batch done", bb.get("state") == "done", bb.get("state"))
r = c.api("GET", "/upload-batches/" + BID)
bg = r.json() if r.status == 200 else {}
check("GET batch after complete carries files", bool(bg.get("files")), bg)
SMALL_NODE = ""
for f in (bg.get("files") or []):
    if f["client_ref"] == "s1":
        SMALL_NODE = f.get("node_id", "")
check("small file committed to a node", bool(SMALL_NODE), bg.get("files"))

# ---------- uploads: multipart ----------
r = c.api("GET", "/upload-batches/" + BID)
check("GET /upload-batches/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
PART = r.json().get("part_size", 8 << 20)

BIG = bytes((i * 31 + 7) & 0xFF for i in range(int(PART * 2 + 12345)))
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": SMOKE, "mode": "files",
    "files": [{"client_ref": "b1", "rel_path": "deep/dir/big.bin", "size": len(BIG),
               "mime": "application/octet-stream", "mtime": 1700000000000}]})
check("POST /upload-batches (big) 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
b2 = r.json()
BID2 = b2["id"]
fstate = b2["files"][0]
UID = fstate["id"]
nparts = fstate["part_count"]
check("part_count computed", nparts == (len(BIG) + PART - 1) // PART, "%d vs %d" % (nparts, len(BIG)))

# wrong part sha
p0 = BIG[:PART]
r = c.api("PUT", "/uploads/%s/parts/0" % UID, body=p0,
          headers={"X-FP-SHA256": "11" * 32, "Content-Type": "application/octet-stream"})
check("part wrong sha rejected", r.status in (400, 409, 422), "%d %s" % (r.status, r.text()[:200]))

for n in range(nparts):
    chunk = BIG[n * PART:(n + 1) * PART]
    r = c.api("PUT", "/uploads/%s/parts/%d" % (UID, n), body=chunk,
              headers={"X-FP-SHA256": sha256hex(chunk), "Content-Type": "application/octet-stream"})
    if r.status not in (200, 204):
        check("PUT part %d" % n, False, "%d %s" % (r.status, r.text()[:300]))
        break
else:
    check("PUT all %d parts 204" % nparts, True)

r = c.api("GET", "/uploads/" + UID)
check("GET /uploads/{id} parts_done 0-based", r.status == 200 and
      sorted(r.json().get("parts_done") or []) == list(range(nparts)), "%d %s" % (r.status, r.text()[:250]))
check("part numbers out of range rejected",
      c.api("PUT", "/uploads/%s/parts/%d" % (UID, nparts), body=b"x",
            headers={"X-FP-SHA256": sha256hex(b"x")}).status == 422, "")
last = BIG[(nparts - 1) * PART:]
r = c.api("PUT", "/uploads/%s/parts/%d" % (UID, nparts - 1), body=last,
          headers={"X-FP-SHA256": sha256hex(last), "Content-Type": "application/octet-stream"})
check("re-send same part same digest 204 (idempotent)", r.status == 204, "%d %s" % (r.status, r.text()[:200]))
r = c.api("PUT", "/uploads/%s/parts/%d" % (UID, nparts - 1), body=last,
          headers={"X-FP-SHA256": sha256hex(last + b"x"), "Content-Type": "application/octet-stream"})
check("re-send same part different digest 409", r.status == 409, "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/uploads/%s/complete" % UID)
check("POST /uploads/{id}/complete", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
r = c.api("POST", "/upload-batches/%s/complete" % BID2)
check("POST batch2 complete", r.status in (200, 202), "%d %s" % (r.status, r.text()[:300]))
check("nested rel_path batch done", r.json().get("state") == "done", r.json().get("state"))
bb2 = c.api("GET", "/upload-batches/" + BID2).json()
BIG_NODE = (bb2.get("files") or [{}])[0].get("node_id", "")
check("big file committed", bool(BIG_NODE), bb2.get("files"))

# the intermediate folders exist
r = c.api("GET", "/nodes/%s/children" % SMOKE)
kids = {n["name"]: n for n in r.json()["items"]}
check("rel_path made 'deep' folder", "deep" in kids, list(kids))

# ---------- abort paths ----------
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": SMOKE, "mode": "files",
    "files": [{"client_ref": "x", "rel_path": "abort.bin", "size": 1024}]})
ab = r.json()
r = c.api("DELETE", "/upload-batches/" + ab["id"])
check("DELETE /upload-batches/{id} 204", r.status == 204, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/upload-batches/" + ab["id"])
check("aborted batch state", r.status != 200 or r.json().get("state") == "aborted",
      "%d %s" % (r.status, r.text()[:200]))

# ---------- content download ----------
r = c.api("GET", "/nodes/%s/content" % SMALL_NODE)
check("GET content 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("content bytes match", r.body == SMALL, "%d bytes" % len(r.body))
etag = r.header("ETag")
check("content has ETag", bool(etag), dict(r.headers))
check("content-type", (r.header("Content-Type") or "").startswith("text/plain"), r.header("Content-Type"))
check("content-disposition", "small.txt" in (r.header("Content-Disposition") or ""), r.header("Content-Disposition"))

r = c.api("HEAD", "/nodes/%s/content" % SMALL_NODE)
check("HEAD content 200", r.status == 200, "%d" % r.status)
check("HEAD content-length", r.header("Content-Length") == str(len(SMALL)), r.header("Content-Length"))
check("HEAD has no body", len(r.body) == 0, len(r.body))
check("HEAD accept-ranges", (r.header("Accept-Ranges") or "") == "bytes", r.header("Accept-Ranges"))

r = c.api("GET", "/nodes/%s/content" % SMALL_NODE, headers={"Range": "bytes=6-19"})
check("Range 206", r.status == 206, "%d %s" % (r.status, r.text()[:200]))
check("Range bytes", r.body == SMALL[6:20], r.body)
check("Content-Range", r.header("Content-Range") == "bytes 6-19/%d" % len(SMALL), r.header("Content-Range"))

r = c.api("GET", "/nodes/%s/content" % SMALL_NODE, headers={"Range": "bytes=-10"})
check("suffix Range 206", r.status == 206 and r.body == SMALL[-10:], "%d %r" % (r.status, r.body[:40]))
r = c.api("GET", "/nodes/%s/content" % SMALL_NODE, headers={"Range": "bytes=%d-" % (len(SMALL) + 99)})
check("unsatisfiable Range 416", r.status == 416, "%d" % r.status)

r = c.api("GET", "/nodes/%s/content" % SMALL_NODE, headers={"If-None-Match": etag})
check("If-None-Match 304", r.status == 304, "%d" % r.status)

# big file range across parts
r = c.api("GET", "/nodes/%s/content" % BIG_NODE, headers={"Range": "bytes=%d-%d" % (PART - 5, PART + 4)})
check("big file cross-part Range", r.status == 206 and r.body == BIG[PART - 5:PART + 5],
      "%d %r" % (r.status, r.body[:40]))
r = c.api("GET", "/nodes/%s/content" % BIG_NODE)
check("big file full download matches", r.status == 200 and hashlib.sha256(r.body).hexdigest() == sha256hex(BIG),
      "%d %d bytes" % (r.status, len(r.body)))

# ---------- thumbnails (PNG) ----------
def png(w, h):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes([(x * 7 + y * 3) % 256, (x * 5) % 256, (y * 11) % 256]) * 1
                   for y in range(h) for x in range(w))
    rows = b"".join(b"\x00" + b"".join(bytes([(x * 7 + y * 3) % 256, (x * 5) % 256, (y * 11) % 256])
                                       for x in range(w)) for y in range(h))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows))
            + chunk(b"IEND", b""))


PNG = png(320, 200)
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": SMOKE, "mode": "files",
    "files": [{"client_ref": "p", "rel_path": "pic.png", "size": len(PNG), "mime": "image/png"}]})
pb = r.json()
r = c.api("PUT", "/upload-batches/%s/small?ref=p" % pb["id"], body=PNG,
          headers={"X-FP-SHA256": sha256hex(PNG), "Content-Type": "application/octet-stream"})
check("png small upload", r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))
c.api("POST", "/upload-batches/%s/complete" % pb["id"])
r = c.api("GET", "/upload-batches/" + pb["id"])
PNG_NODE = (r.json().get("files") or [{}])[0].get("node_id", "")
check("png committed", bool(PNG_NODE), r.text()[:300])

thumb_ok = False
for _ in range(80):
    r = c.api("GET", "/nodes/%s/thumb" % PNG_NODE)
    if r.status == 200:
        thumb_ok = True
        break
    time.sleep(0.25)
check("GET /nodes/{id}/thumb 200", thumb_ok, "%d %s" % (r.status, r.text()[:200]))
if thumb_ok:
    check("thumb is an image", (r.header("Content-Type") or "").startswith("image/"), r.header("Content-Type"))
    check("thumb non-empty + smaller than source", 0 < len(r.body) < len(PNG),
          "%d vs %d" % (len(r.body), len(PNG)))
    r2 = c.api("GET", "/nodes/%s" % PNG_NODE)
    check("node reports has_thumb", r2.json().get("has_thumb") is True, r2.text()[:300])

# text file has no thumbnail
r = c.api("GET", "/nodes/%s/thumb" % SMALL_NODE)
check("thumb of a text file 404", r.status == 404, "%d" % r.status)

# ---------- versions ----------
V2 = b"second version of small.txt\n"
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": SMOKE, "mode": "files", "conflict": "replace",
    "files": [{"client_ref": "s1v2", "rel_path": "small.txt", "size": len(V2), "mime": "text/plain"}]})
check("POST batch conflict=replace", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
vb = r.json()
r = c.api("PUT", "/upload-batches/%s/small?ref=s1v2" % vb["id"], body=V2,
          headers={"X-FP-SHA256": sha256hex(V2), "Content-Type": "application/octet-stream"})
check("v2 uploaded", r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))
r = c.api("POST", "/upload-batches/%s/complete" % vb["id"])
check("v2 batch complete", r.status in (200, 202), "%d %s" % (r.status, r.text()[:300]))
v2node = (c.api("GET", "/upload-batches/" + vb["id"]).json().get("files") or [{}])[0].get("node_id", "")
check("version replaced the same node", v2node == SMALL_NODE, "%s vs %s" % (v2node, SMALL_NODE))

r = c.api("GET", "/nodes/%s/content" % SMALL_NODE)
check("content now v2", r.body == V2, r.body[:60])

r = c.api("GET", "/nodes/%s/versions" % SMALL_NODE)
check("GET /nodes/{id}/versions 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
vers = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("two versions listed", len(vers) >= 2, len(vers))
old = [v for v in vers if v.get("size") == len(SMALL)]
VID = old[0]["id"] if old else ""
check("old version found", bool(VID), vers)

r = c.api("POST", "/nodes/%s/versions/%s/restore" % (SMALL_NODE, VID))
check("POST version restore", r.status in (200, 201, 204), "%d %s" % (r.status, r.text()[:300]))
r = c.api("GET", "/nodes/%s/content" % SMALL_NODE)
check("content restored to v1", r.body == SMALL, r.body[:60])

# ---------- rename / move / copy ----------
r = c.api("PATCH", "/nodes/%s" % SUB, json_body={"name": "sub-renamed"})
check("PATCH rename 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
check("rename applied", r.json().get("name") == "sub-renamed", r.text()[:200])

r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "Dest"})
DEST = r.json().get("id", "")
r = c.api("POST", "/nodes/move", json_body={"ids": [SUB], "dest": DEST})
check("POST /nodes/move 200", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))
r = c.api("GET", "/nodes/" + SUB)
check("moved node has new parent", r.json().get("parent_id") == DEST, r.text()[:200])

r = c.api("POST", "/nodes/move", json_body={"ids": [ROOT], "dest": DEST})
check("move root rejected", r.status not in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("POST", "/nodes/move", json_body={"ids": [DEST], "dest": SUB})
check("move folder into own descendant rejected", r.status not in (200, 204), "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/nodes/copy", json_body={"ids": [SMALL_NODE], "dest": DEST})
check("POST /nodes/copy 200", r.status in (200, 201, 204), "%d %s" % (r.status, r.text()[:300]))
r = c.api("GET", "/nodes/%s/children" % DEST)
copies = [n for n in r.json()["items"] if n["kind"] == "file"]
check("copy landed in dest", len(copies) == 1, r.text()[:300])
COPY = copies[0]["id"] if copies else ""
if COPY:
    r = c.api("GET", "/nodes/%s/content" % COPY)
    check("copy has same content", r.body == SMALL, r.body[:60])

# copy a folder tree
r = c.api("POST", "/nodes/copy", json_body={"ids": [SMOKE], "dest": DEST, "conflict": "rename"})
check("copy folder tree", r.status in (200, 201, 204), "%d %s" % (r.status, r.text()[:300]))

# ---------- star ----------
r = c.api("PUT", "/nodes/%s/star" % SMALL_NODE)
check("PUT star", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/starred")
items = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("GET /starred contains node", any(n["id"] == SMALL_NODE for n in items), r.text()[:300])
r = c.api("DELETE", "/nodes/%s/star" % SMALL_NODE)
check("DELETE star", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/starred")
items = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("star removed", not any(n["id"] == SMALL_NODE for n in items), r.text()[:200])

# ---------- search / recent / stats ----------
found = False
for _ in range(40):
    r = c.api("GET", "/search?q=small")
    items = r.json().get("items", []) if r.status == 200 else []
    if any(n["id"] == SMALL_NODE for n in items):
        found = True
        break
    time.sleep(0.25)
check("GET /search finds small.txt", found, "%d %s" % (r.status, r.text()[:300]))

r = c.api("GET", "/search?q=" + "%22deep%22")
check("GET /search quoted 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/search?q=small*")
check("GET /search prefix 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/search?q=" + "a%20OR%20b%20AND%20(")
check("GET /search malformed FTS query != 500", r.status < 500, "%d %s" % (r.status, r.text()[:200]))

r = c.api("GET", "/recent")
check("GET /recent 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
items = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("recent lists uploads", len(items) > 0, len(items))

r = c.api("GET", "/nodes/%s/stats" % SMOKE)
check("GET /nodes/{id}/stats 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
sstat = r.json() if r.status == 200 else {}
check("stats count files", sstat.get("files", 0) >= 2, sstat)

# ---------- grants ----------
BOB = st["bob"]
r = c.api("POST", "/nodes/%s/grants" % SMOKE,
          json_body={"subject_type": "user", "subject_id": BOB, "role": "viewer"})
check("POST /nodes/{id}/grants 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
gr = r.json() if r.status in (200, 201) else {}
GRID = gr.get("id", "")
r = c.api("GET", "/nodes/%s/grants" % SMOKE)
check("GET /nodes/{id}/grants 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
items = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("grant listed", any(g.get("subject_id") == BOB for g in items), r.text()[:300])
if not GRID and items:
    GRID = items[0].get("id", "")

cbob = login("bob", st["bob_pw"])
r = cbob.api("GET", "/shared-with-me")
check("GET /shared-with-me 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
items = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("bob sees the granted folder", any(n["id"] == SMOKE for n in items), r.text()[:300])
r = cbob.api("GET", "/nodes/%s/children" % SMOKE)
check("bob can read the granted folder", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = cbob.api("POST", "/nodes/%s/folders" % SMOKE, json_body={"name": "nope"})
check("viewer cannot write", r.status == 403, "%d %s" % (r.status, r.text()[:200]))

r = c.api("DELETE", "/nodes/%s/grants/%s" % (SMOKE, GRID))
check("DELETE grant", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = cbob.api("GET", "/nodes/%s/children" % SMOKE)
check("bob loses access after revoke", r.status in (403, 404), "%d %s" % (r.status, r.text()[:200]))

# ---------- archives ----------
r = c.api("POST", "/archives", json_body={"node_ids": [SMOKE], "format": "zip", "name": "smoke"})
check("POST /archives (zip) 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
at = r.json() if r.status in (200, 201) else {}
TICKET = at.get("ticket", "")
check("archive ticket + url", bool(TICKET) and bool(at.get("url")), at)

r = c.api("GET", "/archives/" + TICKET)
check("GET /archives/{ticket} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
# DESIGN 8.2: user content that is not on the inline allow-list is delivered as
# application/octet-stream + nosniff + attachment; the name carries the format.
check("zip served as octet-stream attachment (DESIGN 8.2)",
      r.header("Content-Type") == "application/octet-stream"
      and r.header("X-Content-Type-Options") == "nosniff"
      and "attachment" in (r.header("Content-Disposition") or "")
      and ".zip" in (r.header("Content-Disposition") or ""),
      "%s | %s" % (r.header("Content-Type"), r.header("Content-Disposition")))
check("archive streams without Content-Length", r.header("Content-Length") is None,
      r.header("Content-Length"))
try:
    z = zipfile.ZipFile(io.BytesIO(r.body))
    names = z.namelist()
    check("zip is valid", z.testzip() is None, names[:10])
    check("zip has small.txt", any(n.endswith("small.txt") for n in names), names[:20])
    nm = [n for n in names if n.endswith("small.txt")][0]
    check("zip entry content matches", z.read(nm) == SMALL, z.read(nm)[:60])
except Exception as e:
    check("zip is valid", False, e)

r = c.api("GET", "/archives/" + TICKET)
check("archive ticket single use", r.status != 200, "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/archives", json_body={"node_ids": [SMOKE], "format": "tar", "name": "smoke"})
check("POST /archives (tar) 200", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
t2 = r.json().get("ticket", "")
r = c.api("GET", "/archives/" + t2)
check("GET tar archive 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("tar attachment name", ".tar" in (r.header("Content-Disposition") or ""), r.header("Content-Disposition"))
try:
    tf = tarfile.open(fileobj=io.BytesIO(r.body), mode="r|*")
    names = []
    content = None
    for m in tf:
        names.append(m.name)
        if m.name.endswith("small.txt") and content is None:
            content = tf.extractfile(m).read()
    check("tar is valid + has small.txt", any(n.endswith("small.txt") for n in names), names[:20])
    check("tar entry content matches", content == SMALL, (content or b"")[:60])
except Exception as e:
    check("tar is valid", False, e)

r = c.api("GET", "/archives/deadbeefdeadbeef")
check("bad archive ticket 404", r.status in (403, 404), "%d" % r.status)

# ---------- zip-mode upload batch (job) ----------
r = c.api("POST", "/upload-batches", json_body={
    "folder_id": SMOKE, "mode": "zip", "zip_name": "bundle",
    "files": [{"client_ref": "z1", "rel_path": "a/one.txt", "size": 5},
              {"client_ref": "z2", "rel_path": "a/two.txt", "size": 5}]})
check("POST zip-mode batch 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
zb = r.json() if r.status in (200, 201) else {}
ZBID = zb.get("id", "")
check("zip batch mode=zip", zb.get("mode") == "zip", zb.get("mode"))
for ref, data in [("z1", b"one!!"), ("z2", b"two!!")]:
    r = c.api("PUT", "/upload-batches/%s/small?ref=%s" % (ZBID, ref), body=data,
              headers={"X-FP-SHA256": sha256hex(data), "Content-Type": "application/octet-stream"})
    check("zip batch upload %s" % ref, r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/upload-batches/%s/complete" % ZBID)
check("zip batch complete 202/200", r.status in (200, 202), "%d %s" % (r.status, r.text()[:300]))
zres = r.json()
JOB = zres.get("job_id", "")
check("zip batch returns job_id", bool(JOB) or zres.get("state") == "done", zres)

zip_node = zres.get("result_node_id", "")
if JOB and not zip_node:
    job, err = wait_job(c, JOB)
    check("zip job finished", job and job.get("state") in ("done", "succeeded"), err or (job or {}).get("state"))
    for _ in range(60):
        r = c.api("GET", "/upload-batches/" + ZBID)
        zres = r.json()
        if zres.get("result_node_id"):
            break
        time.sleep(0.3)
    zip_node = zres.get("result_node_id", "")
check("zip batch produced a node", bool(zip_node), zres)

if zip_node:
    r = c.api("GET", "/nodes/" + zip_node)
    check("zip node name ends .zip", (r.json().get("name") or "").endswith(".zip"), r.text()[:200])
    r = c.api("GET", "/nodes/%s/content" % zip_node)
    check("zip node downloadable", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    try:
        z = zipfile.ZipFile(io.BytesIO(r.body))
        check("produced zip is valid", z.testzip() is None, z.namelist())
        check("produced zip has both files",
              sum(1 for n in z.namelist() if n.endswith(".txt")) == 2, z.namelist())
        nm = [n for n in z.namelist() if n.endswith("one.txt")][0]
        check("produced zip content", z.read(nm) == b"one!!", z.read(nm))
    except Exception as e:
        check("produced zip is valid", False, e)

# ---------- trash / restore / purge ----------
r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "Doomed"})
DOOM = r.json()["id"]
r = c.api("POST", "/nodes/trash", json_body={"ids": [DOOM]})
check("POST /nodes/trash", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/trash")
items = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("GET /trash lists it", any(n["id"] == DOOM for n in items), r.text()[:300])
r = c.api("GET", "/nodes/%s/children" % ROOT)
check("trashed node hidden from children", not any(n["id"] == DOOM for n in r.json()["items"]), r.text()[:300])

r = c.api("POST", "/trash/restore", json_body={"ids": [DOOM]})
check("POST /trash/restore", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))
r = c.api("GET", "/nodes/%s/children" % ROOT)
check("restored node back", any(n["id"] == DOOM for n in r.json()["items"]), r.text()[:300])

r = c.api("POST", "/nodes/trash", json_body={"ids": [DOOM]})
r = c.api("POST", "/trash/purge", json_body={"ids": [DOOM]})
check("POST /trash/purge", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))
r = c.api("GET", "/nodes/" + DOOM)
check("purged node gone 404", r.status == 404, "%d" % r.status)

r = c.api("POST", "/nodes/%s/folders" % ROOT, json_body={"name": "Doomed2"})
D2 = r.json()["id"]
c.api("POST", "/nodes/trash", json_body={"ids": [D2]})
r = c.api("DELETE", "/trash")
check("DELETE /trash (empty)", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/trash")
items = r.json()["items"] if isinstance(r.json(), dict) else r.json()
check("trash is empty", len(items) == 0, r.text()[:300])

# ---------- authz: bob must not touch admin's nodes ----------
r = cbob.api("GET", "/nodes/" + SMALL_NODE)
check("other user cannot read node", r.status in (403, 404), "%d %s" % (r.status, r.text()[:200]))
r = cbob.api("GET", "/nodes/%s/content" % SMALL_NODE)
check("other user cannot download", r.status in (403, 404), "%d %s" % (r.status, r.text()[:200]))
r = cbob.api("POST", "/nodes/trash", json_body={"ids": [SMALL_NODE]})
check("other user cannot trash", r.status in (403, 404), "%d %s" % (r.status, r.text()[:200]))

st.update({"root": ROOT, "space": SPACE, "smoke": SMOKE, "small_node": SMALL_NODE,
           "png_node": PNG_NODE, "big_node": BIG_NODE, "dest": DEST})
save_state(st)
sys.exit(1 if summary() else 0)
