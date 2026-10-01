"""FileParcel live smoke-test client (stdlib only)."""
import base64
import hashlib
import hmac
import http.client
import json
import os
import socket
import ssl
import struct
import sys
import time

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
SMOKE_DIR = os.environ.get("FP_SMOKE_DIR", os.path.join(os.environ.get("TMPDIR", "/tmp"), "fileparcel-smoke"))
HOME = os.environ.get("FP_HOME", os.path.join(SMOKE_DIR, "h1"))
# The scripts live in the repo; the binary, the home and the scratch files
# live in FP_SMOKE_DIR. Never mix the two up.
BIN = os.environ.get("FP_BIN", os.path.join(SMOKE_DIR, "fileparcel"))
SRV = os.path.join(SCRIPTS, "srv.sh")
HOST = os.environ.get("FP_HOST", "fileparcel.local")
PORT = int(os.environ.get("FP_PORT", "18443"))
HTTP_PORT = int(os.environ.get("FP_HTTP_PORT", "18080"))
CA = os.path.join(HOME, "certs", "ca", "ca.crt")
ORIGIN = "https://%s:%d" % (HOST, PORT)

# --resolve $FP_HOST:$FP_PORT:127.0.0.1
_orig_gai = socket.getaddrinfo


def _gai(host, port, *a, **kw):
    if host == HOST:
        host = "127.0.0.1"
    return _orig_gai(host, port, *a, **kw)


socket.getaddrinfo = _gai

RESULTS = []
_FAILED = []


def record(name, ok, detail="", fail_detail=""):
    """Print one result line.

    `detail` is printed on PASS and on FAIL, so it must describe what was
    observed, never what went wrong -- "[PASS] the new CA validates the
    server -- new CA rejected" reads as a failure. Put failure-phrased text
    in `fail_detail`: it is shown only when the check fails, and the
    condition is evaluated once instead of being mirrored in the detail.
    """
    if not ok and fail_detail:
        detail = fail_detail if not detail else "%s -- %s" % (fail_detail, detail)
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    if not ok:
        _FAILED.append((name, detail))
    print("[%s] %s%s" % (mark, name, (" -- " + str(detail)[:400]) if detail else ""), flush=True)
    return ok


def check(name, cond, detail="", fail_detail=""):
    return record(name, bool(cond), detail, fail_detail)


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, k):
        for hk, hv in self.headers:
            if hk.lower() == k.lower():
                return hv
        return None

    def headers_all(self, k):
        return [hv for hk, hv in self.headers if hk.lower() == k.lower()]

    def json(self):
        return json.loads(self.body.decode("utf-8"))

    def text(self):
        return self.body.decode("utf-8", "replace")

    def __repr__(self):
        return "<Resp %d %d bytes %s>" % (self.status, len(self.body), self.body[:200])


class Client:
    def __init__(self, token=None, verify=True):
        self.cookies = {}
        self.csrf = None
        self.token = token
        ctx = ssl.create_default_context(cafile=CA)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx

    def request(self, method, path, body=None, headers=None, json_body=None,
                origin=True, stream=False, raw_host=None, port=None):
        h = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode()
            h.setdefault("Content-Type", "application/json")
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        if self.csrf and method not in ("GET", "HEAD", "OPTIONS"):
            h.setdefault("X-FP-CSRF", self.csrf)
        if self.token:
            h.setdefault("Authorization", "Bearer " + self.token)
        if origin and method not in ("GET", "HEAD", "OPTIONS"):
            h.setdefault("Origin", ORIGIN)
            h.setdefault("Sec-Fetch-Site", "same-origin")
        conn = http.client.HTTPSConnection(raw_host or HOST, port or PORT, context=self.ctx, timeout=60)
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read()
            resp = Resp(r.status, r.getheaders(), data)
        finally:
            conn.close()
        for hk, hv in resp.headers:
            if hk.lower() == "set-cookie":
                seg = hv.split(";")[0]
                if "=" in seg:
                    k, v = seg.split("=", 1)
                    if v == "" or "Max-Age=0" in hv:
                        self.cookies.pop(k, None)
                    else:
                        self.cookies[k] = v
        return resp

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def head(self, path, **kw):
        return self.request("HEAD", path, **kw)

    def post(self, path, json_body=None, **kw):
        return self.request("POST", path, json_body=json_body, **kw)

    def put(self, path, json_body=None, **kw):
        return self.request("PUT", path, json_body=json_body, **kw)

    def patch(self, path, json_body=None, **kw):
        return self.request("PATCH", path, json_body=json_body, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def api(self, method, path, **kw):
        return self.request(method, "/api/v1" + path, **kw)


def totp_code(secret_b32, t=None, digits=6, step=30):
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    ctr = int((t if t is not None else time.time()) // step)
    mac = hmac.new(key, struct.pack(">Q", ctr), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def sha256hex(b):
    return hashlib.sha256(b).hexdigest()


STATE_PATH = os.path.join(SMOKE_DIR, "state.json")


def load_state():
    with open(STATE_PATH) as f:
        return json.load(f)


def save_state(s):
    with open(STATE_PATH, "w") as f:
        json.dump(s, f)


def login(username, password, totp_secret=None, elevate=True):
    """Full login incl. second factor; returns an authenticated Client."""
    c = Client()
    # The per-IP failure bucket is shared by the whole suite; back off rather
    # than turning a transient 429 into a cascade of phase failures.
    for attempt in range(12):
        r = c.api("POST", "/auth/login", json_body={"username": username, "password": password})
        if r.status != 429:
            break
        time.sleep(5)
    if r.status != 200:
        raise RuntimeError("login %s failed: %d %s" % (username, r.status, r.text()[:300]))
    lr = r.json()
    c.csrf = lr.get("csrf")
    if lr.get("mfa_required"):
        if not totp_secret:
            raise RuntimeError("login %s needs MFA but no secret given" % username)
        for attempt in range(3):
            r = c.api("POST", "/auth/totp", json_body={"code": totp_code(totp_secret)})
            if r.status == 200:
                break
            time.sleep(31)
        if r.status != 200:
            raise RuntimeError("totp failed: %d %s" % (r.status, r.text()[:300]))
        if r.json().get("csrf"):
            c.csrf = r.json()["csrf"]
    if elevate:
        r = c.api("POST", "/auth/elevate", json_body={"password": password})
        if r.status == 200 and r.json().get("csrf"):
            c.csrf = r.json()["csrf"]
    return c


def admin_client(elevate=True):
    s = load_state()
    return login("admin", s["password"], s.get("totp_secret"), elevate=elevate)


def summary():
    print("\n" + "=" * 70)
    npass = sum(1 for _, ok, _ in RESULTS if ok)
    print("TOTAL %d  PASS %d  FAIL %d" % (len(RESULTS), npass, len(RESULTS) - npass))
    if _FAILED:
        print("\nFAILURES:")
        for n, d in _FAILED:
            print("  - %s: %s" % (n, str(d)[:500]))
    print("=" * 70)
    return len(_FAILED)
