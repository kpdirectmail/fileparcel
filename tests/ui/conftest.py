"""Playwright fixtures for the FileParcel UI tests (DESIGN §17 "Playwright").

The session starts its own server unless FP_UI_BASE_URL points at a running
one: it builds the binary (scripts/build.sh host, or FP_UI_BIN), initialises a
scratch home on a free port, seeds users through the REST API and launches
Chromium with

    --host-resolver-rules=MAP fileparcel.local 127.0.0.1
    --ignore-certificate-errors-spki-list=<base64 SHA-256 of the leaf SPKI>

so the pages run in a real secure context (service worker, WebAuthn) without
trusting the local CA system-wide. When Playwright's own Chromium is missing
the fallback is /usr/bin/brave-browser (or FP_UI_BROWSER).

Every page is watched for console errors, uncaught exceptions and CSP /
Trusted Types violations; tests call ``watch.assert_clean()`` and the
layout helpers (``assert_no_overflow``, ``assert_tap_targets``).
Screenshots go to tests/ui/screenshots/ (gitignored).

Environment:
    FP_UI_BASE_URL      use a running server (https://fileparcel.local:8443)
    FP_UI_CA            its CA certificate (PEM)            [with FP_UI_BASE_URL]
    FP_UI_IP            IP the host name maps to (default 127.0.0.1)
    FP_UI_ADMIN, FP_UI_ADMIN_PASSWORD, FP_UI_TOTP_SECRET     [with FP_UI_BASE_URL]
    FP_UI_BIN           binary to start instead of building one
    FP_UI_BROWSER       browser executable (default: Playwright Chromium, then Brave)
    FP_UI_HEADED=1      show the browser;  FP_UI_SLOWMO=ms  slow motion
    FP_UI_KEEP=1        keep the scratch home and server log
    FP_UI_IGNORE_CONSOLE  regular expression of console errors to ignore

No server started here reaches the tailscaled of this machine: the session server gets a socket path that does
not exist (FILEPARCEL_TAILSCALE_SOCKET), the Funnel tests' server (`funnel_server`) a fake tailscaled
(fake_tailscaled.py).
"""

from __future__ import annotations

import atexit
import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field

import pytest
from fake_tailscaled import FakeTailscaled
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, sync_playwright

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
SHOTS = HERE / "screenshots"
HOST = "fileparcel.local"
BRAVE = "/usr/bin/brave-browser"

DESKTOP = {"viewport": {"width": 1440, "height": 900}, "device_scale_factor": 1}
MOBILE_DEVICES = ["Pixel 7", "iPhone 14"]

# Selectors shared by the tests; adjust here when the UI changes.
# NOTE: components/field.js puts the required marker inside the <label>, so the
# label text is "Password*" - match labels loosely (never exact=True) or use the
# control itself, as `login()` does.
SEL = {
    "login_user": "Username",
    "login_password": "input[type=password]",
    "login_submit": "Sign in",
    "login_code": "input[autocomplete=one-time-code]",
    "login_verify": "Verify",
    "passkey_login": "Sign in with a passkey",
    "tabbar": "nav[aria-label='Primary']",
    "fab": "button[aria-label='Upload or create']",
    "upload_more": "button[aria-label='More upload options']",
    "upload_button": "Upload",
    "page_title": "main h1, #fp-main h1, [data-page-title]",
}

ADMIN_ROUTES = [
    "/admin",
    "/admin/users",
    "/admin/invites",
    "/admin/groups",
    "/admin/settings/general",
    "/admin/settings/auth",
    "/admin/settings/storage",
    "/admin/settings/sharing",
    "/admin/network",
    "/admin/certificates",
    "/admin/encryption",
    "/admin/backups",
    "/admin/audit",
    "/admin/jobs",
    "/admin/system",
]
USER_ROUTES = [
    "/files",
    "/shared",
    "/links",
    "/requests",
    "/starred",
    "/recent",
    "/trash",
    "/activity",
    "/search?q=a",
    "/settings/profile",
    "/settings/security",
    "/settings/sessions",
    "/settings/tokens",
    "/settings/appearance",
    "/settings/devices",
]

# Collects CSP / Trusted Types violations before any page script runs. Init
# scripts are injected by the browser (not subject to the page CSP) and use no
# Trusted Types sinks.
VIOLATION_SCRIPT = """
(() => {
  window.__fpViolations = [];
  document.addEventListener('securitypolicyviolation', (e) => {
    window.__fpViolations.push({directive: e.violatedDirective, blocked: String(e.blockedURI || ''),
      source: String(e.sourceFile || ''), line: e.lineNumber, sample: String(e.sample || '')});
  }, true);
})();
"""


# ---------------------------------------------------------------- utilities
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def totp(secret: str, step: int, digits: int = 6, period: int = 30, algo: str = "sha1") -> str:
    """RFC 6238 code for a time step (python stdlib only)."""
    s = secret.upper().replace(" ", "")
    key = base64.b32decode(s + "=" * (-len(s) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), getattr(hashlib, algo)).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10**digits)
    _ = period
    return str(code).zfill(digits)


class TOTPClock:
    """Hands out codes for time steps never used before (servers reject replays)."""

    def __init__(self) -> None:
        self.last: dict[str, int] = {}

    def code(self, secret: str, period: int = 30) -> str:
        while True:
            now = time.time()
            step = int(now // period)
            if step > self.last.get(secret, -1) and (step + 1) * period - now >= 2:
                self.last[secret] = step
                return totp(secret, step)
            time.sleep(0.25)


def _tlv(buf: bytes, off: int) -> tuple[int, int, int, int]:
    """One DER TLV at off -> (tag, content_start, content_end, next)."""
    tag = buf[off]
    ln = buf[off + 1]
    p = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[p:p + n], "big")
        p += n
    return tag, p, p + ln, p + ln


def spki_sha256_b64(cert_der: bytes) -> str:
    """base64(SHA-256(SubjectPublicKeyInfo)) of a DER certificate, the value
    Chromium's --ignore-certificate-errors-spki-list expects."""
    _, c0, _, _ = _tlv(cert_der, 0)  # Certificate
    _, t0, t1, _ = _tlv(cert_der, c0)  # tbsCertificate
    fields = []
    off = t0
    while off < t1:
        tag, _, _, nxt = _tlv(cert_der, off)
        fields.append((tag, off, nxt))
        off = nxt
    if fields and fields[0][0] == 0xA0:  # [0] version
        fields = fields[1:]
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    _, s, e = fields[5]
    return base64.b64encode(hashlib.sha256(cert_der[s:e]).digest()).decode()


def png_bytes(w: int = 64, h: int = 48, rgb: tuple[int, int, int] = (37, 99, 235)) -> bytes:
    """A solid-colour PNG built with the standard library."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    return png + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def make_png(path: pathlib.Path, w: int = 64, h: int = 48, rgb: tuple[int, int, int] = (37, 99, 235)) -> pathlib.Path:
    """Writes a solid-colour PNG file."""
    path.write_bytes(png_bytes(w, h, rgb))
    return path


# ------------------------------------------------------------- REST client
class _PinnedConn(http.client.HTTPSConnection):
    """HTTPS to a fixed IP while verifying the certificate for the host name."""

    def __init__(self, host: str, ip: str, port: int, context: ssl.SSLContext, timeout: float = 60) -> None:
        super().__init__(host, port, context=context, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:  # noqa: D401 - http.client hook
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self):
        return json.loads(self.body or b"null")


@dataclass
class ApiClient:
    """Minimal REST client (stdlib) with its own cookie store and CSRF token."""

    host: str
    ip: str
    port: int
    ctx: ssl.SSLContext
    cookies: dict[str, str] = field(default_factory=dict)
    csrf: str = ""

    def request(self, method: str, path: str, body=None, headers: dict | None = None, raw: bytes | None = None) -> Response:
        hdr = {"Accept": "application/json"}
        if self.cookies:
            hdr["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.csrf and method not in ("GET", "HEAD"):
            hdr["X-FP-CSRF"] = self.csrf
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            hdr["Content-Type"] = "application/json"
        hdr.update(headers or {})
        conn = _PinnedConn(self.host, self.ip, self.port, self.ctx)
        try:
            conn.request(method, path, body=data, headers=hdr)
            r = conn.getresponse()
            payload = r.read()
            for k, v in r.getheaders():
                if k.lower() == "set-cookie":
                    name, _, rest = v.partition("=")
                    value = rest.split(";", 1)[0]
                    if "max-age=0" in v.lower() or value == "":
                        self.cookies.pop(name.strip(), None)
                    else:
                        self.cookies[name.strip()] = value
            resp = Response(r.status, {k.lower(): v for k, v in r.getheaders()}, payload)
        finally:
            conn.close()
        return resp

    def ok(self, method: str, path: str, body=None, **kw):
        r = self.request(method, path, body, **kw)
        assert 200 <= r.status < 300, f"{method} {path}: HTTP {r.status} {r.body[:300]!r}"
        try:
            return r.json()
        except ValueError:
            return None

    def refresh_csrf(self) -> None:
        me = self.request("GET", "/api/v1/me")
        if me.status == 200:
            self.csrf = me.json().get("csrf") or self.csrf

    def elevate(self, password: str) -> bool:
        """Step-up for the (E) admin routes; the session token is rotated."""
        r = self.request("POST", "/api/v1/auth/elevate", {"password": password})
        if r.status != 200:
            return False
        self.csrf = (r.json() or {}).get("csrf") or self.csrf
        return True

    def login(self, username: str, password: str, totp_secret: str | None = None, clock: TOTPClock | None = None) -> dict:
        self.cookies.clear()
        self.csrf = ""
        # /auth/login is rate limited per client IP and every test signs in from
        # 127.0.0.1, so a busy run can hit 429 - wait for the bucket to refill.
        for attempt in range(4):
            r = self.request("POST", "/api/v1/auth/login", {"username": username, "password": password})
            if r.status != 429:
                assert 200 <= r.status < 300, f"POST /api/v1/auth/login: HTTP {r.status} {r.body[:200]!r}"
                res = r.json()
                break
            assert attempt < 3, "the login rate limit did not refill"
            time.sleep(float(r.headers.get("retry-after") or 10) + 1)
        self.csrf = (res or {}).get("csrf") or ""
        if (res or {}).get("mfa_required"):
            if not self.csrf:
                self.refresh_csrf()
            assert totp_secret and clock, f"{username} needs a TOTP secret"
            # A code is single-use per time step, and a previous run (or another
            # client) may already have spent the current one - retry on the next step.
            for attempt in range(3):
                r = self.request("POST", "/api/v1/auth/totp", {"code": clock.code(totp_secret)})
                if 200 <= r.status < 300:
                    res = r.json()
                    break
                assert attempt < 2, f"POST /api/v1/auth/totp: HTTP {r.status} {r.body[:200]!r}"
                time.sleep(31)
            self.csrf = (res or {}).get("csrf") or ""
        if not self.csrf:
            self.refresh_csrf()
        return res or {}

    def upload_small(self, folder_id: str, name: str, data: bytes) -> str:
        """Uploads one small file (small path) and returns the node id."""
        batch = self.ok("POST", "/api/v1/upload-batches", {
            "folder_id": folder_id, "mode": "files", "conflict": "replace",
            "files": [{"client_ref": "f", "rel_path": name, "size": len(data)}]})
        st = self.ok("PUT", f"/api/v1/upload-batches/{batch['id']}/small?ref=f", raw=data,
                     headers={"Content-Type": "application/octet-stream",
                              "X-FP-SHA256": hashlib.sha256(data).hexdigest()})
        self.ok("POST", f"/api/v1/upload-batches/{batch['id']}/complete")
        return st["node_id"]

    def root_id(self) -> str:
        spaces = self.ok("GET", "/api/v1/spaces")
        return next(s["root_id"] for s in spaces if s["kind"] == "user")


# ------------------------------------------------------------------ server
@dataclass
class Server:
    base: str
    host: str
    ip: str
    port: int
    ca: pathlib.Path
    spki: str
    admin: str
    admin_password: str
    admin_totp: str | None
    clock: TOTPClock
    users: dict[str, str] = field(default_factory=dict)  # username -> password (members, no 2FA)
    work: pathlib.Path | None = None
    proc: subprocess.Popen | None = None

    def ssl_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.ca))

    def client(self) -> ApiClient:
        return ApiClient(self.host, self.ip, self.port, self.ssl_context())

    def url(self, path: str) -> str:
        return self.base + path


_BINARY: list[pathlib.Path] = []  # the binary built for this run (every local server uses it)


def _build_binary() -> pathlib.Path:
    """FP_UI_BIN, or the worktree's binary built once per run (removed at exit unless FP_UI_KEEP)."""
    if os.environ.get("FP_UI_BIN"):
        return pathlib.Path(os.environ["FP_UI_BIN"])
    if not _BINARY:
        out = pathlib.Path(tempfile.mkdtemp(prefix="fp-ui-bin.", dir=os.environ.get("TMPDIR")))
        if not os.environ.get("FP_UI_KEEP"):
            atexit.register(shutil.rmtree, out, True)
        subprocess.run(["sh", str(REPO / "scripts" / "build.sh"), "-q", "-o", str(out), "-v", "ui-test", "host"],
                       check=True, stdout=subprocess.DEVNULL)
        _BINARY.append(out / "fileparcel")
    return _BINARY[0]


def _leaf_der(ip: str, port: int, host: str) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # only to read the certificate; it is verified by the API client
    with socket.create_connection((ip, port), 10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        return t.getpeercert(binary_form=True)


def _wait_healthy(ip: str, port: int, host: str, ca: pathlib.Path, proc: subprocess.Popen | None, log: pathlib.Path) -> None:
    ctx = ssl.create_default_context(cafile=str(ca))
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"fileparcel serve exited ({proc.returncode}): {log.read_text()[-2000:]}")
        try:
            c = _PinnedConn(host, ip, port, ctx, timeout=3)
            c.request("GET", "/healthz")
            if c.getresponse().status == 200:
                return
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError("the server did not become healthy within 60 s")


def _bootstrap(srv: Server) -> None:
    """Admin: change a forced password, enroll TOTP; create member users."""
    api = srv.client()
    res = api.login(srv.admin, srv.admin_password, srv.admin_totp, srv.clock)
    if res.get("must_change_password"):
        new = "Ui-" + secrets.token_hex(12)
        api.ok("POST", "/api/v1/me/password", {"current_password": srv.admin_password, "new_password": new})
        srv.admin_password = new
        api.refresh_csrf()
    if not srv.admin_totp:
        mfa = api.ok("GET", "/api/v1/me/mfa")
        if not mfa.get("totp_enabled"):
            assert api.elevate(srv.admin_password), "step-up before setting up the authenticator app"
            enr = api.ok("POST", "/api/v1/me/totp/begin")
            srv.admin_totp = enr["secret"]
            api.ok("POST", "/api/v1/me/totp/confirm", {"code": srv.clock.code(srv.admin_totp)})
            api.refresh_csrf()
    # alice is the one shared account the tests sign in as (tests that need their own
    # account use the fresh_user factory); bob and carol only exist so the admin user
    # list has more than one row to render. Nothing signs in as them, so a re-used
    # server can leave their credentials alone.
    for name in ("alice",):
        pw = "Ui-" + secrets.token_hex(12)
        r = api.request("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member",
                                                        "display_name": name.title()})
        if r.status in (200, 201):
            srv.users[name] = pw
            continue
        # The user is already there (re-used server): reset its password and MFA so the
        # session can sign in as it again. Both are step-up ("E") routes.
        found = api.ok("GET", f"/api/v1/admin/users?q={name}")
        uid = next((u["id"] for u in found.get("items", []) if u["username"] == name), None)
        assert uid, f"could not create or find user {name}: HTTP {r.status} {r.body[:200]!r}"
        api.elevate(srv.admin_password)
        api.ok("POST", f"/api/v1/admin/users/{uid}/password", {"password": pw, "must_change": False})
        api.request("POST", f"/api/v1/admin/users/{uid}/reset-mfa")
        srv.users[name] = pw
    # Extra rows only; a 409 on a re-used server is fine. They carry a display name *and* an e-mail so the
    # admin user list has a full "Display Name" / "@user · e-mail" identity cell to lay out on a phone
    # (test_mobile.py::test_admin_users_names_are_readable_on_a_phone).
    for name, display in (("bob", "Bob"), ("carol", "Carol Fernández-Whitmore")):
        r = api.request("POST", "/api/v1/admin/users",
                        {"username": name, "password": "Ui-" + secrets.token_hex(12), "role": "member",
                         "display_name": display, "email": f"{name}@example.com"})
        if r.status not in (200, 201):  # already there (re-used server): make sure it carries both fields
            found = api.request("GET", f"/api/v1/admin/users?q={name}")
            items = found.json().get("items", []) if found.status == 200 else []
            uid = next((u["id"] for u in items if u["username"] == name), None)
            if uid:
                api.request("PATCH", f"/api/v1/admin/users/{uid}",
                            {"display_name": display, "email": f"{name}@example.com"})
    # something to look at in alice's files
    alice = srv.client()
    alice.login("alice", srv.users["alice"])
    root = alice.root_id()
    for name, data in (("hello.txt", b"Hello from the UI tests\n"), ("blue.png", png_bytes())):
        try:
            alice.upload_small(root, name, data)
        except AssertionError:
            pass


@contextlib.contextmanager
def local_server(tailscale_socket: str | None = None, prefix: str = "fp-ui."):
    """Starts a FileParcel server on a scratch home and a free port (bootstrapped like the session server) and
    stops it on exit. tailscale_socket is the tailscaled it may talk to (FILEPARCEL_TAILSCALE_SOCKET): a fake
    one (the Funnel tests), or by default a path that does not exist - never this machine's real tailscaled,
    which accepts writes from its operator, who may run these tests (the CLI fallback is disabled as well)."""
    clock = TOTPClock()
    ip = os.environ.get("FP_UI_IP", "127.0.0.1")
    work = pathlib.Path(tempfile.mkdtemp(prefix=prefix, dir=os.environ.get("TMPDIR")))
    home = work / "home"
    log = work / "server.log"
    binary = _build_binary()
    port = free_port()
    password = "Ui-" + secrets.token_hex(12)
    pwfile = work / "admin.pw"
    pwfile.write_text(password + "\n")
    pwfile.chmod(0o600)
    env = {**os.environ, "FILEPARCEL_TAILSCALE_SOCKET": tailscale_socket or str(work / "no-tailscaled.sock")}
    subprocess.run([str(binary), "init", "--home", str(home), "--port", str(port), "--http-port", "0",
                    "--name", HOST.split(".")[0], "--admin", "admin", "--admin-password-file", str(pwfile),
                    "--access", "private", "--non-interactive"], check=True, stdout=subprocess.DEVNULL, env=env)
    for key, value in (("mdns.mode", "off"), ("tls.extra_sans", HOST)):
        subprocess.run([str(binary), "--home", str(home), "--offline", "config", "set", key, value],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    logf = open(log, "ab")  # noqa: SIM115 - closed below
    proc = subprocess.Popen([str(binary), "serve", "--home", str(home)], stdout=logf, stderr=subprocess.STDOUT,
                            env=env)
    ca = home / "certs" / "ca" / "ca.crt"
    try:
        _wait_healthy(ip, port, HOST, ca, proc, log)
        spki = spki_sha256_b64(_leaf_der(ip, port, HOST))
        srv = Server(f"https://{HOST}:{port}", HOST, ip, port, ca, spki, "admin", password, None, clock,
                     work=work, proc=proc)
        _bootstrap(srv)
        yield srv
    finally:
        proc.terminate()
        try:
            proc.wait(40)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        if not os.environ.get("FP_UI_KEEP"):
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"\nUI test home kept in {work}")


@pytest.fixture(scope="session")
def server():
    base = os.environ.get("FP_UI_BASE_URL")
    if base:
        ip = os.environ.get("FP_UI_IP", "127.0.0.1")
        u = urllib.parse.urlparse(base)
        ca = pathlib.Path(os.environ["FP_UI_CA"])
        host, port = u.hostname or HOST, u.port or 443
        spki = spki_sha256_b64(_leaf_der(ip, port, host))
        srv = Server(base.rstrip("/"), host, ip, port, ca, spki, os.environ.get("FP_UI_ADMIN", "admin"),
                     os.environ["FP_UI_ADMIN_PASSWORD"], os.environ.get("FP_UI_TOTP_SECRET"), TOTPClock())
        _bootstrap(srv)
        yield srv
        return
    with local_server() as srv:
        yield srv


@dataclass
class FunnelServer:
    """A server of its own whose tailscaled is fake_tailscaled.FakeTailscaled (Tailscale Funnel/Serve tests)."""

    server: Server
    fake: FakeTailscaled
    browser: object  # a browser that trusts this server's certificate
    _api: ApiClient | None = None

    @property
    def home(self) -> str:
        assert self.server.work is not None
        return str(self.server.work / "home")

    def admin_api(self) -> ApiClient:
        """The administrator's API client (one sign-in per module: every one spends a TOTP step), stepped up
        again on each call for the E routes. Its session is its own: browser states come from other sign-ins."""
        if self._api is None:
            self._api = self.server.client()
            self._api.login(self.server.admin, self.server.admin_password, self.server.admin_totp, self.server.clock)
        assert self._api.elevate(self.server.admin_password), "step-up of the Funnel server's administrator"
        return self._api


@pytest.fixture(scope="module")
def funnel_server(playwright_instance):
    """Module-scoped FunnelServer (skipped against FP_UI_BASE_URL: an external server cannot be pointed at the
    fake tailscaled)."""
    if os.environ.get("FP_UI_BASE_URL"):
        pytest.skip("the Funnel tests start their own server with a fake tailscaled")
    fake = FakeTailscaled()
    try:
        with local_server(fake.path, prefix="fp-ui-funnel.") as srv:
            b = launch_browser(playwright_instance, srv)
            try:
                yield FunnelServer(srv, fake, b)
            finally:
                b.close()
    finally:
        fake.close()


@pytest.fixture
def funnel_page(playwright_instance, funnel_server):
    """new_page for the Funnel server: funnel_page(profile, scheme, storage_state, viewport) -> (page, watch)."""
    make, close = page_factory(playwright_instance, funnel_server.browser, funnel_server.server)
    yield make
    close()


# ------------------------------------------------------------------ browser
@pytest.fixture(scope="session")
def playwright_instance():
    with sync_playwright() as p:
        yield p


def launch_browser(playwright_instance, server: Server):
    """Chromium (or the fallback browser) resolving the server's host name and trusting its leaf certificate."""
    args = [f"--host-resolver-rules=MAP {server.host} {server.ip}",
            f"--ignore-certificate-errors-spki-list={server.spki}"]
    opts = {"args": args, "headless": not os.environ.get("FP_UI_HEADED"),
            "slow_mo": float(os.environ.get("FP_UI_SLOWMO", "0"))}
    exe = os.environ.get("FP_UI_BROWSER")
    try:
        return playwright_instance.chromium.launch(executable_path=exe or None, **opts)
    except PlaywrightError:
        if exe or not os.path.exists(BRAVE):
            raise
        return playwright_instance.chromium.launch(executable_path=BRAVE, **opts)


@pytest.fixture(scope="session")
def browser(playwright_instance, server):
    b = launch_browser(playwright_instance, server)
    yield b
    b.close()


class Watch:
    """Console errors, page errors and CSP / Trusted Types violations of a page."""

    def __init__(self, page: Page) -> None:
        self.page = page
        self.errors: list[str] = []
        ignore = os.environ.get("FP_UI_IGNORE_CONSOLE")
        self._ignore = re.compile(ignore) if ignore else None
        page.on("console", self._console)
        page.on("pageerror", lambda exc: self.errors.append(f"pageerror: {exc}"))

    def _console(self, msg) -> None:
        text = msg.text
        if self._ignore and self._ignore.search(text):
            return
        if msg.type == "error" or re.search(r"Content Security Policy|Trusted ?Type|Refused to", text):
            self.errors.append(f"console.{msg.type}: {text}")

    def violations(self) -> list:
        try:
            return self.page.evaluate("window.__fpViolations || []")
        except PlaywrightError:
            return []

    def assert_clean(self) -> None:
        v = self.violations()
        assert not v, f"CSP / Trusted Types violations: {v}"
        assert not self.errors, "console errors:\n" + "\n".join(self.errors)


def context_options(playwright_instance, profile: str, scheme: str) -> dict:
    if profile == "desktop":
        opts = dict(DESKTOP)
    else:
        opts = dict(playwright_instance.devices[profile])
        opts.pop("default_browser_type", None)  # always Chromium (WebAuthn via CDP)
    opts["color_scheme"] = scheme
    return opts


def page_factory(playwright_instance, browser, server: Server):
    """(make, close): make(profile="desktop"|"Pixel 7"|"iPhone 14", scheme="light"|"dark", storage_state=None,
    viewport=None) -> (page, watch) opens a watched page on server; close() closes every context it made."""
    contexts = []

    def make(profile: str = "desktop", scheme: str = "light", storage_state=None, viewport=None):
        opts = context_options(playwright_instance, profile, scheme)
        if viewport:
            opts["viewport"] = viewport
        ctx = browser.new_context(base_url=server.base, storage_state=storage_state, **opts)
        ctx.add_init_script(VIOLATION_SCRIPT)
        ctx.set_default_timeout(15000)
        contexts.append(ctx)
        page = ctx.new_page()
        return page, Watch(page)

    def close():
        for c in contexts:
            c.close()

    return make, close


@pytest.fixture
def new_page(playwright_instance, browser, server, request):
    """Factory: new_page(profile="desktop"|"Pixel 7"|"iPhone 14", scheme="light"|"dark",
    storage_state=None, viewport=None) -> (page, watch)."""
    make, close = page_factory(playwright_instance, browser, server)
    yield make
    close()


def cookie_state(server: Server, api: "ApiClient") -> dict:
    """A browser storage state built from a signed-in API client's cookie."""
    token = api.cookies.get("__Host-fp_session")
    assert token, "the API client has no session cookie"
    return {"cookies": [{"name": "__Host-fp_session", "value": token, "domain": server.host,
                         "path": "/", "expires": -1, "httpOnly": True, "secure": True,
                         "sameSite": "Lax"}],
            "origins": []}


def api_storage_state(server: Server, username: str, password: str, totp_secret: str | None = None) -> dict:
    """A browser storage state carrying a session cookie obtained over the API.

    /auth/login is rate limited per client IP, and every test here comes from
    127.0.0.1 - signing in through the UI for each fixture exhausts the bucket
    and the next test gets a 429. The tests that are *about* signing in still
    use `login()`; the ones that only need to be signed in use this.
    """
    api = server.client()
    api.login(username, password, totp_secret, server.clock)
    return cookie_state(server, api)


@pytest.fixture(scope="session")
def admin_state(server):
    """Storage state of an admin session (with the second factor)."""
    return api_storage_state(server, server.admin, server.admin_password, server.admin_totp)


@pytest.fixture(scope="session")
def alice_state(server):
    """Storage state of alice's session (member, password only)."""
    return api_storage_state(server, "alice", server.users["alice"])


@pytest.fixture(scope="session")
def sample_state(server):
    """Storage state of a throw-away member whose folder holds exactly two files.

    The shared `alice` account accumulates whatever every other test uploads, so
    a phone-sized viewport pushes her first rows out of the virtualized list.
    Tests that need to see a specific row use this account instead.
    """
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    name = "phone" + secrets.token_hex(4)
    pw = "Ui-" + secrets.token_hex(12)
    api.ok("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member",
                                           "display_name": name.title()})
    user = server.client()
    user.login(name, pw)
    root = user.root_id()
    user.upload_small(root, "hello.txt", b"Hello from the UI tests\n")
    user.upload_small(root, "blue.png", png_bytes())
    return cookie_state(server, user)


@pytest.fixture
def fresh_user(server):
    """Factory for a throw-away member account: fresh_user() -> (username, password).

    Second-factor tests (TOTP enrolment, passkey registration) must not reuse a
    shared account: once an account has a passkey or a TOTP secret its password
    login asks for that factor, and a later run - or a later test in the same
    run - can no longer sign in as it.
    """
    created = []
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)

    def make(prefix: str = "u") -> tuple[str, str]:
        name = f"{prefix}{secrets.token_hex(4)}"
        pw = "Ui-" + secrets.token_hex(12)
        api.ok("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member",
                                               "display_name": name})
        created.append(name)
        return name, pw

    yield make
    api.elevate(server.admin_password)
    for name in created:
        found = api.request("GET", f"/api/v1/admin/users?q={name}")
        if found.status != 200:
            continue
        uid = next((u["id"] for u in found.json().get("items", []) if u["username"] == name), None)
        if uid:
            api.request("DELETE", f"/api/v1/admin/users/{uid}")


# ------------------------------------------------------------------ helpers
def login(page: Page, server: Server, username: str, password: str, totp_secret: str | None = None) -> None:
    """Signs in through /login (password, then the TOTP step when asked)."""
    page.goto("/login")
    page.get_by_label(SEL["login_user"]).fill(username)
    page.locator(SEL["login_password"]).first.fill(password)
    page.get_by_role("button", name=SEL["login_submit"], exact=True).click()
    page.wait_for_function("() => !location.pathname.startsWith('/login') || "
                           "!!document.querySelector('input[autocomplete=one-time-code]')")
    code = page.locator(SEL["login_code"])
    if code.count() and code.first.is_visible():
        assert totp_secret, f"{username} was asked for a TOTP code"
        code.first.fill(server.clock.code(totp_secret))
        # the code field submits by itself once six digits are in; the button is a fallback
        try:
            page.get_by_role("button", name=SEL["login_verify"]).click(timeout=2500)
        except PlaywrightError:
            pass
    page.wait_for_url(re.compile(r"^(?!.*/login).*$"))


def confirm_identity(page: Page, password: str) -> None:
    """Answers the step-up dialog ("Confirm your identity") with the password: setting up an
    authenticator app or a passkey needs step-up (DESIGN §9.3), which the web app asks for."""
    dlg = page.get_by_role("dialog", name=re.compile(r"confirm your identity", re.I))
    # the field itself: get_by_label("Password") also matches the "Show password" toggle
    dlg.get_by_role("textbox", name="Password", exact=True).fill(password)
    dlg.get_by_role("button", name="Confirm").click()


def pick_files(page: Page, opener, paths, folder: bool = False):
    """Runs `opener()` (the click that opens a file picker) and hands it `paths`.

    upload/manager.js creates its <input type=file> inside the click handler and
    removes it again, so there is no stable input to `set_input_files` on - the
    file chooser event is the only hook. `folder=True` also checks that the
    picker really asked for a directory.
    """
    paths = [str(p) for p in (paths if isinstance(paths, (list, tuple)) else [paths])]
    with page.expect_file_chooser() as info:
        opener()
    chooser = info.value
    if folder:
        assert chooser.element.get_attribute("webkitdirectory") is not None, \
            "the folder picker did not ask for a directory"
    chooser.set_files(paths)


def start_upload(page: Page) -> None:
    """Confirms the pre-upload dialog (destination / bundle / conflict policy)."""
    dlg = page.get_by_role("dialog")
    dlg.get_by_role("button", name=re.compile(r"^(upload|start)", re.I)).first.click()
    dlg.wait_for(state="hidden")


def dismiss_uploads(page: Page) -> None:
    """Closes the upload queue card and any toast, which float over the file list.

    Toasts time out on their own, so a button can vanish mid-click - that is a
    success, not a failure.
    """
    for sel in ("[aria-label='Uploads'] button[aria-label='Close']",
                "[aria-label='Notifications'] button[aria-label='Dismiss']"):
        for _ in range(5):
            btn = page.locator(sel).first
            try:
                if not btn.count() or not btn.is_visible():
                    break
                btn.click(timeout=2000)
            except PlaywrightError:
                break
            page.wait_for_timeout(150)
    page.wait_for_timeout(200)


def shot(page: Page, request, name: str) -> pathlib.Path:
    """Full-page screenshot to tests/ui/screenshots/<test>-<name>.png."""
    SHOTS.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{request.node.name}-{name}")
    path = SHOTS / f"{safe}.png"
    page.screenshot(path=str(path), full_page=True)
    return path


def assert_no_overflow(page: Page) -> None:
    """No horizontal scrolling at the current viewport."""
    sizes = page.evaluate("() => [document.documentElement.scrollWidth, window.innerWidth, "
                          "document.body ? document.body.scrollWidth : 0]")
    assert max(sizes[0], sizes[2]) <= sizes[1] + 1, f"horizontal overflow: scrollWidth {sizes[0]}/{sizes[2]} > {sizes[1]}"


TAP_TARGETS_JS = """
(min) => {
  const sel = 'a[href], button, input:not([type=hidden]), select, textarea, summary, [role=button], [role=tab], [role=menuitem], [tabindex="0"]';
  const bad = [];
  for (const el of document.querySelectorAll(sel)) {
    if (el.closest('[hidden], [aria-hidden=true], .visually-hidden, .sr-only')) continue;
    if (el.disabled) continue;
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    if (r.width === 0 || r.height === 0 || cs.visibility === 'hidden' || cs.display === 'none') continue;
    if (r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth) continue;
    // links inside running text are exempt (WCAG 2.5.8 inline exception)
    if (el.tagName === 'A' && el.closest('p, li > span, td') && cs.display === 'inline') continue;
    if (el.type === 'checkbox' || el.type === 'radio') {
      const lab = el.closest('label') || (el.id && document.querySelector(`label[for="${el.id}"]`));
      if (lab) { const lr = lab.getBoundingClientRect(); if (Math.min(lr.width, lr.height) >= min) continue; }
    }
    if (Math.min(r.width, r.height) < min) {
      bad.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${String(el.className).split(' ').join('.')} ` +
               `"${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 30)}" ${Math.round(r.width)}x${Math.round(r.height)}`);
    }
  }
  return bad;
}
"""


# Waivers for targets a verification round reported and that are not fixed yet: the
# flow tests skip them so they keep checking everything else, while the dedicated
# regression test in test_mobile.py holds the full DESIGN §13.5 bar (44 px).
# Empty on purpose - round 2 fixed both entries that used to live here
# (.url-row-link on /admin/network and .row-link on /admin/users + /admin/groups),
# so nothing is waived. Matching is a substring test, so an entry here would also
# cover every class whose name contains it.
KNOWN_SMALL_TARGETS: tuple[str, ...] = ()


def assert_tap_targets(page: Page, min_px: int = 40, ignore: tuple[str, ...] = KNOWN_SMALL_TARGETS) -> None:
    """Every visible interactive element is at least min_px in both dimensions."""
    bad = [b for b in page.evaluate(TAP_TARGETS_JS, min_px) if not any(i in b for i in ignore)]
    assert not bad, f"tap targets smaller than {min_px} px:\n" + "\n".join(bad)


def long_press(page: Page, locator, ms: int = 650) -> None:
    """Touch long-press on the centre of locator (CDP touch events).

    The element is centred first: Playwright's scroll_into_view_if_needed stops
    as soon as the box is inside the layout viewport, which on phones can leave
    it underneath the fixed bottom tab bar - the touch would hit the tab bar.
    """
    locator.evaluate("el => el.scrollIntoView({block: 'center', inline: 'nearest'})")
    page.wait_for_timeout(250)
    box = locator.bounding_box()
    assert box, "element has no box"
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    cdp = page.context.new_cdp_session(page)
    cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [{"x": x, "y": y}]})
    page.wait_for_timeout(ms)
    cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
    cdp.detach()


def add_virtual_authenticator(page: Page) -> tuple:
    """Enables a CTAP2 platform authenticator with user verification (CDP WebAuthn)."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    res = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
    return cdp, res["authenticatorId"]
