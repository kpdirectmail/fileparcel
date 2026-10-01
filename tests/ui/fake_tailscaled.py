"""A fake tailscaled for the Funnel/Serve UI tests (never the real one).

It answers the LocalAPI endpoints FileParcel uses on a Unix socket in a
short temporary directory - status, prefs, serve-config (GET with an Etag,
"null" when empty; POST only with a matching If-Match, 412 otherwise) and
query-feature - and it can play tailscaled's part towards FileParcel: dial
the ingress socket FileParcel opened in its run directory and forward a
request with the proxy headers tailscaled sets (X-Forwarded-For/Host/Proto,
Tailscale-Funnel-Request for internet visitors).

The server under test reaches it through FILEPARCEL_TAILSCALE_SOCKET, which
also disables FileParcel's fallback to the tailscale CLI, so nothing can
reach the tailscaled of the machine running the tests.
"""

from __future__ import annotations

import copy
import hashlib
import http.client
import json
import os
import shutil
import socket
import socketserver
import tempfile
import threading
from http.server import BaseHTTPRequestHandler

NODE_NAME = "node.tail.ts.net"
FUNNEL_PORTS_CAP = "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000"
NO_FUNNEL_URL = "https://tailscale.com/s/no-funnel"


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class FakeTailscaled:
    """The fake daemon. Its attributes may be changed while it runs (under `lock`)."""

    def __init__(self) -> None:
        # AF_UNIX paths are limited to ~104 bytes: stay short, outside TMPDIR.
        self.dir = tempfile.mkdtemp(prefix="fpts", dir="/tmp" if os.path.isdir("/tmp") else None)
        self.path = os.path.join(self.dir, "tailscaled.sock")
        self.lock = threading.Lock()
        self.caps = ["https", "funnel", FUNNEL_PORTS_CAP]
        self.running = True
        self.config: dict | None = None  # the serve configuration (None = "null")
        self.posts: list[dict] = []  # {"if_match": ..., "config": ...} of every accepted POST
        self.query_feature = {"Complete": True}
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def address_string(self) -> str:  # a Unix socket has no peer address
                return "unix"

            def log_message(self, fmt, *args) -> None:  # quiet
                pass

            def _send(self, status: int, body: bytes, headers: dict | None = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json" if status < 400 else "text/plain")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _guard(self) -> bool:
                # tailscaled's LocalAPI refuses browsers: a Host other than its own, Origin or Referer.
                if self.headers.get("Host") not in ("local-tailscaled.sock", None) or \
                        self.headers.get("Origin") or self.headers.get("Referer"):
                    self._send(403, b"invalid localapi request")
                    return False
                return True

            def do_GET(self) -> None:  # noqa: N802 - http.server hook
                if not self._guard():
                    return
                path = self.path.split("?", 1)[0]
                if path == "/localapi/v0/status":
                    self._send(200, json.dumps(fake.status()).encode())
                elif path == "/localapi/v0/prefs":
                    self._send(200, json.dumps({"ControlURL": "https://controlplane.tailscale.com", "OperatorUser": "",
                                                "ShieldsUp": False, "WantRunning": True}).encode())
                elif path == "/localapi/v0/serve-config":
                    body, tag = fake.serve_config()
                    self._send(200, body, {"Etag": tag})
                else:
                    self._send(404, b"not found")

            def do_POST(self) -> None:  # noqa: N802 - http.server hook
                if not self._guard():
                    return
                n = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(n) if n else b""
                path = self.path.split("?", 1)[0]
                if path == "/localapi/v0/query-feature":
                    with fake.lock:
                        answer = dict(fake.query_feature)
                    self._send(200, json.dumps(answer).encode())
                    return
                if path != "/localapi/v0/serve-config":
                    self._send(404, b"not found")
                    return
                with fake.lock:
                    _, tag = fake._serve_config_locked()
                    if_match = self.headers.get("If-Match") or ""
                    if if_match != tag:
                        # FileParcel never sends an empty If-Match (it would overwrite unconditionally).
                        self._send(412, b"etag mismatch")
                        return
                    cfg = json.loads(data or b"null")
                    fake.config = cfg if cfg else None
                    fake.posts.append({"if_match": if_match, "config": copy.deepcopy(cfg)})
                self._send(200, b"")

        self._server = _UnixServer(self.path, Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    # ---------------------------------------------------------------- state
    def status(self) -> dict:
        with self.lock:
            caps = list(self.caps)
            running = self.running
        return {
            "Version": "1.102.4", "TUN": True, "BackendState": "Running" if running else "Stopped",
            # An address no local interface carries: FileParcel skips its self-probe.
            "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1"],
            "Self": {"ID": "nTESTNODE1CNTRL", "HostName": "node", "DNSName": NODE_NAME + ".",
                     "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1"], "CapMap": {c: None for c in caps}},
            "MagicDNSSuffix": "tail.ts.net", "CertDomains": [NODE_NAME],
            "CurrentTailnet": {"Name": "example.org", "MagicDNSSuffix": "tail.ts.net", "MagicDNSEnabled": True},
        }

    def _serve_config_locked(self) -> tuple[bytes, str]:
        body = b"null" if self.config is None else json.dumps(self.config, sort_keys=True).encode()
        return body, hashlib.sha256(body).hexdigest()

    def serve_config(self) -> tuple[bytes, str]:
        with self.lock:
            return self._serve_config_locked()

    def set_config(self, cfg: dict | None) -> None:
        with self.lock:
            self.config = copy.deepcopy(cfg) if cfg else None

    def get_config(self) -> dict | None:
        with self.lock:
            return copy.deepcopy(self.config)

    def set_caps(self, caps: list[str]) -> None:
        with self.lock:
            self.caps = list(caps)

    def set_query_feature(self, answer: dict) -> None:
        with self.lock:
            self.query_feature = dict(answer)

    # ------------------------------------------------------ playing tailscaled
    def forward(self, home: str, method: str, path: str, *, kind: str = "funnel", public: bool = True,
                client: str = "203.0.113.9", host: str = NODE_NAME, headers: dict | None = None,
                body: bytes | None = None) -> tuple[int, dict, bytes]:
        """Sends a request to FileParcel's ingress socket the way tailscaled forwards a visitor.
        Returns (status, lower-cased headers - Set-Cookie values joined by "\\n", body)."""
        sock_path = os.path.join(home, "run", f"ts-{kind}.sock")
        hdr = {"X-Forwarded-For": client, "X-Forwarded-Host": host, "X-Forwarded-Proto": "https"}
        if public:
            hdr["Tailscale-Funnel-Request"] = "?1"
        hdr.update(headers or {})
        conn = _UnixHTTPConnection(sock_path)
        try:
            conn.request(method, path, body=body, headers=hdr)
            r = conn.getresponse()
            data = r.read()
            out: dict[str, str] = {}
            for k, v in r.getheaders():
                k = k.lower()
                out[k] = out[k] + "\n" + v if k in out else v
            return r.status, out, data
        finally:
            conn.close()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 over a Unix socket (Host "localhost", as tailscaled sends for unix: targets)."""

    def __init__(self, path: str, timeout: float = 30) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:  # noqa: D401 - http.client hook
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s
