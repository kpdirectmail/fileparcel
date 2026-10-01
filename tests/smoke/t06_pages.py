#!/usr/bin/env python3
"""Phase 6: pages render with the right headers, static assets, HTTP->HTTPS."""
import http.client
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

st = load_state()
c = admin_client()
anon = Client()

CSP_APP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
           "media-src 'self' blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; "
           "manifest-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; "
           "form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types fp")

TEMPLATE_SMELL = re.compile(r"\{\{|<no value>|&lt;no value&gt;|ZgotmplZ|%!\w\(")


def page(client, path, name, expect=200):
    r = client.get(path)
    ok = check("GET %s -> %d" % (path, expect), r.status == expect, "%d %s" % (r.status, r.text()[:200]))
    if r.status != expect:
        return r
    if expect != 200:
        return r
    body = r.text()
    check("%s is HTML" % name, "text/html" in (r.header("Content-Type") or ""), r.header("Content-Type"))
    check("%s CSP is CSPApp" % name, r.header("Content-Security-Policy") == CSP_APP,
          r.header("Content-Security-Policy"))
    check("%s X-Frame-Options DENY" % name, r.header("X-Frame-Options") == "DENY", r.header("X-Frame-Options"))
    check("%s nosniff" % name, r.header("X-Content-Type-Options") == "nosniff", r.header("X-Content-Type-Options"))
    check("%s referrer-policy" % name, r.header("Referrer-Policy") == "no-referrer", r.header("Referrer-Policy"))
    check("%s Cache-Control no-store" % name, "no-store" in (r.header("Cache-Control") or ""),
          r.header("Cache-Control"))
    check("%s COOP same-origin" % name, r.header("Cross-Origin-Opener-Policy") == "same-origin",
          r.header("Cross-Origin-Opener-Policy"))
    check("%s has no template error" % name, not TEMPLATE_SMELL.search(body),
          (TEMPLATE_SMELL.search(body).group(0) if TEMPLATE_SMELL.search(body) else ""))
    check("%s is a complete document" % name,
          body.lstrip()[:15].lower().startswith("<!doctype html") and "</html>" in body.lower(),
          body[:80])
    # CSP has no 'unsafe-inline': every executable script must be external.
    # <script type="application/json"> is data, not script, and is allowed.
    inline = [m.group(0) for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>", body)
              if "application/json" not in m.group(0)]
    check("%s has no executable inline script" % name, not inline, inline[:3])
    check("%s boot data is a JSON data block" % name,
          ('type="application/json"' in body) or ("fp-boot" not in body),
          fail_detail="fp-boot is not application/json")
    return r


# ---------- public pages ----------
page(anon, "/login", "login")
page(anon, "/trust", "trust")
# /unlock only exists while the keys are sealed; unlocked it sends you home.
r = anon.get("/unlock")
check("GET /unlock while unlocked -> 303 /", r.status == 303 and r.header("Location") == "/",
      "%d %s" % (r.status, r.header("Location")))
page(anon, "/s/%s" % st["share_token"], "share page")
page(anon, "/s/%s" % st["request_token"], "file request page")

# /setup must be gone once the owner exists
r = anon.get("/setup")
check("GET /setup after setup -> not the setup form", r.status in (303, 302, 404, 410) or
      "setup_token" not in r.text(), "%d %s" % (r.status, r.text()[:200]))

# root redirects
r = anon.get("/")
check("GET / answers", r.status in (200, 302, 303, 307), "%d %s" % (r.status, r.text()[:120]))

# invite page
r = c.api("POST", "/admin/invites", json_body={"email": "page@example.org", "role": "member"})
itok = r.json().get("url", "").rstrip("/").rsplit("/", 1)[-1]
page(anon, "/invite/" + itok, "invite page")
# The invite page is static (no oracle): it always renders, and the API
# behind it is what refuses an unknown token.
r = anon.get("/invite/nosuchtoken")
check("bad invite page still renders (no oracle)", r.status == 200, "%d" % r.status)
check("bad invite page leaks nothing", "@example.org" not in r.text(), r.text()[:200])
r = anon.api("GET", "/auth/invite/nosuchtoken")
check("the invite API refuses the unknown token", r.status == 404, "%d %s" % (r.status, r.text()[:150]))

# ---------- SPA routes (authenticated) ----------
for p, name in [("/files", "files"), ("/admin", "admin"), ("/settings", "settings"),
                ("/shared", "shared"), ("/links", "links"), ("/requests", "requests"),
                ("/starred", "starred"), ("/recent", "recent"), ("/trash", "trash"),
                ("/activity", "activity"), ("/search", "search")]:
    page(c, p, name)

# subtrees
page(c, "/files/%s" % st["smoke"], "files/<id>")
page(c, "/admin/users", "admin/users")
page(c, "/settings/security", "settings/security")

# The app shell is served to anonymous visitors too (the SPA then redirects);
# it must never leak data.
r = anon.get("/files")
check("anonymous /files answers without leaking", r.status in (200, 302, 303),
      "%d %s" % (r.status, r.text()[:150]))
if r.status == 200:
    check("anonymous app shell has no user data", "usr_" not in r.text() and "admin@example.org" not in r.text(),
          r.text()[:300])

# ---------- static assets ----------
r = c.get("/theme.css")
check("GET /theme.css 200", r.status == 200, "%d" % r.status)
check("theme.css content-type", "text/css" in (r.header("Content-Type") or ""), r.header("Content-Type"))
r = c.get("/sw.js")
check("GET /sw.js 200", r.status == 200, "%d" % r.status)
check("sw.js content-type", "javascript" in (r.header("Content-Type") or ""), r.header("Content-Type"))
r = c.get("/manifest.webmanifest")
check("GET /manifest.webmanifest 200", r.status == 200, "%d" % r.status)
try:
    mf = json.loads(r.body)
    check("manifest is valid JSON with share_target",
          mf.get("share_target", {}).get("action") == "/share-target", list(mf))
except Exception as e:
    check("manifest is valid JSON", False, e)
r = c.get("/robots.txt")
check("GET /robots.txt 200", r.status == 200 and b"Disallow" in r.body, "%d %s" % (r.status, r.body[:80]))
r = c.get("/.well-known/security.txt")
check("GET /.well-known/security.txt 200", r.status == 200, "%d" % r.status)
r = c.get("/favicon.ico")
check("GET /favicon.ico 200", r.status == 200, "%d" % r.status)

# hashed static assets: find one referenced by the login page and fetch it
r = anon.get("/login")
assets = re.findall(r'["\'](/static/[^"\']+)["\']', r.text())
check("login page references hashed static assets", len(assets) > 0, r.text()[:300])
if assets:
    a = assets[0]
    r = anon.get(a)
    check("GET %s 200" % a, r.status == 200, "%d" % r.status)
    check("hashed asset is immutable-cacheable", "max-age" in (r.header("Cache-Control") or "").lower(),
          r.header("Cache-Control"))
    r = anon.get("/static/deadbeef/js/app.js")
    check("wrong static hash 404", r.status == 404, "%d" % r.status)

# ---------- HTTP -> HTTPS ----------
conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=15)
conn.request("GET", "/files?x=1", headers={"Host": "%s:%d" % (HOST, HTTP_PORT)})
rr = conn.getresponse()
rr.read()
loc = rr.getheader("Location")
conn.close()
check("HTTP redirects to HTTPS", rr.status in (301, 307, 308), rr.status)
check("redirect is 308 permanent", rr.status == 308, rr.status)
check("redirect keeps host, path and query",
      loc == "https://%s:%d/files?x=1" % (HOST, PORT), loc)

conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=15)
conn.request("POST", "/api/v1/auth/login", body=b"{}",
             headers={"Host": "%s:%d" % (HOST, HTTP_PORT), "Content-Type": "application/json"})
rr = conn.getresponse()
rr.read()
check("HTTP POST also redirected (308 keeps the method)", rr.status == 308, rr.status)
conn.close()

# The HTTP port hands /.well-known/acme-challenge/ to certmagic first; with
# no ACME order in flight an unknown token falls through to the redirect.
conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=15)
conn.request("GET", "/.well-known/acme-challenge/probe-token",
             headers={"Host": "%s:%d" % (HOST, HTTP_PORT)})
rr = conn.getresponse()
rr.read()
check("ACME challenge path reaches the challenge handler (no order: redirect)",
      rr.status in (308, 404), rr.status)
conn.close()

# ---------- no 5xx and no template errors in the log ----------
logp = os.path.join(HOME, "logs", "fileparcel.log")
if os.path.exists(logp):
    with open(logp, "r", errors="replace") as f:
        log = f.read()
    bad = [l for l in log.splitlines()
           if ("level=ERROR" in l or "status=500" in l or "status=502" in l or "status=503" in l)
           and "tailscale" not in l.lower() and "acme" not in l.lower()]
    check("no unexplained 5xx / ERROR lines in the log", not bad, bad[:5])
    tmpl = [l for l in log.splitlines() if "template" in l.lower() and "level=ERROR" in l]
    check("no template errors in the log", not tmpl, tmpl[:5])
else:
    check("server log file exists", False, logp)

sys.exit(1 if summary() else 0)
