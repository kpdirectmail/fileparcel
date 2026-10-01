#!/usr/bin/env python3
"""Match every mounted route against what the smoke run actually requested."""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SMOKE_DIR = os.environ.get("FP_SMOKE_DIR", os.path.join(os.environ.get("TMPDIR", "/tmp"), "fileparcel-smoke"))
HOME = os.environ.get("FP_HOME", os.path.join(SMOKE_DIR, "h1"))
LOG_PATH = os.path.join(HOME, "logs", "fileparcel.log")

# The route table is the designRoutes list in internal/wire/routes_test.go;
# TestRouterMatchesDesign keeps it equal to what the router really mounts, so
# reading it here needs no generated file that could go stale.
ROUTES_GO = os.path.join(REPO, "internal", "wire", "routes_test.go")


def load_routes():
    override = os.path.join(HERE, "routes_live.txt")
    if os.path.exists(override):
        src = open(override).read()
    else:
        go = open(ROUTES_GO).read()
        m = re.search(r"designRoutes\s*=\s*\[\]string\{(.*?)\n\}", go, re.S)
        if not m:
            sys.exit("coverage: cannot find designRoutes in %s" % ROUTES_GO)
        src = "\n".join(re.findall(r'"([A-Z]+ /[^"]*)"', m.group(1)))
    out = []
    for line in src.splitlines():
        line = line.strip()
        if not line:
            continue
        meth, path = line.split(None, 1)
        out.append((meth.upper(), path))
    return out


routes = load_routes()


def to_re(p):
    # chi patterns: {id}, {id:regex}, wildcard *
    out = ""
    i = 0
    while i < len(p):
        ch = p[i]
        if ch == "{":
            j = p.index("}", i)
            out += r"[^/]+"
            i = j + 1
        elif ch == "*":
            out += r".*"
            i += 1
        else:
            out += re.escape(ch)
            i += 1
    return re.compile("^" + out + "$")


compiled = [(m, p, to_re(p)) for m, p in routes]
hits = {(m, p): 0 for m, p in routes}

LOG = re.compile(r'method=(\w+) path=(?:"([^"]+)"|(\S+))')
seen = 0
unmatched = set()
if not os.path.exists(LOG_PATH):
    sys.exit("coverage: no server log at %s" % LOG_PATH)
with open(LOG_PATH, errors="replace") as f:
    for line in f:
        mm = LOG.search(line)
        if not mm:
            continue
        method = mm.group(1).upper()
        path = (mm.group(2) or mm.group(3) or "").split("?")[0]
        seen += 1
        got = False
        # longest (most specific) pattern first
        for m, p, rx in sorted(compiled, key=lambda t: -len(t[1])):
            if (m == method or (method == "HEAD" and m == "GET")) and rx.match(path):
                hits[(m, p)] += 1
                got = True
                break
        if not got:
            unmatched.add((method, path))

covered = [k for k, v in hits.items() if v]
missed = sorted(k for k, v in hits.items() if not v)
print("log lines with a request: %d" % seen)
print("routes mounted: %d" % len(routes))
print("routes exercised: %d (%.1f%%)" % (len(covered), 100.0 * len(covered) / len(routes)))
print("routes NOT exercised: %d" % len(missed))
for m, p in missed:
    print("   %-6s %s" % (m, p))
if unmatched:
    print("\nrequests that matched no route (404s etc.): %d" % len(unmatched))
    for m, p in sorted(unmatched)[:15]:
        print("   %-6s %s" % (m, p))
