#!/bin/sh
# Regenerate the runtime settings reference inside docs/FILEPARCEL.md from the
# settings catalog of the program itself ("fileparcel config list --all --json").
#
# Usage: scripts/gen-settings-docs.sh [options]
#
# The text between the lines
#     <!-- BEGIN GENERATED SETTINGS REFERENCE -->
#     <!-- END GENERATED SETTINGS REFERENCE -->
# is replaced by one table per settings section (key, default, label,
# description, allowed values, range, secret/restart markers), in catalog
# order. The catalog is read from a throw-away home created in a temporary
# directory (never from a real installation), so the defaults are the
# program's defaults, not anybody's configured values.
#
# Options:
#   --bin PATH     use this fileparcel binary (default: build one for this
#                  machine with scripts/build.sh into a temporary directory)
#   --doc FILE     the document to update (default: docs/FILEPARCEL.md)
#   --check        do not write; exit 1 when the document is out of date
#   -h, --help     show this help
#
# Needs python3 (standard library only) to format the tables.
# Exit status: 0 ok (or up to date), 1 out of date (--check) or an error,
# 2 usage error.
#
# POSIX sh; works with dash, bash (incl. macOS bash 3.2) and zsh.
set -eu

PROG=gen-settings-docs.sh
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(dirname -- "$SCRIPT_DIR")
BEGIN='<!-- BEGIN GENERATED SETTINGS REFERENCE -->'
END='<!-- END GENERATED SETTINGS REFERENCE -->'

usage() { sed -n '2,/^# POSIX sh/{s/^# \{0,1\}//;p;}' "$SCRIPT_DIR/gen-settings-docs.sh"; }
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

BIN=""
DOC="$REPO/docs/FILEPARCEL.md"
CHECK=0
while [ $# -gt 0 ]; do
    case $1 in
        --bin) [ $# -ge 2 ] || die "--bin needs a path"; BIN=$2; shift ;;
        --bin=*) BIN=${1#*=} ;;
        --doc) [ $# -ge 2 ] || die "--doc needs a file"; DOC=$2; shift ;;
        --doc=*) DOC=${1#*=} ;;
        --check) CHECK=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%s: unknown option: %s (see --help)\n' "$PROG" "$1" >&2; exit 2 ;;
    esac
    shift
done

command -v python3 >/dev/null 2>&1 || die "python3 is needed to format the tables"
[ -f "$DOC" ] || die "no such document: $DOC"
grep -qxF "$BEGIN" "$DOC" || die "$DOC has no line '$BEGIN'"
grep -qxF "$END" "$DOC" || die "$DOC has no line '$END'"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/fp-settings-docs.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "$BIN" ]; then
    sh "$SCRIPT_DIR/build.sh" -q -o "$TMP/bin" -v dev host >/dev/null || die "building fileparcel failed"
    BIN="$TMP/bin/fileparcel"
fi
[ -x "$BIN" ] || die "not executable: $BIN"

# A scratch home: environment overrides must not leak into it.
for v in $(env | sed -n 's/^\(FILEPARCEL_[A-Z0-9_]*\)=.*/\1/p'); do
    unset "$v"
done
(umask 077 && od -An -N18 -tx1 /dev/urandom | tr -d ' \n' >"$TMP/admin.pw")
"$BIN" init --home "$TMP/home" --port 18443 --http-port 0 --admin admin \
    --admin-password-file "$TMP/admin.pw" --access private --non-interactive >"$TMP/init.log" 2>&1 ||
    die "fileparcel init failed: $(tail -n 3 "$TMP/init.log")"
"$BIN" --home "$TMP/home" --offline --json config list --all >"$TMP/catalog.json" 2>"$TMP/config.log" ||
    die "fileparcel config list failed: $(tail -n 3 "$TMP/config.log")"

python3 - "$TMP/catalog.json" >"$TMP/settings.md" <<'PY' || die "formatting the settings tables failed"
import json
import sys

# Section titles as in Admin -> Settings: the SECTIONS labels of
# web/static/js/pages/admin/settings.js (tests/docs checks the two agree).
TITLES = {
    "general": "General", "network": "Network", "mdns": "Local name (mDNS)", "tls": "TLS",
    "acme": "ACME certificates", "tailscale": "Tailscale", "funnel": "Tailscale Funnel", "mtls": "Client certificates",
    "auth": "Sign-in & security", "ratelimit": "Rate limits", "storage": "Storage", "sharing": "Sharing",
    "keys": "Encryption", "backup": "Backups", "email": "Email", "audit": "Audit",
    "server": "Server (stored in fileparcel.toml)",
}


def default(s):
    if s.get("secret"):
        return "*(secret, unset)*"
    d = s.get("default")
    if isinstance(d, bool):
        v = "true" if d else "false"
    elif d is None or d == "":
        v = '""'
    elif isinstance(d, str):
        v = d
    elif isinstance(d, list):
        v = "[" + ", ".join(json.dumps(x, ensure_ascii=False) for x in d) + "]"
    else:
        v = json.dumps(d, ensure_ascii=False)
    return "`" + v + "`"


def row(s):
    parts = ["**" + s["label"].rstrip(".") + ".**"]
    desc = (s.get("description") or "").strip()
    if desc:
        parts.append(desc if desc.endswith((".", ")", "!", "?")) else desc + ".")
    kind = s.get("type")
    if s.get("enum"):
        parts.append("One of: " + ", ".join("`" + e + "`" for e in s["enum"]) + ".")
    if kind == "int" and s.get("min") is not None and s.get("max") is not None:
        parts.append("Range %d–%d." % (s["min"], s["max"]))
    parts.append({"strings": "List.", "cidrs": "List of CIDRs/IPs.",
                  "cron": "Cron expression (5 fields)."}.get(kind, ""))
    if s.get("secret"):
        parts.append("*Secret.*")
    if s.get("restart"):
        parts.append("*Restart.*")
    text = " ".join(p for p in parts if p).replace("|", "\\|").replace("\n", " ")
    return "| `%s` | %s | %s |" % (s["key"], default(s), text)


catalog = json.load(open(sys.argv[1], encoding="utf-8"))
sections, rows = [], {}
for s in catalog:
    if s["section"] not in rows:
        sections.append(s["section"])
        rows[s["section"]] = []
    rows[s["section"]].append(s)
out = []
for sec in sections:
    out += ["#### " + TITLES.get(sec, sec.capitalize()), "", "| Key | Default | Description |", "|---|---|---|"]
    out += [row(s) for s in sorted(rows[sec], key=lambda x: (x.get("order", 0), x["key"]))]
    out.append("")
sys.stdout.write("\n".join(out).rstrip() + "\n")
PY
[ -s "$TMP/settings.md" ] || die "the settings catalog is empty"

awk -v begin="$BEGIN" -v end="$END" -v ref="$TMP/settings.md" '
    $0 == begin {
        print
        print "<!-- Regenerate with scripts/gen-settings-docs.sh; edit the setting labels and descriptions in the owning package (settings.Register) instead. -->"
        print ""
        while ((getline line < ref) > 0) print line
        close(ref)
        print ""
        skip = 1
        next
    }
    $0 == end { skip = 0 }
    !skip { print }
' "$DOC" >"$TMP/doc.md"

if cmp -s "$DOC" "$TMP/doc.md"; then
    printf '%s: %s is up to date\n' "$PROG" "$DOC" >&2
    exit 0
fi
if [ "$CHECK" -eq 1 ]; then
    printf '%s: the settings reference in %s is out of date; run scripts/gen-settings-docs.sh\n' "$PROG" "$DOC" >&2
    exit 1
fi
cat "$TMP/doc.md" >"$DOC"
printf '%s: updated the settings reference in %s\n' "$PROG" "$DOC" >&2
