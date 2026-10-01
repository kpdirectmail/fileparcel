#!/bin/sh
# Regenerate the command reference at the end of docs/COMMANDS.md from the
# program itself ("fileparcel docs --markdown").
#
# Usage: scripts/gen-cli-docs.sh [options]
#
# The text between the lines
#     <!-- BEGIN GENERATED CLI REFERENCE -->
#     <!-- END GENERATED CLI REFERENCE -->
# is replaced by the output of "fileparcel docs --markdown", with every
# heading moved one level down (the reference is the "## Command reference"
# section of the guide). Headings inside fenced code blocks are left alone.
#
# Options:
#   --bin PATH     use this fileparcel binary (default: build one for this
#                  machine with scripts/build.sh into a temporary directory)
#   --doc FILE     the document to update (default: docs/COMMANDS.md)
#   --check        do not write; exit 1 when the document is out of date
#   -h, --help     show this help
#
# Exit status: 0 ok (or up to date), 1 out of date (--check) or an error,
# 2 usage error.
#
# POSIX sh; works with dash, bash (incl. macOS bash 3.2) and zsh.
set -eu

PROG=gen-cli-docs.sh
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(dirname -- "$SCRIPT_DIR")
BEGIN='<!-- BEGIN GENERATED CLI REFERENCE -->'
END='<!-- END GENERATED CLI REFERENCE -->'

usage() { sed -n '2,/^# POSIX sh/{s/^# \{0,1\}//;p;}' "$SCRIPT_DIR/gen-cli-docs.sh"; }
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

BIN=""
DOC="$REPO/docs/COMMANDS.md"
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

[ -f "$DOC" ] || die "no such document: $DOC"
grep -qxF "$BEGIN" "$DOC" || die "$DOC has no line '$BEGIN'"
grep -qxF "$END" "$DOC" || die "$DOC has no line '$END'"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/fp-docs.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "$BIN" ]; then
    sh "$SCRIPT_DIR/build.sh" -q -o "$TMP/bin" -v dev host >/dev/null || die "building fileparcel failed"
    BIN="$TMP/bin/fileparcel"
fi
[ -x "$BIN" ] || die "not executable: $BIN"

"$BIN" docs --markdown -o "$TMP/ref.md" || die "\"fileparcel docs --markdown\" failed"
[ -s "$TMP/ref.md" ] || die "\"fileparcel docs --markdown\" produced no output"

# Shift headings one level down outside fenced code blocks (``` or ~~~).
awk '
    /^[ \t]*(```|~~~)/ { fence = !fence; print; next }
    !fence && /^#+ / { match($0, /^#+/); if (RLENGTH <= 5) { print "#" $0; next } }
    { print }
' "$TMP/ref.md" >"$TMP/ref.shifted.md"

# Splice it between the markers.
awk -v begin="$BEGIN" -v end="$END" -v ref="$TMP/ref.shifted.md" '
    $0 == begin {
        print
        print "<!-- Regenerate with scripts/gen-cli-docs.sh; edit the command help texts in internal/cli instead. -->"
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
    printf '%s: the command reference in %s is out of date; run scripts/gen-cli-docs.sh\n' "$PROG" "$DOC" >&2
    exit 1
fi
cat "$TMP/doc.md" >"$DOC"
printf '%s: updated the command reference in %s\n' "$PROG" "$DOC" >&2
