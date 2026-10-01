#!/bin/sh
# Check that docs/THIRD_PARTY.md lists every Go module linked into the
# fileparcel binary, with the linked version (run after dependency changes),
# and that the curated "Packages used" table in docs/FILEPARCEL.md lists every
# direct (non-indirect) module in go.mod with the same version.
#
# Usage: scripts/check-third-party.sh [--bin PATH] [--no-curated]
#
#   --bin PATH    check this binary (default: build one for this machine with
#                 scripts/build.sh into a temporary directory)
#   --no-curated  skip the docs/FILEPARCEL.md "Packages used" check
#   -h, --help    show this help
#
# Exit status: 0 complete, 1 modules missing or with another version, 2 usage.
#
# POSIX sh; works with dash, bash (incl. macOS bash 3.2) and zsh.
set -eu

PROG=check-third-party.sh
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(dirname -- "$SCRIPT_DIR")
DOC="$REPO/docs/THIRD_PARTY.md"
MANUAL="$REPO/docs/FILEPARCEL.md"

usage() { sed -n '2,/^# POSIX sh/{s/^# \{0,1\}//;p;}' "$SCRIPT_DIR/check-third-party.sh"; }
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

BIN=""
CURATED=1
while [ $# -gt 0 ]; do
    case $1 in
        --bin) [ $# -ge 2 ] || die "--bin needs a path"; BIN=$2; shift ;;
        --bin=*) BIN=${1#*=} ;;
        --no-curated) CURATED=0 ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%s: unknown option: %s (see --help)\n' "$PROG" "$1" >&2; exit 2 ;;
    esac
    shift
done

[ -f "$DOC" ] || die "missing $DOC"

# shellcheck source=scripts/env.sh
. "$SCRIPT_DIR/env.sh" 2>/dev/null || true
command -v go >/dev/null 2>&1 || die "no Go toolchain found (scripts/get-go.sh 1.27.1)"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/fp-3p.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "$BIN" ]; then
    sh "$SCRIPT_DIR/build.sh" -q -o "$TMP" -v dev host >/dev/null || die "building fileparcel failed"
    BIN="$TMP/fileparcel"
fi
[ -f "$BIN" ] || die "no such file: $BIN"

go version -m "$BIN" >"$TMP/mods" || die "go version -m failed for $BIN"
bad=0
n=0
# lines: "<tab>dep<tab><module><tab><version><tab><sum>"; "=>" lines are replacements
while read -r kind mod ver _; do
    [ "$kind" = dep ] || continue
    n=$((n + 1))
    if ! grep -qF "| [$mod](" "$DOC"; then
        printf 'missing: %s %s\n' "$mod" "$ver"
        bad=1
    elif ! grep -F "| [$mod](" "$DOC" | grep -qF "| $ver |"; then
        printf 'version: %s is %s in the binary but listed as: %s\n' "$mod" "$ver" \
            "$(grep -F "| [$mod](" "$DOC" | head -n 1 | cut -d'|' -f3 | tr -d ' ')"
        bad=1
    fi
done <"$TMP/mods"

[ "$n" -gt 0 ] || die "no modules found in $BIN (built with -buildvcs/-trimpath is fine; stripped module info is not)"
if [ "$bad" -ne 0 ]; then
    printf '%s: docs/THIRD_PARTY.md is out of date (add the modules, their licenses and license texts)\n' "$PROG" >&2
fi

# The curated "Packages used" table in the manual lists the direct dependencies
# only, by hand, so nothing else notices when one is added and the table is not.
curated_bad=0
m=0
if [ "$CURATED" -eq 1 ]; then
    [ -f "$MANUAL" ] || die "missing $MANUAL"
    # Every non-indirect module of go.mod's require block(s): "<module> <version>".
    awk '
        /^require[ \t]*\(/        { blk = 1; next }
        blk && /^\)/              { blk = 0; next }
        /\/\/ indirect/           { next }
        blk && $1 ~ /^\/\//       { next }
        blk && NF >= 2            { print $1, $2; next }
        /^require[ \t]+[^(]/ && NF >= 3 { print $2, $3 }
    ' "$REPO/go.mod" >"$TMP/direct" || die "cannot read $REPO/go.mod"
    while read -r mod ver; do
        [ -n "$mod" ] || continue
        m=$((m + 1))
        if ! grep -qF "| [$mod](" "$MANUAL"; then
            printf 'missing from the manual: %s %s\n' "$mod" "$ver"
            curated_bad=1
        elif ! grep -F "| [$mod](" "$MANUAL" | grep -qF "| $ver |"; then
            printf 'version in the manual: %s is %s in go.mod but listed as: %s\n' "$mod" "$ver" \
                "$(grep -F "| [$mod](" "$MANUAL" | head -n 1 | cut -d'|' -f3 | tr -d ' ')"
            curated_bad=1
        fi
    done <"$TMP/direct"
    [ "$m" -gt 0 ] || die "no direct modules found in $REPO/go.mod"
    if [ "$curated_bad" -ne 0 ]; then
        printf '%s: the "Packages used" table in docs/FILEPARCEL.md is out of date\n' "$PROG" >&2
    fi
fi

if [ "$bad" -ne 0 ] || [ "$curated_bad" -ne 0 ]; then
    exit 1
fi
printf '%s: all %d linked modules are listed in docs/THIRD_PARTY.md\n' "$PROG" "$n" >&2
if [ "$CURATED" -eq 1 ]; then
    printf '%s: all %d direct modules are listed in docs/FILEPARCEL.md\n' "$PROG" "$m" >&2
fi
