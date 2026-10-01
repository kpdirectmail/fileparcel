#!/bin/sh
# FileParcel build script: cross-compiles the release targets in parallel, or
# builds the binary for this machine ("host").
#
# Usage: scripts/build.sh [options] [TARGET...]
#
# Targets (default: all):
#   all            linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64
#   host           this machine (go env GOOS/GOARCH/GOARM) -> OUTDIR/fileparcel
#   OS/ARCH        one release target -> OUTDIR/fileparcel-OS-ARCH
#                  (linux/arm is built with GOARM=7)
#
# Options:
#   -o, --out DIR       output directory (default: <src>/dist, or <src>/bin when
#                       only "host" is built)
#   -s, --src DIR       source tree containing go.mod (default: the tree that
#                       contains this script)
#   -v, --version V     buildinfo.Version (default: the vN tag at HEAD, else "dev")
#   -c, --commit C      buildinfo.Commit (default: HEAD, 12 hex digits, "-dirty"
#                       when the working tree has changes)
#   -d, --date D        buildinfo.Date (default: the commit date, else now; UTC ISO 8601)
#   -j, --jobs N        run at most N builds at once (default: all targets at once)
#   -q, --quiet         only print errors and the final summary
#   -h, --help          show this help
#
# Every build uses CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath
# -buildvcs=false -ldflags "-s -w -X fileparcel/internal/buildinfo.…". GOFLAGS
# from the environment is honoured. Go is located with scripts/env.sh (PATH,
# then ~/sdk/go*/bin); Go >= 1.26 is required.
#
# Exit status: 0 ok, 1 a build failed, 2 usage error, 3 no suitable Go toolchain.
#
# POSIX sh; works with dash, bash (incl. macOS bash 3.2) and zsh.
set -eu

PROG=build.sh
RELEASE_TARGETS="linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64"
BUILDINFO_PKG=fileparcel/internal/buildinfo

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

usage() {
    sed -n '2,/^# POSIX sh/{s/^# \{0,1\}//;p;}' "$SCRIPT_DIR/build.sh"
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
usage_error() { printf '%s: %s (see --help)\n' "$PROG" "$*" >&2; exit 2; }

info() {
    [ "$QUIET" -eq 1 ] || printf '%s\n' "$*" >&2
}

OUT=""
SRC=""
VERSION=""
COMMIT=""
DATE=""
JOBS=0
QUIET=0
TARGETS=""

while [ $# -gt 0 ]; do
    case $1 in
        -o|--out) [ $# -ge 2 ] || usage_error "$1 needs a directory"; OUT=$2; shift ;;
        --out=*) OUT=${1#*=} ;;
        -s|--src) [ $# -ge 2 ] || usage_error "$1 needs a directory"; SRC=$2; shift ;;
        --src=*) SRC=${1#*=} ;;
        -v|--version) [ $# -ge 2 ] || usage_error "$1 needs a value"; VERSION=$2; shift ;;
        --version=*) VERSION=${1#*=} ;;
        -c|--commit) [ $# -ge 2 ] || usage_error "$1 needs a value"; COMMIT=$2; shift ;;
        --commit=*) COMMIT=${1#*=} ;;
        -d|--date) [ $# -ge 2 ] || usage_error "$1 needs a value"; DATE=$2; shift ;;
        --date=*) DATE=${1#*=} ;;
        -j|--jobs) [ $# -ge 2 ] || usage_error "$1 needs a number"; JOBS=$2; shift ;;
        --jobs=*) JOBS=${1#*=} ;;
        -q|--quiet) QUIET=1 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) usage_error "unknown option: $1" ;;
        *) TARGETS="$TARGETS $1" ;;
    esac
    shift
done
while [ $# -gt 0 ]; do TARGETS="$TARGETS $1"; shift; done

case $JOBS in
    ''|*[!0-9]*) usage_error "--jobs needs a non-negative integer" ;;
esac

# ---------- targets ----------
[ -n "$TARGETS" ] || TARGETS=all
expanded=""
only_host=1
for t in $TARGETS; do
    case $t in
        all) expanded="$expanded $RELEASE_TARGETS"; only_host=0 ;;
        host) expanded="$expanded host" ;;
        linux/amd64|linux/arm64|linux/arm|darwin/amd64|darwin/arm64) expanded="$expanded $t"; only_host=0 ;;
        *) usage_error "unknown target: $t (use all, host or one of: $RELEASE_TARGETS)" ;;
    esac
done
# de-duplicate, keep order
TARGETS=""
for t in $expanded; do
    case " $TARGETS " in *" $t "*) ;; *) TARGETS="$TARGETS $t" ;; esac
done

# ---------- source tree ----------
if [ -z "$SRC" ]; then
    SRC=$(dirname -- "$SCRIPT_DIR")
fi
[ -d "$SRC" ] || die "source directory not found: $SRC"
SRC=$(CDPATH='' cd -- "$SRC" && pwd -P)
[ -f "$SRC/go.mod" ] && [ -d "$SRC/cmd/fileparcel" ] || die "$SRC does not look like the FileParcel source (go.mod, cmd/fileparcel)"

if [ -z "$OUT" ]; then
    if [ "$only_host" -eq 1 ]; then OUT="$SRC/bin"; else OUT="$SRC/dist"; fi
fi
mkdir -p -- "$OUT"
OUT=$(CDPATH='' cd -- "$OUT" && pwd -P)

# ---------- Go toolchain ----------
# shellcheck source=scripts/env.sh
. "$SCRIPT_DIR/env.sh" 2>/dev/null || true
if ! command -v go >/dev/null 2>&1; then
    printf '%s: no Go toolchain found on PATH or in ~/sdk (install Go >= 1.26, e.g. scripts/get-go.sh 1.27.1)\n' "$PROG" >&2
    exit 3
fi
GOTOOLCHAIN=local
export GOTOOLCHAIN
gover=$(go env GOVERSION 2>/dev/null || true)
case $gover in
    go1.*)
        minor=$(printf '%s' "${gover#go1.}" | sed 's/[^0-9].*$//')
        if [ -z "$minor" ] || [ "$minor" -lt 26 ]; then
            printf '%s: %s is too old; FileParcel needs Go >= 1.26\n' "$PROG" "$gover" >&2
            exit 3
        fi
        ;;
    devel*|go2*) ;;
    *) printf '%s: cannot determine the Go version (go env GOVERSION = %s)\n' "$PROG" "$gover" >&2; exit 3 ;;
esac

# ---------- version metadata ----------
in_git=0
if command -v git >/dev/null 2>&1 && git -C "$SRC" rev-parse --verify -q HEAD >/dev/null 2>&1; then
    in_git=1
fi
if [ -z "$VERSION" ]; then
    VERSION=dev
    if [ "$in_git" -eq 1 ]; then
        tag=$(git -C "$SRC" tag --points-at HEAD 2>/dev/null | grep -E '^v[0-9]+$' | sed 's/^v//' | sort -n | tail -n 1 || true)
        [ -z "$tag" ] || VERSION="v$tag"
    fi
fi
if [ -z "$COMMIT" ]; then
    COMMIT=unknown
    if [ "$in_git" -eq 1 ]; then
        COMMIT=$(git -C "$SRC" rev-parse HEAD | cut -c1-12)
        if [ -n "$(git -C "$SRC" status --porcelain --untracked-files=no 2>/dev/null || true)" ]; then
            COMMIT="$COMMIT-dirty"
        fi
    fi
fi
if [ -z "$DATE" ]; then
    if [ "$in_git" -eq 1 ]; then
        DATE=$(TZ=UTC git -C "$SRC" log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd 2>/dev/null || true)
    fi
    [ -n "$DATE" ] || DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi
for v in "$VERSION" "$COMMIT" "$DATE"; do
    case $v in
        *[!A-Za-z0-9._:+-]*|'') die "invalid version metadata value: '$v' (allowed: letters, digits and . _ : + -)" ;;
    esac
done
LDFLAGS="-s -w -X $BUILDINFO_PKG.Version=$VERSION -X $BUILDINFO_PKG.Commit=$COMMIT -X $BUILDINFO_PKG.Date=$DATE"

# ---------- build ----------
LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/fp-build.XXXXXX")
cleanup() { rm -rf "$LOGDIR"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# out_name TARGET -> file name inside OUT
out_name() {
    case $1 in
        host) printf 'fileparcel' ;;
        *) printf 'fileparcel-%s-%s' "${1%/*}" "${1#*/}" ;;
    esac
}

# build_one TARGET: runs in a background subshell; output goes to its log.
build_one() {
    t=$1
    name=$(out_name "$t")
    tmp="$OUT/.$name.tmp.$$"
    cd "$SRC"
    if [ "$t" = host ]; then
        CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$tmp" ./cmd/fileparcel
    else
        goarm=""
        [ "$t" != linux/arm ] || goarm=7
        CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} GOARM=$goarm \
            go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$tmp" ./cmd/fileparcel
    fi
    chmod 0755 "$tmp"
    mv -f "$tmp" "$OUT/$name"
}

info "Building FileParcel $VERSION (commit $COMMIT, $DATE) with $gover"
info "  source: $SRC"
info "  output: $OUT"

running=""   # "pid:target" entries of builds in flight
failed=""
nfailed=0
nrun=0

reap_one() {
    # wait for the oldest running build
    first=${running%% *}
    running=${running#"$first"}
    running=${running# }
    pid=${first%%:*}
    t=${first#*:}
    if wait "$pid"; then
        info "  ok      $t"
    else
        failed="$failed $t"
        nfailed=$((nfailed + 1))
        printf '%s: build failed: %s\n' "$PROG" "$t" >&2
        sed 's/^/    /' "$LOGDIR/$(out_name "$t").log" >&2 || true
    fi
    nrun=$((nrun - 1))
}

for t in $TARGETS; do
    if [ "$JOBS" -gt 0 ] && [ "$nrun" -ge "$JOBS" ]; then
        reap_one
    fi
    info "  build   $t"
    ( build_one "$t" ) >"$LOGDIR/$(out_name "$t").log" 2>&1 &
    running="$running $!:$t"
    running=${running# }
    nrun=$((nrun + 1))
done
while [ -n "$running" ]; do
    reap_one
done

if [ -n "$failed" ]; then
    printf '%s: %d target(s) failed:%s\n' "$PROG" "$nfailed" "$failed" >&2
    exit 1
fi

for t in $TARGETS; do
    f="$OUT/$(out_name "$t")"
    size=$(wc -c <"$f" | tr -d ' ')
    printf '%s\t%s bytes\n' "$f" "$size"
done
