#!/bin/sh
# FileParcel release builder (DESIGN §15). Normally run by .githooks/post-commit
# after every commit; it can also be run by hand to (re)build the release of HEAD.
#
# Usage: scripts/release.sh [options]
#
# For the commit at HEAD it builds releases/fileparcel-vN.zip (+ .sha256) and
# creates the annotated tag vN:
#   - HEAD already tagged vN            -> rebuild vN (idempotent)
#   - HEAD is an amend of a vK commit   -> reuse K (the tag moves, the zip is replaced)
#   - otherwise                         -> N = 1 + the highest existing vN tag (first release: v1)
# The zip contains fileparcel-vN/{README.md LICENSE NOTICE VERSION SHA256SUMS
# install.sh uninstall.sh docker-compose.yml docs/ bin/ src/}, where src/ is
# exactly the committed tree (git archive) and bin/ holds the binaries for
# linux/amd64, linux/arm64, linux/arm (ARMv7), darwin/amd64 and darwin/arm64.
# The top-level docker-compose.yml builds the image from src/ (its Dockerfile
# and .dockerignore need the source tree as the build context).
#
# Options:
#   --from-hook        invoked by the post-commit hook: never fail (exit 0 with a
#                      warning) and honour FILEPARCEL_NO_RELEASE
#   --async            build in the background (same as FILEPARCEL_RELEASE_ASYNC=1)
#   --sync             build in the foreground even if FILEPARCEL_RELEASE_ASYNC=1
#   --keep N           keep only the N newest release zips (same as RELEASE_KEEP=N;
#                      0 = keep all, the default)
#   -n, --dry-run      print the release number and what would be done, then exit
#   -h, --help         show this help
#
# Environment:
#   FILEPARCEL_NO_RELEASE=1        the hook does nothing
#   FILEPARCEL_RELEASE_ASYNC=1     background the build (log in releases/.logs/)
#   RELEASE_KEEP=N                 prune older zips after a successful release
#   FILEPARCEL_RELEASE_LOCK_WAIT=S seconds to wait for a concurrent release (default 900)
#
# Logs: releases/.logs/vN.log (background runs also write releases/.logs/async.log).
# Without a Go toolchain (>= 1.26, found via scripts/env.sh) it prints a warning
# and exits 0. It never creates commits, so it cannot recurse through the hook.
#
# POSIX sh; works with dash, bash (incl. macOS bash 3.2) and zsh.
set -eu
umask 022

PROG=release
SELF=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")

FROM_HOOK=0
DRY_RUN=0
BACKGROUND=0          # internal: this is the detached background run
SHA=""                # internal: commit to release (captured before detaching)
AMEND_OF=""           # internal: pre-amend commit (captured before detaching)
ASYNC=0
case ${FILEPARCEL_RELEASE_ASYNC:-} in 1|true|yes|on) ASYNC=1 ;; esac
KEEP=${RELEASE_KEEP:-0}
LOCK_WAIT=${FILEPARCEL_RELEASE_LOCK_WAIT:-900}
LOG=""
LOCKED=0

usage() {
    sed -n '2,/^# POSIX sh/{s/^# \{0,1\}//;p;}' "$SELF"
}

stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }

say() {
    printf '%s: %s\n' "$PROG" "$*" >&2
    if [ -n "$LOG" ]; then printf '%s %s\n' "$(stamp)" "$*" >>"$LOG" 2>/dev/null || true; fi
}

warn() { say "WARNING: $*"; }

# fail MSG: from the hook, a failed release must never look like a failed
# commit, so it is a warning and exit 0; run by hand it exits 1.
fail() {
    if [ "$FROM_HOOK" -eq 1 ]; then
        warn "$* (the commit itself is fine; run scripts/release.sh to retry)"
        exit 0
    fi
    say "error: $*"
    exit 1
}

while [ $# -gt 0 ]; do
    case $1 in
        --from-hook) FROM_HOOK=1 ;;
        --async) ASYNC=1 ;;
        --sync) ASYNC=0 ;;
        --keep) [ $# -ge 2 ] || { say "--keep needs a number"; exit 2; }; KEEP=$2; shift ;;
        --keep=*) KEEP=${1#*=} ;;
        -n|--dry-run) DRY_RUN=1 ;;
        --background) BACKGROUND=1 ;;
        --sha) [ $# -ge 2 ] || exit 2; SHA=$2; shift ;;
        --amend-of) [ $# -ge 2 ] || exit 2; AMEND_OF=$2; shift ;;
        -h|--help) usage; exit 0 ;;
        *) say "unknown option: $1 (see --help)"; exit 2 ;;
    esac
    shift
done

case $KEEP in ''|*[!0-9]*) say "RELEASE_KEEP/--keep must be a non-negative integer"; exit 2 ;; esac
case $LOCK_WAIT in ''|*[!0-9]*) LOCK_WAIT=900 ;; esac

if [ "$FROM_HOOK" -eq 1 ] && [ -n "${FILEPARCEL_NO_RELEASE:-}" ]; then
    exit 0
fi

# Anything this script runs must not trigger another release.
FILEPARCEL_RELEASING=1
export FILEPARCEL_RELEASING
# Hooks run with GIT_INDEX_FILE pointing at a (possibly temporary) index; this
# script only reads commits and refs, so do not depend on it.
unset GIT_INDEX_FILE 2>/dev/null || true

command -v git >/dev/null 2>&1 || fail "git not found"
TOP=$(git rev-parse --show-toplevel 2>/dev/null) || fail "not inside a git working tree"
cd "$TOP"

RELDIR="$TOP/releases"
LOGDIR="$RELDIR/.logs"

# ---------- the commit to release (captured now, before any detaching) ----------
if [ -z "$SHA" ]; then
    SHA=$(git rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null) || fail "HEAD has no commit yet"
    subject=$(git reflog -1 --format=%gs HEAD 2>/dev/null || true)
    case $subject in
        "commit (amend)"*) AMEND_OF=$(git rev-parse -q --verify 'HEAD@{1}^{commit}' 2>/dev/null || true) ;;
    esac
fi
case $SHA in *[!0-9a-f]*|'') fail "invalid commit id: $SHA" ;; esac
SHA12=$(printf '%s' "$SHA" | cut -c1-12)

# ---------- Go toolchain (missing Go is a warning, never an error) ----------
if [ -f "$TOP/scripts/env.sh" ]; then
    # shellcheck source=scripts/env.sh
    . "$TOP/scripts/env.sh" 2>/dev/null || true
fi
if ! command -v go >/dev/null 2>&1; then
    warn "no Go toolchain found (PATH or ~/sdk/go*/bin); skipping the release build for $SHA12. Install Go >= 1.26 (scripts/get-go.sh 1.27.1) and run scripts/release.sh."
    exit 0
fi

# ---------- helpers ----------
# highest vN tag pointing at commit $1 (number only), or nothing
tag_at() {
    git tag --points-at "$1" 2>/dev/null | grep -E '^v[0-9]+$' | sed 's/^v//' | sort -n | tail -n 1
}
max_tag() {
    git tag -l 'v[0-9]*' 2>/dev/null | grep -E '^v[0-9]+$' | sed 's/^v//' | sort -n | tail -n 1
}
sha256_file() { # prints "<hex>  <name>" like sha256sum
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1"
    elif command -v openssl >/dev/null 2>&1; then
        printf '%s  %s\n' "$(openssl dgst -sha256 -r -- "$1" | cut -d' ' -f1)" "$1"
    else
        return 1
    fi
}

cleanup() {
    rc=$?
    if [ -n "${BUILD_TREE:-}" ]; then rm -rf "$BUILD_TREE"; fi
    if [ -n "${STAGE:-}" ]; then rm -rf "$STAGE"; fi
    if [ -n "${TMPZIP:-}" ]; then rm -f "$TMPZIP"; fi
    if [ -n "${TARFILE:-}" ]; then rm -f "$TARFILE"; fi
    if [ -n "${SUMS_TMP:-}" ]; then rm -f "$SUMS_TMP"; fi
    if [ -d "$RELDIR/.stage" ]; then rmdir "$RELDIR/.stage" 2>/dev/null || true; fi
    if [ "$LOCKED" -eq 1 ]; then
        if [ "$(cat "$RELDIR/.lock/pid" 2>/dev/null || true)" = "$$" ]; then
            rm -rf "$RELDIR/.lock"
        fi
    fi
    exit "$rc"
}

acquire_lock() {
    waited=0
    while ! mkdir "$RELDIR/.lock" 2>/dev/null; do
        holder=$(cat "$RELDIR/.lock/pid" 2>/dev/null || true)
        if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
            warn "removing a stale release lock (process $holder is gone)"
            rm -rf "$RELDIR/.lock"
            continue
        fi
        if [ -z "$holder" ] && [ -n "$(find "$RELDIR/.lock" -maxdepth 0 -mmin +180 2>/dev/null || true)" ]; then
            warn "removing an abandoned release lock (older than 3 hours)"
            rm -rf "$RELDIR/.lock"
            continue
        fi
        if [ "$waited" -ge "$LOCK_WAIT" ]; then
            fail "another release is still running (lock releases/.lock held by ${holder:-?} for ${waited}s)"
        fi
        if [ "$waited" -eq 0 ]; then say "waiting for another release to finish (lock held by ${holder:-?})"; fi
        sleep 2
        waited=$((waited + 2))
    done
    LOCKED=1
    printf '%s\n' "$$" >"$RELDIR/.lock/pid"
}

# ---------- detach (async) ----------
if [ "$ASYNC" -eq 1 ] && [ "$BACKGROUND" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$LOGDIR"
    set -- --background --sha "$SHA"
    [ -z "$AMEND_OF" ] || set -- "$@" --amend-of "$AMEND_OF"
    [ "$FROM_HOOK" -eq 0 ] || set -- "$@" --from-hook
    set -- "$@" --keep "$KEEP"
    {
        printf '%s release %s: started in the background\n' "$(stamp)" "$SHA12"
    } >>"$LOGDIR/async.log"
    nohup sh "$SELF" "$@" >>"$LOGDIR/async.log" 2>&1 </dev/null &
    say "building the release for $SHA12 in the background (pid $!); log: releases/.logs/"
    exit 0
fi

# ---------- release number (under the lock, so concurrent runs never collide) ----------
mkdir -p "$RELDIR" "$LOGDIR"
if [ "$DRY_RUN" -eq 0 ]; then
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    acquire_lock
fi

N=""
MODE=new
cur=$(tag_at "$SHA" || true)
if [ -n "$cur" ]; then
    N=$cur
    MODE=rebuild
elif [ -n "$AMEND_OF" ]; then
    prev=$(tag_at "$AMEND_OF" || true)
    if [ -n "$prev" ]; then
        N=$prev
        MODE=amend
    fi
fi
if [ -z "$N" ]; then
    max=$(max_tag || true)
    N=$(( ${max:-0} + 1 ))
fi
V="v$N"
NAME="fileparcel-$V"
ZIP="$RELDIR/$NAME.zip"

if [ "$DRY_RUN" -eq 1 ]; then
    case $MODE in
        rebuild) printf 'release %s: HEAD %s is already tagged; would rebuild %s\n' "$V" "$SHA12" "releases/$NAME.zip" ;;
        amend) printf 'release %s: HEAD %s amends %s; would move tag %s and replace %s\n' "$V" "$SHA12" "$(printf '%s' "$AMEND_OF" | cut -c1-12)" "$V" "releases/$NAME.zip" ;;
        new) printf 'release %s: would build %s from %s and tag %s\n' "$V" "releases/$NAME.zip" "$SHA12" "$V" ;;
    esac
    exit 0
fi

LOG="$LOGDIR/$V.log"
{
    printf '\n=== %s  %s (%s) from commit %s ===\n' "$(stamp)" "$V" "$MODE" "$SHA"
} >>"$LOG"
say "building $V from $SHA12 ($MODE); log: releases/.logs/$V.log"

# (amend: the previous zip of vN stays until the new one replaces it, so a
# failed rebuild leaves a consistent vN tag + zip for the pre-amend commit)

DATE=$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd "$SHA")
DAY=$(printf '%s' "$DATE" | cut -c1-10)
TOUCH_TS=$(TZ=UTC git log -1 --date=format-local:%Y%m%d%H%M.%S --format=%cd "$SHA")

# ---------- stage: the committed tree ----------
STAGE_ROOT="$RELDIR/.stage"
STAGE="$STAGE_ROOT/$NAME"
BUILD_TREE="$STAGE_ROOT/build-$V"
rm -rf "$STAGE" "$BUILD_TREE"
mkdir -p "$STAGE/src" "$STAGE/bin" "$BUILD_TREE"

TARFILE="$STAGE_ROOT/$NAME.tar"
git archive --format=tar "$SHA" >"$TARFILE" 2>>"$LOG" || fail "git archive failed (see releases/.logs/$V.log)"
tar -xf "$TARFILE" -C "$STAGE/src" 2>>"$LOG" || fail "extracting the source failed"
# a separate copy to build from, so the shipped src/ stays byte-identical to the commit
tar -xf "$TARFILE" -C "$BUILD_TREE" 2>>"$LOG" || fail "extracting the build tree failed"
rm -f "$TARFILE"
TARFILE=""
[ -f "$BUILD_TREE/go.mod" ] && [ -d "$BUILD_TREE/cmd/fileparcel" ] || fail "the committed tree has no go.mod / cmd/fileparcel"
# A FileParcel home or a secret committed by mistake (e.g. "git add ." after
# the Docker quick start) would be shipped in src/: refuse to package it.
leaked=$(git ls-tree -r --name-only "$SHA" 2>>"$LOG" |
    grep -E '^(server|fileparcel-data|secrets)/|^fileparcel\.toml$|(^|/)keys/master\.key$' | head -n 5 || true)
if [ -n "$leaked" ]; then
    fail "refusing to package a FileParcel home or secret that is in the commit ($(printf '%s' "$leaked" | tr '\n' ' ')); remove it with git rm -r --cached and commit again"
fi

# ---------- build all targets ----------
BUILD_SH="$BUILD_TREE/scripts/build.sh"
[ -f "$BUILD_SH" ] || BUILD_SH="$TOP/scripts/build.sh"
say "cross-compiling linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64"
build_rc=0
sh "$BUILD_SH" -q -s "$BUILD_TREE" -o "$STAGE/bin" -v "$V" -c "$SHA12" -d "$DATE" all >>"$LOG" 2>&1 || build_rc=$?
if [ "$build_rc" -eq 3 ]; then
    # build.sh found no usable Go (older than 1.26, or no version): like a
    # missing toolchain, a warning and no release.
    tail -n 1 "$LOG" | sed 's/^/    /' >&2 || true
    warn "no usable Go toolchain (>= 1.26, PATH or ~/sdk/go*/bin); skipping the release build for $SHA12. Install one (scripts/get-go.sh 1.27.1) and run scripts/release.sh."
    exit 0
fi
if [ "$build_rc" -ne 0 ]; then
    tail -n 25 "$LOG" | sed 's/^/    /' >&2 || true
    fail "the build of $V failed; no zip or tag was created (see releases/.logs/$V.log)"
fi
for t in linux-amd64 linux-arm64 linux-arm darwin-amd64 darwin-arm64; do
    [ -x "$STAGE/bin/fileparcel-$t" ] || fail "missing binary bin/fileparcel-$t after the build"
done
rm -rf "$BUILD_TREE"
BUILD_TREE=""

# ---------- top-level files ----------
# No top-level Dockerfile: it needs the source tree as its build context.
for f in README.md CONTRIBUTING.md LICENSE NOTICE install.sh uninstall.sh docker-compose.yml; do
    if [ -f "$STAGE/src/$f" ]; then
        cp "$STAGE/src/$f" "$STAGE/$f"
    else
        warn "$f is not in the commit; the zip will not contain it"
    fi
done
# The top-level docker-compose.yml builds from src/ (Dockerfile and
# .dockerignore there; bin/ is not sent to the daemon), and the image is
# tagged with this release; ./fileparcel-data and ./secrets stay next to it.
if [ -f "$STAGE/docker-compose.yml" ]; then
    sed -e 's|^\(      context:\) \.$|\1 src|' \
        -e "s|\\\${FILEPARCEL_VERSION:-dev}|\\\${FILEPARCEL_VERSION:-$V}|g" \
        -e "s|\\\${FILEPARCEL_COMMIT:-unknown}|\\\${FILEPARCEL_COMMIT:-$SHA12}|g" \
        "$STAGE/docker-compose.yml" >"$STAGE/docker-compose.yml.tmp" || fail "cannot rewrite docker-compose.yml"
    mv "$STAGE/docker-compose.yml.tmp" "$STAGE/docker-compose.yml" || fail "cannot rewrite docker-compose.yml"
    grep -q '^      context: src$' "$STAGE/docker-compose.yml" ||
        fail "docker-compose.yml: the build context was not rewritten to src (expected a line \"      context: .\")"
fi
if [ -d "$STAGE/src/docs" ]; then
    cp -R "$STAGE/src/docs" "$STAGE/docs"
else
    warn "docs/ is not in the commit"
fi
printf '%s %s %s\n' "$V" "$SHA12" "$DAY" >"$STAGE/VERSION"

# normalise permissions: directories 755, files 644, executables 755
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -perm -u+x -exec chmod 755 {} +
find "$STAGE" -type f ! -perm -u+x -exec chmod 644 {} +
for f in install.sh uninstall.sh; do
    [ ! -f "$STAGE/$f" ] || chmod 755 "$STAGE/$f"
done
chmod 755 "$STAGE"/bin/*

# SHA256SUMS over everything except src/ and itself
SUMS_TMP="$STAGE_ROOT/$NAME.sums"
(
    cd "$STAGE"
    find . -path ./src -prune -o -type f ! -name SHA256SUMS -print | sed 's|^\./||' | LC_ALL=C sort |
        while IFS= read -r f; do sha256_file "$f" || exit 1; done
) >"$SUMS_TMP" || fail "cannot compute checksums (need sha256sum, shasum or openssl)"
mv "$SUMS_TMP" "$STAGE/SHA256SUMS"
SUMS_TMP=""
chmod 644 "$STAGE/SHA256SUMS"

# reproducible timestamps: every entry gets the commit time
find "$STAGE" ! -type l -exec env TZ=UTC touch -t "$TOUCH_TS" {} +

# ---------- zip ----------
TMPZIP="$RELDIR/.tmp-$NAME.zip"
rm -f "$TMPZIP"
if command -v zip >/dev/null 2>&1; then
    # TZ=UTC: zip stores DOS local times; UTC keeps the archive reproducible
    (cd "$STAGE_ROOT" && find "$NAME" | LC_ALL=C sort | TZ=UTC zip -X -q -@ "$TMPZIP") >>"$LOG" 2>&1 ||
        fail "zip failed (see releases/.logs/$V.log)"
elif command -v python3 >/dev/null 2>&1; then
    python3 - "$STAGE_ROOT" "$NAME" "$TMPZIP" >>"$LOG" 2>&1 <<'PY' || fail "creating the zip with python3 failed"
import os, stat, sys, time, zipfile
root, name, out = sys.argv[1:4]
paths = []
for d, dirs, files in os.walk(os.path.join(root, name)):
    for x in dirs + files:
        paths.append(os.path.join(d, x))
paths.append(os.path.join(root, name))
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(paths, key=lambda p: os.path.relpath(p, root)):
        st = os.lstat(p)
        rel = os.path.relpath(p, root)
        dt = time.gmtime(st.st_mtime)[:6]
        if stat.S_ISDIR(st.st_mode):
            zi = zipfile.ZipInfo(rel + "/", dt)
            zi.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
            z.writestr(zi, b"")
        else:
            zi = zipfile.ZipInfo(rel, dt)
            zi.external_attr = (stat.S_IFREG | stat.S_IMODE(st.st_mode)) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(p, "rb") as f:
                z.writestr(zi, f.read())
PY
else
    fail "neither zip nor python3 is available to create the archive"
fi
mv -f "$TMPZIP" "$ZIP"
TMPZIP=""
(cd "$RELDIR" && sha256_file "$NAME.zip") >"$ZIP.sha256" || fail "cannot checksum the zip"
rm -rf "$STAGE"
STAGE=""

# ---------- tag ----------
case $MODE in
    rebuild)
        say "HEAD is already tagged $V; the release zip was rebuilt"
        ;;
    amend)
        git tag -f -a "$V" -m "FileParcel $V" "$SHA" >>"$LOG" 2>&1 || fail "could not move tag $V to $SHA12"
        say "tag $V moved to the amended commit $SHA12"
        ;;
    new)
        git tag -a "$V" -m "FileParcel $V" "$SHA" >>"$LOG" 2>&1 || fail "could not create tag $V (is user.name/user.email configured?)"
        ;;
esac

# ---------- prune ----------
if [ "$KEEP" -gt 0 ]; then
    nums=$(find "$RELDIR" -maxdepth 1 -type f -name 'fileparcel-v*.zip' 2>/dev/null |
        sed -n 's|.*/fileparcel-v\([0-9][0-9]*\)\.zip$|\1|p' | sort -n)
    total=$(printf '%s\n' "$nums" | grep -c . || true)
    drop=$((total - KEEP))
    for n in $nums; do
        [ "$drop" -gt 0 ] || break
        # Only an actual deletion spends the budget; skipping the release that was
        # just built (it is always kept) must not cost one, or one zip too many
        # survives whenever $N is among the oldest (MODE=amend of an old release).
        if [ "$n" != "$N" ]; then
            rm -f "$RELDIR/fileparcel-v$n.zip" "$RELDIR/fileparcel-v$n.zip.sha256" "$LOGDIR/v$n.log"
            drop=$((drop - 1))
            say "pruned fileparcel-v$n.zip (RELEASE_KEEP=$KEEP)"
        fi
    done
fi

size=$(wc -c <"$ZIP" | tr -d ' ')
hash=$(cut -d' ' -f1 "$ZIP.sha256")
say "done: releases/$NAME.zip ($size bytes, sha256 $hash), tag $V"
