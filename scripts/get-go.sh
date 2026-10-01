#!/bin/sh
# Download a Go toolchain from go.dev into ~/sdk/goX.Y.Z, verifying its SHA-256
# against the official release list (https://go.dev/dl/?mode=json&include=all).
#
# Usage: scripts/get-go.sh [-n|--dry-run] [-f|--force] VERSION     (e.g. 1.27.1 or go1.27.1)
#
# POSIX sh; needs curl or wget, tar, and sha256sum or shasum.
set -eu

usage() {
    echo "usage: $0 [-n|--dry-run] [-f|--force] VERSION   (e.g. 1.27.1)" >&2
    exit 2
}

dry=0
force=0
version=""
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run) dry=1 ;;
        -f|--force) force=1 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) [ -z "$version" ] || usage; version=$1 ;;
    esac
    shift
done
[ -n "$version" ] || usage
version=${version#go}
case "$version" in
    *[!0-9A-Za-z.]*|"") echo "invalid version: $version" >&2; exit 2 ;;
esac

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    FreeBSD) os=freebsd ;;
    *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv6l|armv7l|armv7*|armv6*) arch=armv6l ;;
    i386|i686) arch=386 ;;
    riscv64) arch=riscv64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

file="go${version}.${os}-${arch}.tar.gz"
url="https://go.dev/dl/${file}"
dest="$HOME/sdk/go${version}"

if [ -x "$dest/bin/go" ] && [ "$force" -eq 0 ] && [ "$dry" -eq 0 ]; then
    echo "Go ${version} is already installed in ${dest} (use --force to reinstall)"
    exit 0
fi

fetch() { # fetch URL OUTFILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        echo "need curl or wget" >&2
        exit 1
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "need sha256sum or shasum" >&2
        exit 1
    fi
}

tmp=""
stage=""
old=""
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
    # A signal caught between the two renames below would otherwise leave
    # $dest gone; put the toolchain back before removing anything.
    if [ -n "$old" ] && [ -e "$old" ] && [ ! -e "$dest" ]; then
        mv "$old" "$dest" 2>/dev/null || true
    fi
    [ -z "$tmp" ] || rm -rf "$tmp"
    [ -z "$stage" ] || rm -rf "$stage"
    [ -z "$old" ] || rm -rf "$old"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
tmp=$(mktemp -d "${TMPDIR:-/tmp}/get-go.XXXXXX")

fetch "https://go.dev/dl/?mode=json&include=all" "$tmp/releases.json"
# One key/value per line regardless of the JSON formatting, then pick the
# sha256 of the object whose filename matches. (tr maps each of , { } to a
# newline on purpose.)
# shellcheck disable=SC2020
want=$(tr ',{}' '\n\n\n' < "$tmp/releases.json" | awk -v f="\"${file}\"" '
    /"filename"[[:space:]]*:/ { split($0, a, ":"); v = a[2]; gsub(/[[:space:]]/, "", v); cur = (v == f); next }
    cur && /"sha256"[[:space:]]*:/ { split($0, a, ":"); v = a[2]; gsub(/[[:space:]"]/, "", v); print v; exit }')
if [ -z "$want" ]; then
    echo "no release file ${file} found at go.dev (check the version)" >&2
    exit 1
fi

if [ "$dry" -eq 1 ]; then
    echo "url:    ${url}"
    echo "sha256: ${want}"
    echo "dest:   ${dest}"
    exit 0
fi

echo "Downloading ${url}"
fetch "$url" "$tmp/$file"
got=$(sha256_of "$tmp/$file")
if [ "$got" != "$want" ]; then
    echo "SHA-256 mismatch for ${file}: got ${got}, want ${want}" >&2
    exit 1
fi
echo "SHA-256 verified (${want})"

# Stage on the same file system as $dest so every move below is an atomic
# rename: a failed or interrupted install can never leave $dest missing.
# Extracting here also means a full or read-only destination fails at tar,
# before anything is removed. The staging names start with "." so a leftover
# tree cannot be picked up by scripts/env.sh's ~/sdk/go*/bin glob.
mkdir -p "$HOME/sdk"
stage="$HOME/sdk/.get-go.$$"
old="$HOME/sdk/.get-go-old.$$"
rm -rf "$stage" "$old"
mkdir -p "$stage"
tar -xzf "$tmp/$file" -C "$stage"
[ -x "$stage/go/bin/go" ] || { echo "archive does not contain go/bin/go" >&2; exit 1; }
if [ -e "$dest" ]; then
    mv "$dest" "$old"
fi
# Inside an "if" condition "set -e" does not fire, so the rollback is reachable.
if mv "$stage/go" "$dest"; then
    rm -rf "$old"
else
    if [ -e "$old" ]; then
        mv "$old" "$dest"
        echo "install failed; kept the existing ${dest}" >&2
    fi
    exit 1
fi
echo "Installed Go ${version} to ${dest}"
echo "Use it with: . scripts/env.sh   (or: export PATH=\"${dest}/bin:\$PATH\" GOTOOLCHAIN=local)"
