#!/bin/sh
# FileParcel installer (DESIGN §14.1).
#
# A thin POSIX sh wrapper: it picks the right fileparcel binary for this
# machine (bin/fileparcel-<os>-<arch> from the release zip, verified against
# SHA256SUMS; or a fresh build from source when run from a git checkout), then
# runs "fileparcel install" with all remaining options. All questions, the
# service setup and the final summary happen in the Go installer.
#
# Works with dash, bash (incl. macOS bash 3.2), zsh and busybox ash.
set -eu

PROG=install.sh
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

usage() {
    cat <<'EOF'
FileParcel installer

Usage: ./install.sh [options]

Installs FileParcel into one self-contained directory (binary, configuration,
database, encrypted files, keys, certificates, backups and logs), registers it
as a service, and prints the access URLs (with QR codes), the certificate
fingerprint and the admin credentials. If the directory already contains an
installation, it is upgraded in place (with a backup and automatic rollback).
Without options the installer asks a few questions; -y accepts all defaults.

Where and how:
  --dir DIR                   install directory. Defaults:
                                Linux user   ~/.local/share/fileparcel
                                Linux root   /opt/fileparcel
                                macOS user   ~/Library/Application Support/FileParcel
                                macOS root   /usr/local/fileparcel
  --port N                    HTTPS port (default 8443; the next free port is suggested)
  --http-port N               HTTP port that redirects to HTTPS, 0 = none (default 8080)
  --name NAME                 server name: NAME.local via mDNS, CA name (default fileparcel)
  --service user|system|none  service kind (default: user; as root: system)
  --boot | --no-boot          start at boot (default --boot; user services enable linger)
  --symlink PATH              where to link the fileparcel command (default
                              ~/.local/bin/fileparcel; as root /usr/local/bin/fileparcel)
  --no-symlink                do not create the command symlink

Admin account:
  --admin USER                admin username (default admin)
  --generate-password         generate the admin password (default; shown once and
                              must be changed at the first login)
  --admin-password-file F     read the admin password from file F
  --admin-password-stdin      read the admin password from standard input
  --admin-email EMAIL         admin e-mail address (optional)

Security:
  --sealed                    protect the master key with a passphrase; the server then
                              starts locked after every restart until it is unlocked
                              (default: plain key file, unlocked automatically)
  --passphrase-file F         read the master-key passphrase from file F (with --sealed)
  --access MODE               who may connect: private | allowlist | any (default
                              allowlist = loopback + the detected LAN and VPN subnets)
  --allow CIDR                add a network to the allowlist (repeatable)

Binary selection (handled by this script):
  --binary PATH               install this fileparcel binary instead of the bundled
                              bin/fileparcel-<os>-<arch> (not checksum-verified)
  --from-source               build from source with Go >= 1.26, even if a bundled
                              binary exists (needs the source: a git checkout or src/)

Behaviour:
  -y, --yes, --non-interactive  never prompt; accept the defaults
  --upgrade                   upgrade the installation in --dir (automatic when --dir
                              already contains one)
  --force                     replace a foreign command symlink / re-register the service
  --dry-run                   show what would be done without changing anything
  -h, --help                  show this help

Examples:
  ./install.sh                                  interactive install
  ./install.sh -y                               everything default
  ./install.sh -y --dir ~/fileparcel --port 9443 --no-boot
  ./install.sh -y --access private --admin alice --admin-email alice@example.com
  sudo ./install.sh -y --service system         system service running as user "fileparcel"
  ./install.sh --upgrade --dir ~/.local/share/fileparcel

Options not listed here are passed to "fileparcel install" unchanged.
Step by step: docs/INSTALL.md (installing, upgrading, uninstalling).
The user manual is docs/FILEPARCEL.md; the command line is docs/COMMANDS.md.
EOF
}

say() { printf '%s\n' "$*" >&2; }
warn() { printf '%s: warning: %s\n' "$PROG" "$*" >&2; }
die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

# ---------- options ----------
# Options that take a value (their value is passed through verbatim, even if it
# looks like an option).
VALUE_OPTS=" --dir --port --http-port --name --service --admin --admin-password-file --admin-email --passphrase-file --access --allow --symlink --home "

FROM_SOURCE=0
BINARY=""
n=$#
while [ "$n" -gt 0 ]; do
    a=$1
    shift
    n=$((n - 1))
    case $a in
        -h|--help)
            usage
            exit 0
            ;;
        --from-source)
            FROM_SOURCE=1
            ;;
        --binary)
            [ "$n" -gt 0 ] || die "--binary needs a path"
            BINARY=$1
            shift
            n=$((n - 1))
            ;;
        --binary=*)
            BINARY=${a#*=}
            ;;
        --non-interactive)
            set -- "$@" --yes
            ;;
        --)
            set -- "$@" "$a"
            while [ "$n" -gt 0 ]; do
                set -- "$@" "$1"
                shift
                n=$((n - 1))
            done
            ;;
        *)
            set -- "$@" "$a"
            case $VALUE_OPTS in
                *" $a "*)
                    [ "$n" -gt 0 ] || die "$a needs a value"
                    set -- "$@" "$1"
                    shift
                    n=$((n - 1))
                    ;;
            esac
            ;;
    esac
done

# ---------- platform ----------
OS=""
ARCH=""
ARMV6=0
case $(uname -s) in
    Linux) OS=linux ;;
    Darwin) OS=darwin ;;
    *) die "unsupported operating system: $(uname -s). FileParcel runs on Linux and macOS (or in Docker)." ;;
esac
MACHINE=$(uname -m)
case $MACHINE in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    armv7*|armv8l|armhf) ARCH=arm ;;
    armv6*) ARCH=arm; ARMV6=1 ;;
    *) ARCH="" ;;
esac
# Apple Silicon running this shell under Rosetta 2: use the native binary.
if [ "$OS" = darwin ] && [ "$ARCH" = amd64 ] &&
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    ARCH=arm64
fi

# ---------- helpers ----------
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r -- "$1" | cut -d' ' -f1
    else
        return 1
    fi
}

TMPBUILD=""
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
    if [ -n "$TMPBUILD" ]; then rm -rf "$TMPBUILD"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# find_source prints the directory holding the FileParcel source (a git
# checkout next to this script, or src/ inside a release zip).
find_source() {
    for d in "$SCRIPT_DIR" "$SCRIPT_DIR/src"; do
        if [ -f "$d/go.mod" ] && [ -d "$d/cmd/fileparcel" ] && [ -f "$d/scripts/build.sh" ]; then
            printf '%s\n' "$d"
            return 0
        fi
    done
    return 1
}

build_from_source() {
    src=$(find_source) || die "no FileParcel source found next to install.sh (expected go.mod and scripts/build.sh here or in src/)"
    TMPBUILD=$(mktemp -d "${TMPDIR:-/tmp}/fileparcel-install.XXXXXX")
    set -- -q -o "$TMPBUILD"
    if [ -f "$SCRIPT_DIR/VERSION" ]; then
        # release zip: "vN <commit> <date>"
        read -r rv rc rd _ <"$SCRIPT_DIR/VERSION" || true
        [ -z "${rv:-}" ] || set -- "$@" -v "$rv"
        [ -z "${rc:-}" ] || set -- "$@" -c "$rc"
        [ -z "${rd:-}" ] || set -- "$@" -d "$rd"
    fi
    if [ "$ARMV6" -eq 1 ]; then
        GOARM=6
        export GOARM
    fi
    say "Building FileParcel from source ($src) - this takes a minute or two..."
    status=0
    sh "$src/scripts/build.sh" "$@" host >/dev/null || status=$?
    case $status in
        0) ;;
        3) die "building from source needs Go >= 1.26. Install it from https://go.dev/dl/ (or run \"sh $src/scripts/get-go.sh 1.27.1\", which installs into ~/sdk and is used even when an older go is on the PATH), or use a release zip that contains bin/." ;;
        *) die "the build failed (exit $status); see the messages above" ;;
    esac
    BIN="$TMPBUILD/fileparcel"
}

# ---------- choose the binary ----------
BIN=""
if [ -n "$BINARY" ]; then
    [ -f "$BINARY" ] || die "--binary: no such file: $BINARY"
    BIN=$(CDPATH='' cd -- "$(dirname -- "$BINARY")" && pwd -P)/$(basename -- "$BINARY")
    warn "installing $BIN as given with --binary (no checksum verification)"
elif [ "$FROM_SOURCE" -eq 1 ]; then
    build_from_source
elif [ "$ARMV6" -eq 1 ]; then
    # The bundled linux/arm binary targets ARMv7 (Raspberry Pi 2 and newer).
    if find_source >/dev/null 2>&1; then
        say "This is an ARMv6 CPU ($MACHINE); the bundled ARM binary needs ARMv7, so FileParcel is built from source."
        build_from_source
    else
        die "this ARMv6 CPU ($MACHINE, e.g. Raspberry Pi Zero/1) cannot run the bundled ARMv7 binary, and no source was found to build from"
    fi
elif [ -z "$ARCH" ]; then
    if find_source >/dev/null 2>&1; then
        say "No prebuilt binary for $OS/$MACHINE; building from source."
        build_from_source
    else
        die "unsupported CPU architecture: $MACHINE. Prebuilt binaries exist for amd64, arm64 and armv7; build from source with Go >= 1.26 (git checkout or the release's src/)."
    fi
else
    rel="bin/fileparcel-$OS-$ARCH"
    if [ -f "$SCRIPT_DIR/$rel" ]; then
        sums="$SCRIPT_DIR/SHA256SUMS"
        [ -f "$sums" ] || die "SHA256SUMS is missing next to install.sh, so $rel cannot be verified. Re-download the release, or use --binary PATH / --from-source."
        want=$(awk -v f="$rel" '{ n = $2; sub(/^\*/, "", n); sub(/^\.\//, "", n); if (n == f) { print tolower($1); exit } }' "$sums")
        [ -n "$want" ] || die "SHA256SUMS has no entry for $rel"
        got=$(sha256_of "$SCRIPT_DIR/$rel") || die "cannot verify $rel: need sha256sum, shasum or openssl"
        if [ "$got" != "$want" ]; then
            die "checksum mismatch for $rel (expected $want, got $got). The download is corrupt or was modified; do not install it."
        fi
        say "Verified $rel (sha256 $got)"
        BIN="$SCRIPT_DIR/$rel"
    elif find_source >/dev/null 2>&1; then
        say "No bundled binary (bin/ is absent - a source checkout?); building from source."
        build_from_source
    else
        die "neither $rel nor the FileParcel source was found next to install.sh. Download the release zip for your platform."
    fi
fi

# ---------- prepare it ----------
if [ "$OS" = darwin ] && command -v xattr >/dev/null 2>&1; then
    # Downloaded files carry the Gatekeeper quarantine attribute, which would
    # block the unsigned binary (and the copy made into the install directory).
    for f in "$BIN" "$SCRIPT_DIR/uninstall.sh" "$SCRIPT_DIR/install.sh"; do
        [ ! -e "$f" ] || xattr -d com.apple.quarantine "$f" 2>/dev/null || true
    done
    [ ! -d "$SCRIPT_DIR/bin" ] || xattr -dr com.apple.quarantine "$SCRIPT_DIR/bin" 2>/dev/null || true
fi
SHOWN_BIN=$BIN # the path the user knows, also after a temporary copy
if [ ! -x "$BIN" ]; then
    # e.g. unzipped with a tool that drops the executable bit
    if ! chmod +x "$BIN" 2>/dev/null; then
        [ -n "$TMPBUILD" ] || TMPBUILD=$(mktemp -d "${TMPDIR:-/tmp}/fileparcel-install.XXXXXX")
        cp "$BIN" "$TMPBUILD/fileparcel.copy"
        chmod 0755 "$TMPBUILD/fileparcel.copy"
        BIN="$TMPBUILD/fileparcel.copy"
    fi
fi
if ! "$BIN" version >/dev/null 2>&1; then
    die "$SHOWN_BIN does not run on this machine ($OS/$MACHINE). Try --from-source."
fi

# The Go installer copies uninstall.sh, docs/ and VERSION from here into the
# install directory (the binary itself may live in a temporary build directory).
FILEPARCEL_INSTALL_SOURCE=$SCRIPT_DIR
export FILEPARCEL_INSTALL_SOURCE

if [ -z "$TMPBUILD" ]; then
    exec "$BIN" install "$@"
fi
# A temporary build: run it as a child so the build directory is removed afterwards.
status=0
"$BIN" install "$@" || status=$?
exit "$status"
