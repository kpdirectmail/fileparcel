#!/bin/sh
# Run a FileParcel development server with a scratch home on 127.0.0.1:18443.
#
# Usage: scripts/dev.sh [options] [-- extra "fileparcel serve" arguments]
#
# The first run builds the binary for this machine (scripts/build.sh host ->
# bin/fileparcel), initialises a throw-away home (admin "admin" with a random
# password stored next to the home, access mode "private", mDNS off so it never
# collides with a real installation's fileparcel.local) and starts
# "fileparcel serve --foreground --dev" bound to 127.0.0.1 only. Later runs
# rebuild and reuse the home. Stop it with Ctrl-C.
#
# Options:
#   --home DIR        dev home (default: $FILEPARCEL_DEV_HOME or <repo>/tmp/dev-home;
#                     tmp/ is gitignored). Never point this at a real installation.
#   --port N          HTTPS port (default 18443)
#   --http-port N     HTTP redirect port, 0 = none (default 0)
#   --bind ADDR       listen address (default 127.0.0.1; "::" = all interfaces,
#                     still filtered by the access policy)
#   --name NAME       server name (default fileparcel)
#   --mdns            keep mDNS publishing on (default: off for the dev home)
#   --reset           delete the dev home first and start from scratch
#   --race            build with the race detector (needs cgo)
#   --no-build        do not rebuild; use the existing bin/fileparcel
#   -y, --yes         do not ask before --reset
#   -h, --help        show this help
#
# Environment: FILEPARCEL_DEV_HOME, and any FILEPARCEL_<SECTION>_<KEY> override.
#
# POSIX sh; works with dash, bash (incl. macOS bash 3.2) and zsh.
set -eu

PROG=dev.sh
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(dirname -- "$SCRIPT_DIR")

usage() {
    sed -n '2,/^# POSIX sh/{s/^# \{0,1\}//;p;}' "$SCRIPT_DIR/dev.sh"
}
say() { printf '%s\n' "$*" >&2; }
die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

DEV_HOME=${FILEPARCEL_DEV_HOME:-$REPO/tmp/dev-home}
PORT=18443
HTTP_PORT=0
BIND=127.0.0.1
NAME=fileparcel
MDNS=0
RESET=0
RACE=0
BUILD=1
YES=0

need() { [ "$2" -gt 1 ] || die "$1 needs a value"; }
while [ $# -gt 0 ]; do
    case $1 in
        --home) need "$1" $#; DEV_HOME=$2; shift ;;
        --home=*) DEV_HOME=${1#*=} ;;
        --port) need "$1" $#; PORT=$2; shift ;;
        --port=*) PORT=${1#*=} ;;
        --http-port) need "$1" $#; HTTP_PORT=$2; shift ;;
        --http-port=*) HTTP_PORT=${1#*=} ;;
        --bind) need "$1" $#; BIND=$2; shift ;;
        --bind=*) BIND=${1#*=} ;;
        --name) need "$1" $#; NAME=$2; shift ;;
        --name=*) NAME=${1#*=} ;;
        --mdns) MDNS=1 ;;
        --reset) RESET=1 ;;
        --race) RACE=1 ;;
        --no-build) BUILD=0 ;;
        -y|--yes) YES=1 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        *) die "unknown option: $1 (see --help; pass serve arguments after --)" ;;
    esac
    shift
done

for p in "$PORT" "$HTTP_PORT"; do
    case $p in ''|*[!0-9]*) die "invalid port: $p" ;; esac
done
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "invalid --port: $PORT"
[ "$HTTP_PORT" -le 65535 ] || die "invalid --http-port: $HTTP_PORT"
case $NAME in
    ''|-*|*[!a-z0-9-]*) die "invalid --name: $NAME (lowercase letters, digits and -)" ;;
esac

# refuse obviously wrong homes: the live install and anything that is not ours
case $DEV_HOME in
    /*) ;;
    *) DEV_HOME=$(pwd -P)/$DEV_HOME ;;
esac
# Canonicalise before comparing: ./server, scripts/../server, <repo>//server
# or a symlink to it must not get past the string guard below (--reset
# deletes the directory).
if [ -d "$DEV_HOME" ]; then
    DEV_HOME=$(CDPATH='' cd -- "$DEV_HOME" && pwd -P) || die "cannot resolve $DEV_HOME"
else
    dev_parent=$(dirname -- "$DEV_HOME")
    dev_base=$(basename -- "$DEV_HOME")
    case $dev_base in .|..|/) die "invalid --home: $DEV_HOME" ;; esac
    if [ -d "$dev_parent" ]; then
        dev_parent=$(CDPATH='' cd -- "$dev_parent" && pwd -P) || die "cannot resolve $dev_parent"
        DEV_HOME=${dev_parent%/}/$dev_base
    else
        # init creates the missing parents later: a . or .. in them could
        # still lead into the live installation once they exist.
        case /$DEV_HOME/ in
            */../* | */./*) die "invalid --home: $DEV_HOME (use a path without . or .. components)" ;;
        esac
    fi
    unset dev_parent dev_base
fi
LIVE="$REPO/server"
if [ -d "$LIVE" ]; then LIVE=$(CDPATH='' cd -- "$LIVE" && pwd -P) || LIVE="$REPO/server"; fi
case $DEV_HOME in
    "$REPO/server" | "$REPO/server/"* | "$LIVE" | "$LIVE/"*) die "refusing to use $DEV_HOME: that is the live installation" ;;
esac
# Only the installer and "fileparcel service" write service/installed.json;
# a dev home never has one, whatever its path.
if [ -e "$DEV_HOME/service/installed.json" ]; then
    die "refusing to use $DEV_HOME: it is an installed FileParcel home (service/installed.json)"
fi
if [ -e "$DEV_HOME" ] && [ ! -f "$DEV_HOME/fileparcel.toml" ] && [ -n "$(ls -A "$DEV_HOME" 2>/dev/null || true)" ]; then
    die "$DEV_HOME exists, is not empty and is not a FileParcel home; choose another --home"
fi
PASSFILE="$DEV_HOME.admin-password"

if [ "$RESET" -eq 1 ] && [ -e "$DEV_HOME" ]; then
    [ -f "$DEV_HOME/fileparcel.toml" ] || die "refusing to delete $DEV_HOME: not a FileParcel home"
    if [ "$YES" -eq 0 ]; then
        printf 'Delete the dev home %s? [y/N] ' "$DEV_HOME" >&2
        read -r ans || ans=""
        case $ans in [yY]|[yY][eE][sS]) ;; *) die "aborted" ;; esac
    fi
    rm -rf -- "$DEV_HOME"
    rm -f -- "$PASSFILE"
    say "Deleted $DEV_HOME"
fi

# ---------- build ----------
BIN="$REPO/bin/fileparcel"
if [ "$BUILD" -eq 1 ]; then
    if [ "$RACE" -eq 1 ]; then
        # shellcheck source=scripts/env.sh
        . "$SCRIPT_DIR/env.sh"
        command -v go >/dev/null 2>&1 || die "no Go toolchain found (scripts/get-go.sh 1.27.1)"
        say "Building bin/fileparcel with -race"
        mkdir -p "$REPO/bin"
        (cd "$REPO" && go build -race -o "$BIN" ./cmd/fileparcel) || die "build failed"
    else
        sh "$SCRIPT_DIR/build.sh" -q -o "$REPO/bin" -v dev host >/dev/null || die "build failed"
    fi
fi
[ -x "$BIN" ] || die "$BIN does not exist (run without --no-build)"

# ---------- environment for init and serve ----------
FILEPARCEL_HOME=$DEV_HOME
FILEPARCEL_SERVER_BIND=$BIND
FILEPARCEL_SERVER_HTTPS_PORT=$PORT
FILEPARCEL_SERVER_HTTP_PORT=$HTTP_PORT
export FILEPARCEL_HOME FILEPARCEL_SERVER_BIND FILEPARCEL_SERVER_HTTPS_PORT FILEPARCEL_SERVER_HTTP_PORT

# ---------- first run: init ----------
if [ ! -f "$DEV_HOME/fileparcel.toml" ]; then
    mkdir -p "$(dirname -- "$DEV_HOME")"
    if [ ! -s "$PASSFILE" ]; then
        (umask 077 && od -An -N18 -tx1 /dev/urandom | tr -d ' \n' >"$PASSFILE")
    fi
    say "Initialising the dev home $DEV_HOME"
    "$BIN" init --home "$DEV_HOME" --port "$PORT" --http-port "$HTTP_PORT" --name "$NAME" \
        --admin admin --admin-password-file "$PASSFILE" --access private --non-interactive ||
        die "fileparcel init failed"
    if [ "$MDNS" -eq 0 ]; then
        "$BIN" --home "$DEV_HOME" --offline config set mdns.mode off >/dev/null ||
            say "warning: could not turn mDNS off for the dev home"
    fi
fi

CA="$DEV_HOME/certs/ca/ca.crt"
host=$BIND
case $host in
    ::|0.0.0.0|'') host=127.0.0.1 ;;
    *:*) host="[$host]" ;;
esac
say ""
say "FileParcel dev server"
say "  URL       https://$host:$PORT/   (also https://$NAME.local:$PORT/ with --resolve/hosts entry)"
say "  home      $DEV_HOME"
say "  login     admin / $(cat "$PASSFILE" 2>/dev/null || echo '(see the init output)')"
say "  CA        $CA"
say "  API test  curl --cacert $CA https://$host:$PORT/healthz"
say "  CLI       FILEPARCEL_HOME=$DEV_HOME $BIN status"
say ""

exec "$BIN" serve --home "$DEV_HOME" --foreground --dev "$@"
