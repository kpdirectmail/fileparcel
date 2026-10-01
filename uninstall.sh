#!/bin/sh
# FileParcel uninstaller (DESIGN §14.6).
#
# A thin POSIX sh wrapper: it finds the installation directory (HOME) and runs
# "<HOME>/bin/fileparcel uninstall" with all remaining options. That command
# asks for confirmation, can make a final backup, stops and unregisters the
# service, removes the command symlink and - with --purge - destroys the keys
# and deletes the directory.
#
# If the binary is missing or broken, a limited fallback runs instead: it stops
# and unregisters the service with systemctl/launchctl, removes the command
# symlink and (with --purge) shreds the key files and deletes HOME.
#
# Works with dash, bash (incl. macOS bash 3.2), zsh and busybox ash.
set -eu

PROG=uninstall.sh
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
LABEL=com.fileparcel.server
UNIT=fileparcel.service

usage() {
    cat <<'EOF'
FileParcel uninstaller

Usage: uninstall.sh [options]

Finds the FileParcel installation and removes it. By default the data is kept
(--keep-data): the service and the command symlink are removed, but the
installation directory with all files, keys, backups and logs stays where it
is, so a later ./install.sh --dir DIR picks it up again.

Which installation:
  --dir DIR           the installation directory (the one containing fileparcel.toml)
                      otherwise the directory of this script, when it lives in an
                      installation; otherwise $FILEPARCEL_HOME, the target of the
                      fileparcel command symlink and the default install locations
                      (including $XDG_DATA_HOME/fileparcel) are all checked. If they
                      find more than one installation, they are listed and the
                      uninstaller stops: choose one with --dir DIR

What to remove:
  --keep-data         remove the service and the symlink, keep the directory (default)
  --purge             also destroy the master key and CA keys (overwritten with random
                      bytes) and delete the whole installation directory. No backup is
                      made unless --final-backup is given; without one the stored
                      files are unrecoverable.
  --final-backup      create a full backup before removing anything
  --backup-to DIR     copy the final backup into DIR (outside the installation
                      directory; created if missing; implies --final-backup). Required
                      when --final-backup is combined with --purge (a backup left in
                      the installation directory would be deleted with it); if the
                      copy fails the uninstall stops before removing anything
  --remove-user       also delete the "fileparcel" system account created by a
                      system-wide (root) installation

Behaviour:
  --dry-run           print what would be done without changing anything
  -y, --yes           do not ask for confirmation (also: --non-interactive)
  -h, --help          show this help

Examples:
  ~/.local/share/fileparcel/uninstall.sh                 keep the data
  ./uninstall.sh --dir ~/fileparcel --final-backup --backup-to ~/fp-final --purge
  sudo /opt/fileparcel/uninstall.sh -y --purge --remove-user

Options not listed here are passed to "fileparcel uninstall" unchanged.
EOF
}

say() { printf '%s\n' "$*" >&2; }
warn() { printf '%s: warning: %s\n' "$PROG" "$*" >&2; }
die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

# ---------- options ----------
VALUE_OPTS=" --backup-to --home "
DIR=""
PURGE=0
YES=0
FINAL_BACKUP=0
REMOVE_USER=0
DRY_RUN=0
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
        --dir|--home)
            [ "$n" -gt 0 ] || die "$a needs a directory"
            DIR=$1
            shift
            n=$((n - 1))
            ;;
        --dir=*|--home=*)
            DIR=${a#*=}
            ;;
        *)
            case $a in
                --purge) PURGE=1 ;;
                --keep-data) PURGE=0 ;;
                -y|--yes|--non-interactive) YES=1 ;;
                --final-backup | --backup-to | --backup-to=*) FINAL_BACKUP=1 ;;
                --remove-user) REMOVE_USER=1 ;;
                --dry-run) DRY_RUN=1 ;;
            esac
            if [ "$a" = --non-interactive ]; then a=--yes; fi
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

# ---------- locate HOME ----------
# abs_dir DIR: prints the physical absolute path of an existing directory.
abs_dir() {
    (CDPATH='' cd -- "$1" 2>/dev/null && pwd -P)
}

# is_home DIR: true when DIR is a FileParcel installation (the marker file
# plus at least one of the directories an installation always has).
is_home() {
    [ -n "$1" ] && [ -d "$1" ] && [ -f "$1/fileparcel.toml" ] &&
        { [ -d "$1/bin" ] || [ -d "$1/keys" ] || [ -d "$1/data" ]; }
}

# link_target LINK: prints the absolute target of a symlink (one level; the
# installer links straight to <HOME>/bin/fileparcel).
link_target() {
    if command -v readlink >/dev/null 2>&1; then
        t=$(readlink -- "$1" 2>/dev/null || true)
    else
        # shellcheck disable=SC2012 # no readlink: parse "ls -l" (FileParcel paths have no " -> ")
        t=$(ls -ld -- "$1" 2>/dev/null | sed -n 's/.* -> //p')
    fi
    [ -n "$t" ] || return 1
    case $t in
        /*) printf '%s\n' "$t" ;;
        *) printf '%s/%s\n' "$(abs_dir "$(dirname -- "$1")")" "$t" ;;
    esac
}

# home_of_binary PATH: the installation that contains bin/fileparcel PATH.
home_of_binary() {
    d=$(dirname -- "$1")
    d=$(abs_dir "$d") || return 1
    for c in "$d" "$(dirname -- "$d")"; do
        if is_home "$c"; then
            printf '%s\n' "$c"
            return 0
        fi
    done
    return 1
}

CANDIDATES=""
add_candidate() { # add_candidate DIR SOURCE
    is_home "$1" || return 0
    c=$(abs_dir "$1") || return 0
    case "
$CANDIDATES" in
        *"
$c	"*) return 0 ;;
    esac
    CANDIDATES="$CANDIDATES$c	$2
"
}

if [ -n "$DIR" ]; then
    [ -d "$DIR" ] || die "--dir: no such directory: $DIR"
    is_home "$DIR" || die "$DIR is not a FileParcel installation (no fileparcel.toml in it)"
    FP_HOME=$(abs_dir "$DIR")
elif is_home "$SCRIPT_DIR"; then
    FP_HOME=$SCRIPT_DIR
else
    if [ -n "${FILEPARCEL_HOME:-}" ]; then add_candidate "$FILEPARCEL_HOME" "\$FILEPARCEL_HOME"; fi
    for l in "$(command -v fileparcel 2>/dev/null || true)" "${HOME:-/nonexistent}/.local/bin/fileparcel" /usr/local/bin/fileparcel; do
        [ -n "$l" ] && [ -L "$l" ] || continue
        tgt=$(link_target "$l") || continue
        h=$(home_of_binary "$tgt") || continue
        add_candidate "$h" "symlink $l"
    done
    # The installer's defaults (svc.DefaultHome): $XDG_DATA_HOME/fileparcel for
    # a user on Linux when it is set and absolute, else ~/.local/share/fileparcel
    # (kept: XDG_DATA_HOME may have been unset at install time).
    if [ "$(uname -s)" != Darwin ] && [ "$(id -u)" -ne 0 ]; then
        case ${XDG_DATA_HOME:-} in
            /*) add_candidate "$XDG_DATA_HOME/fileparcel" "default location (\$XDG_DATA_HOME)" ;;
        esac
    fi
    for d in "${HOME:-/nonexistent}/.local/share/fileparcel" \
        "${HOME:-/nonexistent}/Library/Application Support/FileParcel" \
        /opt/fileparcel /usr/local/fileparcel; do
        add_candidate "$d" "default location"
    done
    count=$(printf '%s' "$CANDIDATES" | grep -c . || true)
    if [ "$count" -eq 0 ]; then
        die "no FileParcel installation found. Pass --dir DIR (the directory that contains fileparcel.toml)."
    fi
    if [ "$count" -gt 1 ]; then
        say "More than one FileParcel installation was found:"
        printf '%s' "$CANDIDATES" | while IFS='	' read -r c src; do say "  $c   ($src)"; done
        die "choose one with --dir DIR"
    fi
    FP_HOME=$(printf '%s' "$CANDIDATES" | head -n 1 | cut -f1)
    src=$(printf '%s' "$CANDIDATES" | head -n 1 | cut -f2)
    say "Found the FileParcel installation in $FP_HOME ($src)"
fi

BIN="$FP_HOME/bin/fileparcel"

# ---------- normal path: the Go uninstaller ----------
if [ -x "$BIN" ] && "$BIN" version >/dev/null 2>&1; then
    exec "$BIN" uninstall --home "$FP_HOME" "$@"
fi

# ---------- fallback: no working binary ----------
warn "$BIN is missing or does not run; using the limited fallback uninstaller"
if [ "$FINAL_BACKUP" -eq 1 ]; then
    die "--final-backup needs a working $BIN. Copy $FP_HOME somewhere safe instead (with the server stopped), then run again without --final-backup."
fi

OS=$(uname -s)
UID_NOW=$(id -u)
is_root() { [ "$UID_NOW" -eq 0 ]; }

confirm() { # confirm QUESTION -> true on yes
    [ "$YES" -eq 0 ] || return 0
    if [ ! -t 0 ]; then
        die "not a terminal; re-run with -y to confirm"
    fi
    printf '%s [y/N] ' "$1" >&2
    read -r ans || ans=""
    case $ans in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

# json_str KEY FILE: crude reader for a top-level string in installed.json.
json_str() {
    [ -f "$2" ] || return 1
    sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$2" | head -n 1
}
json_num() { # json_num KEY FILE: an unquoted integer value
    [ -f "$2" ] || return 1
    sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$2" | head -n 1
}
json_true() { # json_true KEY FILE
    [ -f "$2" ] && grep -E -q '"'"$1"'"[[:space:]]*:[[:space:]]*true' "$2" 2>/dev/null
}

# depth PATH: number of components of an absolute path ("/opt/fp" -> 2).
depth() {
    printf '%s' "$1" | tr -cd '/' | wc -c | tr -d ' '
}

# guard_home: refuse to delete anything that is not clearly a FileParcel home.
guard_home() {
    is_home "$FP_HOME" || die "refusing to delete $FP_HOME: it does not look like a FileParcel installation"
    case $FP_HOME in
        /*) ;;
        *) die "refusing to delete a relative path: $FP_HOME" ;;
    esac
    case $FP_HOME in
        */. | */.. | */./* | */../*) die "refusing to delete $FP_HOME: not a canonical path" ;;
    esac
    [ "$(depth "$FP_HOME")" -ge 2 ] || die "refusing to delete the top-level directory $FP_HOME"
    case $FP_HOME in
        /usr/local | /usr/local/bin | /usr/local/sbin | /usr/local/lib | /usr/local/share | /usr/local/etc | \
            /usr/local/var | /usr/local/opt | /usr/bin | /usr/sbin | /usr/lib | /usr/lib64 | /usr/libexec | \
            /usr/share | /usr/include | /usr/src | /var/lib | /var/log | /var/tmp | /var/cache | /var/spool | \
            /var/db | /var/root | /var/mail | /opt/homebrew | /opt/local | /private/tmp | /private/var | \
            /private/etc | /Library/* | /System/* | /Users/Shared | /etc/*)
            die "refusing to delete the system directory $FP_HOME"
            ;;
    esac
    # somebody's home directory itself
    case $FP_HOME in
        /home/* | /Users/*)
            [ "$(depth "$FP_HOME")" -ge 3 ] || die "refusing to delete the home directory $FP_HOME"
            ;;
    esac
    if [ -n "${HOME:-}" ]; then
        uh=$(abs_dir "$HOME" || printf '%s' "$HOME")
        case $uh/ in
            "$FP_HOME"/*) die "refusing to delete $FP_HOME: it contains your home directory $uh" ;;
        esac
    fi
    case $(basename -- "$FP_HOME") in
        Documents | Desktop | Downloads | .local | share | .config | "Application Support" | Library | tmp)
            die "refusing to delete the generic directory $FP_HOME"
            ;;
    esac
}

REC="$FP_HOME/service/installed.json"
if [ "$PURGE" -eq 1 ]; then guard_home; fi

# FP_HOME is the physical path, but the installer records HOME as it was
# given (e.g. /opt/fileparcel where /opt links to /var/opt, as on Fedora
# Silverblue), and the service registration and the command link name that
# spelling. REG_HOME is the recorded one when it is the same directory; the
# checks below accept both. Deleting (guard_home, rm) uses FP_HOME only.
REG_HOME=$FP_HOME
rec_home=$(json_str home "$REC" 2>/dev/null || true)
case $rec_home in
    /*)
        if [ "$rec_home" != "$FP_HOME" ] && [ "$(abs_dir "$rec_home" || true)" = "$FP_HOME" ]; then
            REG_HOME=$rec_home
        fi
        ;;
esac

# in_home PATH: PATH lies inside this installation (either spelling).
in_home() {
    case $1 in
        "$FP_HOME"/* | "$REG_HOME"/*) return 0 ;;
    esac
    return 1
}

# unit_is_ours FILE: the systemd unit serves exactly this HOME - the marker
# svc.systemdManager.ownership checks: --home "<HOME quoted for systemd>".
# The closing quote keeps /opt/fileparcel from matching /opt/fileparcel-new.
unit_is_ours() {
    [ -f "$1" ] || return 1
    for h in "$FP_HOME" "$REG_HOME"; do
        q=$(printf '%s' "$h" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\$/$$/g' -e 's/%/%%/g')
        if grep -F -q -- "--home \"$q\"" "$1" 2>/dev/null; then return 0; fi
    done
    return 1
}

# plist_is_ours FILE: the launchd plist's arguments name exactly this HOME
# (XML-escaped like svc.launchdManager.ownership: <string>HOME</string>).
plist_is_ours() {
    [ -f "$1" ] || return 1
    for h in "$FP_HOME" "$REG_HOME"; do
        x=$(printf '%s' "$h" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e "s/'/\\&#39;/g" -e 's/"/\&#34;/g')
        if grep -F -q -- "<string>$x</string>" "$1" 2>/dev/null; then return 0; fi
    done
    return 1
}

if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run (limited fallback uninstaller); nothing is changed. It would:"
    say "  - stop and unregister the systemd/launchd service if it belongs to $FP_HOME"
    say "  - stop a server started by hand (run/fileparcel.pid)"
    say "  - remove the fileparcel command symlink if it points into $FP_HOME"
    if [ "$REMOVE_USER" -eq 1 ]; then
        say "  - delete the system account named in service/installed.json"
    fi
    if [ "$PURGE" -eq 1 ]; then
        say "  - overwrite every key file (keys/, certs/ and their copies in pre-restore-*/) with random bytes"
        say "  - delete $FP_HOME with all its data"
    else
        say "  - keep $FP_HOME with all its data"
    fi
    exit 0
fi
if [ "$PURGE" -eq 1 ]; then
    what="remove the service and the command symlink, DESTROY the keys and DELETE $FP_HOME with all files"
else
    what="remove the service and the command symlink (the data in $FP_HOME is kept)"
fi
confirm "Uninstall FileParcel: $what?" || die "aborted"

SUDO_HINTS=""
hint() { SUDO_HINTS="$SUDO_HINTS  $*
"; }

# --- service ---
# Only registrations that point into this HOME are touched, so another
# installation's service is never stopped by mistake.
case $OS in
    Linux)
        if command -v systemctl >/dev/null 2>&1; then
            if ! is_root; then
                if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$UID_NOW" ]; then
                    XDG_RUNTIME_DIR=/run/user/$UID_NOW
                    export XDG_RUNTIME_DIR
                fi
                user_link="${XDG_CONFIG_HOME:-${HOME:-/nonexistent}/.config}/systemd/user/$UNIT"
                ours=0
                frag=$(systemctl --user show -p FragmentPath --value "$UNIT" 2>/dev/null || true)
                if in_home "$frag"; then ours=1; fi
                if [ -L "$user_link" ]; then
                    if in_home "$(link_target "$user_link" || true)"; then ours=1; fi
                elif unit_is_ours "$user_link"; then
                    ours=1
                fi
                if [ "$ours" -eq 1 ]; then
                    say "Stopping and disabling the systemd user service"
                    systemctl --user stop "$UNIT" 2>/dev/null || true
                    systemctl --user disable "$UNIT" 2>/dev/null || true
                    if [ -L "$user_link" ]; then rm -f "$user_link"; fi
                    systemctl --user daemon-reload 2>/dev/null || true
                    systemctl --user reset-failed "$UNIT" 2>/dev/null || true
                fi
            fi
            sys_unit=/etc/systemd/system/$UNIT
            if unit_is_ours "$sys_unit"; then
                if is_root; then
                    say "Stopping and removing the systemd system service"
                    systemctl stop "$UNIT" 2>/dev/null || true
                    systemctl disable "$UNIT" 2>/dev/null || true
                    rm -f "$sys_unit"
                    systemctl daemon-reload 2>/dev/null || true
                    systemctl reset-failed "$UNIT" 2>/dev/null || true
                else
                    hint "sudo systemctl disable --now $UNIT && sudo rm -f $sys_unit && sudo systemctl daemon-reload"
                fi
            elif [ -f "$sys_unit" ]; then
                say "Note: $sys_unit serves another FileParcel installation; not touching it"
            fi
        fi
        if json_true linger_enabled_by_us "$REC"; then
            say "Note: the installer enabled lingering for $(id -un). If no other user services need it:"
            say "  loginctl disable-linger $(id -un)"
        fi
        ;;
    Darwin)
        # The plist is in LaunchAgents/LaunchDaemons with start at boot, else
        # in "Application Support/com.fileparcel.server" next to them.
        for agent in "${HOME:-/nonexistent}/Library/LaunchAgents/$LABEL.plist" \
            "${HOME:-/nonexistent}/Library/Application Support/$LABEL/$LABEL.plist"; do
            if ! is_root && plist_is_ours "$agent"; then
                say "Unloading the launchd agent"
                launchctl bootout "gui/$UID_NOW/$LABEL" 2>/dev/null || launchctl unload "$agent" 2>/dev/null || true
                rm -f "$agent"
            fi
        done
        for daemon in "/Library/LaunchDaemons/$LABEL.plist" "/Library/Application Support/$LABEL/$LABEL.plist"; do
            if plist_is_ours "$daemon"; then
                if is_root; then
                    say "Unloading the launchd daemon"
                    launchctl bootout "system/$LABEL" 2>/dev/null || launchctl unload "$daemon" 2>/dev/null || true
                    rm -f "$daemon"
                else
                    hint "sudo launchctl bootout system/$LABEL; sudo rm -f '$daemon'"
                fi
            fi
        done
        ;;
esac
# a server started by hand (no service) still holds the pid file
pidf="$FP_HOME/run/fileparcel.pid"
if [ -f "$pidf" ]; then
    pid=$(tr -cd '0-9' <"$pidf" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null &&
        ps -p "$pid" -o comm= 2>/dev/null | grep -q fileparcel; then
        say "Stopping the running server (pid $pid)"
        kill -TERM "$pid" 2>/dev/null || true
        i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 40 ]; do
            sleep 1
            i=$((i + 1))
        done
    fi
fi

# --- command symlink (only when it points into HOME) ---
rec_link=$(json_str symlink "$REC" 2>/dev/null || true)
for l in "$rec_link" "${HOME:-/nonexistent}/.local/bin/fileparcel" /usr/local/bin/fileparcel; do
    [ -n "$l" ] && [ -L "$l" ] || continue
    tgt=$(link_target "$l") || continue
    if in_home "$tgt"; then
        if rm -f "$l" 2>/dev/null; then
            say "Removed the symlink $l"
        else
            hint "sudo rm -f $l"
        fi
    fi
done

# --- system account ---
if [ "$REMOVE_USER" -eq 1 ]; then
    acct=$(json_str created_user "$REC" 2>/dev/null || true)
    if [ -z "$acct" ]; then
        warn "--remove-user: the installation record names no created account; nothing removed"
    elif [ "$acct" != fileparcel ] && [ "$acct" != _fileparcel ]; then
        # The service account itself can write the record: only ever delete
        # the account the installer creates.
        warn "--remove-user: the installation record names $acct, not the service account; nothing removed"
    elif ! is_root; then
        case $OS in
            Darwin) hint "sudo dscl . -delete /Users/$acct; sudo dscl . -delete /Groups/$acct" ;;
            *) hint "sudo userdel $acct" ;;
        esac
    else
        case $OS in
            Darwin)
                dscl . -delete "/Users/$acct" 2>/dev/null || warn "could not delete the account $acct"
                dscl . -delete "/Groups/$acct" 2>/dev/null || true
                ;;
            *)
                if command -v userdel >/dev/null 2>&1; then
                    userdel "$acct" 2>/dev/null || warn "could not delete the account $acct"
                elif command -v deluser >/dev/null 2>&1; then
                    deluser "$acct" 2>/dev/null || warn "could not delete the account $acct"
                fi
                ;;
        esac
    fi
fi

# --- purge ---
# shred_file FILE: overwrite with random bytes of the same size (at most
# 4 MiB, like the Go uninstaller), then delete. Symlinks are not followed.
shred_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 0
    size=$(wc -c <"$1" | tr -d ' ')
    [ "$size" -gt 0 ] || size=64
    [ "$size" -le 4194304 ] || size=4194304
    dd if=/dev/urandom of="$1" bs="$size" count=1 conv=notrunc 2>/dev/null || true
    sync 2>/dev/null || true
    rm -f "$1"
}

# shred_tree DIR: shred every regular file below DIR. A symlinked DIR is
# skipped, and find does not follow the symlinks below it.
shred_tree() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 0
    find "$1" -type f -print | while IFS= read -r f; do shred_file "$f"; done
}

if [ "$PURGE" -eq 1 ]; then
    guard_home
    say "Destroying the keys"
    # All of keys/ and certs/ (also the Tailscale and ACME keys), the copies
    # every restore keeps in pre-restore-*/, those of restore and verify
    # staging a crash left in tmp/, and the key of a pending restore.
    shred_tree "$FP_HOME/keys"
    shred_tree "$FP_HOME/certs"
    for d in "$FP_HOME"/pre-restore-*; do
        [ -d "$d" ] && [ ! -L "$d" ] || continue
        shred_tree "$d/keys"
        shred_tree "$d/certs"
    done
    for t in restore verify; do
        [ ! -L "$FP_HOME/tmp" ] && [ -d "$FP_HOME/tmp/$t" ] && [ ! -L "$FP_HOME/tmp/$t" ] || continue
        for d in "$FP_HOME/tmp/$t"/*; do
            [ -d "$d" ] && [ ! -L "$d" ] || continue
            shred_tree "$d/keys"
            shred_tree "$d/certs"
        done
    done
    shred_file "$FP_HOME/run/restore.key"
    say "Note: on SSDs and copy-on-write file systems overwriting cannot guarantee that the old key"
    say "bytes are physically gone; full-disk encryption (LUKS/FileVault) covers that."
    say "Deleting $FP_HOME"
    rm -rf -- "$FP_HOME"
fi

if [ -n "$SUDO_HINTS" ]; then
    say ""
    say "Some steps need administrator rights. Run:"
    printf '%s' "$SUDO_HINTS" >&2
fi
say ""
# the ports the installation recorded (the defaults when it recorded none)
fw_https=$(json_num https_port "$REC" 2>/dev/null || true)
fw_http=$(json_num http_port "$REC" 2>/dev/null || true)
fw_ports="--remove-port=${fw_https:-8443}/tcp"
if [ -z "$fw_https" ] && [ -z "$fw_http" ]; then
    fw_ports="$fw_ports --remove-port=8080/tcp"
elif [ -n "$fw_http" ] && [ "$fw_http" != 0 ]; then
    fw_ports="$fw_ports --remove-port=$fw_http/tcp"
fi
say "If you opened firewall ports for FileParcel, remove those rules too, e.g.:"
say "  sudo ufw status numbered            (then: sudo ufw delete <number>)"
say "  sudo firewall-cmd --permanent $fw_ports && sudo firewall-cmd --reload"
if [ "$PURGE" -eq 1 ]; then
    say "FileParcel was removed."
else
    say "FileParcel was uninstalled; the data is still in $FP_HOME."
    say "Reinstall with: ./install.sh --dir \"$FP_HOME\"    or delete it with: $PROG --dir \"$FP_HOME\" --purge"
fi
