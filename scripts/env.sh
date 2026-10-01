# shellcheck shell=sh
# FileParcel development environment. Source it (do not execute):
#
#     . scripts/env.sh
#
# - If `go` is not on PATH or is older than 1.26 (what FileParcel needs),
#   prepends every ~/sdk/go*/bin (newest version first); a go >= 1.26 on PATH
#   stays first.
# - Exports GOTOOLCHAIN=local so the installed toolchain is always used.
# POSIX sh; works in bash, zsh, dash and macOS bash 3.2.

fp_env_sdk_bins() {
    # Print "<sortkey> <dir>" for each ~/sdk/goX.Y[.Z]/bin, then sort newest first.
    for fp_d in "$HOME"/sdk/go*/bin; do
        [ -x "$fp_d/go" ] || continue
        fp_v=$(basename "$(dirname "$fp_d")")
        fp_v=${fp_v#go}
        printf '%s %s\n' "$(printf '%s' "$fp_v" | awk -F. '{
            maj = $1 + 0; min = $2 + 0; pat = $3 + 0;
            # pre-releases (1.27rc1) sort below the release
            if ($2 ~ /[a-z]/) { pat = -1 }
            printf "%06d%06d%06d", maj, min, pat + 1 }')" "$fp_d"
    done | sort -r | while read -r _ fp_dir; do printf '%s\n' "$fp_dir"; done
    unset fp_d fp_v
}

# fp_env_need: 1 when the go on PATH is missing or too old (a distro go 1.19
# must not hide a ~/sdk toolchain installed by scripts/get-go.sh). Without
# GOVERSION (go < 1.16, or a go.mod newer than a local-only toolchain) it is
# too old as well.
fp_env_need=1
if command -v go >/dev/null 2>&1; then
    fp_env_gv=$(GOTOOLCHAIN=local go env GOVERSION 2>/dev/null || true)
    case $fp_env_gv in
        go1.*)
            fp_env_min=$(printf '%s' "${fp_env_gv#go1.}" | sed 's/[^0-9].*$//')
            if [ -n "$fp_env_min" ] && [ "$fp_env_min" -ge 26 ]; then fp_env_need=0; fi
            ;;
        devel*|go2*) fp_env_need=0 ;;
    esac
    unset fp_env_gv fp_env_min
fi

if [ "$fp_env_need" -eq 1 ]; then
    fp_env_path=""
    for fp_env_bin in $(fp_env_sdk_bins); do
        if [ -z "$fp_env_path" ]; then
            fp_env_path="$fp_env_bin"
        else
            fp_env_path="$fp_env_path:$fp_env_bin"
        fi
    done
    if [ -n "$fp_env_path" ]; then
        PATH="$fp_env_path:$PATH"
        export PATH
    elif ! command -v go >/dev/null 2>&1; then
        echo "scripts/env.sh: no Go toolchain found on PATH or in ~/sdk (run scripts/get-go.sh 1.27.1)" >&2
    fi
    unset fp_env_path fp_env_bin
fi
unset fp_env_need
unset -f fp_env_sdk_bins 2>/dev/null || true

GOTOOLCHAIN=local
export GOTOOLCHAIN
