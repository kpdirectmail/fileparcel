package svc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultHome returns the default install directory (DESIGN §14.2): Linux
// root /opt/fileparcel, Linux user ~/.local/share/fileparcel ($XDG_DATA_HOME
// honoured), macOS root /usr/local/fileparcel, macOS user
// ~/Library/Application Support/FileParcel (not ~/Documents: TCC prompts
// for launchd jobs).
func DefaultHome(h *Host) string {
	switch {
	case h.GOOS == "darwin" && h.Root():
		return "/usr/local/fileparcel"
	case h.GOOS == "darwin":
		return filepath.Join(h.HomeDir, "Library", "Application Support", "FileParcel")
	case h.Root():
		return "/opt/fileparcel"
	}
	if x := h.getenv("XDG_DATA_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "fileparcel")
	}
	return filepath.Join(h.HomeDir, ".local", "share", "fileparcel")
}

// DefaultSymlink returns the default PATH symlink: /usr/local/bin/fileparcel
// for root, ~/.local/bin/fileparcel otherwise.
func DefaultSymlink(h *Host) string {
	if h.Root() {
		return "/usr/local/bin/fileparcel"
	}
	return filepath.Join(h.HomeDir, ".local", "bin", "fileparcel")
}

// ErrNeedsRoot is ResolveKind's answer to --service system without root.
var ErrNeedsRoot = errors.New("--service system needs root (run the installer with sudo)")

// SystemKind is the system service kind of goos (KindNone where there is
// none): what --service system resolves to for root.
func SystemKind(goos string) Kind {
	switch goos {
	case "linux":
		return KindSystemdSystem
	case "darwin":
		return KindLaunchdDaemon
	}
	return KindNone
}

// ResolveKind maps the --service flag (user | system | none | "" = default)
// to a Kind for h: root → system, otherwise user; Linux without systemd —
// no systemctl, or systemd not running as init (WSL without systemd=true,
// most containers) — and other systems → none (with a reason). An explicit
// user or system kind that cannot work is an error.
func ResolveKind(h *Host, service string) (Kind, string, error) {
	switch service {
	case "", "user", "system", "none":
	default:
		return "", "", fmt.Errorf("--service must be user, system or none (got %q)", service)
	}
	if service == "none" {
		return KindNone, "", nil
	}
	explicit := service != ""
	if !explicit {
		service = "user"
		if h.Root() {
			service = "system"
		}
	}
	switch h.GOOS {
	case "linux":
		if !h.Has("systemctl") {
			return KindNone, "systemd (systemctl) not found: no service will be installed", nil
		}
		if !systemdBooted(h) {
			if explicit {
				return "", "", fmt.Errorf("--service %s needs systemd running as the init system (%s does not exist); "+
					"use --service none, or on WSL set systemd=true in the [boot] section of /etc/wsl.conf and run \"wsl --shutdown\"",
					service, h.Paths.SystemdRunDir)
			}
			return KindNone, "systemd is not running as the init system (no " + h.Paths.SystemdRunDir +
				"; e.g. WSL without systemd=true, or a container): no service will be installed", nil
		}
		if service == "system" {
			if !h.Root() {
				return "", "", ErrNeedsRoot
			}
			return KindSystemdSystem, "", nil
		}
		if h.Root() {
			return "", "", errors.New("--service user cannot be used as root; use --service system or run as the user")
		}
		return KindSystemdUser, "", nil
	case "darwin":
		if service == "system" {
			if !h.Root() {
				return "", "", ErrNeedsRoot
			}
			return KindLaunchdDaemon, "", nil
		}
		if h.Root() {
			return "", "", errors.New("--service user cannot be used as root; use --service system or run as the user")
		}
		return KindLaunchdAgent, "", nil
	}
	return KindNone, "service registration is not supported on " + h.GOOS, nil
}

// systemdBooted reports whether systemd is the running init: sd_booted(3)
// checks for /run/systemd/system. systemctl alone proves nothing — WSL
// without systemd and container images ship it, and then only fail to
// reach systemd, after the home was already initialised.
func systemdBooted(h *Host) bool {
	if h.Paths.SystemdRunDir == "" {
		return true
	}
	fi, err := os.Lstat(h.Paths.SystemdRunDir)
	return err == nil && fi.IsDir()
}

// ServiceUser returns the account system services run as on h.
func ServiceUser(h *Host) string {
	if h.GOOS == "darwin" {
		return DefaultMacSystemUser
	}
	return DefaultSystemUser
}

// SymlinkState describes an existing path where the PATH symlink should go.
type SymlinkState int

// Symlink states.
const (
	SymlinkMissing SymlinkState = iota // nothing there
	SymlinkOurs                        // a symlink pointing at the target
	SymlinkOther                       // a symlink pointing elsewhere
	SymlinkForeign                     // a regular file or directory
)

// InspectSymlink reports what is at link relative to target.
func InspectSymlink(link, target string) (SymlinkState, string) {
	fi, err := os.Lstat(link)
	if err != nil {
		return SymlinkMissing, ""
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		return SymlinkForeign, ""
	}
	t, err := os.Readlink(link)
	if err != nil {
		return SymlinkOther, ""
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(link), t)
	}
	if filepath.Clean(t) == filepath.Clean(target) {
		return SymlinkOurs, t
	}
	return SymlinkOther, t
}

// EnsureSymlink points link at target, creating the parent directory. It
// never replaces a foreign file or a symlink to something else unless
// force is set (DESIGN §14.2 step 4). changed reports whether anything was
// created or replaced.
func EnsureSymlink(link, target string, force bool) (changed bool, err error) {
	st, cur := InspectSymlink(link, target)
	switch st {
	case SymlinkOurs:
		return false, nil
	case SymlinkOther:
		if !force {
			return false, fmt.Errorf("%s already links to %s; use --force to replace it or --no-symlink", link, cur)
		}
		if err := os.Remove(link); err != nil {
			return false, err
		}
	case SymlinkForeign:
		if !force {
			return false, fmt.Errorf("%s already exists and is not a symlink; use --force to replace it or --no-symlink", link)
		}
		if fi, err := os.Lstat(link); err == nil && fi.IsDir() {
			return false, fmt.Errorf("%s is a directory", link)
		}
		if err := os.Remove(link); err != nil {
			return false, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return false, err
	}
	if err := os.Symlink(target, link); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveSymlink removes link only when it is a symlink pointing into home
// (DESIGN §14.6). removed reports whether it was removed.
func RemoveSymlink(link, home string) (removed bool, err error) {
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return false, nil
	}
	t, err := os.Readlink(link)
	if err != nil {
		return false, nil
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(link), t)
	}
	if !Within(home, t) {
		return false, nil
	}
	if err := os.Remove(link); err != nil {
		return false, err
	}
	return true, nil
}

// Within reports whether p is dir or below it (lexically, after Clean).
func Within(dir, p string) bool {
	dir, p = filepath.Clean(dir), filepath.Clean(p)
	if dir == p {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}

// OnPath reports whether dir is listed in the PATH value.
func OnPath(dir, pathEnv string) bool {
	for _, p := range filepath.SplitList(pathEnv) {
		if p != "" && filepath.Clean(p) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

// PortFree reports whether TCP port p can be bound on all interfaces.
func PortFree(p int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// NextFreePort returns the first port ≥ p for which free reports true
// (skipping the ports in avoid), or 0 when none is free below 65536.
func NextFreePort(p int, free func(int) bool, avoid ...int) int {
	for ; p > 0 && p < 65536; p++ {
		skip := false
		for _, a := range avoid {
			if a == p {
				skip = true
			}
		}
		if !skip && free(p) {
			return p
		}
	}
	return 0
}

// osGetenv is os.Getenv (tests replace it).
var osGetenv = os.Getenv

// DangerousHome reports whether dir must never be purged or used as a home:
// the filesystem root, system directories, the user's own home directory
// itself and the shared directories in it — among them the parents of the
// default homes (~/.local/share or $XDG_DATA_HOME, ~/Library/Application
// Support), which hold other applications' data (DESIGN §14.6 guards).
func DangerousHome(dir, userHome string) bool {
	d := filepath.Clean(dir)
	if d == "/" || d == "." || d == "" || !filepath.IsAbs(d) {
		return true
	}
	if userHome != "" && d == filepath.Clean(userHome) {
		return true
	}
	for _, s := range []string{"/usr", "/usr/local", "/usr/local/bin", "/usr/bin", "/bin", "/sbin", "/etc", "/var", "/var/lib",
		"/opt", "/home", "/root", "/tmp", "/boot", "/dev", "/proc", "/sys", "/run", "/lib", "/lib64", "/srv", "/mnt", "/media",
		"/Users", "/Library", "/System", "/Applications", "/private", "/private/var", "/private/tmp", "/Volumes"} {
		if d == s {
			return true
		}
	}
	if userHome != "" {
		for _, s := range []string{"Documents", "Desktop", "Downloads", "Library", "Library/Application Support",
			"Library/Preferences", "Library/Caches", ".local", ".local/share", ".local/state", ".local/bin", ".config", ".cache"} {
			if d == filepath.Join(userHome, s) {
				return true
			}
		}
	}
	for _, k := range []string{"XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
		if x := osGetenv(k); x != "" && filepath.IsAbs(x) && d == filepath.Clean(x) {
			return true
		}
	}
	return false
}
