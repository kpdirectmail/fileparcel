// Package svc generates and controls the OS service registration of a
// FileParcel home (DESIGN §14.2–14.6):
//
//   - systemd user units (<HOME>/service/fileparcel.service, linked with
//     `systemctl --user link`, linger for start-at-boot) and system units
//     (copied to /etc/systemd/system, hardened, run as the fileparcel
//     account) — systemd.go;
//   - launchd agents (~/Library/LaunchAgents) and daemons
//     (/Library/LaunchDaemons, UserName=_fileparcel) — launchd.go;
//   - a Manager (install/uninstall/start/stop/restart/status/boot) for each
//     kind — manager.go;
//   - linger bookkeeping (loginctl) — linger.go; system account creation
//     (useradd / adduser / dscl) — account.go;
//   - firewall detection and the exact commands to open the ports —
//     firewall.go;
//   - platform defaults (install dir, PATH symlink) and the PATH symlink —
//     platform.go;
//   - the <HOME>/service/installed.json record — this file;
//   - dry-run plans — plan.go; the pinned local health check — health.go.
//
// External commands run through a Runner (runner.go) so everything is unit
// testable with a fake. Owned by unit I. Subpackages: provision (the `init`
// logic) and installer (install/upgrade/uninstall orchestration).
package svc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"fileparcel/internal/home"
)

// Kind is the kind of service registration.
type Kind string

// Service kinds.
const (
	KindNone          Kind = "none"
	KindSystemdUser   Kind = "systemd-user"
	KindSystemdSystem Kind = "systemd-system"
	KindLaunchdAgent  Kind = "launchd-agent"
	KindLaunchdDaemon Kind = "launchd-daemon"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindNone, KindSystemdUser, KindSystemdSystem, KindLaunchdAgent, KindLaunchdDaemon:
		return true
	}
	return false
}

// System reports whether k is a system-wide (root) registration.
func (k Kind) System() bool { return k == KindSystemdSystem || k == KindLaunchdDaemon }

// Systemd reports whether k is a systemd kind.
func (k Kind) Systemd() bool { return k == KindSystemdUser || k == KindSystemdSystem }

// Launchd reports whether k is a launchd kind.
func (k Kind) Launchd() bool { return k == KindLaunchdAgent || k == KindLaunchdDaemon }

// Describe returns a human description ("systemd user service", …).
func (k Kind) Describe() string {
	switch k {
	case KindSystemdUser:
		return "systemd user service"
	case KindSystemdSystem:
		return "systemd system service"
	case KindLaunchdAgent:
		return "launchd agent"
	case KindLaunchdDaemon:
		return "launchd daemon"
	}
	return "no service (run \"fileparcel serve\" yourself)"
}

// Label is the launchd label.
const Label = "com.fileparcel.server"

// UnitName is the systemd unit file name.
const UnitName = "fileparcel.service"

// PlistName is the launchd plist file name.
const PlistName = Label + ".plist"

// DefaultSystemUser is the service account of system installs on Linux;
// DefaultMacSystemUser the role account on macOS (DESIGN §14.4, §14.5).
const (
	DefaultSystemUser    = "fileparcel"
	DefaultMacSystemUser = "_fileparcel"
)

// InstalledFile is the name of the install record in <HOME>/service.
const InstalledFile = "installed.json"

// Installed is the content of <HOME>/service/installed.json (DESIGN §14.2):
// what the installer created, so uninstall/upgrade/doctor undo or check
// exactly that.
type Installed struct {
	Kind              Kind      `json:"kind"`
	UnitPath          string    `json:"unit_path,omitempty"` // registration file (link or copy) outside HOME
	Boot              bool      `json:"boot"`
	LingerEnabledByUs bool      `json:"linger_enabled_by_us"`
	Symlink           string    `json:"symlink,omitempty"`      // PATH symlink we created
	CreatedUser       string    `json:"created_user,omitempty"` // system account we created
	ServiceUser       string    `json:"service_user,omitempty"` // account the service runs as (system kinds)
	Home              string    `json:"home"`
	HTTPSPort         int       `json:"https_port,omitempty"`
	HTTPPort          int       `json:"http_port,omitempty"`
	Version           string    `json:"version"`
	InstalledAt       time.Time `json:"installed_at"`
	UpgradedAt        time.Time `json:"upgraded_at,omitzero"`
	// Incomplete marks a home that is not (or no longer) fully installed:
	// `uninstall --keep-data` removed its service and command link, or an
	// install failed after initialising it. The next `install` on the home
	// registers the service and the link again from its own options instead
	// of only replacing the binary.
	Incomplete bool `json:"incomplete,omitempty"`
	// FirewallSubnets, FirewallIfaces and FirewallAnywhere (access mode any:
	// the ports open to every source) are what the firewall hints were
	// computed from, so uninstall prints the matching removal commands.
	FirewallSubnets  []string `json:"firewall_subnets,omitempty"`
	FirewallIfaces   []string `json:"firewall_ifaces,omitempty"`
	FirewallAnywhere bool     `json:"firewall_anywhere,omitempty"`
}

// Options describes a service to generate or install.
type Options struct {
	Kind      Kind
	Home      string // absolute HOME
	Binary    string // absolute path of <HOME>/bin/fileparcel
	Boot      bool   // start at boot (linger for systemd --user; launchd: the plist in LaunchAgents/LaunchDaemons)
	User      string // system installs: service account
	Group     string // system installs: service group ("" = User)
	HTTPSPort int
	HTTPPort  int
	// Force replaces a registration that belongs to another FileParcel home.
	Force bool
}

// Validate checks the fields every generator needs.
func (o Options) Validate() error {
	switch {
	case !o.Kind.Valid():
		return fmt.Errorf("svc: unknown service kind %q", o.Kind)
	case o.Home == "" || !filepath.IsAbs(o.Home):
		return errors.New("svc: home must be an absolute path")
	case o.Binary == "" || !filepath.IsAbs(o.Binary):
		return errors.New("svc: binary must be an absolute path")
	case o.Kind.System() && o.User == "":
		return errors.New("svc: system services need a service user")
	case o.Kind.System() && o.User != DefaultSystemUser && o.User != DefaultMacSystemUser:
		// The user often comes from installed.json, which the service
		// account itself can write: root must never render a unit or plist
		// that runs the server as root or as any other account.
		return fmt.Errorf("svc: system services run as %s (%s on macOS), not %q", DefaultSystemUser, DefaultMacSystemUser, o.User)
	}
	return nil
}

func (o Options) group() string {
	if o.Group != "" {
		return o.Group
	}
	return o.User
}

// InstalledPath returns <HOME>/service/installed.json.
func InstalledPath(h *home.Home) string { return filepath.Join(h.ServiceDir(), InstalledFile) }

// ReadInstalled reads <HOME>/service/installed.json; (nil, nil) when absent.
func ReadInstalled(h *home.Home) (*Installed, error) {
	b, err := os.ReadFile(InstalledPath(h))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var in Installed
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("svc: %s: %w", InstalledPath(h), err)
	}
	if in.Kind == "" {
		in.Kind = KindNone
	}
	return &in, nil
}

// WriteInstalled writes <HOME>/service/installed.json atomically (0640).
func WriteInstalled(h *home.Home, in *Installed) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.ServiceDir(), home.ModeService); err != nil {
		return err
	}
	return WriteFileAtomic(InstalledPath(h), append(b, '\n'), 0o640)
}

// WriteFileAtomic writes data to path via a temporary file in the same
// directory, fsync and rename, with the given mode.
func WriteFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
