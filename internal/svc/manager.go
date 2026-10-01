package svc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrNoService is returned by NewManager for KindNone.
var ErrNoService = errors.New("svc: no service registration (kind none)")

// ErrNotOurs means the service registration belongs to another FileParcel
// home (or is not a FileParcel file at all) and is left alone.
var ErrNotOurs = errors.New("the service registration belongs to something else")

// ErrNotInstalled means no service is registered for this home.
var ErrNotInstalled = errors.New("the service is not installed for this home (run \"fileparcel service install\")")

// RegState says who owns an existing registration file.
type RegState int

// Registration states.
const (
	RegAbsent  RegState = iota // nothing registered
	RegStale                   // a dangling link (e.g. to a deleted home): replaceable
	RegOurs                    // registered for this home
	RegOther                   // a FileParcel registration of another home
	RegForeign                 // not a FileParcel file
)

// registrationState inspects reg (a link or a copied file): ours when it
// links to unitFile or its content contains homeMarker; another FileParcel
// home when it contains fpMarker; foreign otherwise.
func registrationState(reg, unitFile string, homeMarker, fpMarker []byte) (RegState, string) {
	fi, err := os.Lstat(reg)
	if err != nil {
		return RegAbsent, ""
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		t, err := os.Readlink(reg)
		if err == nil && t == unitFile {
			return RegOurs, ""
		}
		if _, err := os.Stat(reg); err != nil {
			return RegStale, "dangling link to " + t
		}
	}
	b, err := os.ReadFile(reg)
	if err != nil {
		return RegForeign, err.Error()
	}
	switch {
	case bytes.Contains(b, homeMarker):
		return RegOurs, ""
	case bytes.Contains(b, fpMarker):
		return RegOther, "registered for another FileParcel home"
	}
	return RegForeign, "not a FileParcel service file"
}

// checkInstallable refuses to overwrite another home's or a foreign
// registration unless force is set (then only another home's).
func checkInstallable(own func() (RegState, string), reg string, force bool) error {
	switch st, who := own(); st {
	case RegOther:
		if !force {
			return fmt.Errorf("%w: %s is %s; uninstall that service first or use --force", ErrNotOurs, reg, who)
		}
	case RegForeign:
		return fmt.Errorf("%w: %s exists and is %s; remove it first", ErrNotOurs, reg, who)
	}
	return nil
}

// checkControllable allows start/stop/boot changes only for our own registration.
func checkControllable(own func() (RegState, string), reg string) error {
	switch st, who := own(); st {
	case RegOurs:
		return nil
	case RegOther, RegForeign:
		return fmt.Errorf("%w: %s is %s", ErrNotOurs, reg, who)
	}
	return ErrNotInstalled
}

// Status is the observed state of a service registration.
type Status struct {
	Kind         Kind   `json:"kind"`
	Registration string `json:"registration"` // unit link/file or plist path
	Installed    bool   `json:"installed"`    // registration file present
	Enabled      bool   `json:"enabled"`      // starts at boot/login
	Active       bool   `json:"active"`       // running (or starting)
	State        string `json:"state"`        // systemd ActiveState / launchd state
	SubState     string `json:"sub_state,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// Manager controls one service registration.
type Manager interface {
	Kind() Kind
	// Render returns the unit file or plist content.
	Render() ([]byte, error)
	// Install writes and registers the service (idempotent), enables it
	// when Options.Boot is set and (re)starts it when start is set.
	Install(ctx context.Context, start bool) error
	// Uninstall stops, disables and unregisters the service.
	Uninstall(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
	EnableBoot(ctx context.Context) error
	DisableBoot(ctx context.Context) error
	Status(ctx context.Context) (*Status, error)
	// RegistrationPath is the file the service manager loads.
	RegistrationPath() string
}

// RegistrationPath implements Manager.
func (m *launchdManager) RegistrationPath() string { return m.PlistPath() }

// NewManager returns the Manager of o.Kind on host h. User kinds must not be
// managed as root and system kinds need root (checked here so mistakes fail
// before anything is written).
func NewManager(h *Host, o Options) (Manager, error) {
	if o.Kind == KindNone {
		return nil, ErrNoService
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	switch o.Kind {
	case KindSystemdUser, KindSystemdSystem:
		if h.GOOS != "linux" {
			return nil, fmt.Errorf("svc: systemd services need Linux (this is %s)", h.GOOS)
		}
		if o.Kind == KindSystemdSystem && !h.Root() {
			return nil, errors.New("svc: a system service needs root (use sudo, or --service user)")
		}
		if o.Kind == KindSystemdUser && h.Root() {
			return nil, errors.New("svc: refusing to install a systemd user service for root (use --service system)")
		}
		return &systemdManager{h: h, o: o, user: o.Kind == KindSystemdUser}, nil
	case KindLaunchdAgent, KindLaunchdDaemon:
		if h.GOOS != "darwin" {
			return nil, fmt.Errorf("svc: launchd services need macOS (this is %s)", h.GOOS)
		}
		if o.Kind == KindLaunchdDaemon && !h.Root() {
			return nil, errors.New("svc: a launchd daemon needs root (use sudo, or --service user)")
		}
		return &launchdManager{h: h, o: o}, nil
	}
	return nil, fmt.Errorf("svc: unknown service kind %q", o.Kind)
}

// Render returns the registration file content for o without touching the
// system (for `service print` and dry runs).
func Render(o Options) ([]byte, error) {
	switch {
	case o.Kind.Systemd():
		return SystemdUnit(o)
	case o.Kind.Launchd():
		return LaunchdPlist(o)
	}
	return nil, ErrNoService
}
