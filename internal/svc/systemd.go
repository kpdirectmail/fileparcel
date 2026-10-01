package svc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SystemdUnit renders the systemd unit of DESIGN §14.3 (user) or §14.3 +
// §14.4 (system: service account, capability for ports < 1024, sandboxing).
func SystemdUnit(o Options) ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if !o.Kind.Systemd() {
		return nil, fmt.Errorf("svc: %s is not a systemd kind", o.Kind)
	}
	for _, s := range []string{o.Home, o.Binary, o.User, o.Group} {
		if strings.ContainsAny(s, "\x00\n\r") {
			return nil, errors.New("svc: control characters in unit values")
		}
	}
	docs := (&url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(o.Home, "docs", "FILEPARCEL.md"))}).String()
	var b bytes.Buffer
	line := func(s string) { b.WriteString(s + "\n") }
	line("[Unit]")
	line("Description=FileParcel file sharing server")
	line("Documentation=" + systemdEscapeSpecifiers(docs))
	line("After=network-online.target")
	line("Wants=network-online.target")
	line("[Service]")
	line("Type=notify")
	line("NotifyAccess=main")
	line("ExecStart=" + systemdQuote(o.Binary) + " serve --home " + systemdQuote(o.Home))
	line("Restart=always")
	line("RestartSec=2")
	line("TimeoutStopSec=40")
	line("WatchdogSec=60")
	line("UMask=0077")
	line("NoNewPrivileges=yes")
	line("LimitNOFILE=65536")
	if o.Kind == KindSystemdSystem {
		line("User=" + o.User)
		line("Group=" + o.group())
		if lowPort(o.HTTPSPort) || lowPort(o.HTTPPort) {
			line("AmbientCapabilities=CAP_NET_BIND_SERVICE")
			line("CapabilityBoundingSet=CAP_NET_BIND_SERVICE")
		}
		line("ProtectSystem=strict")
		line("ReadWritePaths=" + systemdQuotePath(o.Home))
		if underHomeDirs(o.Home) {
			line("ProtectHome=no")
		} else {
			line("ProtectHome=read-only")
		}
		line("PrivateTmp=yes")
		line("PrivateDevices=yes")
		line("ProtectKernelTunables=yes")
		line("ProtectKernelModules=yes")
		line("ProtectKernelLogs=yes")
		line("ProtectControlGroups=yes")
		line("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK")
		line("RestrictNamespaces=yes")
		line("LockPersonality=yes")
		line("MemoryDenyWriteExecute=yes")
		line("SystemCallArchitectures=native")
		line("SystemCallFilter=@system-service")
	}
	line("[Install]")
	if o.Kind == KindSystemdSystem {
		line("WantedBy=multi-user.target")
	} else {
		line("WantedBy=default.target")
	}
	return b.Bytes(), nil
}

func lowPort(p int) bool { return p > 0 && p < 1024 }

// underHomeDirs reports paths that ProtectHome would hide or make read-only.
func underHomeDirs(p string) bool {
	for _, d := range []string{"/home", "/root", "/run/user"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// systemdQuote quotes a word for ExecStart/ReadWritePaths: double quotes,
// backslash escapes, and "%" / "$" doubled so they are never expanded as
// specifiers or environment variables.
func systemdQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "$", "$$")
	return `"` + systemdEscapeSpecifiers(s) + `"`
}

func systemdEscapeSpecifiers(s string) string { return strings.ReplaceAll(s, "%", "%%") }

// systemdQuotePath quotes a path for path-list settings (ReadWritePaths=):
// specifiers are expanded there but environment variables are not.
func systemdQuotePath(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + systemdEscapeSpecifiers(s) + `"`
}

// ---------- control ----------

// systemdManager controls a systemd user or system unit.
type systemdManager struct {
	h    *Host
	o    Options
	user bool
}

// UnitFile returns where the unit file lives: <HOME>/service/fileparcel.service
// for user units (linked into the user unit dir), /etc/systemd/system/… for
// system units.
func (m *systemdManager) UnitFile() string {
	if m.user {
		return filepath.Join(m.o.Home, "service", UnitName)
	}
	return filepath.Join(m.h.Paths.SystemUnitDir, UnitName)
}

// RegistrationPath returns the file systemd loads the unit from.
func (m *systemdManager) RegistrationPath() string {
	if m.user {
		return filepath.Join(m.h.userUnitDir(), UnitName)
	}
	return m.UnitFile()
}

// userUnitDir returns the directory `systemctl --user link` registers user
// units in (Paths.UserUnitDir). The user manager makes that link itself
// (LinkUnitFiles over D-Bus), in the configuration directory it derived
// from its own environment when it started; this process's
// $XDG_CONFIG_HOME — a shell's, which the manager need not share — says
// nothing about it. When unset, the directory is asked from the manager
// once, falling back to ~/.config/systemd/user when it cannot be reached.
func (h *Host) userUnitDir() string {
	if h.Paths.UserUnitDir == "" {
		h.Paths.UserUnitDir = filepath.Join(h.HomeDir, ".config", "systemd", "user")
		if h.GOOS == "linux" && !h.Root() && h.Has("systemctl") {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			res, err := h.run(ctx, UserBusEnv(h), "systemctl", "--user", "show", "--property=UnitPath", "--value")
			if d := persistentUserUnitDir(string(res.Stdout)); err == nil && d != "" {
				h.Paths.UserUnitDir = d
			}
		}
	}
	return h.Paths.UserUnitDir
}

// persistentUserUnitDir picks the directory `systemctl --user link` writes
// to out of a user manager's UnitPath: its first ".../systemd/user.control"
// entry is the persistent control directory, which systemd puts next to
// that directory (listed too). "" when there is none (systemd < 233).
func persistentUserUnitDir(unitPath string) string {
	dirs := strings.Fields(unitPath)
	for _, d := range dirs {
		if strings.HasSuffix(d, "/systemd/user.control") {
			if cfg := strings.TrimSuffix(d, ".control"); filepath.IsAbs(cfg) && slices.Contains(dirs, cfg) {
				return filepath.Clean(cfg)
			}
			return ""
		}
	}
	return ""
}

// env returns the environment systemctl --user needs without a login
// session (XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS).
func (m *systemdManager) env() []string {
	if !m.user {
		return nil
	}
	return UserBusEnv(m.h)
}

// UserBusEnv returns XDG_RUNTIME_DIR=/run/user/<uid> and
// DBUS_SESSION_BUS_ADDRESS when they are not set (e.g. over ssh without a
// login session or from sudo -u), so `systemctl --user` can reach the user
// manager (DESIGN §14.3, §18.2).
func UserBusEnv(h *Host) []string {
	var env []string
	rt := h.getenv("XDG_RUNTIME_DIR")
	if rt == "" {
		rt = filepath.Join(h.Paths.RunUserDir, strconv.Itoa(h.UID))
		env = append(env, "XDG_RUNTIME_DIR="+rt)
	}
	if h.getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+filepath.Join(rt, "bus"))
	}
	return env
}

func (m *systemdManager) systemctl(ctx context.Context, args ...string) (Result, error) {
	if m.user {
		args = append([]string{"--user"}, args...)
	}
	return m.h.run(ctx, m.env(), "systemctl", args...)
}

// Kind implements Manager.
func (m *systemdManager) Kind() Kind { return m.o.Kind }

// Render implements Manager.
func (m *systemdManager) Render() ([]byte, error) { return SystemdUnit(m.o) }

// Install writes the unit, registers it (link for user units), reloads
// systemd, enables it when Boot is set and starts it when start is set. It
// is idempotent: an existing registration of the same unit is replaced.
func (m *systemdManager) Install(ctx context.Context, start bool) error {
	unit, err := m.Render()
	if err != nil {
		return err
	}
	if err := checkInstallable(m.ownership, m.RegistrationPath(), m.o.Force); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.UnitFile()), 0o755); err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if err := WriteFileAtomic(m.UnitFile(), unit, mode); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if m.user {
		if err := m.link(ctx); err != nil {
			return err
		}
	}
	if _, err := m.systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if m.o.Boot {
		if _, err := m.systemctl(ctx, "enable", UnitName); err != nil {
			return err
		}
	} else {
		_, _ = m.systemctl(ctx, "disable", UnitName)
		if err := m.relink(ctx); err != nil {
			return err
		}
	}
	if start {
		if _, err := m.systemctl(ctx, "restart", UnitName); err != nil {
			return err
		}
	}
	return nil
}

// link registers <HOME>/service/fileparcel.service in the user unit dir
// (the caller has checked ownership: the registration is absent, stale,
// ours, or Force was given).
func (m *systemdManager) link(ctx context.Context) error {
	reg := m.RegistrationPath()
	if fi, err := os.Lstat(reg); err == nil {
		if fi.Mode()&fs.ModeSymlink != 0 {
			if t, err := os.Readlink(reg); err == nil && t == m.UnitFile() {
				return nil
			}
		}
		if err := os.Remove(reg); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(reg), 0o755); err != nil {
		return err
	}
	_, err := m.systemctl(ctx, "link", m.UnitFile())
	return err
}

// relink registers a user unit again after `systemctl disable`, which
// removes every symlink to the unit file — the `systemctl link`
// registration included ("undoes any changes made by enable or link",
// systemctl(1)) — so turning start at boot off would otherwise unregister
// the service. `link` reloads systemd itself. System units are a copy in
// /etc/systemd/system and stay registered.
func (m *systemdManager) relink(ctx context.Context) error {
	if !m.user {
		return nil
	}
	return m.link(ctx)
}

// ownership reports who owns the current registration.
func (m *systemdManager) ownership() (RegState, string) {
	return registrationState(m.RegistrationPath(), m.UnitFile(), []byte("--home "+systemdQuote(m.o.Home)+"\n"),
		[]byte("Description=FileParcel"))
}

// Uninstall stops and disables the unit and removes its registration (the
// user-dir link or /etc/systemd/system file) and the generated unit file.
func (m *systemdManager) Uninstall(ctx context.Context) error {
	var errs []error
	switch st, who := m.ownership(); st {
	case RegOther, RegForeign:
		return fmt.Errorf("%w: %s (%s); not touching it", ErrNotOurs, m.RegistrationPath(), who)
	case RegOurs:
		if _, err := m.systemctl(ctx, "stop", UnitName); err != nil && !notLoaded(err) {
			errs = append(errs, err)
		}
		if _, err := m.systemctl(ctx, "disable", UnitName); err != nil && !notLoaded(err) {
			errs = append(errs, err)
		}
		if err := os.Remove(m.RegistrationPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	case RegStale:
		_ = os.Remove(m.RegistrationPath())
	}
	if m.user {
		if err := os.Remove(m.UnitFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	_, _ = m.systemctl(ctx, "daemon-reload")
	_, _ = m.systemctl(ctx, "reset-failed", UnitName)
	return errors.Join(errs...)
}

// notLoaded reports systemctl errors meaning the unit does not exist.
func notLoaded(err error) bool {
	var ce *CommandError
	if !errors.As(err, &ce) {
		return false
	}
	s := strings.ToLower(ce.Stderr)
	return ce.ExitCode == 5 || strings.Contains(s, "not loaded") || strings.Contains(s, "does not exist") ||
		strings.Contains(s, "not found")
}

// Start implements Manager.
func (m *systemdManager) Start(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.RegistrationPath()); err != nil {
		return err
	}
	_, err := m.systemctl(ctx, "start", UnitName)
	return err
}

// Stop implements Manager.
func (m *systemdManager) Stop(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.RegistrationPath()); err != nil {
		return err
	}
	_, err := m.systemctl(ctx, "stop", UnitName)
	return err
}

// Restart implements Manager.
func (m *systemdManager) Restart(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.RegistrationPath()); err != nil {
		return err
	}
	_, err := m.systemctl(ctx, "restart", UnitName)
	return err
}

// EnableBoot implements Manager (linger is handled by the caller).
func (m *systemdManager) EnableBoot(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.RegistrationPath()); err != nil {
		return err
	}
	_, err := m.systemctl(ctx, "enable", UnitName)
	return err
}

// DisableBoot implements Manager. A user unit stays registered (relink).
func (m *systemdManager) DisableBoot(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.RegistrationPath()); err != nil {
		return err
	}
	_, err := m.systemctl(ctx, "disable", UnitName)
	if lerr := m.relink(ctx); lerr != nil {
		return lerr
	}
	return err
}

// Status queries `systemctl show`.
func (m *systemdManager) Status(ctx context.Context) (*Status, error) {
	st := &Status{Kind: m.o.Kind, Registration: m.RegistrationPath()}
	switch own, who := m.ownership(); own {
	case RegOurs:
		st.Installed = true
	case RegOther, RegForeign:
		st.State, st.Detail = "other", who
		return st, nil
	}
	res, err := m.systemctl(ctx, "show", UnitName, "--no-pager",
		"--property=LoadState,ActiveState,SubState,MainPID,UnitFileState,ExecMainStatus,Result")
	if err != nil {
		if st.Installed {
			return st, err
		}
		st.State = "not-installed"
		return st, nil
	}
	props := parseProps(res.Stdout)
	st.State = props["ActiveState"]
	st.SubState = props["SubState"]
	st.PID, _ = strconv.Atoi(props["MainPID"])
	st.Enabled = strings.HasPrefix(props["UnitFileState"], "enabled") || props["UnitFileState"] == "linked-runtime"
	st.Active = st.State == "active" || st.State == "reloading" || st.State == "activating"
	if props["LoadState"] == "not-found" {
		st.Installed = false
		st.State = "not-installed"
	}
	if r := props["Result"]; r != "" && r != "success" {
		st.Detail = "last result: " + r
		if code := props["ExecMainStatus"]; code != "" && code != "0" {
			st.Detail += " (exit status " + code + ")"
		}
	}
	return st, nil
}

// parseProps parses `systemctl show` KEY=VALUE lines.
func parseProps(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}
