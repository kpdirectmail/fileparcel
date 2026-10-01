package svc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LaunchdPlist renders the launchd property list of DESIGN §14.5 (agent or
// daemon). RunAtLoad follows Options.Boot; daemons run as Options.User.
// KeepAlive{SuccessfulExit=false} (the restart after exit 75) implies
// RunAtLoad (launchd.plist(5)): the job runs whenever the plist is loaded,
// so start at boot is decided by where the plist lives (launchdManager).
func LaunchdPlist(o Options) ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if !o.Kind.Launchd() {
		return nil, fmt.Errorf("svc: %s is not a launchd kind", o.Kind)
	}
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	key := func(k string) { b.WriteString("\t<key>" + xmlEscape(k) + "</key>\n") }
	str := func(indent, s string) { b.WriteString(indent + "<string>" + xmlEscape(s) + "</string>\n") }
	boolean := func(indent string, v bool) {
		if v {
			b.WriteString(indent + "<true/>\n")
		} else {
			b.WriteString(indent + "<false/>\n")
		}
	}
	key("Label")
	str("\t", Label)
	key("ProgramArguments")
	b.WriteString("\t<array>\n")
	for _, a := range []string{o.Binary, "serve", "--home", o.Home} {
		str("\t\t", a)
	}
	b.WriteString("\t</array>\n")
	key("EnvironmentVariables")
	b.WriteString("\t<dict>\n\t\t<key>FILEPARCEL_HOME</key>\n")
	str("\t\t", o.Home)
	b.WriteString("\t</dict>\n")
	if o.Kind == KindLaunchdDaemon {
		key("UserName")
		str("\t", o.User)
		key("GroupName")
		str("\t", o.group())
	}
	key("RunAtLoad")
	boolean("\t", o.Boot)
	key("KeepAlive")
	b.WriteString("\t<dict>\n\t\t<key>SuccessfulExit</key>\n")
	boolean("\t\t", false)
	b.WriteString("\t</dict>\n")
	key("Umask")
	b.WriteString("\t<integer>63</integer>\n")
	key("SoftResourceLimits")
	b.WriteString("\t<dict>\n\t\t<key>NumberOfFiles</key>\n\t\t<integer>65536</integer>\n\t</dict>\n")
	key("StandardOutPath")
	str("\t", filepath.Join(o.Home, "logs", "launchd.out.log"))
	key("StandardErrorPath")
	str("\t", filepath.Join(o.Home, "logs", "launchd.err.log"))
	key("WorkingDirectory")
	str("\t", o.Home)
	// The server drains for up to 30 s (server.ShutdownTimeout) after
	// SIGTERM; launchd's default of about 20 s would SIGKILL it mid-drain.
	// 40 s matches the systemd unit's TimeoutStopSec.
	key("ExitTimeOut")
	b.WriteString("\t<integer>40</integer>\n")
	key("ProcessType")
	str("\t", "Background")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// launchdManager controls a launchd agent (gui/<uid>) or daemon (system).
type launchdManager struct {
	h *Host
	o Options
}

// bootPath is where launchd loads the plist by itself — and so runs the job
// (see LaunchdPlist) — at every login (~/Library/LaunchAgents) or boot
// (/Library/LaunchDaemons): the plist lives here while start at boot is on.
func (m *launchdManager) bootPath() string {
	if m.o.Kind == KindLaunchdDaemon {
		return filepath.Join(m.h.Paths.LaunchDaemonsDir, PlistName)
	}
	return filepath.Join(m.h.Paths.LaunchAgentsDir, PlistName)
}

// offPath is where the plist lives while start at boot is off:
// "Application Support/com.fileparcel.server" next to the LaunchAgents
// (LaunchDaemons) directory, i.e. ~/Library/… or /Library/…, which launchd
// never loads by itself (`launchctl bootstrap` takes any path). The daemon's
// copy stays in a root-owned directory outside HOME: the service account
// must not be able to edit a plist that root loads.
func (m *launchdManager) offPath() string {
	dir := m.h.Paths.LaunchAgentsDir
	if m.o.Kind == KindLaunchdDaemon {
		dir = m.h.Paths.LaunchDaemonsDir
	}
	return filepath.Join(filepath.Dir(dir), "Application Support", Label, PlistName)
}

// plistPaths are both places the plist can be registered in.
func (m *launchdManager) plistPaths() []string { return []string{m.bootPath(), m.offPath()} }

// PlistPath is the registered plist: the one at bootPath or offPath that
// exists (bootPath first), otherwise where Install writes it for
// Options.Boot. It is copied, never symlinked: launchd ignores symlinked
// plists.
func (m *launchdManager) PlistPath() string {
	for _, p := range m.plistPaths() {
		if _, err := os.Lstat(p); err == nil {
			return p
		}
	}
	if m.o.Boot {
		return m.bootPath()
	}
	return m.offPath()
}

// Domain is the launchctl domain target: "system" or "gui/<uid>".
func (m *launchdManager) Domain() string {
	if m.o.Kind == KindLaunchdDaemon {
		return "system"
	}
	return "gui/" + strconv.Itoa(m.h.UID)
}

func (m *launchdManager) service() string { return m.Domain() + "/" + Label }

// ownership reports who owns the plist at PlistPath.
func (m *launchdManager) ownership() (RegState, string) { return m.ownershipOf(m.PlistPath()) }

// ownershipOf reports who owns the plist at p.
func (m *launchdManager) ownershipOf(p string) (RegState, string) {
	return registrationState(p, "",
		[]byte("<string>--home</string>\n\t\t<string>"+xmlEscape(m.o.Home)+"</string>"),
		[]byte("<string>"+Label+"</string>"))
}

// writePlist writes pl where it belongs for boot (bootPath or offPath) and
// removes this home's copy at the other place, so launchd loads it at login
// or boot exactly when boot is on.
func (m *launchdManager) writePlist(pl []byte, boot bool) error {
	dst, other := m.offPath(), m.bootPath()
	if boot {
		dst, other = other, dst
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(dst); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if err := os.Remove(dst); err != nil {
			return err
		}
	}
	if err := WriteFileAtomic(dst, pl, 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	switch st, _ := m.ownershipOf(other); {
	case st == RegOurs, st == RegStale, st == RegOther && m.o.Force:
		if err := os.Remove(other); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// bootstrap loads the job from PlistPath, which runs it (see LaunchdPlist).
func (m *launchdManager) bootstrap(ctx context.Context) error {
	// Best effort: clear a persistent "launchctl disable" override (left by
	// an older version's disable-boot, or a manual `launchctl disable`),
	// which would make bootstrap fail.
	_, _ = m.launchctl(ctx, "enable", m.service())
	_, err := m.launchctl(ctx, "bootstrap", m.Domain(), m.PlistPath())
	return err
}

func (m *launchdManager) launchctl(ctx context.Context, args ...string) (Result, error) {
	return m.h.run(ctx, nil, "launchctl", args...)
}

// Kind implements Manager.
func (m *launchdManager) Kind() Kind { return m.o.Kind }

// Render implements Manager.
func (m *launchdManager) Render() ([]byte, error) { return LaunchdPlist(m.o) }

// Install writes the plist to bootPath (Boot) or offPath and bootstraps it
// (replacing a loaded older version). A job that was loaded is bootstrapped
// again and left running, so re-registering never stops a running server.
// Without start or Boot a job that is not loaded stays unloaded: loading it
// would run it.
func (m *launchdManager) Install(ctx context.Context, start bool) error {
	pl, err := m.Render()
	if err != nil {
		return err
	}
	for _, p := range m.plistPaths() {
		if err := checkInstallable(func() (RegState, string) { return m.ownershipOf(p) }, p, m.o.Force); err != nil {
			return err
		}
	}
	if err := m.writePlist(pl, m.o.Boot); err != nil {
		return err
	}
	// Re-registering must never leave a running server stopped: a job that
	// was loaded is booted out with the old plist and bootstrapped again.
	loaded := m.loaded(ctx)
	if loaded {
		_, _ = m.launchctl(ctx, "bootout", m.service())
	}
	if !start && !m.o.Boot && !loaded {
		return nil // registered on disk (offPath: not loaded at login or boot either); loaded at the next start
	}
	if err := m.bootstrap(ctx); err != nil {
		return err
	}
	// The bootstrap runs the job (SuccessfulExit implies RunAtLoad); the
	// kickstart makes sure a deliberate start or a job that was running is
	// running whatever RunAtLoad says.
	if (start || loaded) && !m.o.Boot {
		_, err = m.launchctl(ctx, "kickstart", m.service())
	}
	return err
}

// loaded reports whether the job is loaded in its domain.
func (m *launchdManager) loaded(ctx context.Context) bool {
	_, err := m.launchctl(ctx, "print", m.service())
	return err == nil
}

// Uninstall unloads the job and removes the plist (from bootPath and
// offPath).
func (m *launchdManager) Uninstall(ctx context.Context) error {
	var errs []error
	var ours []string
	for _, p := range m.plistPaths() {
		switch st, who := m.ownershipOf(p); st {
		case RegOther, RegForeign:
			return fmt.Errorf("%w: %s (%s); not touching it", ErrNotOurs, p, who)
		case RegOurs, RegStale:
			ours = append(ours, p)
		}
	}
	if len(ours) == 0 {
		return nil
	}
	if m.loaded(ctx) {
		if _, err := m.launchctl(ctx, "bootout", m.service()); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range ours {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(filepath.Dir(m.offPath())) // only when empty
	return errors.Join(errs...)
}

// Start loads the job if needed and kickstarts it.
func (m *launchdManager) Start(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.PlistPath()); err != nil {
		return err
	}
	if !m.loaded(ctx) {
		if err := m.bootstrap(ctx); err != nil {
			return err
		}
	}
	_, err := m.launchctl(ctx, "kickstart", m.service())
	return err
}

// Stop unloads the job (KeepAlive would otherwise restart a killed server).
func (m *launchdManager) Stop(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.PlistPath()); err != nil {
		return err
	}
	if !m.loaded(ctx) {
		return nil
	}
	_, err := m.launchctl(ctx, "bootout", m.service())
	return err
}

// Restart kills and restarts the job (kickstart -k).
func (m *launchdManager) Restart(ctx context.Context) error {
	if err := checkControllable(m.ownership, m.PlistPath()); err != nil {
		return err
	}
	if !m.loaded(ctx) {
		return m.Start(ctx)
	}
	_, err := m.launchctl(ctx, "kickstart", "-k", m.service())
	return err
}

// EnableBoot moves the plist to bootPath (RunAtLoad true), where launchd
// loads it at the next login or boot.
func (m *launchdManager) EnableBoot(ctx context.Context) error { return m.setBoot(ctx, true) }

// DisableBoot moves the plist to offPath (RunAtLoad false), where launchd
// never loads it by itself (the running job keeps running).
func (m *launchdManager) DisableBoot(ctx context.Context) error { return m.setBoot(ctx, false) }

func (m *launchdManager) setBoot(ctx context.Context, on bool) error {
	if err := checkControllable(m.ownership, m.PlistPath()); err != nil {
		return err
	}
	m.o.Boot = on
	pl, err := m.Render()
	if err != nil {
		return err
	}
	if err := m.writePlist(pl, on); err != nil {
		return err
	}
	if on {
		// Where the plist lives is the boot switch; `enable` only clears a
		// persistent disabled override left by an older version.
		// `disable` is deliberately not used for DisableBoot: it would
		// survive in launchd's store and make a later
		// "fileparcel service start" fail.
		_, _ = m.launchctl(ctx, "enable", m.service())
	}
	return nil
}

// Status parses `launchctl print`.
func (m *launchdManager) Status(ctx context.Context) (*Status, error) {
	st := &Status{Kind: m.o.Kind, Registration: m.PlistPath()}
	if own, who := m.ownership(); own == RegOther || own == RegForeign {
		st.State, st.Detail = "other", who
		return st, nil
	}
	if _, err := os.Stat(st.Registration); err == nil {
		st.Installed = true
		// launchd loads (and so runs) a plist in LaunchAgents/LaunchDaemons
		// at login or boot, whatever its RunAtLoad says.
		st.Enabled = st.Registration == m.bootPath()
	}
	res, err := m.launchctl(ctx, "print", m.service())
	if err != nil {
		st.State = "not-loaded"
		if !st.Installed {
			st.State = "not-installed"
		}
		return st, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " = ")
		if !ok {
			continue
		}
		switch k {
		case "state":
			if st.State == "" {
				st.State = v
			}
		case "pid":
			st.PID, _ = strconv.Atoi(v)
		case "last exit code":
			if v != "0" && v != "(never exited)" {
				st.Detail = "last exit code " + v
			}
		}
	}
	st.Active = st.State == "running"
	return st, nil
}
