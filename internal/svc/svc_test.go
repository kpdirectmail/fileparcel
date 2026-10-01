package svc

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/home"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

// ---------- fake runner ----------

type call struct {
	env  []string
	line string
}

// fakeRunner records commands; responses are matched by command-line prefix.
type fakeRunner struct {
	mu    sync.Mutex
	calls []call
	resp  map[string]fakeResp
	// hook (optional) sees every command line before it is answered, e.g. to
	// model what the real command changes on disk.
	hook func(line string)
}

type fakeResp struct {
	out  string
	code int // non-zero → *CommandError
	err  error
	stde string
}

func (f *fakeRunner) Run(ctx context.Context, env []string, name string, args ...string) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := CommandLine(name, args...)
	f.calls = append(f.calls, call{env: env, line: line})
	if f.hook != nil {
		f.hook(line)
	}
	best := ""
	for k := range f.resp {
		if strings.HasPrefix(line, k) && len(k) > len(best) {
			best = k
		}
	}
	if best == "" {
		return Result{}, nil
	}
	r := f.resp[best]
	if r.err != nil {
		return Result{}, r.err
	}
	res := Result{Stdout: []byte(r.out), Stderr: []byte(r.stde), ExitCode: r.code}
	if r.code != 0 {
		return res, &CommandError{Cmd: line, ExitCode: r.code, Stderr: r.stde}
	}
	return res, nil
}

func (f *fakeRunner) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.line
	}
	return out
}

func testHost(t *testing.T, goos string, uid int) (*Host, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	fr := &fakeRunner{resp: map[string]fakeResp{}}
	env := map[string]string{}
	h := &Host{
		GOOS: goos, UID: uid, GID: uid, User: "alice", HomeDir: filepath.Join(dir, "home"),
		Runner: fr, Getenv: func(k string) string { return env[k] },
		LookPath: func(n string) (string, error) {
			switch n {
			case "systemctl", "loginctl", "useradd", "userdel", "launchctl", "dscl":
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("not found")
		},
	}
	h.Paths = Paths{
		UserUnitDir: filepath.Join(dir, "home", ".config", "systemd", "user"), SystemUnitDir: filepath.Join(dir, "etc-systemd"),
		LaunchAgentsDir: filepath.Join(dir, "home", "Library", "LaunchAgents"), LaunchDaemonsDir: filepath.Join(dir, "LaunchDaemons"),
		LingerDir: filepath.Join(dir, "linger"), RunUserDir: "/run/user",
	}
	return h, fr
}

// ---------- golden files ----------

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("golden %s: %v (run go test -update)", p, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestGoldenUnits(t *testing.T) {
	cases := []struct {
		file string
		o    Options
	}{
		{"systemd-user.service", Options{Kind: KindSystemdUser, Home: "/home/alice/fileparcel",
			Binary: "/home/alice/fileparcel/bin/fileparcel", Boot: true, HTTPSPort: 8443, HTTPPort: 8080}},
		{"systemd-user-special.service", Options{Kind: KindSystemdUser, Home: "/home/a b/100%$x\"q",
			Binary: "/home/a b/100%$x\"q/bin/fileparcel", HTTPSPort: 8443}},
		{"systemd-system.service", Options{Kind: KindSystemdSystem, Home: "/opt/fileparcel", Binary: "/opt/fileparcel/bin/fileparcel",
			Boot: true, User: "fileparcel", HTTPSPort: 8443, HTTPPort: 8080}},
		{"systemd-system-lowport.service", Options{Kind: KindSystemdSystem, Home: "/home/srv/fileparcel",
			Binary: "/home/srv/fileparcel/bin/fileparcel", User: "fileparcel", Group: "fpgroup", HTTPSPort: 443, HTTPPort: 80}},
		{"launchd-agent.plist", Options{Kind: KindLaunchdAgent, Home: "/Users/alice/Library/Application Support/FileParcel",
			Binary: "/Users/alice/Library/Application Support/FileParcel/bin/fileparcel", Boot: true, HTTPSPort: 8443}},
		{"launchd-daemon.plist", Options{Kind: KindLaunchdDaemon, Home: "/usr/local/fileparcel", Binary: "/usr/local/fileparcel/bin/fileparcel",
			Boot: false, User: "_fileparcel", HTTPSPort: 8443, HTTPPort: 8080}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			got, err := Render(c.o)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, c.file, got)
			if c.o.Kind.Launchd() {
				// Must be well-formed XML.
				dec := xml.NewDecoder(bytes.NewReader(got))
				dec.Strict = true
				for {
					if _, err := dec.Token(); err != nil {
						if err != io.EOF {
							t.Fatalf("plist XML: %v", err)
						}
						break
					}
				}
			}
		})
	}
}

func TestRenderErrors(t *testing.T) {
	bad := []Options{
		{Kind: "bogus", Home: "/h", Binary: "/h/bin/fileparcel"},
		{Kind: KindSystemdUser, Home: "rel", Binary: "/h/bin/fileparcel"},
		{Kind: KindSystemdUser, Home: "/h", Binary: ""},
		{Kind: KindSystemdSystem, Home: "/h", Binary: "/h/bin/fileparcel"}, // no user
		{Kind: KindSystemdUser, Home: "/h\nExecStartPre=/bin/evil", Binary: "/h/bin/fileparcel"},
		{Kind: KindNone, Home: "/h", Binary: "/h/bin/fileparcel"},
	}
	for i, o := range bad {
		if _, err := Render(o); err == nil {
			t.Errorf("case %d: no error", i)
		}
	}
	if _, err := SystemdUnit(Options{Kind: KindLaunchdAgent, Home: "/h", Binary: "/h/b"}); err == nil {
		t.Error("systemd unit for launchd kind")
	}
	if _, err := LaunchdPlist(Options{Kind: KindSystemdUser, Home: "/h", Binary: "/h/b"}); err == nil {
		t.Error("plist for systemd kind")
	}
}

// ---------- systemd control ----------

func TestSystemdUserLifecycle(t *testing.T) {
	h, fr := testHost(t, "linux", 1000)
	hd := t.TempDir()
	o := Options{Kind: KindSystemdUser, Home: hd, Binary: filepath.Join(hd, "bin", "fileparcel"), Boot: true, HTTPSPort: 8443}
	m, err := NewManager(h, o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// systemctl link is faked: create the link like systemd would.
	sm := m.(*systemdManager)
	if err := m.Install(ctx, true); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(filepath.Join(hd, "service", UnitName))
	if err != nil || !bytes.Contains(unit, []byte("WantedBy=default.target")) {
		t.Fatalf("unit file: %v", err)
	}
	want := []string{
		"systemctl --user link " + ShellQuote(sm.UnitFile()),
		"systemctl --user daemon-reload",
		"systemctl --user enable fileparcel.service",
		"systemctl --user restart fileparcel.service",
	}
	if got := fr.lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// XDG_RUNTIME_DIR and the bus address are provided without a login session.
	env := fr.calls[0].env
	if len(env) != 2 || env[0] != "XDG_RUNTIME_DIR=/run/user/1000" || env[1] != "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus" {
		t.Fatalf("env %v", env)
	}

	// Simulate the link systemd created; reinstall keeps it (no second link call).
	if err := os.MkdirAll(h.Paths.UserUnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sm.UnitFile(), sm.RegistrationPath()); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil
	if err := m.Install(ctx, false); err != nil {
		t.Fatal(err)
	}
	for _, l := range fr.lines() {
		if strings.Contains(l, " link ") || strings.Contains(l, "restart") {
			t.Fatalf("unexpected %q", l)
		}
	}

	// Status parsing.
	fr.resp["systemctl --user show"] = fakeResp{out: "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nUnitFileState=enabled\nExecMainStatus=0\nResult=success\n"}
	st, err := m.Status(ctx)
	if err != nil || !st.Installed || !st.Active || !st.Enabled || st.PID != 4242 || st.State != "active" || st.SubState != "running" {
		t.Fatalf("status %+v %v", st, err)
	}
	fr.resp["systemctl --user show"] = fakeResp{out: "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nUnitFileState=disabled\nExecMainStatus=1\nResult=exit-code\n"}
	st, _ = m.Status(ctx)
	if st.Active || st.Enabled || st.Detail != "last result: exit-code (exit status 1)" {
		t.Fatalf("failed status %+v", st)
	}

	for name, fn := range map[string]func(context.Context) error{"start": m.Start, "stop": m.Stop, "restart": m.Restart,
		"enable": m.EnableBoot, "disable": m.DisableBoot} {
		fr.calls = nil
		if err := fn(ctx); err != nil {
			t.Fatal(err)
		}
		if l := fr.lines(); len(l) != 1 || l[0] != "systemctl --user "+name+" fileparcel.service" {
			t.Fatalf("%s: %v", name, l)
		}
	}

	// Uninstall removes the link and the generated unit, even if stop fails because it is not loaded.
	fr.calls = nil
	fr.resp["systemctl --user stop"] = fakeResp{code: 5, stde: "Unit fileparcel.service not loaded."}
	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sm.RegistrationPath()); err == nil {
		t.Fatal("link not removed")
	}
	if _, err := os.Stat(sm.UnitFile()); err == nil {
		t.Fatal("unit file not removed")
	}
	// Uninstalling again is a no-op; control commands now report "not installed".
	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("start after uninstall: %v", err)
	}
	// A real failure is reported.
	os.WriteFile(sm.UnitFile(), unit, 0o644)
	os.Symlink(sm.UnitFile(), sm.RegistrationPath())
	fr.resp["systemctl --user disable"] = fakeResp{code: 1, stde: "Access denied"}
	if err := m.Uninstall(ctx); err == nil || !strings.Contains(err.Error(), "Access denied") {
		t.Fatalf("uninstall error %v", err)
	}
}

// `systemctl disable` removes every symlink to the unit file, the `systemctl
// link` registration included: turning start at boot off (install --no-boot,
// disable-boot) must leave a user unit registered.
func TestSystemdUserNoBootKeepsRegistration(t *testing.T) {
	h, fr := testHost(t, "linux", 1000)
	hd := t.TempDir()
	m, err := NewManager(h, Options{Kind: KindSystemdUser, Home: hd, Binary: filepath.Join(hd, "bin", "fileparcel"), HTTPSPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	sm, ctx := m.(*systemdManager), context.Background()
	wants := filepath.Join(h.Paths.UserUnitDir, "default.target.wants", UnitName)
	// Model what systemctl does to the user unit directory.
	fr.hook = func(line string) {
		switch line {
		case "systemctl --user link " + ShellQuote(sm.UnitFile()):
			_ = os.Symlink(sm.UnitFile(), sm.RegistrationPath())
		case "systemctl --user enable " + UnitName:
			_ = os.MkdirAll(filepath.Dir(wants), 0o755)
			_ = os.Symlink(sm.UnitFile(), wants)
		case "systemctl --user disable " + UnitName:
			_ = os.Remove(wants)
			_ = os.Remove(sm.RegistrationPath())
		}
	}
	registered := func(when string) {
		t.Helper()
		if st, _ := sm.ownership(); st != RegOurs {
			t.Fatalf("%s: registration state %v", when, st)
		}
		if l, err := os.Readlink(sm.RegistrationPath()); err != nil || l != sm.UnitFile() {
			t.Fatalf("%s: link %q %v", when, l, err)
		}
	}
	if err := m.Install(ctx, true); err != nil {
		t.Fatal(err)
	}
	registered("install --no-boot")
	want := []string{
		"systemctl --user link " + ShellQuote(sm.UnitFile()),
		"systemctl --user daemon-reload",
		"systemctl --user disable fileparcel.service",
		"systemctl --user link " + ShellQuote(sm.UnitFile()),
		"systemctl --user restart fileparcel.service",
	}
	if got := fr.lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if err := m.EnableBoot(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(wants); err != nil {
		t.Fatal("enable-boot made no wants link")
	}
	if err := m.DisableBoot(ctx); err != nil {
		t.Fatal(err)
	}
	registered("disable-boot")
	if _, err := os.Lstat(wants); err == nil {
		t.Fatal("disable-boot kept the wants link")
	}
	for _, fn := range []func(context.Context) error{m.Start, m.EnableBoot} {
		if err := fn(ctx); err != nil {
			t.Fatalf("after disable-boot: %v", err)
		}
	}
	// Uninstall still removes the registration.
	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sm.RegistrationPath()); err == nil {
		t.Fatal("uninstall kept the registration")
	}
}

func TestSystemdLinkConflicts(t *testing.T) {
	h, fr := testHost(t, "linux", 1000)
	hd := t.TempDir()
	o := Options{Kind: KindSystemdUser, Home: hd, Binary: filepath.Join(hd, "bin", "fileparcel")}
	m, _ := NewManager(h, o)
	sm := m.(*systemdManager)
	ctx := context.Background()
	if err := os.MkdirAll(h.Paths.UserUnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A foreign regular file with our name is never overwritten, even with --force.
	if err := os.WriteFile(sm.RegistrationPath(), []byte("[Unit]\nDescription=Something else\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, force := range []bool{false, true} {
		sm.o.Force = force
		if err := m.Install(ctx, false); !errors.Is(err, ErrNotOurs) {
			t.Fatalf("foreign file (force %v): %v", force, err)
		}
	}
	sm.o.Force = false
	if err := m.Uninstall(ctx); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("uninstall of a foreign unit: %v", err)
	}
	if _, err := os.Stat(sm.RegistrationPath()); err != nil {
		t.Fatal("foreign unit removed")
	}
	os.Remove(sm.RegistrationPath())

	// Another FileParcel home's unit: refused without --force; start/stop/uninstall never touch it.
	otherHome := t.TempDir()
	om, _ := NewManager(h, Options{Kind: KindSystemdUser, Home: otherHome, Binary: filepath.Join(otherHome, "bin", "fileparcel")})
	unit, _ := om.Render()
	os.MkdirAll(filepath.Join(otherHome, "service"), 0o755)
	os.WriteFile(filepath.Join(otherHome, "service", UnitName), unit, 0o644)
	os.Symlink(filepath.Join(otherHome, "service", UnitName), sm.RegistrationPath())
	if err := m.Install(ctx, false); !errors.Is(err, ErrNotOurs) || !strings.Contains(err.Error(), "another FileParcel home") {
		t.Fatalf("other home: %v", err)
	}
	fr.calls = nil
	for _, fn := range []func(context.Context) error{m.Start, m.Stop, m.Restart, m.EnableBoot, m.DisableBoot, m.Uninstall} {
		if err := fn(ctx); !errors.Is(err, ErrNotOurs) {
			t.Fatalf("control of another home's unit: %v", err)
		}
	}
	if len(fr.calls) != 0 {
		t.Fatalf("commands run against another home's unit: %v", fr.lines())
	}
	if st, _ := m.Status(ctx); st.State != "other" || st.Installed {
		t.Fatalf("status %+v", st)
	}
	if st, _ := om.Status(ctx); !st.Installed {
		t.Fatalf("owner status %+v", st)
	}
	sm.o.Force = true
	if err := m.Install(ctx, false); err != nil {
		t.Fatalf("forced: %v", err)
	}
	sm.o.Force = false

	// A dangling link (deleted home) is replaced.
	os.Remove(sm.RegistrationPath())
	os.Symlink(filepath.Join(t.TempDir(), "gone", UnitName), sm.RegistrationPath())
	if st, _ := sm.ownership(); st != RegStale {
		t.Fatalf("state %v", st)
	}
	if err := m.Install(ctx, false); err != nil {
		t.Fatalf("dangling link: %v", err)
	}
	if _, err := os.Lstat(sm.RegistrationPath()); err == nil {
		t.Fatal("dangling link kept") // systemctl link is faked, so nothing re-creates it
	}
}

func TestSystemdSystem(t *testing.T) {
	h, fr := testHost(t, "linux", 0)
	o := Options{Kind: KindSystemdSystem, Home: "/opt/fileparcel", Binary: "/opt/fileparcel/bin/fileparcel", User: "fileparcel", Boot: false}
	m, err := NewManager(h, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(h.Paths.SystemUnitDir, UnitName))
	if err != nil || !bytes.Contains(b, []byte("User=fileparcel")) {
		t.Fatalf("system unit: %v", err)
	}
	got := strings.Join(fr.lines(), "\n")
	want := "systemctl daemon-reload\nsystemctl disable fileparcel.service\nsystemctl restart fileparcel.service"
	if got != want {
		t.Fatalf("commands:\n%s", got)
	}
	if fr.calls[0].env != nil {
		t.Fatal("system units need no user bus env")
	}
}

func TestNewManagerChecks(t *testing.T) {
	lin, _ := testHost(t, "linux", 1000)
	root, _ := testHost(t, "linux", 0)
	mac, _ := testHost(t, "darwin", 501)
	opt := func(k Kind) Options {
		return Options{Kind: k, Home: "/h", Binary: "/h/bin/fileparcel", User: "fileparcel"}
	}
	for _, c := range []struct {
		h  *Host
		k  Kind
		ok bool
	}{
		{lin, KindSystemdUser, true}, {lin, KindSystemdSystem, false}, {root, KindSystemdSystem, true}, {root, KindSystemdUser, false},
		{lin, KindLaunchdAgent, false}, {mac, KindLaunchdAgent, true}, {mac, KindLaunchdDaemon, false}, {mac, KindSystemdUser, false},
		{lin, KindNone, false},
	} {
		_, err := NewManager(c.h, opt(c.k))
		if (err == nil) != c.ok {
			t.Errorf("%s uid %d %s: %v", c.h.GOOS, c.h.UID, c.k, err)
		}
	}
	if _, err := NewManager(lin, opt(KindNone)); !errors.Is(err, ErrNoService) {
		t.Fatal(err)
	}
}

// ---------- launchd ----------

func TestLaunchdAgentLifecycle(t *testing.T) {
	h, fr := testHost(t, "darwin", 501)
	hd := "/Users/alice/Library/Application Support/FileParcel"
	o := Options{Kind: KindLaunchdAgent, Home: hd, Binary: hd + "/bin/fileparcel", Boot: true}
	m, err := NewManager(h, o)
	if err != nil {
		t.Fatal(err)
	}
	lm := m.(*launchdManager)
	ctx := context.Background()
	fr.resp["launchctl print"] = fakeResp{code: 113, stde: "Could not find service"}
	if err := m.Install(ctx, true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl print gui/501/com.fileparcel.server",
		"launchctl enable gui/501/com.fileparcel.server",
		"launchctl bootstrap gui/501 " + ShellQuote(lm.PlistPath()),
	}
	if got := fr.lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("install commands: %v", got)
	}
	// Start at boot: the plist is in LaunchAgents, which launchd loads at login.
	if lm.PlistPath() != filepath.Join(h.Paths.LaunchAgentsDir, PlistName) {
		t.Fatalf("boot plist at %s", lm.PlistPath())
	}
	if b, err := os.ReadFile(lm.PlistPath()); err != nil || !bytes.Contains(b, []byte("<string>com.fileparcel.server</string>")) {
		t.Fatalf("plist: %v", err)
	}
	// Loaded + running status.
	fr.resp["launchctl print"] = fakeResp{out: "gui/501/com.fileparcel.server = {\n\tactive count = 1\n\tstate = running\n\tpid = 777\n\tlast exit code = 75\n}\n"}
	st, err := m.Status(ctx)
	if err != nil || !st.Active || st.PID != 777 || !st.Installed || !st.Enabled || st.Detail != "last exit code 75" {
		t.Fatalf("status %+v", st)
	}
	fr.calls = nil
	if err := m.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	if l := fr.lines(); l[len(l)-1] != "launchctl kickstart -k gui/501/com.fileparcel.server" {
		t.Fatalf("restart %v", l)
	}
	fr.calls = nil
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if l := fr.lines(); l[len(l)-1] != "launchctl bootout gui/501/com.fileparcel.server" {
		t.Fatalf("stop %v", l)
	}
	// KeepAlive{SuccessfulExit} implies RunAtLoad, so launchd would run a
	// plist in LaunchAgents at the next login whatever RunAtLoad says:
	// disable-boot moves it out of there.
	if err := m.DisableBoot(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(lm.bootPath()); err == nil {
		t.Fatal("plist left in LaunchAgents after disable-boot")
	}
	if lm.PlistPath() != lm.offPath() || !strings.Contains(lm.offPath(), filepath.Join("Library", "Application Support", Label)) {
		t.Fatalf("plist at %s", lm.PlistPath())
	}
	if b, _ := os.ReadFile(lm.PlistPath()); !bytes.Contains(b, []byte("<key>RunAtLoad</key>\n\t<false/>")) ||
		!bytes.Contains(b, []byte("<key>SuccessfulExit</key>")) {
		t.Fatal("RunAtLoad not cleared, or KeepAlive (the exit-75 restart) lost")
	}
	if st, _ := m.Status(ctx); !st.Installed || st.Enabled || st.Registration != lm.offPath() {
		t.Fatalf("status after disable-boot %+v", st)
	}
	if err := m.EnableBoot(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(lm.offPath()); err == nil || lm.PlistPath() != lm.bootPath() {
		t.Fatalf("enable-boot: plist at %s", lm.PlistPath())
	}
	if st, _ := m.Status(ctx); !st.Enabled {
		t.Fatalf("status after enable-boot %+v", st)
	}
	if err := m.DisableBoot(ctx); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil
	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{lm.bootPath(), lm.offPath(), filepath.Dir(lm.offPath())} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s not removed", p)
		}
	}
	if l := fr.lines(); l[len(l)-1] != "launchctl bootout gui/501/com.fileparcel.server" {
		t.Fatalf("uninstall %v", l)
	}
	fr.resp["launchctl print"] = fakeResp{code: 113}
	st, _ = m.Status(ctx)
	if st.State != "not-installed" || st.Active {
		t.Fatalf("status after uninstall %+v", st)
	}
	if err := m.Start(ctx); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("start after uninstall: %v", err)
	}
	// Registered but not loaded (no boot, not started): start bootstraps then kickstarts.
	lm.o.Boot = false
	fr.calls = nil
	if err := m.Install(ctx, false); err != nil {
		t.Fatal(err)
	}
	if l := fr.lines(); len(l) != 1 {
		t.Fatalf("install without start/boot: %v", l)
	}
	if _, err := os.Lstat(lm.bootPath()); err == nil || lm.PlistPath() != lm.offPath() {
		t.Fatalf("install --no-boot put the plist in LaunchAgents (%s)", lm.PlistPath())
	}
	fr.calls = nil
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if l := fr.lines(); len(l) != 4 || l[1] != "launchctl enable gui/501/com.fileparcel.server" ||
		!strings.HasPrefix(l[2], "launchctl bootstrap gui/501 ") || l[3] != "launchctl kickstart gui/501/com.fileparcel.server" {
		t.Fatalf("start %v", l)
	}
	// Another home's plist is never touched.
	other := &launchdManager{h: h, o: Options{Kind: KindLaunchdAgent, Home: "/elsewhere", Binary: "/elsewhere/bin/fileparcel"}}
	if err := other.Uninstall(ctx); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("other uninstall %v", err)
	}
	if err := other.Install(ctx, false); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("other install %v", err)
	}
	if st, _ := other.Status(ctx); st.State != "other" {
		t.Fatalf("other status %+v", st)
	}
}

// Re-registering a loaded job must leave the server running, and
// DisableBoot must not write a persistent "launchctl disable" override that
// a later Start would trip over.
func TestLaunchdInstallKeepsRunningJob(t *testing.T) {
	h, fr := testHost(t, "darwin", 501)
	hd := "/Users/alice/Library/Application Support/FileParcel"
	m, err := NewManager(h, Options{Kind: KindLaunchdAgent, Home: hd, Binary: hd + "/bin/fileparcel", Boot: false})
	if err != nil {
		t.Fatal(err)
	}
	lm, ctx := m.(*launchdManager), context.Background()
	// The job is loaded and running: "service install --no-boot" (start
	// false, Boot false) must boot it out and bring it back up.
	fr.resp["launchctl print"] = fakeResp{out: "gui/501/com.fileparcel.server = {\n\tstate = running\n\tpid = 42\n}\n"}
	if err := m.Install(ctx, false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl print gui/501/com.fileparcel.server",
		"launchctl bootout gui/501/com.fileparcel.server",
		"launchctl enable gui/501/com.fileparcel.server",
		"launchctl bootstrap gui/501 " + ShellQuote(lm.PlistPath()),
		"launchctl kickstart gui/501/com.fileparcel.server",
	}
	if got := fr.lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("install over a loaded job:\n%s", strings.Join(got, "\n"))
	}
	// A job that is not loaded stays unloaded (registered on disk only).
	fr.calls = nil
	fr.resp["launchctl print"] = fakeResp{code: 113, stde: "Could not find service"}
	if err := m.Install(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := fr.lines(); len(got) != 1 {
		t.Fatalf("install without start/boot over an unloaded job: %v", got)
	}
	// disable-boot only rewrites the plist; start still works afterwards.
	fr.calls = nil
	if err := m.DisableBoot(ctx); err != nil {
		t.Fatal(err)
	}
	for _, l := range fr.lines() {
		if strings.HasPrefix(l, "launchctl disable") {
			t.Fatalf("disable-boot must not disable the service in launchd: %v", fr.lines())
		}
	}
	fr.calls = nil
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	got := fr.lines()
	if len(got) != 4 || got[1] != "launchctl enable gui/501/com.fileparcel.server" ||
		!strings.HasPrefix(got[2], "launchctl bootstrap gui/501 ") || got[3] != "launchctl kickstart gui/501/com.fileparcel.server" {
		t.Fatalf("start after disable-boot: %v", got)
	}
}

func TestLaunchdDaemonDomain(t *testing.T) {
	h, fr := testHost(t, "darwin", 0)
	m, err := NewManager(h, Options{Kind: KindLaunchdDaemon, Home: "/usr/local/fileparcel", Binary: "/usr/local/fileparcel/bin/fileparcel",
		User: "_fileparcel"})
	if err != nil {
		t.Fatal(err)
	}
	fr.resp["launchctl print"] = fakeResp{code: 113}
	if err := m.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	l := fr.lines()
	if l[1] != "launchctl enable system/com.fileparcel.server" || !strings.HasPrefix(l[2], "launchctl bootstrap system ") ||
		l[3] != "launchctl kickstart system/com.fileparcel.server" {
		t.Fatalf("daemon commands %v", l)
	}
	// No start at boot: the plist stays out of /Library/LaunchDaemons, in a
	// root-owned directory next to it (never in HOME, which the service
	// account owns).
	want := filepath.Join(filepath.Dir(h.Paths.LaunchDaemonsDir), "Application Support", Label, PlistName)
	if m.RegistrationPath() != want {
		t.Fatal(m.RegistrationPath())
	}
	if _, err := os.Lstat(filepath.Join(h.Paths.LaunchDaemonsDir, PlistName)); err == nil {
		t.Fatal("daemon plist in LaunchDaemons without start at boot")
	}
	if err := m.EnableBoot(context.Background()); err != nil || m.RegistrationPath() != filepath.Join(h.Paths.LaunchDaemonsDir, PlistName) {
		t.Fatal(m.RegistrationPath(), err)
	}
}

// A job carrying a persistent "launchctl disable" override (an older
// version's disable-boot, or a manual disable) cannot be bootstrapped:
// Install clears it first, as Start does, so an upgrade that stopped the
// server does not leave it down.
func TestLaunchdInstallClearsDisabledOverride(t *testing.T) {
	h, fr := testHost(t, "darwin", 501)
	hd := "/Users/alice/Library/Application Support/FileParcel"
	m, err := NewManager(h, Options{Kind: KindLaunchdAgent, Home: hd, Binary: hd + "/bin/fileparcel", Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	fr.resp["launchctl print"] = fakeResp{code: 113, stde: "Could not find service"}
	fr.resp["launchctl bootstrap"] = fakeResp{code: 5, stde: "Bootstrap failed: 5: Input/output error (Service is disabled)"}
	enabled := false
	fr.hook = func(line string) {
		if strings.HasPrefix(line, "launchctl enable ") {
			enabled = true
			delete(fr.resp, "launchctl bootstrap")
		}
	}
	if err := m.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatalf("install did not clear the disabled override: %v", fr.lines())
	}
}

// ---------- linger ----------

func TestLinger(t *testing.T) {
	h, fr := testHost(t, "linux", 1000)
	ctx := context.Background()
	changed, err := EnableLinger(ctx, h)
	if err != nil || !changed || fr.lines()[0] != "loginctl enable-linger alice" {
		t.Fatalf("enable: %v %v %v", changed, err, fr.lines())
	}
	os.MkdirAll(h.Paths.LingerDir, 0o755)
	os.WriteFile(filepath.Join(h.Paths.LingerDir, "alice"), nil, 0o644)
	fr.calls = nil
	if changed, err := EnableLinger(ctx, h); err != nil || changed || len(fr.calls) != 0 {
		t.Fatalf("already enabled: %v %v", changed, err)
	}
	if err := DisableLinger(ctx, h); err != nil || fr.lines()[0] != "loginctl disable-linger alice" {
		t.Fatalf("disable %v %v", err, fr.lines())
	}
	h.User = ""
	if _, err := EnableLinger(ctx, h); err == nil {
		t.Fatal("no user")
	}

	h.User = "alice"
	if got := OtherUserUnitsEnabled(h); len(got) != 0 {
		t.Fatalf("no units: %v", got)
	}
	wants := filepath.Join(h.Paths.UserUnitDir, "default.target.wants")
	os.MkdirAll(wants, 0o755)
	os.Symlink("/x/fileparcel.service", filepath.Join(wants, UnitName))
	if got := OtherUserUnitsEnabled(h); len(got) != 0 {
		t.Fatalf("only ours: %v", got)
	}
	os.Symlink("/x/syncthing.service", filepath.Join(wants, "syncthing.service"))
	timers := filepath.Join(h.Paths.UserUnitDir, "timers.target.wants")
	os.MkdirAll(timers, 0o755)
	os.Symlink("/x/b.timer", filepath.Join(timers, "b.timer"))
	if got := OtherUserUnitsEnabled(h); len(got) != 2 {
		t.Fatalf("others: %v", got)
	}
}

// `systemctl --user link` is carried out by the user manager, in the
// configuration directory of its own environment: an XDG_CONFIG_HOME
// exported only in the installing shell must not move where the
// registration is looked for (ownership, status, uninstall, linger).
func TestUserUnitDirFromManager(t *testing.T) {
	if p := DefaultPaths("/home/alice"); p.UserUnitDir != "" || p.SystemUnitDir != "/etc/systemd/system" {
		t.Fatalf("default paths %+v", p)
	}
	h, fr := testHost(t, "linux", 1000)
	h.Getenv = func(k string) string {
		if k == "XDG_CONFIG_HOME" {
			return "/shell/cfg"
		}
		return ""
	}
	cfg := filepath.Join(t.TempDir(), "cfg")
	fr.resp["systemctl --user show --property=UnitPath --value"] = fakeResp{out: cfg + "/systemd/user.control /run/user/1000/systemd/user.control " +
		"/run/user/1000/systemd/transient " + cfg + "/systemd/user /etc/systemd/user /run/user/1000/systemd/user /usr/lib/systemd/user\n"}
	h.Paths.UserUnitDir = ""
	m, err := NewManager(h, Options{Kind: KindSystemdUser, Home: "/h", Binary: "/h/bin/fileparcel"})
	must(t, err)
	want := filepath.Join(cfg, "systemd", "user", UnitName)
	if got := m.RegistrationPath(); got != want {
		t.Fatalf("registration %s, want %s", got, want)
	}
	must(t, os.MkdirAll(filepath.Join(cfg, "systemd", "user", "default.target.wants"), 0o755))
	must(t, os.Symlink("/x/syncthing.service", filepath.Join(cfg, "systemd", "user", "default.target.wants", "syncthing.service")))
	if got := OtherUserUnitsEnabled(h); len(got) != 1 {
		t.Fatalf("other units %v", got)
	}
	if n := len(fr.lines()); n != 1 {
		t.Fatalf("asked the manager %d times: %v", n, fr.lines())
	}
	if c := fr.calls[0]; !slices.Contains(c.env, "XDG_RUNTIME_DIR=/run/user/1000") {
		t.Fatalf("no user bus environment: %v", c.env)
	}

	// No user manager (or an old one without control directories):
	// ~/.config/systemd/user, whatever the shell's XDG_CONFIG_HOME.
	for _, r := range []fakeResp{{code: 1, stde: "Failed to connect to bus"}, {out: "/etc/systemd/user /usr/lib/systemd/user\n"}} {
		fr.resp["systemctl --user show --property=UnitPath --value"] = r
		h.Paths.UserUnitDir = ""
		if got := h.userUnitDir(); got != filepath.Join(h.HomeDir, ".config", "systemd", "user") {
			t.Errorf("%+v: %s", r, got)
		}
	}
	for in, want := range map[string]string{
		"/a/systemd/user.control /a/systemd/user":      "/a/systemd/user",
		"/a/systemd/user.control /b/systemd/user":      "", // not listed next to it
		"rel/systemd/user.control rel/systemd/user":    "",
		"/run/user/1/systemd/user.control /x /a/b/c/d": "",
		"": "",
	} {
		if got := persistentUserUnitDir(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// ---------- accounts ----------

func TestSystemUserCommands(t *testing.T) {
	lin, _ := testHost(t, "linux", 0)
	cmds, err := SystemUserCommands(lin, "fileparcel", "/opt/fileparcel", 0)
	if err != nil || len(cmds) != 1 || cmds[0][0] != "useradd" ||
		!strings.Contains(strings.Join(cmds[0], " "), "--system --home-dir /opt/fileparcel --no-create-home --shell") ||
		cmds[0][len(cmds[0])-1] != "fileparcel" {
		t.Fatalf("useradd %v %v", cmds, err)
	}
	alpine, _ := testHost(t, "linux", 0)
	alpine.LookPath = func(n string) (string, error) {
		if n == "adduser" || n == "addgroup" {
			return "/bin/" + n, nil
		}
		return "", errors.New("no")
	}
	cmds, err = SystemUserCommands(alpine, "fileparcel", "/opt/fileparcel", 0)
	if err != nil || len(cmds) != 2 || cmds[0][0] != "addgroup" || cmds[1][0] != "adduser" {
		t.Fatalf("alpine %v %v", cmds, err)
	}
	alpine.LookPath = func(string) (string, error) { return "", errors.New("no") }
	if _, err := SystemUserCommands(alpine, "fileparcel", "/x", 0); err == nil {
		t.Fatal("no tools")
	}
	mac, fr := testHost(t, "darwin", 0)
	fr.resp["dscl . -list /Users UniqueID"] = fakeResp{out: "_www 70\n_x 400\n_y 401\nalice 501\n"}
	fr.resp["dscl . -list /Groups PrimaryGroupID"] = fakeResp{out: "_g 402\nstaff 20\n"}
	id, err := FreeMacID(context.Background(), mac)
	if err != nil || id != 403 {
		t.Fatalf("free id %d %v", id, err)
	}
	cmds, err = SystemUserCommands(mac, "_fileparcel", "/usr/local/fileparcel", id)
	if err != nil || len(cmds) != 12 || strings.Join(cmds[5], " ") != "dscl . -create /Users/_fileparcel UniqueID 403" {
		t.Fatalf("dscl %v %v", cmds, err)
	}
	if _, err := SystemUserCommands(mac, "_fileparcel", "/x", 999); err == nil {
		t.Fatal("id out of range")
	}
	for _, bad := range []string{"", "Root", "a b", "x;rm", strings.Repeat("a", 40)} {
		if _, err := SystemUserCommands(lin, bad, "/x", 0); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	win, _ := testHost(t, "windows", 0)
	if _, err := SystemUserCommands(win, "fileparcel", "/x", 0); err == nil {
		t.Fatal("windows")
	}
}

func TestEnsureSystemUser(t *testing.T) {
	old := lookupUser
	t.Cleanup(func() { lookupUser = old })
	exists := map[string]bool{"taken": true}
	lookupUser = func(name string) (*user.User, error) {
		if exists[name] {
			return &user.User{Username: name, Uid: "990", Gid: "990"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	h, fr := testHost(t, "linux", 0)
	ctx := context.Background()
	if created, err := EnsureSystemUser(ctx, h, "taken", "/opt/x"); err != nil || created || len(fr.calls) != 0 {
		t.Fatalf("existing: %v %v", created, err)
	}
	if created, err := EnsureSystemUser(ctx, h, "fileparcel", "/opt/x"); err != nil || !created || !strings.HasPrefix(fr.lines()[0], "useradd --system") {
		t.Fatalf("create: %v %v %v", created, err, fr.lines())
	}
	if uid, gid, err := AccountIDs("taken"); err != nil || uid != 990 || gid != 990 {
		t.Fatal(uid, gid, err)
	}
	user1, _ := testHost(t, "linux", 1000)
	if _, err := EnsureSystemUser(ctx, user1, "fileparcel", "/opt/x"); err == nil {
		t.Fatal("non-root created an account")
	}
	fr.calls = nil
	exists["fileparcel"], exists["_fileparcel"] = true, true
	if err := RemoveSystemUser(ctx, h, "fileparcel"); err != nil || fr.lines()[0] != "userdel fileparcel" {
		t.Fatalf("remove %v %v", err, fr.lines())
	}
	// Only the service account is ever deleted: the name comes from
	// installed.json, which that account can write on system installs.
	fr.calls = nil
	for _, name := range []string{"taken", "root", "alice"} {
		exists[name] = true
		if err := RemoveSystemUser(ctx, h, name); err == nil || len(fr.calls) != 0 {
			t.Fatalf("removed %s: %v %v", name, err, fr.lines())
		}
	}
	delete(exists, "fileparcel")
	if err := RemoveSystemUser(ctx, h, "fileparcel"); err != nil || len(fr.calls) != 0 {
		t.Fatal("absent account", err)
	}
	mac, mfr := testHost(t, "darwin", 0)
	if err := RemoveSystemUser(ctx, mac, "_fileparcel"); err != nil || len(mfr.lines()) != 2 {
		t.Fatalf("mac remove %v %v", err, mfr.lines())
	}
	// Never an account with uid 0, whatever its name.
	lookupUser = func(name string) (*user.User, error) { return &user.User{Username: name, Uid: "0", Gid: "0"}, nil }
	fr.calls = nil
	if err := RemoveSystemUser(ctx, h, "fileparcel"); err == nil || len(fr.calls) != 0 {
		t.Fatalf("removed a uid-0 account: %v %v", err, fr.lines())
	}
}

// A system service never runs as another account than the service account:
// the user often comes from installed.json, which that account can write.
func TestValidateSystemUser(t *testing.T) {
	for _, c := range []struct {
		k    Kind
		user string
		ok   bool
	}{
		{KindSystemdSystem, "fileparcel", true}, {KindLaunchdDaemon, "_fileparcel", true},
		{KindSystemdSystem, "root", false}, {KindSystemdSystem, "alice", false}, {KindLaunchdDaemon, "root", false},
		{KindSystemdUser, "", true}, {KindLaunchdAgent, "", true},
	} {
		o := Options{Kind: c.k, Home: "/h", Binary: "/h/bin/fileparcel", User: c.user}
		if _, err := Render(o); (err == nil) != c.ok {
			t.Errorf("%s as %q: %v", c.k, c.user, err)
		}
	}
}

func TestChownTree(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	os.MkdirAll(filepath.Join(root, "data", "x"), 0o700)
	os.WriteFile(filepath.Join(root, "data", "x", "f"), nil, 0o600)
	// Chown to ourselves always works and walks the tree.
	if err := ChownTree(root, os.Getuid(), os.Getgid(), filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	if err := ChownTree(filepath.Join(root, "missing"), 0, 0); err == nil {
		t.Fatal("missing root")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// chownCalls replaces lchown, chown and fchown with recorders.
func chownCalls(t *testing.T) map[string][2]int {
	t.Helper()
	oldL, oldC, oldF := lchown, chown, fchown
	t.Cleanup(func() { lchown, chown, fchown = oldL, oldC, oldF })
	got := map[string][2]int{}
	lchown = func(p string, uid, gid int) error {
		if _, err := os.Lstat(p); err != nil {
			return err
		}
		got[p] = [2]int{uid, gid}
		return nil
	}
	chown = func(p string, uid, gid int) error {
		got["follow:"+p] = [2]int{uid, gid}
		return nil
	}
	fchown = func(f *os.File, uid, gid int) error {
		got[f.Name()] = [2]int{uid, gid}
		return nil
	}
	return got
}

// A home moved to another disk and linked back (/opt/fileparcel ->
// /srv/fileparcel): WalkDir alone visits only the link, leaving the whole
// home root-owned. The link is followed once; bin/ (given relative to the
// link) still stays alone, and symlinks below the root are never followed.
func TestChownTreeSymlinkedRoot(t *testing.T) {
	dir := t.TempDir()
	real, elsewhere, link := filepath.Join(dir, "srv"), filepath.Join(dir, "elsewhere"), filepath.Join(dir, "opt")
	for _, d := range []string{filepath.Join(real, "bin"), filepath.Join(real, "data", "x"), filepath.Join(real, "keys"), elsewhere} {
		must(t, os.MkdirAll(d, 0o755))
	}
	for _, f := range []string{filepath.Join(real, "bin", "fileparcel"), filepath.Join(real, "data", "x", "f"),
		filepath.Join(real, "fileparcel.toml"), filepath.Join(real, "keys", "master.key"), filepath.Join(elsewhere, "secret")} {
		must(t, os.WriteFile(f, nil, 0o600))
	}
	must(t, os.Symlink(elsewhere, filepath.Join(real, "data", "ext")))
	must(t, os.Symlink(real, link))
	got := chownCalls(t)
	must(t, ChownTree(link, 1234, 5678, filepath.Join(link, "bin")))
	for _, p := range []string{real, filepath.Join(real, "fileparcel.toml"), filepath.Join(real, "keys", "master.key"),
		filepath.Join(real, "data", "x", "f")} {
		if got[p] != [2]int{1234, 5678} {
			t.Errorf("%s not chowned (%v)", p, got[p])
		}
	}
	for _, p := range []string{filepath.Join(real, "bin"), filepath.Join(real, "bin", "fileparcel"), filepath.Join(elsewhere, "secret"), elsewhere,
		filepath.Join(real, "data", "ext")} {
		if _, ok := got[p]; ok {
			t.Errorf("%s chowned", p)
		}
	}
}

// Root walks trees the service account owns and can change meanwhile
// (`service install --system` on a live home): an entry swapped for a
// symlink after it was listed is never followed — the path-based walk this
// replaces (WalkDir + Lchown) went on through such a link, to /etc or to
// the root-owned bin/. The swaps happen after the entry was examined, just
// before it is opened.
func TestChownTreeSwaps(t *testing.T) {
	for _, c := range []struct {
		name       string
		when, swap string // at the visit of when, swap is replaced by a symlink to target
		target     func(root, out string) string
	}{
		{"dir to outside", "zz", "zz", func(_, out string) string { return out }},
		{"dir to bin", "zz", "zz", func(root, _ string) string { return filepath.Join(root, "bin") }},
		{"dir to the root", "zz", "zz", func(string, string) string { return "." }},
		{"file to outside", "a/f", "a/f", func(_, out string) string { return filepath.Join(out, "shadow") }},
		// A directory already opened: what is below it is reached through
		// its descriptor, never through its name again.
		{"open parent to outside", "a/f", "a", func(_, out string) string { return out }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			root, out := filepath.Join(dir, "home"), filepath.Join(dir, "etc")
			for _, d := range []string{filepath.Join(root, "bin"), filepath.Join(root, "a"), filepath.Join(root, "zz"),
				filepath.Join(out, "sub")} {
				must(t, os.MkdirAll(d, 0o700))
			}
			var protected []os.FileInfo
			for _, f := range []string{filepath.Join(root, "bin", "fileparcel"), filepath.Join(root, "a", "f"), filepath.Join(root, "a", "g"),
				filepath.Join(root, "zz", "h"), filepath.Join(out, "shadow"), filepath.Join(out, "sub", "x")} {
				must(t, os.WriteFile(f, nil, 0o600))
			}
			for _, p := range []string{filepath.Join(root, "bin"), filepath.Join(root, "bin", "fileparcel"), out,
				filepath.Join(out, "shadow"), filepath.Join(out, "sub"), filepath.Join(out, "sub", "x")} {
				fi, err := os.Lstat(p)
				must(t, err)
				protected = append(protected, fi)
			}
			got := chownCalls(t)
			var changed []os.FileInfo
			fchown = func(f *os.File, uid, gid int) error {
				fi, err := f.Stat()
				if err != nil {
					return err
				}
				changed = append(changed, fi)
				got[f.Name()] = [2]int{uid, gid}
				return nil
			}
			swapped := false
			chownVisit = func(p string) {
				if p != filepath.Join(root, c.when) || swapped {
					return
				}
				swapped = true
				s := filepath.Join(root, c.swap)
				must(t, os.Rename(s, s+".moved"))
				must(t, os.Symlink(c.target(root, out), s))
			}
			t.Cleanup(func() { chownVisit = nil })
			must(t, ChownTree(root, 1234, 5678, filepath.Join(root, "bin")))
			if !swapped {
				t.Fatal("no swap")
			}
			for _, fi := range changed {
				for _, p := range protected {
					if os.SameFile(fi, p) {
						t.Errorf("changed %s through a swapped entry", p.Name())
					}
				}
			}
			if got[root] != [2]int{1234, 5678} || got[filepath.Join(root, "a", "g")] != [2]int{1234, 5678} {
				t.Errorf("tree not changed: %v", got)
			}
		})
	}
}

// Where hard links are not protected (macOS, fs.protected_hardlinks=0) the
// service account could link a file of root's into its tree: a file with
// several links is only changed when uid owns it already. skip is matched
// by identity, so another name for a skipped file is skipped too.
func TestChownTreeHardLinks(t *testing.T) {
	dir := t.TempDir()
	root, outside := filepath.Join(dir, "home"), filepath.Join(dir, "shadow")
	must(t, os.MkdirAll(filepath.Join(root, "data"), 0o700))
	for _, f := range []string{outside, filepath.Join(root, "plain"), filepath.Join(root, "uninstall.sh")} {
		must(t, os.WriteFile(f, nil, 0o600))
	}
	if err := os.Link(outside, filepath.Join(root, "data", "hl")); err != nil {
		t.Skip("no hard links:", err)
	}
	must(t, os.Link(filepath.Join(root, "uninstall.sh"), filepath.Join(root, "data", "u")))
	got := chownCalls(t)
	must(t, ChownTree(root, 1234, 5678))
	if _, ok := got[filepath.Join(root, "data", "hl")]; ok {
		t.Error("a file with another link outside the tree was changed")
	}
	if got[filepath.Join(root, "plain")] != [2]int{1234, 5678} {
		t.Error("plain file not changed")
	}
	clear(got)
	must(t, ChownTree(root, os.Getuid(), 5678, filepath.Join(root, "uninstall.sh")))
	if got[filepath.Join(root, "data", "hl")] != [2]int{os.Getuid(), 5678} {
		t.Errorf("a linked file uid owns: %v", got)
	}
	if _, ok := got[filepath.Join(root, "data", "u")]; ok {
		t.Error("another name for a skipped file was changed")
	}
}

// A system install's HOME is root:<group> 01770: the service account can
// write in it but cannot rename or replace the root-owned bin/ and
// uninstall.sh (which root runs) — owning HOME, it could.
func TestSecureSystemHome(t *testing.T) {
	h, err := home.New(filepath.Join(t.TempDir(), "opt"))
	must(t, err)
	must(t, h.EnsureLayout())
	for _, f := range []string{h.Binary(), h.UninstallScript(), h.Config(), h.VersionFile(), h.KeysFile(), filepath.Join(h.DocsDir(), "FILEPARCEL.md")} {
		must(t, os.WriteFile(f, nil, 0o600))
	}
	got := chownCalls(t)
	must(t, SecureSystemHome(h, 990, 991))
	for _, p := range []string{h.DataDir(), h.KeysDir(), h.KeysFile(), h.Config(), h.ServiceDir(), h.LogsDir(), h.RunDir(), h.DocsDir(), h.VersionFile()} {
		if got[p] != [2]int{990, 991} {
			t.Errorf("%s: %v, want the service account", p, got[p])
		}
	}
	for _, p := range []string{h.BinDir(), h.UninstallScript()} {
		if got[p] != [2]int{0, 0} {
			t.Errorf("%s: %v, want root", p, got[p])
		}
	}
	if _, ok := got[h.Binary()]; ok {
		t.Error("bin/fileparcel given away")
	}
	if _, ok := got[h.Dir()]; ok {
		t.Error("HOME itself given to the service account")
	}
	if got["follow:"+h.Dir()] != [2]int{0, 991} {
		t.Errorf("HOME owner %v, want root:991", got["follow:"+h.Dir()])
	}
	fi, err := os.Stat(h.Dir())
	if err != nil || !home.IsSystemHomeMode(fi.Mode()) {
		t.Fatalf("HOME mode %v %v", fi.Mode(), err)
	}
	// The server's own EnsureLayout keeps it that way.
	must(t, h.EnsureLayout())
	if fi, _ := os.Stat(h.Dir()); !home.IsSystemHomeMode(fi.Mode()) {
		t.Fatalf("EnsureLayout changed HOME to %v", fi.Mode())
	}
}

// ---------- firewall ----------

func TestDetectFirewalls(t *testing.T) {
	old := readFile
	t.Cleanup(func() { readFile = old })
	readFile = func(p string) ([]byte, error) {
		if p == "/etc/ufw/ufw.conf" {
			return []byte("# comment\nENABLED=yes\nLOGLEVEL=low\n"), nil
		}
		return nil, os.ErrNotExist
	}
	h, fr := testHost(t, "linux", 1000)
	h.LookPath = func(n string) (string, error) {
		if n == "firewall-cmd" || n == "systemctl" || n == "nft" {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("no")
	}
	fr.resp["firewall-cmd --state"] = fakeResp{code: 252, out: "not running\n"}
	fr.resp["systemctl is-active nftables"] = fakeResp{out: "active\n"}
	fws := DetectFirewalls(context.Background(), h)
	if len(fws) != 3 || fws[0] != (Firewall{Kind: FirewallUFW, Active: true, Detail: "/etc/ufw/ufw.conf"}) ||
		fws[1].Active || !fws[2].Active {
		t.Fatalf("%+v", fws)
	}
	for in, want := range map[string]bool{"ENABLED=no": false, "ENABLED=\"yes\"": true, " ENABLED = YES ": true, "": false} {
		if ufwEnabled([]byte(in)) != want {
			t.Errorf("ufwEnabled(%q)", in)
		}
	}
	mac, mfr := testHost(t, "darwin", 501)
	mac.LookPath = func(n string) (string, error) { return n, nil }
	mfr.resp[SocketFilterFW] = fakeResp{out: "Firewall is enabled. (State = 1)\n"}
	if fws := DetectFirewalls(context.Background(), mac); len(fws) != 1 || !fws[0].Active {
		t.Fatalf("mac %+v", fws)
	}
}

func TestBuiltinMDNSLikely(t *testing.T) {
	old := statPath
	t.Cleanup(func() { statPath = old })
	avahi := false
	statPath = func(p string) (os.FileInfo, error) {
		if avahi && p == "/run/avahi-daemon/socket" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	linux, _ := testHost(t, "linux", 1000)
	mac, _ := testHost(t, "darwin", 501)
	if !BuiltinMDNSLikely(linux) || BuiltinMDNSLikely(mac) {
		t.Fatal("without avahi: linux builtin, macOS dns-sd")
	}
	avahi = true
	if BuiltinMDNSLikely(linux) {
		t.Fatal("avahi running: not builtin")
	}
}

func TestFirewallHints(t *testing.T) {
	in := HintInput{HTTPSPort: 8443, HTTPPort: 8080,
		Subnets:   []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24"), netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("127.0.0.1/8"), netip.MustParsePrefix("fd00:1::5/64")},
		VPNIfaces: []string{"tailscale0"}, Binary: "/opt/fp/bin/fileparcel"}
	got := Hints(FirewallUFW, in)
	want := []string{
		"sudo ufw allow from 192.168.1.0/24 to any port 8443,8080 proto tcp",
		"sudo ufw allow from fd00:1::/64 to any port 8443,8080 proto tcp",
		"sudo ufw allow in on tailscale0 to any port 8443 proto tcp",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ufw:\n%s", strings.Join(got, "\n"))
	}
	rm := RemovalHints(FirewallUFW, in)
	if rm[0] != "sudo ufw delete allow from 192.168.1.0/24 to any port 8443,8080 proto tcp" {
		t.Fatal(rm[0])
	}
	in.BuiltinMDNS = true
	if got := Hints(FirewallUFW, in); got[len(got)-1] != "sudo ufw allow from 192.168.1.0/24 to any port 5353 proto udp" {
		t.Fatalf("mdns %v", got)
	}
	fd := Hints(FirewallFirewalld, in)
	if !strings.Contains(fd[0], `rule family="ipv4" source address="192.168.1.0/24" port port="8443" protocol="tcp" accept`) ||
		!strings.Contains(strings.Join(fd, "\n"), `family="ipv6" source address="fd00:1::/64"`) || fd[len(fd)-1] != "sudo firewall-cmd --reload" ||
		!strings.Contains(strings.Join(fd, "\n"), "--add-service=mdns") {
		t.Fatalf("firewalld %v", fd)
	}
	if r := RemovalHints(FirewallFirewalld, in); !strings.Contains(r[0], "--remove-rich-rule") {
		t.Fatalf("firewalld removal %v", r)
	}
	// A VPN interface bound to no zone ("no zone", exit 2) falls back to the
	// default zone, which is where firewalld sends its traffic.
	const zoneHint = `zone=$(firewall-cmd --get-zone-of-interface=tailscale0 2>/dev/null) || zone=$(firewall-cmd --get-default-zone); ` +
		`sudo firewall-cmd --permanent --zone="$zone" --add-port=8443/tcp`
	if !slices.Contains(fd, zoneHint) {
		t.Fatalf("firewalld VPN interface hint:\n%s", strings.Join(fd, "\n"))
	}
	if r := RemovalHints(FirewallFirewalld, in); !slices.Contains(r, strings.Replace(zoneHint, "--add-port", "--remove-port", 1)) {
		t.Fatalf("firewalld VPN interface removal:\n%s", strings.Join(r, "\n"))
	}
	nft := Hints(FirewallNftables, in)
	if nft[0] != "sudo nft insert rule inet filter input ip saddr 192.168.1.0/24 tcp dport { 8443, 8080 } accept" ||
		!strings.Contains(nft[2], `iifname "tailscale0" tcp dport 8443`) {
		t.Fatalf("nft %v", nft)
	}
	// Accept rules are inserted at the head of the chain (an appended rule
	// comes after the drop/reject rule that made nftables count as active),
	// and the builtin mDNS responder gets UDP 5353 for the IPv4 subnets.
	for _, l := range nft[:len(nft)-1] {
		if !strings.HasPrefix(l, "sudo nft insert rule inet filter input ") || strings.Contains(l, " add rule ") {
			t.Fatalf("nft rule %q", l)
		}
		if strings.Contains(l, "ip6 saddr") && strings.Contains(l, "5353") {
			t.Fatalf("mDNS rule for IPv6: %q", l)
		}
	}
	if !slices.Contains(nft, "sudo nft insert rule inet filter input ip saddr 192.168.1.0/24 udp dport 5353 accept") ||
		!strings.HasPrefix(nft[len(nft)-1], "# adjust") || !strings.Contains(nft[len(nft)-1], "before any drop/reject rule") {
		t.Fatalf("nft mdns %v", nft)
	}
	in.BuiltinMDNS = false
	if strings.Contains(strings.Join(Hints(FirewallNftables, in), "\n"), "5353") {
		t.Fatal("nft 5353 rule without the builtin responder")
	}
	in.BuiltinMDNS = true
	if r := RemovalHints(FirewallNftables, in); len(r) != 1 {
		t.Fatal(r)
	}
	mac := Hints(FirewallMacOS, in)
	if len(mac) != 2 || mac[0] != "sudo "+SocketFilterFW+" --add /opt/fp/bin/fileparcel" {
		t.Fatalf("mac %v", mac)
	}
	if r := RemovalHints(FirewallMacOS, in); r[0] != "sudo "+SocketFilterFW+" --remove /opt/fp/bin/fileparcel" {
		t.Fatal(r)
	}
	// No HTTP port → only the HTTPS port.
	if got := Hints(FirewallUFW, HintInput{HTTPSPort: 9443, Subnets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}); got[0] != "sudo ufw allow from 10.0.0.0/8 to any port 9443 proto tcp" {
		t.Fatal(got)
	}
	if got := Hints("unknown", in); got != nil {
		t.Fatal(got)
	}
	any := HintInput{HTTPSPort: 8443, HTTPPort: 8080, Anywhere: true}
	if got := Hints(FirewallUFW, any); len(got) != 1 || got[0] != "sudo ufw allow proto tcp to any port 8443,8080" {
		t.Fatal(got)
	}
	if got := Hints(FirewallFirewalld, any); len(got) != 3 || got[0] != "sudo firewall-cmd --permanent --add-port=8443/tcp" {
		t.Fatal(got)
	}
	if got := Hints(FirewallNftables, any); got[0] != "sudo nft insert rule inet filter input tcp dport { 8443, 8080 } accept" {
		t.Fatal(got)
	}
	if got := RemovalHints(FirewallFirewalld, any); got[0] != "sudo firewall-cmd --permanent --remove-port=8443/tcp" {
		t.Fatal(got)
	}
	// Open to every address: no per-network or per-interface TCP rules next
	// to the any-source rule (mDNS keeps its UDP rule); the removal still
	// lists them (earlier advice may have added them).
	wide := HintInput{HTTPSPort: 8443, Anywhere: true, BuiltinMDNS: true, VPNIfaces: []string{"wg0"},
		Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}
	if got := Hints(FirewallUFW, wide); len(got) != 2 || got[0] != "sudo ufw allow proto tcp to any port 8443" ||
		got[1] != "sudo ufw allow from 192.168.1.0/24 to any port 5353 proto udp" {
		t.Fatal(got)
	}
	if got := Hints(FirewallNftables, wide); strings.Contains(strings.Join(got, "\n"), "saddr 192.168.1.0/24 tcp") ||
		strings.Contains(strings.Join(got, "\n"), "wg0") {
		t.Fatal(got)
	}
	if got := RemovalHints(FirewallUFW, wide); !strings.Contains(strings.Join(got, "\n"), "sudo ufw delete allow from 192.168.1.0/24 to any port 8443 proto tcp") {
		t.Fatal(got)
	}
}

// ---------- platform ----------

func TestPlatformDefaults(t *testing.T) {
	lin, _ := testHost(t, "linux", 1000)
	root, _ := testHost(t, "linux", 0)
	mac, _ := testHost(t, "darwin", 501)
	macRoot, _ := testHost(t, "darwin", 0)
	if DefaultHome(lin) != filepath.Join(lin.HomeDir, ".local/share/fileparcel") || DefaultHome(root) != "/opt/fileparcel" ||
		DefaultHome(mac) != filepath.Join(mac.HomeDir, "Library/Application Support/FileParcel") || DefaultHome(macRoot) != "/usr/local/fileparcel" {
		t.Fatal("default homes")
	}
	lin.Getenv = func(k string) string {
		if k == "XDG_DATA_HOME" {
			return "/data/xdg"
		}
		return ""
	}
	if DefaultHome(lin) != "/data/xdg/fileparcel" {
		t.Fatal(DefaultHome(lin))
	}
	if DefaultSymlink(root) != "/usr/local/bin/fileparcel" || DefaultSymlink(mac) != filepath.Join(mac.HomeDir, ".local/bin/fileparcel") {
		t.Fatal("symlinks")
	}
	for _, c := range []struct {
		h       *Host
		service string
		want    Kind
		err     bool
	}{
		{lin, "", KindSystemdUser, false}, {lin, "user", KindSystemdUser, false}, {lin, "system", "", true}, {lin, "none", KindNone, false},
		{root, "", KindSystemdSystem, false}, {root, "user", "", true}, {mac, "", KindLaunchdAgent, false}, {mac, "system", "", true},
		{macRoot, "", KindLaunchdDaemon, false}, {macRoot, "user", "", true}, {lin, "bogus", "", true},
	} {
		k, _, err := ResolveKind(c.h, c.service)
		if (err != nil) != c.err || (!c.err && k != c.want) {
			t.Errorf("%s uid %d %q: %s %v", c.h.GOOS, c.h.UID, c.service, k, err)
		}
	}
	nosd, _ := testHost(t, "linux", 1000)
	nosd.LookPath = func(string) (string, error) { return "", errors.New("no") }
	if k, why, err := ResolveKind(nosd, ""); err != nil || k != KindNone || why == "" {
		t.Fatal(k, why, err)
	}
	fb, _ := testHost(t, "freebsd", 1000)
	if k, why, _ := ResolveKind(fb, ""); k != KindNone || why == "" {
		t.Fatal(k)
	}
	// systemctl present but systemd not the running init (WSL without
	// systemd=true, containers): the default is no service, an explicit
	// systemd kind an error — before anything is installed.
	for _, uid := range []int{1000, 0} {
		h, fr := testHost(t, "linux", uid)
		h.Paths.SystemdRunDir = filepath.Join(t.TempDir(), "run", "systemd", "system")
		if k, why, err := ResolveKind(h, ""); err != nil || k != KindNone || !strings.Contains(why, "not running as the init system") {
			t.Fatalf("uid %d: %s %q %v", uid, k, why, err)
		}
		service := map[int]string{1000: "user", 0: "system"}[uid]
		if _, _, err := ResolveKind(h, service); err == nil || !strings.Contains(err.Error(), "--service none") {
			t.Fatalf("uid %d --service %s: %v", uid, service, err)
		}
		if k, _, err := ResolveKind(h, "none"); err != nil || k != KindNone {
			t.Fatal(k, err)
		}
		must(t, os.MkdirAll(h.Paths.SystemdRunDir, 0o755))
		if k, _, err := ResolveKind(h, ""); err != nil || !k.Systemd() {
			t.Fatalf("uid %d booted: %s %v", uid, k, err)
		}
		if len(fr.calls) != 0 {
			t.Fatal(fr.lines())
		}
	}
	if p := DefaultPaths("/home/alice"); p.SystemdRunDir != "/run/systemd/system" {
		t.Fatal(p.SystemdRunDir)
	}
	if ServiceUser(mac) != "_fileparcel" || ServiceUser(lin) != "fileparcel" {
		t.Fatal("service users")
	}
}

func TestSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "home", "bin", "fileparcel")
	link := filepath.Join(dir, "local", "bin", "fileparcel")
	if changed, err := EnsureSymlink(link, target, false); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if st, _ := InspectSymlink(link, target); st != SymlinkOurs {
		t.Fatal(st)
	}
	if changed, err := EnsureSymlink(link, target, false); err != nil || changed {
		t.Fatal("idempotent", changed, err)
	}
	other := filepath.Join(dir, "other", "bin", "fileparcel")
	if _, err := EnsureSymlink(link, other, false); err == nil {
		t.Fatal("replaced a link to another install without --force")
	}
	if changed, err := EnsureSymlink(link, other, true); err != nil || !changed {
		t.Fatal("force", err)
	}
	// RemoveSymlink only removes links into the given home.
	if removed, _ := RemoveSymlink(link, filepath.Join(dir, "home")); removed {
		t.Fatal("removed a link to another home")
	}
	if removed, err := RemoveSymlink(link, filepath.Join(dir, "other")); err != nil || !removed {
		t.Fatal(removed, err)
	}
	foreign := filepath.Join(dir, "foreign")
	os.WriteFile(foreign, []byte("x"), 0o755)
	if _, err := EnsureSymlink(foreign, target, false); err == nil {
		t.Fatal("replaced a regular file")
	}
	if removed, _ := RemoveSymlink(foreign, dir); removed {
		t.Fatal("removed a regular file")
	}
	if _, err := EnsureSymlink(foreign, target, true); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "adir"), 0o755)
	if _, err := EnsureSymlink(filepath.Join(dir, "adir"), target, true); err == nil {
		t.Fatal("replaced a directory")
	}
	// Relative links resolve against the link's directory.
	rel := filepath.Join(dir, "rel")
	os.Symlink("home/bin/fileparcel", rel)
	if st, _ := InspectSymlink(rel, target); st != SymlinkOurs {
		t.Fatal("relative link")
	}
	if !OnPath("/a/b", "/x:/a/b/:/y") || OnPath("/a/b", "/x:/y") {
		t.Fatal("OnPath")
	}
	if !Within("/a/b", "/a/b/c") || !Within("/a/b", "/a/b") || Within("/a/b", "/a/bc") || Within("/a/b", "/a") {
		t.Fatal("Within")
	}
}

func TestPorts(t *testing.T) {
	busy := map[int]bool{8443: true, 8444: true}
	free := func(p int) bool { return !busy[p] }
	if p := NextFreePort(8443, free); p != 8445 {
		t.Fatal(p)
	}
	if p := NextFreePort(8445, free, 8445); p != 8446 {
		t.Fatal(p)
	}
	if p := NextFreePort(65535, func(int) bool { return false }); p != 0 {
		t.Fatal(p)
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	if PortFree(ln.Addr().(*net.TCPAddr).Port) {
		t.Fatal("bound port reported free")
	}
}

func TestDangerousHome(t *testing.T) {
	uh := "/home/alice"
	for _, d := range []string{"/", "", ".", "rel/dir", "/usr", "/etc/", "/opt", "/home", "/home/alice", "/home/alice/Documents", "/Users", "/var"} {
		if !DangerousHome(d, uh) {
			t.Errorf("%q not dangerous", d)
		}
	}
	for _, d := range []string{"/opt/fileparcel", "/home/alice/.local/share/fileparcel", "/home/alice/Documents/fileparcel/server", "/srv/fp"} {
		if DangerousHome(d, uh) {
			t.Errorf("%q dangerous", d)
		}
	}
	// The parents of the default homes (and other shared per-user
	// directories) hold other applications' data: never a home, never purged.
	old := osGetenv
	t.Cleanup(func() { osGetenv = old })
	osGetenv = func(k string) string {
		return map[string]string{"XDG_DATA_HOME": "/data/xdg", "XDG_CONFIG_HOME": "/data/cfg/"}[k]
	}
	mac := "/Users/alice"
	for _, c := range []struct{ dir, uh string }{
		{"/Users/alice/Library/Application Support", mac}, {"/Users/alice/Library/Preferences", mac},
		{"/home/alice/.local/state", uh}, {"/home/alice/.cache", uh}, {"/data/xdg", uh}, {"/data/xdg/", uh}, {"/data/cfg", uh},
	} {
		if !DangerousHome(c.dir, c.uh) {
			t.Errorf("%q not dangerous", c.dir)
		}
	}
	for _, c := range []struct{ dir, uh string }{
		{"/Users/alice/Library/Application Support/FileParcel", mac}, {"/data/xdg/fileparcel", uh},
	} {
		if DangerousHome(c.dir, c.uh) {
			t.Errorf("%q dangerous", c.dir)
		}
	}
}

// ---------- installed.json, plan, runner ----------

func TestInstalledRoundTrip(t *testing.T) {
	h, _ := home.New(t.TempDir())
	if in, err := ReadInstalled(h); err != nil || in != nil {
		t.Fatal(in, err)
	}
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	in := &Installed{Kind: KindSystemdUser, UnitPath: "/x", Boot: true, LingerEnabledByUs: true, Symlink: "/l",
		Home: h.Dir(), HTTPSPort: 8443, Version: "v1", InstalledAt: now}
	if err := WriteInstalled(h, in); err != nil {
		t.Fatal(err)
	}
	in.FirewallSubnets, in.FirewallIfaces = []string{"192.168.1.0/24"}, []string{"tailscale0"}
	in.FirewallAnywhere, in.Incomplete = true, true
	if err := WriteInstalled(h, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadInstalled(h)
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Fatalf("%+v %v", got, err)
	}
	fi, _ := os.Stat(InstalledPath(h))
	if fi.Mode().Perm() != 0o640 {
		t.Fatal(fi.Mode())
	}
	os.WriteFile(InstalledPath(h), []byte("{bad"), 0o640)
	if _, err := ReadInstalled(h); err == nil {
		t.Fatal("bad json")
	}
	os.WriteFile(InstalledPath(h), []byte("{}"), 0o640)
	if got, _ := ReadInstalled(h); got.Kind != KindNone {
		t.Fatal(got.Kind)
	}
}

func TestPlan(t *testing.T) {
	var p Plan
	p.Title = "Plan"
	p.Fact("Home", "/h")
	p.Fact("Service", "user")
	ran := []string{}
	p.Add("first", func(context.Context) error { ran = append(ran, "1"); return nil }, "detail a")
	p.Add("info", nil)
	p.Add("fails", func(context.Context) error { return errors.New("boom") })
	p.Add("never", func(context.Context) error { ran = append(ran, "4"); return nil })
	p.Note("note %d", 1)
	var b bytes.Buffer
	p.Print(&b)
	want := "Plan\n\n  Home:     /h\n  Service:  user\n\nSteps:\n   1. first\n        detail a\n   2. info\n   3. fails\n   4. never\n\nnote 1\n"
	if b.String() != want {
		t.Fatalf("print:\n%q\nwant\n%q", b.String(), want)
	}
	b.Reset()
	err := p.Execute(context.Background(), &b)
	if err == nil || err.Error() != "fails: boom" || strings.Join(ran, ",") != "1" || !strings.Contains(b.String(), "[3/4] fails") {
		t.Fatalf("execute %v %v %q", err, ran, b.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Execute(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestExecRunner(t *testing.T) {
	r := ExecRunner{Timeout: 10 * time.Second}
	ctx := context.Background()
	res, err := r.Run(ctx, []string{"FP_TEST=1"}, "sh", "-c", "echo $FP_TEST; echo err >&2")
	if err != nil || string(res.Stdout) != "1\n" || string(res.Stderr) != "err\n" {
		t.Fatalf("%q %q %v", res.Stdout, res.Stderr, err)
	}
	_, err = r.Run(ctx, nil, "sh", "-c", "echo nope >&2; exit 3")
	var ce *CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 3 || ExitCodeOf(err) != 3 || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("%v", err)
	}
	if _, err := r.Run(ctx, nil, "/nonexistent/binary"); err == nil || ExitCodeOf(err) != -1 {
		t.Fatal(err)
	}
	if got := CommandLine("a", "b c", "", "it's", "x=y"); got != `a 'b c' '' 'it'\''s' x=y` {
		t.Fatal(got)
	}
	h := CurrentHost()
	if h.GOOS == "" || h.Runner == nil || h.Paths.SystemUnitDir == "" || h.UID != os.Geteuid() {
		t.Fatalf("%+v", h)
	}
	_ = strconv.Itoa
}
