package installer

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/buildinfo"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/svc/provision"
)

var update = flag.Bool("update", false, "rewrite golden files")

// ---------- fakes ----------

// fakeRunner records commands; responses are matched by the longest
// command-line prefix.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	resp  map[string]fakeResp
	// onRun is called for every command (after recording).
	onRun func(line string)
}

type fakeResp struct {
	out  string
	code int
}

func (f *fakeRunner) Run(ctx context.Context, env []string, name string, args ...string) (svc.Result, error) {
	if err := ctx.Err(); err != nil {
		return svc.Result{}, err // like ExecRunner: nothing runs on a done context
	}
	f.mu.Lock()
	line := svc.CommandLine(name, args...)
	f.calls = append(f.calls, line)
	on := f.onRun
	best, found := "", false
	for k := range f.resp {
		if strings.HasPrefix(line, k) && len(k) >= len(best) {
			best, found = k, true
		}
	}
	r := f.resp[best]
	f.mu.Unlock()
	if on != nil {
		on(line)
	}
	if !found {
		return svc.Result{}, nil
	}
	res := svc.Result{Stdout: []byte(r.out), ExitCode: r.code}
	if r.code != 0 {
		return res, &svc.CommandError{Cmd: line, ExitCode: r.code}
	}
	return res, nil
}

func (f *fakeRunner) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

// changes returns the recorded commands without the read-only firewall
// probes of the summary (which depend on what the test machine has).
func (f *fakeRunner) changes() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "systemctl is-active nftables") && !strings.HasPrefix(c, "firewall-cmd --state") {
			out = append(out, c)
		}
	}
	return strings.Join(out, "\n")
}

// fakePrompter answers from queues.
type fakePrompter struct {
	interactive bool
	asks        []string
	confirms    []bool
	secrets     []string
	questions   []string
}

func (p *fakePrompter) Interactive() bool { return p.interactive }
func (p *fakePrompter) Ask(q, def string) (string, error) {
	p.questions = append(p.questions, q)
	if len(p.asks) == 0 {
		return def, nil
	}
	a := p.asks[0]
	p.asks = p.asks[1:]
	if a == "" {
		return def, nil
	}
	return a, nil
}
func (p *fakePrompter) Confirm(q string, def bool) (bool, error) {
	p.questions = append(p.questions, q)
	if len(p.confirms) == 0 {
		return def, nil
	}
	c := p.confirms[0]
	p.confirms = p.confirms[1:]
	return c, nil
}
func (p *fakePrompter) Secret(q string, confirm bool) (string, error) {
	p.questions = append(p.questions, q)
	if len(p.secrets) == 0 {
		return "", errors.New("no secret")
	}
	s := p.secrets[0]
	p.secrets = p.secrets[1:]
	return s, nil
}

type env struct {
	t      *testing.T
	root   string
	host   *svc.Host
	runner *fakeRunner
	out    bytes.Buffer
	errOut bytes.Buffer
	in     *Installer
	exe    string
	inits  []provision.Options
	cfgs   []provision.ConfigOptions
	backup []core.BackupInput
	health []int // ports health-checked
	// healthErrs are returned by successive health checks (nil when exhausted).
	healthErrs []error
	backupErr  error
	// backupNoFile makes the Backup hook report a backup without writing its
	// archive into <HOME>/backups.
	backupNoFile bool
}

func newEnv(t *testing.T, goos string, uid int) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{t: t, root: root, runner: &fakeRunner{resp: map[string]fakeResp{}}}
	userHome := filepath.Join(root, "home", "alice")
	must(t, os.MkdirAll(userHome, 0o755))
	vars := map[string]string{"PATH": "/usr/bin:" + filepath.Join(userHome, ".local", "bin")}
	e.host = &svc.Host{
		GOOS: goos, UID: uid, GID: uid, User: "alice", HomeDir: userHome, Runner: e.runner,
		Getenv: func(k string) string { return vars[k] },
		LookPath: func(n string) (string, error) {
			switch n {
			case "systemctl", "loginctl", "launchctl", "useradd", "userdel":
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("not found")
		},
		Paths: svc.Paths{
			UserUnitDir: filepath.Join(userHome, ".config", "systemd", "user"), SystemUnitDir: filepath.Join(root, "etc-systemd"),
			LaunchAgentsDir: filepath.Join(userHome, "Library", "LaunchAgents"), LaunchDaemonsDir: filepath.Join(root, "LaunchDaemons"),
			LingerDir: filepath.Join(root, "linger"), RunUserDir: "/run/user",
		},
	}
	// The binary being installed, with uninstall.sh and docs/ next to it
	// (release layout: <src>/bin/fileparcel-linux-amd64).
	src := filepath.Join(root, "release")
	must(t, os.MkdirAll(filepath.Join(src, "bin"), 0o755))
	must(t, os.MkdirAll(filepath.Join(src, "docs", "img"), 0o755))
	e.exe = filepath.Join(src, "bin", "fileparcel-linux-amd64")
	must(t, os.WriteFile(e.exe, []byte("#!/bin/sh\necho new\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(src, "uninstall.sh"), []byte("#!/bin/sh\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(src, "docs", "FILEPARCEL.md"), []byte("# manual\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(src, "docs", "img", "a.png"), []byte("png"), 0o644))
	must(t, os.WriteFile(filepath.Join(src, "docs", ".hidden"), []byte("x"), 0o644))
	// Its SHA256SUMS makes it a release the installer takes support files from.
	must(t, os.WriteFile(filepath.Join(src, "SHA256SUMS"), []byte(sum("#!/bin/sh\necho new\n")+"  bin/fileparcel-linux-amd64\n"+
		sum("#!/bin/sh\n")+"  uninstall.sh\n"+sum("# manual\n")+"  docs/FILEPARCEL.md\n"+sum("png")+"  docs/img/a.png\n"), 0o644))

	e.in = &Installer{
		Host: e.host, Out: &e.out, Err: &e.errOut, Prompt: &fakePrompter{}, Executable: e.exe,
		Build:    buildinfo.Info{Version: "v7", Commit: "abc1234", Date: "2026-09-19"},
		Now:      func() time.Time { return time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC) },
		PortFree: func(p int) bool { return p != 8443 }, // 8443 is taken → 8444 is suggested
		HealthWait: func(ctx context.Context, h *home.Home, port int, total time.Duration) error {
			e.health = append(e.health, port)
			if len(e.healthErrs) > 0 {
				err := e.healthErrs[0]
				e.healthErrs = e.healthErrs[1:]
				return err
			}
			return nil
		},
		BinaryInfo: func(ctx context.Context, bin string) (buildinfo.Info, error) {
			// The "old binary" the tests put into bin/ is the v7 that VERSION
			// names; every other binary is the new v8. Like the real
			// BinaryInfo, a missing binary does not run.
			b, err := os.ReadFile(bin)
			if err != nil {
				return buildinfo.Info{}, err
			}
			if string(b) == "old binary" {
				return buildinfo.Info{Version: "v7", Commit: "abc1234", Date: "2026-09-19"}, nil
			}
			return buildinfo.Info{Version: "v8", Commit: "def5678", Date: "2026-10-01"}, nil
		},
		HealthTimeout: time.Second,
	}
	e.in.Hooks = Hooks{
		InitHome: func(ctx context.Context, dir string, c provision.ConfigOptions, o provision.Options) (*provision.Result, error) {
			e.inits = append(e.inits, o)
			e.cfgs = append(e.cfgs, c)
			p, err := provision.PrepareHome(dir, c)
			if err != nil {
				return nil, err
			}
			must(t, os.WriteFile(p.Home.KeysFile(), []byte(`{"mode":"plain"}`), 0o600))
			must(t, os.WriteFile(filepath.Join(p.Home.CertsDir(), "ca", "ca.key.enc"), []byte("secret-ca-key"), 0o600))
			res := &provision.Result{Home: dir, Owner: o.Admin, KeyMode: core.KeyModePlain, CAFingerprint: "AA:BB:CC",
				AccessMode: core.AccessAllowlist, AllowCIDRs: []string{"192.168.1.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/48"},
				BackupIdentity: "# comment\nAGE-SECRET-KEY-1TEST", BackupRecipient: "age1test",
				URLs: []core.AccessURL{
					{URL: "https://fileparcel.local:8444/", Kind: core.URLKindMDNS, Label: "Local network name (mDNS)", Recommended: true},
					{URL: "https://192.168.1.10:8444/", Kind: core.URLKindIP, Interface: "eth0", Label: "LAN (eth0)", Recommended: true},
				},
				Interfaces: []core.NetInterface{
					{Name: "eth0", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}},
					{Name: "tailscale0", Kind: core.IfTailscale, Up: true, IsVPN: true,
						Addrs: []netip.Prefix{netip.MustParsePrefix("100.81.1.2/32")}},
				},
				Tailscale: &core.TailscaleInfo{Running: true, DNSName: "box.tail.ts.net", Kind: core.IfTailscale},
			}
			if o.AdminPassword == "" && o.Admin != "" {
				res.Password, res.PasswordGenerated = "gen-erated-pass-word", true
			}
			if o.Sealed {
				res.RecoveryKey, res.KeyMode = "FPRK-TEST", core.KeyModeSealed
			}
			return res, nil
		},
		Backup: func(ctx context.Context, h *home.Home, in core.BackupInput) (*core.Backup, error) {
			e.backup = append(e.backup, in)
			if e.backupErr != nil {
				return nil, e.backupErr
			}
			// Like backup.Service: the archive is written to <HOME>/backups;
			// a copy to in.CopyTo is best effort (not made here).
			b := &core.Backup{ID: "bkp_1", FileName: "fp-20260919.fpbak", State: core.BackupReady}
			if !e.backupNoFile {
				content := []byte("encrypted archive " + in.Trigger)
				must(t, os.MkdirAll(h.BackupsDir(), 0o700))
				must(t, os.WriteFile(filepath.Join(h.BackupsDir(), b.FileName), content, 0o600))
				b.Size, b.SHA256 = int64(len(content)), sum(string(content))
			}
			if in.CopyTo != "" {
				b.Error = "copy to " + in.CopyTo + " failed: not made by the fake"
			}
			return b, nil
		},
	}
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) dir(name string) string { return filepath.Join(e.root, name) }

// golden compares got with testdata/<name> (after replacing the temp root).
func (e *env) golden(name, got string) {
	e.t.Helper()
	got = strings.ReplaceAll(got, e.root, "/ROOT")
	p := filepath.Join("testdata", name)
	if *update {
		must(e.t, os.MkdirAll("testdata", 0o755))
		must(e.t, os.WriteFile(p, []byte(got), 0o644))
	}
	want, err := os.ReadFile(p)
	if err != nil {
		e.t.Fatalf("golden %s: %v (run go test -update)", p, err)
	}
	if got != string(want) {
		e.t.Errorf("%s differs:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// ---------- fresh install ----------

func TestInstallDryRun(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	boot := true
	err := e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), Yes: true, DryRun: true, Boot: &boot,
		Admin: "alice", Allow: []string{"10.8.0.0/24"}})
	must(t, err)
	e.golden("install-dry-run.txt", e.out.String())
	if _, err := os.Stat(e.dir("fp")); !os.IsNotExist(err) {
		t.Fatal("dry run created the install directory")
	}
	if len(e.inits) != 0 || e.runner.joined() != "" {
		t.Fatalf("dry run did something: inits %d, commands %q", len(e.inits), e.runner.joined())
	}
}

func TestInstallDryRunSystemAndMac(t *testing.T) {
	e := newEnv(t, "linux", 0)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("opt"), Yes: true, DryRun: true, NoSymlink: true,
		HTTPSPort: 443, HTTPPort: ptr(80)}))
	e.golden("install-dry-run-system.txt", e.out.String())

	e = newEnv(t, "darwin", 501)
	must(t, e.in.Install(context.Background(), InstallOptions{Yes: true, DryRun: true, Service: "user", Boot: ptr(false)}))
	out := e.out.String()
	for _, want := range []string{"Library/Application Support/FileParcel", "launchd agent, start at boot: no",
		"com.fileparcel.server.plist"} {
		if !strings.Contains(out, want) {
			t.Errorf("mac dry run lacks %q:\n%s", want, out)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func TestInstallFreshUserService(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	link := filepath.Join(e.host.HomeDir, ".local", "bin", "fileparcel")
	err := e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true})
	must(t, err)
	h, _ := home.New(dir)

	// Files.
	if b, err := os.ReadFile(h.Binary()); err != nil || string(b) != "#!/bin/sh\necho new\n" {
		t.Fatalf("binary %q %v", b, err)
	}
	if fi, _ := os.Stat(h.Binary()); fi.Mode().Perm() != 0o755 {
		t.Errorf("binary mode %v", fi.Mode())
	}
	if v, _ := os.ReadFile(h.VersionFile()); string(v) != "v7 abc1234 2026-09-19\n" {
		t.Errorf("VERSION %q", v)
	}
	if _, err := os.Stat(h.UninstallScript()); err != nil {
		t.Error("uninstall.sh not copied")
	}
	if b, err := os.ReadFile(filepath.Join(h.DocsDir(), "img", "a.png")); err != nil || string(b) != "png" {
		t.Error("docs not copied", err)
	}
	if _, err := os.Stat(filepath.Join(h.DocsDir(), ".hidden")); !os.IsNotExist(err) {
		t.Error("dotfile copied into docs")
	}
	if fi, _ := os.Stat(h.DocsDir()); fi.Mode().Perm() != home.ModeDocs {
		t.Errorf("docs mode %v", fi.Mode().Perm())
	}
	if st, _ := svc.InspectSymlink(link, h.Binary()); st != svc.SymlinkOurs {
		t.Errorf("symlink state %v", st)
	}

	// Provisioning inputs: port 8443 was busy → 8444; HTTP default 8080.
	if len(e.inits) != 1 || e.inits[0].Admin != "admin" || e.inits[0].Access != core.AccessAllowlist ||
		e.cfgs[0].HTTPSPort != 8444 || e.cfgs[0].HTTPPort != 8080 {
		t.Fatalf("init %+v %+v", e.inits, e.cfgs)
	}

	// Service commands.
	cmds := e.runner.joined()
	for _, want := range []string{
		"loginctl enable-linger alice",
		"systemctl --user link " + filepath.Join(dir, "service", "fileparcel.service"),
		"systemctl --user daemon-reload",
		"systemctl --user enable fileparcel.service",
		"systemctl --user restart fileparcel.service",
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("missing command %q in\n%s", want, cmds)
		}
	}
	unit, err := os.ReadFile(filepath.Join(dir, "service", "fileparcel.service"))
	if err != nil || !bytes.Contains(unit, []byte(`ExecStart="`+h.Binary()+`" serve --home "`+dir+`"`)) {
		t.Fatalf("unit %s %v", unit, err)
	}
	if len(e.health) != 1 || e.health[0] != 8444 {
		t.Errorf("health checks %v", e.health)
	}

	// Install record.
	rec, err := svc.ReadInstalled(h)
	must(t, err)
	if rec.Kind != svc.KindSystemdUser || !rec.Boot || !rec.LingerEnabledByUs || rec.Symlink != link || rec.HTTPSPort != 8444 ||
		rec.HTTPPort != 8080 || rec.Version != "v7" || rec.UnitPath != filepath.Join(e.host.Paths.UserUnitDir, "fileparcel.service") ||
		strings.Join(rec.FirewallSubnets, ",") != "192.168.1.0/24" || strings.Join(rec.FirewallIfaces, ",") != "tailscale0" {
		t.Fatalf("record %+v", rec)
	}

	// Summary: URLs, QR code, credentials once, Tailscale hint, next steps.
	out := e.out.String()
	for _, want := range []string{
		"FileParcel v7 is installed in " + dir,
		"Service: systemd user service, running (start at boot: yes)",
		"https://fileparcel.local:8444/", "▀", "https://fileparcel.local:8444/trust", "CA fingerprint (SHA-256): AA:BB:CC",
		"username: admin", "password: gen-erated-pass-word", "  # comment\n  AGE-SECRET-KEY-1TEST",
		"sudo tailscale set --operator=alice", "Share links on the internet: fileparcel network funnel enable", "Command: " + link,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(e.errOut.String(), "[1/6] Initialise") {
		t.Errorf("progress:\n%s", e.errOut.String())
	}
}

func TestInstallFreshJSONAndNoService(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	e.in.JSON = true
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true,
		HTTPSPort: 9443, HTTPPort: ptr(0), AdminPassword: "a good long password", Sealed: true, Passphrase: []byte("pp")}))
	var s Summary
	must(t, json.Unmarshal(e.out.Bytes(), &s))
	if s.Action != "install" || s.Service != svc.KindNone || s.Started || s.Password != "" || s.RecoveryKey != "FPRK-TEST" ||
		s.Admin != "admin" || len(s.URLs) != 2 {
		t.Fatalf("summary %+v", s)
	}
	if e.cfgs[0].HTTPPort != -1 || e.cfgs[0].HTTPSPort != 9443 || !e.inits[0].Sealed || string(e.inits[0].Passphrase) != "pp" {
		t.Fatalf("init %+v %+v", e.cfgs[0], e.inits[0])
	}
	if e.runner.changes() != "" || len(e.health) != 0 {
		t.Fatalf("no service expected: %q %v", e.runner.changes(), e.health)
	}
	joined := strings.Join(s.NextSteps, "\n")
	if !strings.Contains(joined, "serve --home") || !strings.Contains(joined, "starts locked") {
		t.Fatalf("next steps %q", joined)
	}
}

func TestInstallInteractive(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	p := &fakePrompter{interactive: true,
		asks:     []string{e.dir("chosen"), "9443", "0", "bob"},
		confirms: []bool{false /* boot */, false /* generate */, true /* install now */},
		secrets:  []string{"tall granite orbit 47"}}
	e.in.Prompt = p
	must(t, e.in.Install(context.Background(), InstallOptions{NoSymlink: true}))
	if len(e.inits) != 1 || e.inits[0].Admin != "bob" || e.inits[0].AdminPassword != "tall granite orbit 47" ||
		e.cfgs[0].HTTPSPort != 9443 || e.cfgs[0].HTTPPort != -1 {
		t.Fatalf("answers not applied: %+v %+v (questions %q)", e.inits, e.cfgs, p.questions)
	}
	rec, _ := svc.ReadInstalled(mustHome(t, e.dir("chosen")))
	if rec == nil || rec.Boot || rec.LingerEnabledByUs {
		t.Fatalf("record %+v", rec)
	}
	if strings.Contains(e.runner.joined(), "enable-linger") {
		t.Error("linger enabled without boot")
	}
	if !strings.Contains(e.errOut.String(), "FileParcel install plan") {
		t.Error("the plan was not shown before confirming")
	}

	// Declining the confirmation aborts before anything happens.
	e = newEnv(t, "linux", 1000)
	e.in.Prompt = &fakePrompter{interactive: true, confirms: []bool{true, true, false}}
	if err := e.in.Install(context.Background(), InstallOptions{Dir: e.dir("x"), NoSymlink: true}); err == nil ||
		!strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err %v", err)
	}
	if len(e.inits) != 0 {
		t.Fatal("installed despite cancellation")
	}
}

func mustHome(t *testing.T, dir string) *home.Home {
	t.Helper()
	h, err := home.New(dir)
	must(t, err)
	return h
}

func TestInstallValidation(t *testing.T) {
	cases := []struct {
		name  string
		uid   int
		o     func(e *env) InstallOptions
		setup func(e *env)
		want  string
	}{
		{"dangerous dir", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.host.HomeDir} }, nil, "refusing to install"},
		{"root dir", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: "/"} }, nil, "refusing to install"},
		{"bad service", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Service: "cron"} }, nil, "--service"},
		{"system as user", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Service: "system"} }, nil, "needs root"},
		{"user as root", 0, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Service: "user"} }, nil, "cannot be used as root"},
		{"low port", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), HTTPSPort: 443} }, nil, "below 1024"},
		{"same ports", 1000, func(e *env) InstallOptions {
			return InstallOptions{Dir: e.dir("a"), HTTPSPort: 9000, HTTPPort: ptr(9000)}
		}, nil, "must differ"},
		{"busy port", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), HTTPSPort: 8443} }, nil, "already in use"},
		{"bad http port", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), HTTPPort: ptr(70000)} }, nil, "invalid HTTP port"},
		{"bad access", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Access: "world"} }, nil, "access mode"},
		{"bad cidr", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Allow: []string{"nope"}} }, nil, "invalid CIDR"},
		{"bad admin", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Admin: "a b"} }, nil, "invalid admin"},
		{"sealed without passphrase", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Sealed: true} }, nil, "--sealed needs"},
		{"relative symlink", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Symlink: "bin/fp"} }, nil, "absolute"},
		{"symlink inside home", 1000, func(e *env) InstallOptions {
			return InstallOptions{Dir: e.dir("a"), Symlink: filepath.Join(e.dir("a"), "fp")}
		}, nil, "outside the install directory"},
		{"foreign symlink", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Symlink: e.dir("other-link")} },
			func(e *env) { must(e.t, os.Symlink("/usr/bin/true", e.dir("other-link"))) }, "already links to"},
		{"foreign file", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Symlink: e.dir("file")} },
			func(e *env) { must(e.t, os.WriteFile(e.dir("file"), nil, 0o644)) }, "not a symlink"},
		{"upgrade without home", 1000, func(e *env) InstallOptions { return InstallOptions{Dir: e.dir("a"), Upgrade: true} }, nil, "does not contain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, "linux", c.uid)
			if c.setup != nil {
				c.setup(e)
			}
			o := c.o(e)
			o.Yes = true
			err := e.in.Install(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if len(e.inits) != 0 {
				t.Fatal("init ran despite the error")
			}
		})
	}
}

func TestInstallForceReplacesSymlink(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	link := e.dir("fp-link")
	must(t, os.Symlink("/usr/bin/true", link))
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), Yes: true, Service: "none", Symlink: link, Force: true}))
	if st, _ := svc.InspectSymlink(link, filepath.Join(e.dir("fp"), "bin", "fileparcel")); st != svc.SymlinkOurs {
		t.Fatal("symlink not replaced with --force")
	}
}

func TestInstallInitFailure(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	e.in.Hooks.InitHome = func(context.Context, string, provision.ConfigOptions, provision.Options) (*provision.Result, error) {
		return nil, errors.New("weak password")
	}
	err := e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), Yes: true})
	if err == nil || !strings.Contains(err.Error(), "weak password") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(e.runner.joined(), "systemctl") {
		t.Fatal("service registered after a failed init")
	}
}

// ---------- upgrade ----------

// installedHome creates an installed home with a registered, running
// systemd user service and an old binary.
func installedHome(t *testing.T, e *env) *home.Home {
	t.Helper()
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, NoSymlink: true, HTTPSPort: 9443}))
	h := mustHome(t, dir)
	must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755))
	// `systemctl --user link` is faked: create the link it would create.
	reg := filepath.Join(e.host.Paths.UserUnitDir, svc.UnitName)
	must(t, os.MkdirAll(filepath.Dir(reg), 0o755))
	must(t, os.Symlink(filepath.Join(dir, "service", svc.UnitName), reg))
	e.runner.resp["systemctl --user show"] = fakeResp{out: "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n"}
	e.runner.calls = nil
	e.out.Reset()
	e.errOut.Reset()
	e.health = nil
	return h
}

func TestUpgrade(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("new-fileparcel")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))

	// Dry run first: nothing changes.
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true, DryRun: true}))
	e.golden("upgrade-dry-run.txt", e.out.String())
	if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
		t.Fatal("dry run swapped the binary")
	}
	e.out.Reset()

	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true}))
	if b, _ := os.ReadFile(h.Binary()); string(b) != "new binary" {
		t.Fatalf("binary %q", b)
	}
	if b, _ := os.ReadFile(h.PrevBinary()); string(b) != "old binary" {
		t.Fatalf("prev %q", b)
	}
	if len(e.backup) != 1 || e.backup[0].Trigger != core.TriggerPreUpgrade || e.backup[0].Scope != core.BackupMetadata {
		t.Fatalf("backup %+v", e.backup)
	}
	cmds := e.runner.joined()
	stop := strings.Index(cmds, "systemctl --user stop fileparcel.service")
	restart := strings.Index(cmds, "systemctl --user restart fileparcel.service")
	if stop < 0 || restart < stop {
		t.Fatalf("stop/restart order wrong:\n%s", cmds)
	}
	if len(e.health) != 1 || e.health[0] != 9443 {
		t.Fatalf("health %v", e.health)
	}
	if v, _ := os.ReadFile(h.VersionFile()); !strings.HasPrefix(string(v), "v8 def5678") {
		t.Errorf("VERSION %q", v)
	}
	rec, _ := svc.ReadInstalled(h)
	if rec.Version != "v8" || rec.UpgradedAt.IsZero() {
		t.Errorf("record %+v", rec)
	}
	out := e.out.String()
	if !strings.Contains(out, "upgraded from v7 to v8") || !strings.Contains(out, "pre-upgrade backup bkp_1") {
		t.Errorf("summary:\n%s", out)
	}

	// The same binary again: nothing to do.
	e.out.Reset()
	e.in.Executable = h.Binary()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: h.Binary(), Yes: true}))
	if !strings.Contains(e.out.String(), "FileParcel v8 is already installed in "+h.Dir()+"; nothing to upgrade") {
		t.Fatalf("out %q", e.out.String())
	}

	// With --json too (upgrade, and install on the installed home).
	e.in.JSON = true
	e.runner.calls = nil
	for _, run := range []func() error{
		func() error {
			return e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: h.Binary(), Yes: true})
		},
		func() error {
			return e.in.Install(context.Background(), InstallOptions{Dir: h.Dir(), Yes: true, NoSymlink: true})
		},
	} {
		e.out.Reset()
		must(t, run())
		var s Summary
		if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
			t.Fatalf("not JSON (%v): %q", err, e.out.String())
		}
		if s.Action != "upgrade" || !s.Unchanged || s.Version != "v8" || s.PreviousVersion != "v8" || s.Home != h.Dir() ||
			s.Service != svc.KindSystemdUser {
			t.Fatalf("summary %+v", s)
		}
	}
	if strings.Contains(e.runner.joined(), "stop") || strings.Contains(e.runner.joined(), "restart") {
		t.Fatalf("service touched:\n%s", e.runner.joined())
	}
}

func TestUpgradeRollback(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("bad-fileparcel")
	must(t, os.WriteFile(newBin, []byte("bad binary"), 0o755))
	e.healthErrs = []error{errors.New("connection refused")} // new version unhealthy, old one fine
	err := e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
		t.Fatalf("binary after rollback %q", b)
	}
	// VERSION (and docs/, uninstall.sh) must describe the binary in bin/:
	// status, doctor and the next upgrade all read it.
	if v := readVersion(h); v != "v7 abc1234 2026-09-19" {
		t.Errorf("VERSION after rollback = %q, want the old version", v)
	}
	if !strings.Contains(e.runner.joined(), "systemctl --user start fileparcel.service") || len(e.health) != 2 {
		t.Fatalf("restart after rollback missing: %s %v", e.runner.joined(), e.health)
	}

	// Both unhealthy: the message points at the pre-upgrade backup.
	e = newEnv(t, "linux", 1000)
	h = installedHome(t, e)
	must(t, os.WriteFile(newBin, []byte("bad binary"), 0o755))
	e.healthErrs = []error{errors.New("down"), errors.New("still down")}
	err = e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "not healthy either") || !strings.Contains(err.Error(), "bkp_1") {
		t.Fatalf("err %v", err)
	}
}

// A systemd start waits for READY=1: a new version that exits before it
// fails `systemctl restart`, and that is rolled back like a failed health
// check.
func TestUpgradeStartFailureRollsBack(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("bad-fileparcel")
	must(t, os.WriteFile(newBin, []byte("bad binary"), 0o755))
	e.runner.resp["systemctl --user restart"] = fakeResp{code: 1}
	err := e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "rolled back") || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
		t.Fatalf("binary after rollback %q", b)
	}
	if v := readVersion(h); v != "v7 abc1234 2026-09-19" {
		t.Errorf("VERSION %q", v)
	}
	if rec, _ := svc.ReadInstalled(h); rec.Version != "v7" {
		t.Errorf("record %+v", rec)
	}
	cmds := e.runner.joined()
	if restart, start := strings.Index(cmds, "systemctl --user restart"), strings.LastIndex(cmds, "systemctl --user start fileparcel.service"); restart < 0 || start < restart {
		t.Fatalf("no restart of the previous version:\n%s", cmds)
	}
	if len(e.health) != 1 {
		t.Fatalf("health %v", e.health)
	}
}

// Ctrl-C during the health check still rolls back completely: the rollback
// does not run on the cancelled context, so bin/ matches what runs.
func TestUpgradeInterruptedHealthCheck(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("new-fileparcel")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := e.in.HealthWait
	e.in.HealthWait = func(hctx context.Context, h *home.Home, port int, total time.Duration) error {
		if len(e.health) == 0 {
			e.health = append(e.health, port)
			cancel()
			return hctx.Err()
		}
		if hctx.Err() != nil {
			return hctx.Err()
		}
		return wait(hctx, h, port, total)
	}
	err := e.in.Upgrade(ctx, UpgradeOptions{Home: h, Binary: newBin, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "interrupted") || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
		t.Fatalf("binary %q", b)
	}
	cmds := e.runner.joined()
	if !strings.Contains(cmds, "systemctl --user stop fileparcel.service\nsystemctl --user start fileparcel.service") {
		t.Fatalf("rollback commands:\n%s", cmds)
	}
}

// A home made with `init` has no binary to roll back to: a failed health
// check after installing one only warns (the service keeps running), and a
// stale fileparcel.prev is never "restored".
func TestInstallRepairInitHomeUnhealthyNoPrev(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	_, err := e.in.Hooks.InitHome(context.Background(), dir, provision.ConfigOptions{HTTPSPort: 9555}, provision.Options{Admin: "admin"})
	must(t, err)
	h := mustHome(t, dir)
	must(t, os.WriteFile(h.PrevBinary(), []byte("stale"), 0o755))
	e.healthErrs = []error{errors.New("slow first start")}
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, NoSymlink: true}))
	if !strings.Contains(e.out.String(), "no previous binary to roll back to") {
		t.Fatalf("summary:\n%s", e.out.String())
	}
	if strings.Contains(e.runner.joined(), "systemctl --user stop") {
		t.Fatal("service stopped")
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "#!/bin/sh\necho new\n" {
		t.Fatalf("binary %q", b)
	}
	if _, err := os.Stat(h.PrevBinary()); !os.IsNotExist(err) {
		t.Fatal("stale fileparcel.prev kept")
	}
	if rec, _ := svc.ReadInstalled(h); rec == nil || rec.Version != "v8" {
		t.Fatalf("record %+v", rec)
	}
}

// A binary replaced after PrepareRelease verified it is neither run nor
// installed.
func TestUpgradeChecksVerifiedHash(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("new-fileparcel")
	must(t, os.WriteFile(newBin, []byte("swapped payload"), 0o755))
	ran := false
	e.in.BinaryInfo = func(context.Context, string) (buildinfo.Info, error) {
		ran = true
		return buildinfo.Info{Version: "v8"}, nil
	}
	err := e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, BinarySHA256: sum("new binary"), Yes: true})
	if err == nil || !strings.Contains(err.Error(), "changed after it was verified") || ran {
		t.Fatalf("err %v (ran %v)", err, ran)
	}
	// The staged copy is checked too (the file swapped after the first check).
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	if _, err := swapBinary(h, e.dir("new-fileparcel"), sum("other")); err == nil {
		t.Fatal("mismatching copy installed")
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
		t.Fatalf("binary %q", b)
	}
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, BinarySHA256: sum("new binary"), Yes: true}))
	if b, _ := os.ReadFile(h.Binary()); string(b) != "new binary" {
		t.Fatalf("binary %q", b)
	}
}

func TestStagingDir(t *testing.T) {
	h := mustHome(t, t.TempDir())
	must(t, h.EnsureLayout())
	if got := stagingDir(h, os.Geteuid()); got != h.TmpDir("") {
		t.Fatalf("own tmp/: %s", got)
	}
	if os.Geteuid() != 0 {
		// Root with a tmp/ that belongs to the service account.
		if got := stagingDir(h, 0); got != h.BinDir() {
			t.Fatalf("root: %s", got)
		}
	}
	// A shared directory is refused for extraction.
	shared := filepath.Join(t.TempDir(), "shared")
	must(t, os.Mkdir(shared, 0o700))
	must(t, os.Chmod(shared, 0o777))
	if err := checkPrivateDir(shared); err == nil {
		t.Fatal("world-writable directory accepted")
	}
	must(t, os.Chmod(shared, 0o700))
	must(t, checkPrivateDir(shared))
}

func TestUpgradeBackupFailure(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("new")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	e.backupErr = errors.New("disk full")
	err := e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "disk full") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
		t.Fatal("binary swapped after the backup failed")
	}
	// --force continues with a warning.
	e.out.Reset()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true, Force: true}))
	if !strings.Contains(e.out.String(), "pre-upgrade backup failed") {
		t.Fatalf("no warning:\n%s", e.out.String())
	}
	// --skip-backup does not call the hook.
	e.backup = nil
	must(t, os.WriteFile(newBin, []byte("newer binary"), 0o755))
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true, SkipBackup: true}))
	if len(e.backup) != 0 {
		t.Fatal("backup made with SkipBackup")
	}
}

func TestUpgradeRefusesForeignProcess(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true}))
	h := mustHome(t, dir)
	must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755)) // the v7 of VERSION
	unlock, err := h.Lock()
	must(t, err)
	defer unlock()
	newBin := e.dir("new")
	must(t, os.WriteFile(newBin, []byte("new"), 0o755))
	if err := e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true}); err == nil ||
		!strings.Contains(err.Error(), "outside the service manager") {
		t.Fatalf("err %v", err)
	}
}

func TestInstallRepairsExistingHome(t *testing.T) {
	// A home made by `init` (no installed.json): install registers the
	// service and writes the record, without re-initialising.
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	_, err := e.in.Hooks.InitHome(context.Background(), dir, provision.ConfigOptions{HTTPSPort: 9555}, provision.Options{Admin: "admin"})
	must(t, err)
	e.inits = nil
	h := mustHome(t, dir)
	must(t, os.WriteFile(h.Binary(), []byte("#!/bin/sh\necho new\n"), 0o755))
	e.in.Executable = h.Binary()
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, NoSymlink: true}))
	if len(e.inits) != 0 {
		t.Fatal("existing home re-initialised")
	}
	rec, _ := svc.ReadInstalled(h)
	if rec == nil || rec.Kind != svc.KindSystemdUser || rec.HTTPSPort != 9555 {
		t.Fatalf("record %+v", rec)
	}
	if !strings.Contains(e.runner.joined(), "systemctl --user restart fileparcel.service") {
		t.Fatalf("service not started:\n%s", e.runner.joined())
	}
}

// A repair honours --no-start and checks --symlink like a fresh install,
// before anything changes.
func TestInstallRepairOptions(t *testing.T) {
	initHome := func(t *testing.T) (*env, *home.Home) {
		e := newEnv(t, "linux", 1000)
		dir := e.dir("fp")
		_, err := e.in.Hooks.InitHome(context.Background(), dir, provision.ConfigOptions{HTTPSPort: 9555}, provision.Options{Admin: "admin"})
		must(t, err)
		h := mustHome(t, dir)
		must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755))
		return e, h
	}

	t.Run("no start", func(t *testing.T) {
		e, h := initHome(t)
		must(t, e.in.Install(context.Background(), InstallOptions{Dir: h.Dir(), Yes: true, NoSymlink: true, NoStart: true}))
		cmds := e.runner.joined()
		if !strings.Contains(cmds, "systemctl --user enable fileparcel.service") ||
			strings.Contains(cmds, "restart fileparcel.service") || strings.Contains(cmds, "start fileparcel.service") {
			t.Fatalf("commands:\n%s", cmds)
		}
		if len(e.health) != 0 {
			t.Fatalf("health checked: %v", e.health)
		}
		if rec, _ := svc.ReadInstalled(h); rec == nil || rec.Kind != svc.KindSystemdUser {
			t.Fatalf("record %+v", rec)
		}
		if out := e.out.String(); !strings.Contains(out, "systemd user service, registered") || !strings.Contains(out, "fileparcel service start") {
			t.Fatalf("summary:\n%s", out)
		}
	})

	for _, c := range []struct {
		name  string
		o     func(e *env, h *home.Home) InstallOptions
		setup func(e *env)
		want  string
	}{
		{"relative symlink", func(e *env, h *home.Home) InstallOptions { return InstallOptions{Symlink: "bin/fp"} }, nil, "absolute"},
		{"symlink inside home", func(e *env, h *home.Home) InstallOptions { return InstallOptions{Symlink: h.Binary(), Force: true} },
			nil, "outside the install directory"},
		{"foreign file", func(e *env, h *home.Home) InstallOptions { return InstallOptions{Symlink: e.dir("file")} },
			func(e *env) { must(e.t, os.WriteFile(e.dir("file"), nil, 0o644)) }, "not a symlink"},
		{"other link", func(e *env, h *home.Home) InstallOptions { return InstallOptions{Symlink: e.dir("other-link")} },
			func(e *env) { must(e.t, os.Symlink("/usr/bin/true", e.dir("other-link"))) }, "already links to"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, h := initHome(t)
			if c.setup != nil {
				c.setup(e)
			}
			o := c.o(e, h)
			o.Dir, o.Yes = h.Dir(), true
			err := e.in.Install(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if fi, err := os.Lstat(h.Binary()); err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("binary: %v %v", fi, err)
			}
			if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
				t.Fatalf("binary swapped: %q", b)
			}
			if _, err := os.Lstat("bin/fp"); !os.IsNotExist(err) {
				t.Fatal("link created in the working directory")
			}
			if e.runner.changes() != "" {
				t.Fatalf("commands run:\n%s", e.runner.changes())
			}
			if rec, _ := svc.ReadInstalled(h); rec != nil {
				t.Fatalf("record written: %+v", rec)
			}
		})
	}
}

// `uninstall --keep-data` followed by install.sh --dir (the documented
// reinstall, also after moving the home) registers the service and the
// command link again, whether or not the binary changed.
func TestInstallAfterUninstallKeepData(t *testing.T) {
	for _, sameBinary := range []bool{false, true} {
		t.Run(fmt.Sprint("same binary ", sameBinary), func(t *testing.T) {
			e := newEnv(t, "linux", 1000)
			dir := e.dir("fp")
			must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true}))
			h := mustHome(t, dir)
			link := filepath.Join(e.host.HomeDir, ".local", "bin", "fileparcel")
			must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
			before, _ := svc.ReadInstalled(h)
			if _, err := os.Lstat(link); !os.IsNotExist(err) {
				t.Fatal("link not removed")
			}
			if sameBinary {
				e.in.Executable = h.Binary()
			} else {
				must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755))
			}
			e.runner.calls = nil
			e.out.Reset()
			must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true}))
			if strings.Contains(e.out.String(), "nothing to upgrade") {
				t.Fatalf("not repaired:\n%s", e.out.String())
			}
			if !strings.Contains(e.runner.joined(), "systemctl --user restart fileparcel.service") {
				t.Fatalf("service not registered:\n%s", e.runner.joined())
			}
			if st, _ := svc.InspectSymlink(link, h.Binary()); st != svc.SymlinkOurs {
				t.Fatal("command link not restored")
			}
			rec, _ := svc.ReadInstalled(h)
			if rec.Kind != svc.KindSystemdUser || !rec.Boot || rec.Symlink != link || rec.Incomplete ||
				!rec.InstalledAt.Equal(before.InstalledAt) || strings.Join(rec.FirewallSubnets, ",") != "192.168.1.0/24" {
				t.Fatalf("record %+v", rec)
			}
		})
	}

	// A moved home (its record names the old directory) is repaired too.
	e := newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("old"), Yes: true, NoSymlink: true}))
	must(t, os.Rename(e.dir("old"), e.dir("new")))
	h := mustHome(t, e.dir("new"))
	e.in.Executable = h.Binary()
	e.runner.calls = nil
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("new"), Yes: true, NoSymlink: true}))
	if rec, _ := svc.ReadInstalled(h); rec.Home != e.dir("new") || !strings.Contains(e.runner.joined(), "systemctl --user link "+e.dir("new")) {
		t.Fatalf("moved home not repaired: %+v\n%s", rec, e.runner.joined())
	}

	// A deliberate --service none install stays without a service.
	e = newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), Yes: true, Service: "none", NoSymlink: true}))
	e.in.Executable = mustHome(t, e.dir("fp")).Binary()
	e.out.Reset()
	e.runner.calls = nil
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), Yes: true}))
	if !strings.Contains(e.out.String(), "nothing to upgrade") || e.runner.changes() != "" {
		t.Fatalf("service none repaired:\n%s\n%s", e.out.String(), e.runner.changes())
	}
}

// An install that fails after the home was initialised still shows the
// credentials (they exist only in this run) and records the home as
// incomplete, with the linger it enabled; the rerun finishes it.
func TestInstallFailureAfterInitShowsCredentials(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	e.runner.resp["systemctl --user daemon-reload"] = fakeResp{code: 1}
	e.runner.onRun = func(line string) {
		if line == "loginctl enable-linger alice" {
			must(t, os.MkdirAll(e.host.Paths.LingerDir, 0o755))
			must(t, os.WriteFile(filepath.Join(e.host.Paths.LingerDir, "alice"), nil, 0o644))
		}
	}
	err := e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, NoSymlink: true})
	if err == nil {
		t.Fatal("no error")
	}
	out := e.out.String()
	for _, want := range []string{"installation did not finish", "gen-erated-pass-word", "AGE-SECRET-KEY-1TEST", "run the installer again"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	h := mustHome(t, dir)
	rec, _ := svc.ReadInstalled(h)
	if rec == nil || !rec.Incomplete || !rec.LingerEnabledByUs {
		t.Fatalf("record %+v", rec)
	}

	delete(e.runner.resp, "systemctl --user daemon-reload")
	e.runner.calls = nil
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, NoSymlink: true}))
	if !strings.Contains(e.runner.joined(), "systemctl --user restart fileparcel.service") {
		t.Fatalf("not finished:\n%s", e.runner.joined())
	}
	if rec, _ := svc.ReadInstalled(h); rec.Incomplete || !rec.LingerEnabledByUs || rec.Kind != svc.KindSystemdUser {
		t.Fatalf("record %+v", rec)
	}
}

// A system install whose initialisation fails removes the service account it
// created (a rerun would not know it created it).
func TestInstallInitFailureRemovesCreatedAccount(t *testing.T) {
	e := newEnv(t, "linux", 0)
	var removed []string
	e.in.removeUser = func(ctx context.Context, h *svc.Host, name string) error {
		removed = append(removed, name)
		return nil
	}
	e.in.Hooks.InitHome = func(context.Context, string, provision.ConfigOptions, provision.Options) (*provision.Result, error) {
		return nil, errors.New("admin password: too short")
	}
	err := e.in.Install(context.Background(), InstallOptions{Dir: e.dir("opt"), Yes: true, NoSymlink: true, HTTPSPort: 9443})
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(e.runner.joined(), "useradd") {
		t.Skipf("the account %s exists on this machine", svc.DefaultSystemUser)
	}
	if strings.Join(removed, ",") != svc.DefaultSystemUser {
		t.Fatalf("removed %v", removed)
	}
}

// Repairing a home as a system install creates the service account and gives
// it the home, like a fresh system install.
func TestInstallRepairSystemHome(t *testing.T) {
	e := newEnv(t, "linux", 0)
	dir := e.dir("opt")
	_, err := e.in.Hooks.InitHome(context.Background(), dir, provision.ConfigOptions{HTTPSPort: 9443}, provision.Options{Admin: "admin"})
	must(t, err)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, NoSymlink: true, DryRun: true}))
	out := e.out.String()
	account := strings.Index(out, "Create the service account fileparcel")
	chown := strings.Index(out, "Give "+dir+" to fileparcel (bin/ stays owned by root)")
	register := strings.Index(out, "Register the systemd system service")
	if account < 0 || chown < account || register < chown {
		t.Fatalf("plan:\n%s", out)
	}
}

// installed.json rewritten by root (upgrade, keep-data uninstall) goes back
// to the service account, which must keep reading it; the account is the
// host's, never the name in the record.
func TestRecordOwnership(t *testing.T) {
	e := newEnv(t, "linux", 0)
	dir := e.dir("opt")
	_, err := e.in.Hooks.InitHome(context.Background(), dir, provision.ConfigOptions{HTTPSPort: 9443}, provision.Options{Admin: "admin"})
	must(t, err)
	h := mustHome(t, dir)
	must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755))
	// A system home after `uninstall --keep-data` (no service to manage), its
	// service_user rewritten by the account.
	must(t, svc.WriteInstalled(h, &svc.Installed{Kind: svc.KindNone, Home: dir, ServiceUser: "mallory", Version: "v7"}))
	var chowned []string
	e.in.chown = func(p, account string) error {
		chowned = append(chowned, p+" "+account)
		return nil
	}
	want := svc.InstalledPath(h) + " " + svc.DefaultSystemUser

	newBin := e.dir("new")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true, SkipBackup: true}))
	if strings.Join(chowned, "|") != want {
		t.Fatalf("upgrade chowned %q, want %q", chowned, want)
	}
	if fi, _ := os.Stat(svc.InstalledPath(h)); fi.Mode().Perm() != 0o640 {
		t.Errorf("record mode %v", fi.Mode())
	}

	chowned = nil
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	if strings.Join(chowned, "|") != want {
		t.Fatalf("keep-data uninstall chowned %q, want %q", chowned, want)
	}

	// Not as another user, and not for a record without a service account.
	chowned = nil
	e.host.UID = 1000
	must(t, e.in.writeRecord(h, &svc.Installed{Kind: svc.KindNone, Home: dir, ServiceUser: "fileparcel"}))
	e.host.UID = 0
	must(t, e.in.writeRecord(h, &svc.Installed{Kind: svc.KindNone, Home: dir}))
	if len(chowned) != 0 {
		t.Fatalf("chowned %q", chowned)
	}
}

// ---------- uninstall ----------

func TestUninstallKeepData(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true}))
	h := mustHome(t, dir)
	reg := filepath.Join(e.host.Paths.UserUnitDir, svc.UnitName)
	must(t, os.MkdirAll(filepath.Dir(reg), 0o755))
	must(t, os.Symlink(filepath.Join(dir, "service", svc.UnitName), reg))
	// linger "enabled" (by us, per the record) and no other user units.
	must(t, os.MkdirAll(e.host.Paths.LingerDir, 0o755))
	must(t, os.WriteFile(filepath.Join(e.host.Paths.LingerDir, "alice"), nil, 0o644))
	e.runner.calls = nil
	e.out.Reset()

	// Without -y and without a terminal: refused.
	if err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h}); err == nil ||
		!strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("err %v", err)
	}
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true, FinalBackup: true, BackupTo: e.dir("final")}))
	cmds := e.runner.joined()
	for _, want := range []string{"systemctl --user stop fileparcel.service", "systemctl --user disable fileparcel.service",
		"loginctl disable-linger alice"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("missing %q in\n%s", want, cmds)
		}
	}
	if _, err := os.Lstat(reg); !os.IsNotExist(err) {
		t.Error("registration link not removed")
	}
	if _, err := os.Lstat(filepath.Join(e.host.HomeDir, ".local", "bin", "fileparcel")); !os.IsNotExist(err) {
		t.Error("command link not removed")
	}
	if !h.Exists() {
		t.Fatal("keep-data removed the home")
	}
	rec, _ := svc.ReadInstalled(h)
	if rec.Kind != svc.KindNone || rec.Symlink != "" || rec.LingerEnabledByUs || !rec.Incomplete {
		t.Fatalf("record %+v", rec)
	}
	// The server only makes the backup; the uninstaller copies it (into a
	// directory it creates), so a sandboxed system service needs no write
	// access outside HOME.
	if len(e.backup) != 1 || e.backup[0].Trigger != core.TriggerFinal || e.backup[0].Scope != core.BackupFull ||
		e.backup[0].CopyTo != "" {
		t.Fatalf("final backup %+v", e.backup)
	}
	copied := filepath.Join(e.dir("final"), "fp-20260919.fpbak")
	if b, err := os.ReadFile(copied); err != nil || string(b) != "encrypted archive final" {
		t.Fatalf("copy %q %v", b, err)
	}
	if fi, _ := os.Stat(copied); fi.Mode().Perm() != 0o600 {
		t.Errorf("copy mode %v", fi.Mode())
	}
	out := e.out.String()
	if !strings.Contains(out, "uninstalled from") || !strings.Contains(out, "copied to "+copied) {
		t.Errorf("summary:\n%s", out)
	}
}

// A final backup that cannot be copied to --backup-to stops the uninstall
// before anything is removed (the backup would otherwise be deleted with
// the home by --purge).
func TestUninstallPurgeStopsWhenFinalCopyFails(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(e *env) string // returns BackupTo
	}{
		{"unwritable target", func(e *env) string {
			must(t, os.WriteFile(e.dir("file"), nil, 0o644))
			return filepath.Join(e.dir("file"), "final") // below a regular file: cannot be created
		}},
		{"archive missing", func(e *env) string {
			e.backupNoFile = true
			return e.dir("final")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, "linux", 1000)
			h := installedHome(t, e)
			keys, _ := os.ReadFile(h.KeysFile())
			to := c.setup(e)
			err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true, Purge: true, BackupTo: to})
			if err == nil || !strings.Contains(err.Error(), "could not be copied") || !strings.Contains(err.Error(), "nothing was removed") {
				t.Fatalf("err %v", err)
			}
			if !h.Exists() {
				t.Fatal("home deleted although the final backup was not copied")
			}
			if b, _ := os.ReadFile(h.KeysFile()); !bytes.Equal(b, keys) {
				t.Fatal("keys overwritten although the final backup was not copied")
			}
			if cmds := e.runner.joined(); strings.Contains(cmds, "stop") || strings.Contains(cmds, "disable") {
				t.Fatalf("service touched:\n%s", cmds)
			}
		})
	}
}

// --final-backup --purge needs --backup-to (the backup would stay in
// <HOME>/backups and be deleted with it); a hook that returns no backup
// stops the uninstall.
func TestUninstallFinalBackupGuards(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true}))
	h := mustHome(t, dir)
	for _, dry := range []bool{true, false} {
		err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true, Purge: true, FinalBackup: true, DryRun: dry})
		if err == nil || !strings.Contains(err.Error(), "--backup-to") {
			t.Fatalf("dry %v: err %v", dry, err)
		}
	}
	if len(e.backup) != 0 || !h.Exists() {
		t.Fatal("something ran")
	}
	// --backup-to naming a file is refused before the plan.
	must(t, os.WriteFile(e.dir("file"), nil, 0o644))
	if err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true, BackupTo: e.dir("file")}); err == nil ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("err %v", err)
	}
	e.in.Hooks.Backup = func(context.Context, *home.Home, core.BackupInput) (*core.Backup, error) { return nil, nil }
	if err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true, Purge: true, BackupTo: e.dir("final")}); err == nil ||
		!strings.Contains(err.Error(), "not created") {
		t.Fatalf("err %v", err)
	}
	if !h.Exists() {
		t.Fatal("home deleted without a final backup")
	}
	// Without --purge the backup may stay in the home.
	e = newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir + "2", Yes: true, Service: "none", NoSymlink: true}))
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: mustHome(t, dir+"2"), Yes: true, FinalBackup: true}))
	if !strings.Contains(e.out.String(), "final backup bkp_1") {
		t.Fatalf("summary:\n%s", e.out.String())
	}
}

func TestUninstallLingerKeptForOtherUnits(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, NoSymlink: true}))
	must(t, os.MkdirAll(e.host.Paths.LingerDir, 0o755))
	must(t, os.WriteFile(filepath.Join(e.host.Paths.LingerDir, "alice"), nil, 0o644))
	wants := filepath.Join(e.host.Paths.UserUnitDir, "default.target.wants")
	must(t, os.MkdirAll(wants, 0o755))
	must(t, os.Symlink("/x/syncthing.service", filepath.Join(wants, "syncthing.service")))
	e.runner.calls = nil
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: mustHome(t, dir), Yes: true}))
	if strings.Contains(e.runner.joined(), "disable-linger") {
		t.Fatal("linger disabled although another user unit needs it")
	}
	if !strings.Contains(e.out.String(), "linger stays enabled") {
		t.Errorf("no warning:\n%s", e.out.String())
	}
}

func TestUninstallPurge(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true}))
	h := mustHome(t, dir)

	// Dry run keeps everything.
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Purge: true, DryRun: true}))
	if !h.Exists() || !strings.Contains(e.out.String(), "DELETED (keys overwritten first)") {
		t.Fatalf("dry run:\n%s", e.out.String())
	}

	// A process holding the lock blocks the purge before anything changes
	// (the dry run says so), and nothing is deleted.
	unlock, err := h.Lock()
	must(t, err)
	e.out.Reset()
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Purge: true, DryRun: true}))
	if !strings.Contains(e.out.String(), "Blocked: a FileParcel process that is not the service uses the home") {
		t.Fatalf("dry run while in use:\n%s", e.out.String())
	}
	if err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Purge: true, Yes: true}); err == nil ||
		!strings.Contains(err.Error(), "nothing was removed") {
		t.Fatalf("err %v", err)
	}
	unlock()
	if b, _ := os.ReadFile(h.KeysFile()); string(b) != `{"mode":"plain"}` {
		t.Fatal("keys touched although the purge was refused")
	}

	// Interactive purge requires typing the directory name.
	e.in.Prompt = &fakePrompter{interactive: true, confirms: []bool{true}, asks: []string{"wrong"}}
	if err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Purge: true}); err == nil ||
		!strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err %v", err)
	}
	e.in.Prompt = &fakePrompter{interactive: true, confirms: []bool{true}, asks: []string{"fp"}}
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Purge: true}))
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("home not deleted")
	}
}

func TestUninstallGuards(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	if err := e.in.Uninstall(context.Background(), UninstallOptions{Home: mustHome(t, e.dir("none")), Yes: true}); err == nil {
		t.Fatal("uninstall of a non-home accepted")
	}
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true}))
	if err := e.in.Uninstall(context.Background(), UninstallOptions{Home: mustHome(t, dir), Yes: true,
		BackupTo: filepath.Join(dir, "backups")}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("backup inside home accepted: %v", err)
	}
}

// A user service cannot be managed as root (sudo uninstall.sh on a per-user
// install): nothing is changed rather than recording "no service" while the
// unit stays registered and running.
func TestUninstallRefusesUnmanageableService(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true}))
	h := mustHome(t, dir)
	reg := filepath.Join(e.host.Paths.UserUnitDir, svc.UnitName)
	must(t, os.MkdirAll(filepath.Dir(reg), 0o755))
	must(t, os.Symlink(filepath.Join(dir, "service", svc.UnitName), reg))
	link := filepath.Join(e.host.HomeDir, ".local", "bin", "fileparcel")
	e.host.UID, e.host.User = 0, "root"
	e.runner.calls = nil
	err := e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "cannot manage") || !strings.Contains(err.Error(), "without sudo") {
		t.Fatalf("err %v", err)
	}
	if e.runner.joined() != "" {
		t.Fatalf("commands ran: %s", e.runner.joined())
	}
	rec, _ := svc.ReadInstalled(h)
	if rec.Kind != svc.KindSystemdUser || rec.Symlink != link || !rec.LingerEnabledByUs {
		t.Fatalf("record changed: %+v", rec)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("command link removed")
	}

	// A kind that cannot exist on this system (a home copied from a Mac)
	// is only warned about.
	rec.Kind = svc.KindLaunchdAgent
	must(t, svc.WriteInstalled(h, rec))
	e.host.UID, e.host.User = 1000, "alice"
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	if !strings.Contains(e.errOut.String(), "cannot manage the launchd agent") {
		t.Fatalf("no warning:\n%s", e.errOut.String())
	}
}

// Access mode any: the install records that the ports were opened to every
// source, so uninstall lists the removal of that rule too.
func TestUninstallFirewallAnywhere(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	init := e.in.Hooks.InitHome
	e.in.Hooks.InitHome = func(ctx context.Context, dir string, c provision.ConfigOptions, o provision.Options) (*provision.Result, error) {
		res, err := init(ctx, dir, c, o)
		if res != nil && o.Access != "" {
			res.AccessMode = o.Access
		}
		return res, err
	}
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true,
		HTTPSPort: 9443, HTTPPort: ptr(9080), Access: core.AccessAny}))
	h := mustHome(t, dir)
	rec, _ := svc.ReadInstalled(h)
	if rec == nil || !rec.FirewallAnywhere {
		t.Fatalf("record %+v", rec)
	}
	// firewalld is present (a probe answers), so removal commands are printed.
	e.host.LookPath = func(n string) (string, error) { return "/usr/bin/" + n, nil }
	e.runner.resp["firewall-cmd --state"] = fakeResp{out: "running\n"}
	e.out.Reset()
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	if out := e.out.String(); !strings.Contains(out, "firewall-cmd --permanent --remove-port=9443/tcp") ||
		!strings.Contains(out, "--remove-port=9080/tcp") {
		t.Fatalf("no removal of the open-to-everyone rule:\n%s", out)
	}

	// The default allowlist install does not record it.
	e = newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir + "2", Yes: true, Service: "none", NoSymlink: true}))
	if rec, _ := svc.ReadInstalled(mustHome(t, dir+"2")); rec == nil || rec.FirewallAnywhere {
		t.Fatalf("record %+v", rec)
	}
}

func TestShredKeys(t *testing.T) {
	h := mustHome(t, t.TempDir())
	must(t, h.EnsureLayout())
	secret := bytes.Repeat([]byte("K"), 100)
	// The live keys, the copies a restore keeps in pre-restore-<ts>/, the
	// staging a crashed restore or deep verify left behind, and the key of
	// a pending restore.
	files := []string{h.KeysFile(), filepath.Join(h.CertsDir(), "server", "leaf.key"),
		filepath.Join(h.CertsDir(), "tailscale", "key.pem"),
		h.Path("pre-restore-20260901-120000", "keys", "master.key"),
		h.Path("pre-restore-20260901-120000", "certs", "ca", "ca.key.enc"),
		filepath.Join(h.TmpDir(home.TmpRestore), "restore-1", "keys", "master.key"),
		filepath.Join(h.TmpDir(home.TmpVerify), "verify-1", "certs", "server", "leaf.key"),
		filepath.Join(h.RunDir(), "restore.key")}
	for _, p := range files {
		must(t, os.MkdirAll(filepath.Dir(p), 0o700))
		must(t, os.WriteFile(p, secret, 0o600))
	}
	// Not key material: left alone (a database is not rewritten).
	db := h.Path("pre-restore-20260901-120000", "data", "fileparcel.db")
	must(t, os.MkdirAll(filepath.Dir(db), 0o700))
	must(t, os.WriteFile(db, secret, 0o600))
	// A pre-restore entry that is a symlink out of the home is not followed.
	outside := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(outside, "keys"), 0o700))
	must(t, os.WriteFile(filepath.Join(outside, "keys", "master.key"), secret, 0o600))
	must(t, os.Symlink(outside, h.Path("pre-restore-evil")))

	must(t, shredKeys(h))
	for _, p := range files {
		b, _ := os.ReadFile(p)
		if len(b) != 100 || bytes.Equal(b, secret) {
			t.Errorf("%s not overwritten", p)
		}
	}
	for _, p := range []string{db, filepath.Join(outside, "keys", "master.key")} {
		if b, _ := os.ReadFile(p); !bytes.Equal(b, secret) {
			t.Errorf("%s overwritten", p)
		}
	}
}

// ---------- releases ----------

func makeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	must(t, err)
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		must(t, err)
		_, err = w.Write([]byte(content))
		must(t, err)
	}
	must(t, zw.Close())
	must(t, f.Close())
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestPrepareReleaseZip(t *testing.T) {
	dir := t.TempDir()
	bin := "binary for linux amd64"
	good := filepath.Join(dir, "fileparcel-v9.zip")
	makeZip(t, good, map[string]string{
		"fileparcel-v9/bin/fileparcel-linux-amd64":  bin,
		"fileparcel-v9/bin/fileparcel-darwin-arm64": "mac",
		"fileparcel-v9/SHA256SUMS":                  fmt.Sprintf("%s  bin/fileparcel-linux-amd64\n%s *bin/fileparcel-darwin-arm64\n", sum(bin), sum("mac")),
		"fileparcel-v9/uninstall.sh":                "#!/bin/sh\n",
		"fileparcel-v9/docs/FILEPARCEL.md":          "# doc\n",
		"fileparcel-v9/docs/../../evil":             "x",
		"fileparcel-v9/src/main.go":                 "package main",
	})
	rel, err := PrepareRelease(good, filepath.Join(dir, "tmp"), "linux", "amd64", false)
	must(t, err)
	if !rel.Verified {
		t.Fatal("not verified")
	}
	if b, _ := os.ReadFile(rel.Binary); string(b) != bin {
		t.Fatalf("binary %q", b)
	}
	if fi, _ := os.Stat(rel.Binary); fi.Mode().Perm()&0o100 == 0 {
		t.Error("binary not executable")
	}
	sf := FindSupportFiles(rel.SourceDir)
	if sf.Uninstall == "" || sf.Docs == "" {
		t.Fatalf("support files %+v", sf)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); !os.IsNotExist(err) {
		t.Fatal("zip traversal entry extracted")
	}
	if _, err := os.Stat(filepath.Join(rel.SourceDir, "src")); !os.IsNotExist(err) {
		t.Error("unneeded entries extracted")
	}
	src := rel.SourceDir
	rel.Close()
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("Close left the extraction behind")
	}

	for name, files := range map[string]map[string]string{
		"mismatch": {"r/bin/fileparcel-linux-amd64": bin, "r/SHA256SUMS": sum("other") + "  bin/fileparcel-linux-amd64\n"},
		"no sums":  {"r/bin/fileparcel-linux-amd64": bin},
		"no entry": {"r/bin/fileparcel-linux-amd64": bin, "r/SHA256SUMS": sum("mac") + "  bin/fileparcel-darwin-arm64\n"},
		"platform": {"r/bin/fileparcel-darwin-arm64": "mac", "r/SHA256SUMS": sum("mac") + "  bin/fileparcel-darwin-arm64\n"},
	} {
		p := filepath.Join(dir, name+".zip")
		makeZip(t, p, files)
		if _, err := PrepareRelease(p, filepath.Join(dir, "tmp"), "linux", "amd64", true); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(dir, "tmp")); len(left) != 0 {
		t.Errorf("failed extractions left %d entries", len(left))
	}
}

func TestPrepareReleaseBinary(t *testing.T) {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	bin := filepath.Join(dir, "bin", "fileparcel-linux-amd64")
	must(t, os.WriteFile(bin, []byte("ELF"), 0o755))

	if _, err := PrepareRelease(bin, t.TempDir(), "linux", "amd64", false); err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("unverified accepted: %v", err)
	}
	rel, err := PrepareRelease(bin, t.TempDir(), "linux", "amd64", true)
	if err != nil || rel.Verified {
		t.Fatalf("allowUnverified: %+v %v", rel, err)
	}
	// SHA256SUMS one directory up (release layout).
	must(t, os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sum("ELF")+"  bin/fileparcel-linux-amd64\n"), 0o644))
	rel, err = PrepareRelease(bin, t.TempDir(), "linux", "amd64", false)
	// No SourceDir: the support files are looked up around the binary by
	// releaseFiles, which verifies them.
	if err != nil || !rel.Verified || rel.Binary != bin || rel.SourceDir != "" {
		t.Fatalf("%+v %v", rel, err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sum("tampered")+"  bin/fileparcel-linux-amd64\n"), 0o644))
	if _, err := PrepareRelease(bin, t.TempDir(), "linux", "amd64", true); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered binary accepted: %v", err)
	}
}

// uninstall.sh and docs/ come only from a named source or from the release
// whose SHA256SUMS lists the binary and uninstall.sh; never from whatever
// lies next to a bare binary (~/Downloads, a shared /tmp).
func TestSupportFilesDiscovery(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	release := e.dir("release")
	want := SupportFiles{Uninstall: filepath.Join(release, "uninstall.sh"), Docs: filepath.Join(release, "docs")}
	if sf := e.in.supportFiles(e.exe, ""); sf != want {
		t.Fatalf("release layout: %+v", sf)
	}

	// A binary in a plain directory, a foreign uninstall.sh beside it and a
	// personal docs/ one level up.
	dl := e.dir("home/alice/Downloads")
	must(t, os.MkdirAll(dl, 0o755))
	must(t, os.WriteFile(filepath.Join(dl, "fileparcel"), []byte("bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(dl, "uninstall.sh"), []byte("#!/bin/sh\nrm -rf ~\n"), 0o755))
	must(t, os.MkdirAll(e.dir("home/alice/docs"), 0o755))
	if sf := e.in.supportFiles(filepath.Join(dl, "fileparcel"), ""); sf != (SupportFiles{}) {
		t.Fatalf("plain directory: %+v", sf)
	}
	// A SHA256SUMS there that does not list the binary is another one's.
	must(t, os.WriteFile(filepath.Join(dl, "SHA256SUMS"), []byte(sum("#!/bin/sh\nrm -rf ~\n")+"  uninstall.sh\n"), 0o644))
	if sf := e.in.supportFiles(filepath.Join(dl, "fileparcel"), ""); sf != (SupportFiles{}) {
		t.Fatalf("unrelated SHA256SUMS: %+v", sf)
	}

	// $FILEPARCEL_INSTALL_SOURCE (and --source) is taken as it is, but
	// alone: a source without docs/ does not fall through to the release.
	src := e.dir("src")
	must(t, os.MkdirAll(src, 0o755))
	must(t, os.WriteFile(filepath.Join(src, "uninstall.sh"), []byte("#!/bin/sh\n# checkout\n"), 0o755))
	getenv := e.host.Getenv
	e.host.Getenv = func(k string) string {
		if k == SourceEnv {
			return src
		}
		return getenv(k)
	}
	if sf := e.in.supportFiles(e.exe, ""); sf != (SupportFiles{Uninstall: filepath.Join(src, "uninstall.sh")}) {
		t.Fatalf("env source: %+v", sf)
	}
	if sf := e.in.supportFiles(e.exe, release); sf != want {
		t.Fatalf("explicit source: %+v", sf)
	}
	e.host.Getenv = getenv

	// A tampered or symlinked uninstall.sh in the release is not taken.
	must(t, os.WriteFile(filepath.Join(release, "uninstall.sh"), []byte("#!/bin/sh\n# tampered\n"), 0o755))
	if sf := e.in.supportFiles(e.exe, ""); sf != (SupportFiles{}) || !strings.Contains(e.errOut.String(), "does not match") {
		t.Fatalf("tampered: %+v\n%s", sf, e.errOut.String())
	}
	must(t, os.WriteFile(e.dir("real-uninstall.sh"), []byte("#!/bin/sh\n"), 0o755))
	must(t, os.Remove(filepath.Join(release, "uninstall.sh")))
	must(t, os.Symlink(e.dir("real-uninstall.sh"), filepath.Join(release, "uninstall.sh")))
	if sf := e.in.supportFiles(e.exe, ""); sf != (SupportFiles{}) {
		t.Fatalf("symlink: %+v", sf)
	}
}

// Upgrading to an unverified bare binary (--force) leaves uninstall.sh and
// docs/ alone instead of taking what lies next to the binary.
func TestUpgradeBareBinaryKeepsSupportFiles(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	// From a verified release the plan names the files it takes.
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: e.exe, Yes: true, DryRun: true}))
	if out := e.out.String(); !strings.Contains(out, "Update VERSION, uninstall.sh and docs/") ||
		!strings.Contains(out, filepath.Join(e.dir("release"), "uninstall.sh")+" -> "+h.UninstallScript()) {
		t.Fatalf("plan:\n%s", out)
	}
	e.out.Reset()

	dl := e.dir("dl")
	must(t, os.MkdirAll(filepath.Join(dl, "bin"), 0o755))
	must(t, os.MkdirAll(filepath.Join(dl, "docs"), 0o755))
	bin := filepath.Join(dl, "bin", "fileparcel-linux-amd64")
	must(t, os.WriteFile(bin, []byte("new binary"), 0o755))
	must(t, os.WriteFile(filepath.Join(dl, "uninstall.sh"), []byte("#!/bin/sh\n# foreign\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(dl, "docs", "FILEPARCEL.md"), []byte("personal"), 0o644))
	rel, err := PrepareRelease(bin, t.TempDir(), "linux", "amd64", true)
	must(t, err)
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: rel.Binary, BinarySHA256: rel.SHA256,
		SourceDir: rel.SourceDir, Yes: true}))
	if b, _ := os.ReadFile(h.Binary()); string(b) != "new binary" {
		t.Fatalf("binary %q", b)
	}
	if b, _ := os.ReadFile(h.UninstallScript()); string(b) != "#!/bin/sh\n" {
		t.Fatalf("uninstall.sh %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(h.DocsDir(), "FILEPARCEL.md")); string(b) != "# manual\n" {
		t.Fatalf("docs %q", b)
	}
	if rec, _ := svc.ReadInstalled(h); rec.Version != "v8" {
		t.Fatalf("record %+v", rec)
	}
}

func TestParseSums(t *testing.T) {
	s := parseSums(strings.NewReader(sum("a") + "  ./x\n" + sum("b") + " *y\nbad line\n" + strings.Repeat("z", 64) + "  w\n"))
	if s["x"] != sum("a") || s["y"] != sum("b") || len(s) != 2 {
		t.Fatalf("%v", s)
	}
}

// ---------- summary helpers ----------

func TestSummaryHelpers(t *testing.T) {
	urls := []core.AccessURL{
		{URL: "https://192.168.1.10:8443/", Kind: core.URLKindIP, Recommended: true},
		{URL: "https://box.local:8443/", Kind: core.URLKindMDNS, Recommended: true},
	}
	if got := trustURL(urls); got != "https://box.local:8443/trust" {
		t.Fatal(got)
	}
	if got := trustURL(urls[:1]); got != "https://192.168.1.10:8443/trust" {
		t.Fatal(got)
	}
	if trustURL(nil) != "" {
		t.Fatal("trust URL without URLs")
	}
	if tailscaleHints(nil, "a") != nil || tailscaleHints(&core.TailscaleInfo{Running: true, DNSName: "x", Kind: core.IfHeadscale}, "a") != nil {
		t.Fatal("hints for headscale")
	}
	if h := tailscaleHints(&core.TailscaleInfo{Running: true, DNSName: "x.ts.net", CertCapable: true}, "a"); len(h) != 2 ||
		!strings.Contains(h[0], "cert tailscale enable") || h[1] != "Share links on the internet: fileparcel network funnel enable" {
		t.Fatal(h)
	}
	if h := tailscaleHints(&core.TailscaleInfo{Running: true, DNSName: "x.ts.net"}, "a"); len(h) != 4 ||
		!strings.Contains(h[1], "--operator=a") || h[3] != "Share links on the internet: fileparcel network funnel enable" {
		t.Fatal(h)
	}
	res := &provision.Result{AccessMode: core.AccessAny, AllowCIDRs: []string{"192.168.1.0/24", "10.8.0.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		Interfaces: []core.NetInterface{
			{Name: "wg0", Kind: core.IfWireGuard, Up: true, IsVPN: true, Role: core.VPNRoleUnknown, Addrs: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")}},
			{Name: "tailscale0", Kind: core.IfHeadscale, Up: true, IsVPN: true, Role: core.VPNRoleMesh, Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}},
			{Name: "docker0", Kind: core.IfContainer, Up: true},
			{Name: "down0", Kind: core.IfVPN, Up: false},
			// outgoing only: no rule (DESIGN §10.1)
			{Name: "wg0-mullvad", Kind: core.IfExitVPN, Up: true, IsVPN: true, Role: core.VPNRoleEgress, Addrs: []netip.Prefix{netip.MustParsePrefix("10.64.1.2/32")}},
			{Name: "cscotun0", Kind: core.IfCorpVPN, Up: true, IsVPN: true, Role: core.VPNRoleAccess},
		}}
	in := firewallInput(res, 8443, 8080, "/b")
	if !in.Anywhere || len(in.Subnets) != 2 || in.Subnets[0].String() != "192.168.1.0/24" || in.Subnets[1].String() != "fd7a:115c:a1e0::/48" ||
		strings.Join(in.VPNIfaces, ",") != "wg0,tailscale0" {
		t.Fatalf("%+v", in)
	}
	adv := firewallAdvice([]svc.Firewall{{Kind: svc.FirewallUFW, Active: true}, {Kind: svc.FirewallFirewalld, Active: false}}, in, false)
	if len(adv) != 1 || adv[0].Kind != svc.FirewallUFW {
		t.Fatalf("%+v", adv)
	}
	if rem := firewallAdvice([]svc.Firewall{{Kind: svc.FirewallUFW}}, in, true); len(rem) != 1 ||
		!strings.Contains(rem[0].Commands[0], "ufw delete allow") {
		t.Fatalf("%+v", rem)
	}
	if indent("a\n\nb\n", "  ") != "  a\n\n  b\n" {
		t.Fatalf("%q", indent("a\n\nb\n", "  "))
	}

	var buf bytes.Buffer
	s := ResultSummary("init", "v7", &provision.Result{Home: "/h", Owner: "admin", SetupToken: "tok", RecoveryKey: "FPRK-1",
		Warnings: []string{"w1"}}, "alice")
	must(t, s.Print(&buf, false))
	for _, want := range []string{"home initialised in /h", "setup token", "tok", "FPRK-1", "w1"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("init summary lacks %q:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "Service:") {
		t.Error("init summary shows a service line")
	}
}

// A system service runs as the service account, not as the root installer
// that probed CertCapable: the hint names the account and keeps the
// operator step.
func TestInstallSummaryTailscaleHint(t *testing.T) {
	ts := &core.TailscaleInfo{Running: true, Kind: core.IfTailscale, DNSName: "box.tail.ts.net", CertCapable: true}
	res := &provision.Result{Home: "/opt/fileparcel", Tailscale: ts}

	e := newEnv(t, "linux", 0)
	p := &installParams{h: mustHome(t, e.dir("opt")), kind: svc.KindSystemdSystem, svcUser: svc.DefaultSystemUser, https: 443}
	s := e.in.installSummary(context.Background(), p, res, true, true)
	got := strings.Join(s.Tailscale, "\n")
	if !strings.Contains(got, "sudo tailscale set --operator=fileparcel") || strings.Contains(got, "--operator=root") ||
		strings.Contains(got, "run: fileparcel cert tailscale enable") {
		t.Fatalf("system hint:\n%s", got)
	}
	if !res.Tailscale.CertCapable {
		t.Fatal("the provisioning result was changed")
	}

	// A user service runs as the installing user, who was probed.
	e = newEnv(t, "linux", 1000)
	p = &installParams{h: mustHome(t, e.dir("fp")), kind: svc.KindSystemdUser, https: 8443}
	s = e.in.installSummary(context.Background(), p, res, true, true)
	if len(s.Tailscale) != 2 || !strings.Contains(s.Tailscale[0], "run: fileparcel cert tailscale enable") ||
		s.Tailscale[1] != "Share links on the internet: fileparcel network funnel enable" {
		t.Fatalf("user hint: %q", s.Tailscale)
	}
	ts.CertCapable = false
	s = e.in.installSummary(context.Background(), p, res, true, true)
	if !strings.Contains(strings.Join(s.Tailscale, "\n"), "--operator=alice") {
		t.Fatalf("user hint: %q", s.Tailscale)
	}
}

func TestConfigPortAndHelpers(t *testing.T) {
	h := mustHome(t, t.TempDir())
	must(t, os.WriteFile(h.Config(), []byte("install_id = \"x\"\n[log]\nhttps_port = 1\n[server]\nname = \"a\"\nhttps_port = 9443 # c\n"), 0o640))
	if p := configPort(h); p != 9443 {
		t.Fatal(p)
	}
	if expandHome("~/x", "/home/a") != "/home/a/x" || expandHome("~", "/home/a") != "/home/a" || expandHome("/x", "/h") != "/x" {
		t.Fatal("expandHome")
	}
	if firstWord(" v7 abc ") != "v7" || dashIfEmpty("") != "-" || portOrNone(0) != -1 || portOrNone(80) != 80 {
		t.Fatal("helpers")
	}
	if ReleaseBinaryName("linux", "arm") != "bin/fileparcel-linux-arm" {
		t.Fatal("release name")
	}
}

func TestBinaryInfoRunsBinary(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fp")
	must(t, os.WriteFile(script, []byte("#!/bin/sh\necho '{\"version\":\"v9\",\"commit\":\"c\"}'\n"), 0o755))
	bi, err := BinaryInfo(context.Background(), script)
	if err != nil || bi.Version != "v9" {
		t.Fatalf("%+v %v", bi, err)
	}
	must(t, os.WriteFile(script, []byte("#!/bin/sh\necho nope\n"), 0o755))
	if _, err := BinaryInfo(context.Background(), script); err == nil {
		t.Fatal("garbage accepted")
	}
	must(t, os.WriteFile(script, []byte("#!/bin/sh\necho broken >&2\nexit 3\n"), 0o755))
	if _, err := BinaryInfo(context.Background(), script); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("err %v", err)
	}
}
