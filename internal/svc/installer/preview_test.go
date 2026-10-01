package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

// Running the installer (or `upgrade`) again with the release that is
// installed changes nothing: no backup, no swap, and bin/fileparcel.prev
// keeps the previous version for the documented rollback.
func TestUpgradeSameReleaseKeepsPrev(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("new-fileparcel")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true}))
	if b, _ := os.ReadFile(h.PrevBinary()); string(b) != "old binary" {
		t.Fatalf("prev %q", b)
	}
	backups := len(e.backup)

	// The same bytes from another path (install.sh run twice).
	again := e.dir("again-fileparcel")
	must(t, os.WriteFile(again, []byte("new binary"), 0o755))
	e.out.Reset()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: again, Yes: true}))
	if !strings.Contains(e.out.String(), "FileParcel v8 is already installed") {
		t.Fatalf("out %q", e.out.String())
	}
	// A rebuild of the same version and commit.
	must(t, os.WriteFile(again, []byte("rebuilt binary"), 0o755))
	e.out.Reset()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: again, Yes: true}))
	if !strings.Contains(e.out.String(), "already installed") {
		t.Fatalf("rebuild: %q", e.out.String())
	}
	if b, _ := os.ReadFile(h.PrevBinary()); string(b) != "old binary" {
		t.Fatalf("prev after the same release again: %q", b)
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "new binary" || len(e.backup) != backups {
		t.Fatalf("binary %q, backups %d → %d", b, backups, len(e.backup))
	}
}

// After a rollback by hand (INSTALL.md "Roll back by hand": the previous
// program copied back over bin/fileparcel) VERSION still names the newer
// release. Retrying that upgrade must not be taken for "the same release
// again": what bin/fileparcel reports decides, not VERSION.
func TestUpgradeAfterManualRollback(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	newBin := e.dir("new-fileparcel")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true}))
	if v := readVersion(h); !strings.HasPrefix(v, "v8 def5678") {
		t.Fatalf("VERSION after the upgrade %q", v)
	}
	// The rollback by hand: cp bin/fileparcel.prev bin/fileparcel.
	must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755))
	// A rebuild of v8 (other bytes, same version and commit) is an upgrade now.
	rebuilt := e.dir("rebuilt-fileparcel")
	must(t, os.WriteFile(rebuilt, []byte("rebuilt binary"), 0o755))
	e.out.Reset()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: rebuilt, Yes: true}))
	if strings.Contains(e.out.String(), "already installed") {
		t.Fatalf("the retried upgrade was skipped:\n%s", e.out.String())
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "rebuilt binary" {
		t.Fatalf("binary %q", b)
	}
}

// An older release is refused unless --force (the database may already be
// migrated past what it can open); a dry run shows the plan with the
// blocker; --force goes on with a warning.
func TestUpgradeDowngradeNeedsForce(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	h := installedHome(t, e)
	must(t, os.WriteFile(h.VersionFile(), []byte("v9 fff0000 2026-11-01\n"), 0o644))
	older := e.dir("older-fileparcel")
	must(t, os.WriteFile(older, []byte("older binary"), 0o755))
	err := e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: older, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "v8 is older than the installed v9") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(h.Binary()); string(b) != "old binary" {
		t.Fatal("binary swapped")
	}
	e.out.Reset()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: older, Yes: true, DryRun: true}))
	if !strings.Contains(e.out.String(), "Blocked: v8 is older than the installed v9") {
		t.Fatalf("dry run:\n%s", e.out.String())
	}
	e.out.Reset()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: older, Yes: true, Force: true}))
	if b, _ := os.ReadFile(h.Binary()); string(b) != "older binary" || !strings.Contains(e.out.String(), "downgrade: v8 is older") {
		t.Fatalf("forced downgrade: %q\n%s", b, e.out.String())
	}
	if older, ok := olderRelease("v40", "v41"); !older || !ok {
		t.Fatal("v40 < v41")
	}
	for _, c := range [][2]string{{"dev", "v41"}, {"v41", "dev"}, {"v41", ""}, {"41", "v40"}} {
		if _, ok := olderRelease(c[0], c[1]); ok {
			t.Errorf("olderRelease%q compared", c)
		}
	}
}

// A dry run previews an upgrade while a server started by hand runs (the
// real run refuses), and a system install as a normal user.
func TestDryRunPreviewsBlockedCases(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true}))
	h := mustHome(t, dir)
	must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755)) // the v7 of VERSION
	newBin := e.dir("new-fileparcel")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	unlock, err := h.Lock()
	must(t, err)
	e.out.Reset()
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true, DryRun: true}))
	if !strings.Contains(e.out.String(), "FileParcel upgrade plan (dry run") ||
		!strings.Contains(e.out.String(), "Blocked: a FileParcel server or command is using this home") {
		t.Fatalf("dry run:\n%s", e.out.String())
	}
	if err := e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true}); err == nil {
		t.Fatal("upgraded while the home is in use")
	}
	unlock()

	e = newEnv(t, "linux", 1000)
	e.out.Reset()
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("sys"), Yes: true, DryRun: true, NoSymlink: true,
		Service: "system", HTTPSPort: 18629, HTTPPort: ptr(0)}))
	if out := e.out.String(); !strings.Contains(out, "systemd system service") || !strings.Contains(out, "a system install needs root") {
		t.Fatalf("system dry run as a user:\n%s", out)
	}
	if err := e.in.Install(context.Background(), InstallOptions{Dir: e.dir("sys"), Yes: true, NoSymlink: true,
		Service: "system"}); !errors.Is(err, svc.ErrNeedsRoot) {
		t.Fatalf("real system install as a user: %v", err)
	}
}

// Everything the initialisation refuses is refused before the plan: a dry
// run is a reliable preview, errors are short.
func TestInstallValidatesInputsUpFront(t *testing.T) {
	for _, c := range []struct {
		o    InstallOptions
		want string
	}{
		{InstallOptions{Name: "bad_name!"}, `invalid --name "bad_name!": use lowercase letters`},
		{InstallOptions{Name: "UPPER"}, `invalid --name "UPPER"`},
		{InstallOptions{Name: "-lead"}, `invalid --name "-lead"`},
		{InstallOptions{Name: strings.Repeat("a", 70)}, "invalid --name"},
		{InstallOptions{AdminPassword: "short"}, "the admin password is not accepted: the password must be at least 12 characters long"},
		{InstallOptions{AdminPassword: "admin admin admin"}, "the admin password is not accepted: the password must not contain your username"},
		{InstallOptions{AdminEmail: "not an address"}, `invalid --admin-email "not an address"`},
		{InstallOptions{AdminEmail: strings.Repeat("x", 250) + "@example.com"}, "invalid --admin-email"},
		{InstallOptions{Sealed: true}, "--sealed needs --passphrase-file or --passphrase-stdin"},
	} {
		for _, dry := range []bool{true, false} {
			e := newEnv(t, "linux", 1000)
			o := c.o
			o.Dir, o.Yes, o.DryRun, o.NoSymlink, o.Service = e.dir("fp"), true, dry, true, "none"
			err := e.in.Install(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "Initialise") {
				t.Errorf("%+v (dry run %v): %v", c.o, dry, err)
			}
			if len(e.inits) != 0 || e.out.Len() != 0 {
				t.Errorf("%+v: something happened (inits %d, out %q)", c.o, len(e.inits), e.out.String())
			}
		}
	}
}

// The "port in use, using another" note is kept only when the suggested
// port is used; the HTTP redirect's fallback gets one too; boot is not
// recorded for an install without a service.
func TestInstallPortNotesAndBoot(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	p := &fakePrompter{interactive: true, asks: []string{"18629", ""}, confirms: []bool{true, true, false}}
	e.in.Prompt = p
	e.in.PortFree = func(p int) bool { return p != 8443 && p != 8080 }
	_ = e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), NoSymlink: true, Service: "none"})
	plan := e.errOut.String()
	if strings.Contains(plan, "port 8443 is in use") || !strings.Contains(plan, "Ports: ") && !strings.Contains(plan, "HTTPS 18629") {
		t.Fatalf("stale note:\n%s", plan)
	}
	if !strings.Contains(plan, "port 8080 is in use; the HTTP redirect uses 8081 instead") {
		t.Fatalf("no HTTP fallback note:\n%s", plan)
	}

	e = newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("none"), Yes: true, NoSymlink: true, Service: "none"}))
	if rec, _ := svc.ReadInstalled(mustHome(t, e.dir("none"))); rec == nil || rec.Boot {
		t.Fatalf("boot recorded for --service none: %+v", rec)
	}
}

// --access any says what it means in the plan and warns in the summary.
func TestInstallAccessAnyIsExplained(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), Yes: true, DryRun: true, NoSymlink: true,
		Service: "none", Access: core.AccessAny}))
	if !strings.Contains(e.out.String(), "any (every address: the server is reachable from the internet") {
		t.Fatalf("plan:\n%s", e.out.String())
	}
	e = newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: e.dir("fp"), Yes: true, NoSymlink: true,
		Service: "none", Access: core.AccessAny}))
	if !strings.Contains(e.out.String(), `network access is "any"`) {
		t.Fatalf("summary:\n%s", e.out.String())
	}
	var buf bytes.Buffer
	s := &Summary{Action: "install", FirewallAnywhere: true,
		Firewall: []FirewallAdvice{{Kind: svc.FirewallUFW, Active: true, Commands: []string{"sudo ufw allow proto tcp to any port 18629"}}}}
	must(t, s.Print(&buf, false))
	if !strings.Contains(buf.String(), "to allow access from anywhere") || strings.Contains(buf.String(), "from your networks") {
		t.Fatalf("firewall heading:\n%s", buf.String())
	}
}

// uninstall stops a server started by hand (like uninstall.sh's fallback),
// and warns about a process that holds the home but cannot be identified.
func TestUninstallHandStartedServer(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true, Service: "none", NoSymlink: true}))
	h := mustHome(t, dir)
	unlock, err := h.Lock()
	must(t, err)
	var stopped []int
	e.in.HandServer = func(*home.Home) int { return 4242 }
	e.in.StopServer = func(_ context.Context, _ *home.Home, pid int) error {
		stopped = append(stopped, pid)
		unlock()
		return nil
	}
	e.out.Reset()
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, DryRun: true}))
	if !strings.Contains(e.out.String(), "Stop the server started by hand (pid 4242)") || len(stopped) != 0 {
		t.Fatalf("dry run:\n%s", e.out.String())
	}
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	if fmt.Sprint(stopped) != "[4242]" {
		t.Fatalf("stopped %v", stopped)
	}

	// Not identifiable: kept data, with a warning.
	e = newEnv(t, "linux", 1000)
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir + "2", Yes: true, Service: "none", NoSymlink: true}))
	h = mustHome(t, dir+"2")
	unlock, err = h.Lock()
	must(t, err)
	defer unlock()
	e.in.HandServer = func(*home.Home) int { return 0 }
	e.out.Reset()
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	if !strings.Contains(e.out.String(), "keeps serving from "+h.Dir()) {
		t.Fatalf("no warning:\n%s", e.out.String())
	}
}

// The summary's URL column fits the URLs; a long one gets its label on the
// next line.
func TestSummaryURLColumn(t *testing.T) {
	var buf bytes.Buffer
	s := &Summary{Action: "install", URLs: []core.AccessURL{
		{URL: "https://box.local:18629/", Label: "Local network name (mDNS)"},
		{URL: "https://192.168.1.10:18629/", Label: "LAN", Interface: "eth2"},
		{URL: "https://[2001:db8:f030:b300:393:9548:676a:9ded]:18629/", Label: "LAN", Interface: "eth2"},
	}}
	must(t, s.Print(&buf, false))
	lines := strings.Split(buf.String(), "\n")
	var got []string
	for _, l := range lines {
		if strings.HasPrefix(l, "  ") {
			got = append(got, l)
		}
	}
	col := len("  https://192.168.1.10:18629/ ")
	if len(got) < 4 || strings.Index(got[0], "Local network") != col || strings.Index(got[1], "LAN eth2") != col ||
		strings.TrimSpace(got[2]) != "https://[2001:db8:f030:b300:393:9548:676a:9ded]:18629/" || strings.Index(got[3], "LAN eth2") != col {
		t.Fatalf("table:\n%s", buf.String())
	}
}

// Errors of the pre-upgrade backup name the cause, not the layers it went
// through.
func TestCauseText(t *testing.T) {
	pe := &fs.PathError{Op: "mkdir", Path: "/h/backups", Err: fs.ErrExist}
	err := fmt.Errorf("wire: %w", fmt.Errorf("layout: %w", fmt.Errorf("home: create: %w", pe)))
	if got := causeText(err); got != "mkdir /h/backups: file already exists" {
		t.Fatal(got)
	}
	if got := causeText(fmt.Errorf("a: %w", errors.New("root cause"))); got != "root cause" {
		t.Fatal(got)
	}
	ce := &causeError{msg: "shown", err: pe}
	if !errors.Is(ce, fs.ErrExist) || ce.Error() != "shown" {
		t.Fatal(ce)
	}
}
