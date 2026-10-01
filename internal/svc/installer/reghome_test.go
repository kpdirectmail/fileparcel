package installer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/svc"
)

// symlinkedInstall installs into <root>/opt/fp where <root>/opt links to
// var/opt (like /opt on Fedora Silverblue): the record, the unit's --home,
// the registration link and the command link all name the logical path.
// It returns the logical and the physical home directory.
func symlinkedInstall(t *testing.T, e *env) (logical, physical string) {
	t.Helper()
	must(t, os.MkdirAll(e.dir("var/opt"), 0o755))
	must(t, os.Symlink("var/opt", e.dir("opt")))
	logical, physical = e.dir("opt/fp"), e.dir("var/opt/fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: logical, Yes: true}))
	// `systemctl --user link` is faked: create the link it would create.
	reg := filepath.Join(e.host.Paths.UserUnitDir, svc.UnitName)
	must(t, os.MkdirAll(filepath.Dir(reg), 0o755))
	must(t, os.Symlink(filepath.Join(logical, "service", svc.UnitName), reg))
	e.runner.resp["systemctl --user show"] = fakeResp{out: "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n"}
	e.runner.calls = nil
	e.out.Reset()
	e.errOut.Reset()
	e.health = nil
	return logical, physical
}

func TestRegisteredHomeUninstallThroughPhysicalPath(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	_, physical := symlinkedInstall(t, e)
	// uninstall.sh and home.Resolve (through the command link) pass the
	// physical path.
	h := mustHome(t, physical)
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	cmds := e.runner.joined()
	for _, want := range []string{"systemctl --user stop fileparcel.service", "systemctl --user disable fileparcel.service"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("missing %q in\n%s", want, cmds)
		}
	}
	if _, err := os.Lstat(filepath.Join(e.host.Paths.UserUnitDir, svc.UnitName)); !os.IsNotExist(err) {
		t.Error("registration link not removed")
	}
	if _, err := os.Lstat(filepath.Join(e.host.HomeDir, ".local", "bin", "fileparcel")); !os.IsNotExist(err) {
		t.Error("command link not removed")
	}
	if out := e.out.String() + e.errOut.String(); strings.Contains(out, "belongs to something else") ||
		strings.Contains(out, "not touching") {
		t.Errorf("the home's own service was taken for another's:\n%s", out)
	}
	if !h.Exists() {
		t.Fatal("keep-data removed the home")
	}
}

func TestRegisteredHomeUpgradeThroughPhysicalPath(t *testing.T) {
	e := newEnv(t, "linux", 1000)
	logical, physical := symlinkedInstall(t, e)
	h := mustHome(t, physical)
	must(t, os.WriteFile(h.Binary(), []byte("old binary"), 0o755))
	newBin := e.dir("new-fileparcel")
	must(t, os.WriteFile(newBin, []byte("new binary"), 0o755))
	must(t, e.in.Upgrade(context.Background(), UpgradeOptions{Home: h, Binary: newBin, Yes: true}))
	cmds := e.runner.joined()
	if !strings.Contains(cmds, "systemctl --user stop fileparcel.service") ||
		!strings.Contains(cmds, "systemctl --user restart fileparcel.service") {
		t.Fatalf("the running service was not stopped and restarted:\n%s", cmds)
	}
	// The refreshed unit still serves the recorded path.
	unit, err := os.ReadFile(filepath.Join(physical, "service", svc.UnitName))
	if err != nil || !strings.Contains(string(unit), `--home "`+logical+`"`) {
		t.Fatalf("unit %s %v", unit, err)
	}
}
