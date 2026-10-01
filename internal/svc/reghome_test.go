package svc

import (
	"os"
	"path/filepath"
	"testing"

	"fileparcel/internal/home"
)

func TestRegisteredHome(t *testing.T) {
	root := t.TempDir()
	physical := filepath.Join(root, "var", "opt", "fp")
	if err := os.MkdirAll(physical, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("var", "opt"), filepath.Join(root, "opt")); err != nil {
		t.Fatal(err)
	}
	logical := filepath.Join(root, "opt", "fp")
	other := filepath.Join(root, "var", "opt", "fp-new")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	hp, _ := home.New(physical)
	hl, _ := home.New(logical)
	for _, c := range []struct {
		name string
		h    *home.Home
		rec  *Installed
		want string
	}{
		{"no record", hp, nil, physical},
		{"no home recorded", hp, &Installed{}, physical},
		{"same spelling", hp, &Installed{Home: physical}, physical},
		{"physical path, logical recorded", hp, &Installed{Home: logical}, logical},
		{"logical path, physical recorded", hl, &Installed{Home: physical}, physical},
		{"recorded with a trailing slash", hp, &Installed{Home: logical + "/"}, logical},
		{"another directory", hp, &Installed{Home: other}, physical},
		{"a prefix of the name", hp, &Installed{Home: physical + "-new"}, physical},
		{"recorded path gone", hp, &Installed{Home: filepath.Join(root, "moved")}, physical},
		{"relative record", hp, &Installed{Home: "opt/fp"}, physical},
	} {
		if got := RegisteredHome(c.h, c.rec); got != c.want {
			t.Errorf("%s: RegisteredHome = %q, want %q", c.name, got, c.want)
		}
	}
}

// A manager built for the recorded spelling recognises the registration a
// home installed under a symlinked directory got, and removes the command
// link; one built for the physical path does not (the reason for
// RegisteredHome).
func TestRegisteredHomeOwnership(t *testing.T) {
	root := t.TempDir()
	physical := filepath.Join(root, "var", "opt", "fp")
	if err := os.MkdirAll(filepath.Join(physical, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("var", "opt"), filepath.Join(root, "opt")); err != nil {
		t.Fatal(err)
	}
	logical := filepath.Join(root, "opt", "fp")
	unitDir := filepath.Join(root, "etc-systemd")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	host := &Host{GOOS: "linux", UID: 0, User: "root", HomeDir: filepath.Join(root, "root"),
		Getenv: func(string) string { return "" }, Paths: Paths{SystemUnitDir: unitDir}}
	unit, err := SystemdUnit(Options{Kind: KindSystemdSystem, Home: logical, Binary: filepath.Join(logical, "bin", "fileparcel"),
		User: "fileparcel"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, UnitName), unit, 0o644); err != nil {
		t.Fatal(err)
	}
	hp, _ := home.New(physical)
	rec := &Installed{Kind: KindSystemdSystem, Home: logical}
	for _, c := range []struct {
		home string
		want RegState
	}{{physical, RegOther}, {RegisteredHome(hp, rec), RegOurs}} {
		m := &systemdManager{h: host, o: Options{Kind: KindSystemdSystem, Home: c.home}}
		if st, who := m.ownership(); st != c.want {
			t.Errorf("home %s: ownership %v (%s), want %v", c.home, st, who, c.want)
		}
	}

	link := filepath.Join(root, "fileparcel")
	if err := os.Symlink(filepath.Join(logical, "bin", "fileparcel"), link); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveSymlink(link, RegisteredHome(hp, rec)); err != nil || !removed {
		t.Fatalf("RemoveSymlink = %v, %v", removed, err)
	}
}
