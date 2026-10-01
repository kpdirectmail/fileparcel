package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc/installer"
)

// lcInitTestHome runs `init` for a new home in a temp dir (free ports, mDNS
// off) and returns it with the JSON summary.
func lcInitTestHome(t *testing.T, extra ...string) (*home.Home, installer.Summary) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fp")
	https, http := lcFreePort(t), lcFreePort(t)
	for http == https {
		http = lcFreePort(t)
	}
	args := append([]string{"init", "--home", dir, "--port", fmt.Sprint(https), "--http-port", fmt.Sprint(http),
		"--json", "-y"}, extra...)
	r := lcRun(t, "", args...)
	if r.code != 0 {
		t.Fatalf("init: exit %d\n%s\n%s", r.code, r.out, r.err)
	}
	var s installer.Summary
	if err := json.Unmarshal([]byte(r.out), &s); err != nil {
		t.Fatalf("init output: %v\n%s", err, r.out)
	}
	h, _ := home.New(dir)
	lcSetOffline(t, h, map[string]any{"mdns.mode": "off"})
	return h, s
}

// lcSetOffline changes runtime settings in-process (the server is stopped).
func lcSetOffline(t *testing.T, h *home.Home, kv map[string]any) {
	t.Helper()
	c, err := Connect(Options{Home: h.Dir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ch := map[string]json.RawMessage{}
	for k, v := range kv {
		b, _ := json.Marshal(v)
		ch[k] = b
	}
	if _, err := c.Deps().Settings.Set(context.Background(), core.SystemPrincipal(core.ViaOffline), ch); err != nil {
		t.Fatal(err)
	}
}

// lcVerifyPassword checks the owner's password in-process.
func lcVerifyPassword(t *testing.T, h *home.Home, user, pw string) bool {
	t.Helper()
	c, err := Connect(Options{Home: h.Dir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d := c.Deps()
	u, err := d.Users.GetByUsername(context.Background(), user)
	if err != nil {
		t.Fatalf("user %s: %v", user, err)
	}
	ok, _ := d.Auth.VerifyPassword(u.PasswordHash, pw)
	return ok
}

func TestInitCommand(t *testing.T) {
	h, s := lcInitTestHome(t, "--name", "box", "--admin-email", "admin@example.org", "--allow", "10.9.0.0/16")
	if s.Action != "init" || s.Admin != "admin" || s.Password == "" || s.CAFingerprint == "" || s.BackupIdentity == "" ||
		s.Home != h.Dir() {
		t.Fatalf("summary %+v", s)
	}
	if !h.Exists() {
		t.Fatal("no home")
	}
	cfg, err := config.Load(h)
	if err != nil || cfg.Server.Name != "box" {
		t.Fatalf("config %+v %v", cfg, err)
	}
	for _, p := range []string{h.KeysFile(), filepath.Join(h.CertsDir(), "ca", "ca.crt"), h.DB()} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if !lcVerifyPassword(t, h, "admin", s.Password) {
		t.Fatal("generated password does not verify")
	}
	// The network policy includes the extra CIDR.
	c, err := Connect(Options{Home: h.Dir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	allow := c.Deps().Settings.Strings("network.allow_cidrs")
	mode := c.Deps().Settings.String("network.access_mode")
	c.Close()
	if mode != core.AccessAllowlist || !strings.Contains(strings.Join(allow, ","), "10.9.0.0/16") {
		t.Fatalf("policy %s %v", mode, allow)
	}

	// A second init refuses the existing home.
	r := lcRun(t, "", "init", "--home", h.Dir(), "-y")
	if r.code == 0 || !strings.Contains(r.err, "already a FileParcel home") {
		t.Fatalf("second init: %d %s", r.code, r.err)
	}
}

func TestInitPasswordsAndSealed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fp")
	pw := "a very long and good password"
	r := lcRun(t, pw+"\n", "init", "--home", dir, "--port", fmt.Sprint(lcFreePort(t)), "--http-port", "0",
		"--admin", "carol", "--admin-password-stdin", "--json")
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.err)
	}
	var s installer.Summary
	if err := json.Unmarshal([]byte(r.out), &s); err != nil || s.Admin != "carol" || s.Password != "" {
		t.Fatalf("%+v %v", s, err)
	}
	h, _ := home.New(dir)
	if !lcVerifyPassword(t, h, "carol", pw) {
		t.Fatal("password from stdin not used")
	}

	// Sealed with a passphrase file; a weak admin password aborts and leaves nothing behind.
	pp := filepath.Join(t.TempDir(), "pp")
	if err := os.WriteFile(pp, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir2 := filepath.Join(t.TempDir(), "fp2")
	r = lcRun(t, "short\n", "init", "--home", dir2, "--port", fmt.Sprint(lcFreePort(t)), "--http-port", "0",
		"--admin-password-stdin", "--sealed", "--passphrase-file", pp)
	if r.code == 0 || lcExists(dir2) {
		t.Fatalf("weak password accepted or home left behind: %d %s", r.code, r.err)
	}
	r = lcRun(t, "", "init", "--home", dir2, "--port", fmt.Sprint(lcFreePort(t)), "--http-port", "0",
		"--sealed", "--passphrase-file", pp, "--json", "-y")
	if r.code != 0 {
		t.Fatalf("sealed init: %d %s", r.code, r.err)
	}
	var sealed installer.Summary
	if err := json.Unmarshal([]byte(r.out), &sealed); err != nil || !strings.HasPrefix(sealed.RecoveryKey, "FPRK-") {
		t.Fatalf("recovery key: %+v %v", sealed, err)
	}

	// No admin: a setup token instead of an account.
	dir3 := filepath.Join(t.TempDir(), "fp3")
	r = lcRun(t, "", "init", "--home", dir3, "--port", fmt.Sprint(lcFreePort(t)), "--http-port", "0", "--no-admin", "--json", "-y")
	var noAdmin installer.Summary
	if err := json.Unmarshal([]byte(r.out), &noAdmin); r.code != 0 || err != nil || noAdmin.SetupToken == "" ||
		noAdmin.Admin != "" || noAdmin.Password != "" {
		t.Fatalf("no-admin: %d %s %+v", r.code, r.err, noAdmin)
	}
}

func TestInitInteractive(t *testing.T) {
	// Scripted terminal: decline the generated password, type one twice.
	dir := filepath.Join(t.TempDir(), "fp")
	pw := "typed interactively 123"
	r := lcRun(t, "n\n"+pw+"\n"+pw+"\n", "init", "--home", dir, "--port", fmt.Sprint(lcFreePort(t)), "--http-port", "0")
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.err)
	}
	if !strings.Contains(r.err, "Generate a secure password for admin?") || !strings.Contains(r.out, "Admin account: admin") {
		t.Fatalf("prompts/summary:\n%s\n%s", r.err, r.out)
	}
	h, _ := home.New(dir)
	if !lcVerifyPassword(t, h, "admin", pw) {
		t.Fatal("typed password not used")
	}
}

func TestInitRefusesDangerousDirs(t *testing.T) {
	r := lcRun(t, "", "init", "--home", "/", "-y")
	if r.code == 0 || !strings.Contains(r.err, "refusing") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	// $FILEPARCEL_HOME is used when --home is absent.
	dir := filepath.Join(t.TempDir(), "envhome")
	t.Setenv(home.EnvVar, dir)
	NewRootCmd() // resets the global flags
	if got := lcHomeDir(); got != dir {
		t.Fatal(got)
	}
}

func TestSecretFlags(t *testing.T) {
	root := NewRootCmd()
	cmd := lcFind(root, "init")
	cmd.SetIn(strings.NewReader("s3cret\nignored\n"))
	if v, err := (lcSecretFlags{stdin: true}).read(cmd); err != nil || v != "s3cret" {
		t.Fatal(v, err)
	}
	f := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(f, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := (lcSecretFlags{file: f}).read(cmd); err != nil || v != "from-file" {
		t.Fatal(v, err)
	}
	if v, err := (lcSecretFlags{}).read(cmd); err != nil || v != "" {
		t.Fatal(v, err)
	}
	if _, err := (lcSecretFlags{stdin: true, file: f}).read(cmd); err == nil {
		t.Fatal("both accepted")
	}
	if err := lcCheckAccess("any"); err != nil || lcCheckAccess("") != nil || lcCheckAccess("x") == nil {
		t.Fatal("lcCheckAccess")
	}
}
