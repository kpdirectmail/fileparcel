package provision

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
)

// ---------- fakes ----------

type fakeKeys struct {
	core.Keys
	sealed bool
	pass   []byte
	err    error
}

func (k *fakeKeys) Init(ctx context.Context, sealed bool, pass []byte) (string, error) {
	if k.err != nil {
		return "", k.err
	}
	k.sealed, k.pass = sealed, pass
	if sealed {
		return "FPRK-TEST", nil
	}
	return "", nil
}

type fakeCerts struct {
	core.Certs
	inited bool
	err    error
}

func (c *fakeCerts) Init(ctx context.Context) error { c.inited = true; return c.err }
func (c *fakeCerts) Fingerprint() string            { return "AA:BB" }

type fakeNet struct {
	core.Network
	ifaces []core.NetInterface
	policy *core.AccessPolicy
	ts     *core.TailscaleInfo // nil: not running
}

func (n *fakeNet) Interfaces(ctx context.Context) ([]core.NetInterface, error) { return n.ifaces, nil }
func (n *fakeNet) URLs(ctx context.Context) ([]core.AccessURL, error) {
	return []core.AccessURL{{URL: "https://fileparcel.local:8443/", Kind: core.URLKindMDNS, Recommended: true}}, nil
}
func (n *fakeNet) Policy() core.AccessPolicy { return core.AccessPolicy{Mode: "allowlist"} }
func (n *fakeNet) Tailscale(ctx context.Context) (*core.TailscaleInfo, error) {
	if n.ts == nil {
		return &core.TailscaleInfo{}, nil
	}
	return n.ts, nil
}
func (n *fakeNet) SetPolicy(ctx context.Context, by *core.Principal, p core.AccessPolicy, cur netip.Addr, force bool) ([]string, error) {
	n.policy = &p
	return nil, nil
}

type fakeSettings struct {
	core.Settings
	set map[string]json.RawMessage
	err error
}

func (s *fakeSettings) Set(ctx context.Context, by *core.Principal, ch map[string]json.RawMessage) (*core.SettingsResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	if !by.IsSystem() || core.PrincipalFrom(ctx) == nil {
		return nil, errors.New("not system")
	}
	s.set = ch
	return &core.SettingsResult{}, nil
}

type fakeAuth struct {
	core.Auth
	policyErr error
}

func (a *fakeAuth) CheckPasswordPolicy(pw string, u *core.User) error {
	if a.policyErr != nil {
		return a.policyErr
	}
	if len(pw) < 12 || strings.Contains(strings.ToLower(pw), strings.ToLower(u.Username)) {
		return core.Invalid("password", "too weak")
	}
	return nil
}
func (a *fakeAuth) HashPassword(pw string) (string, error) { return "$argon2id$" + pw, nil }
func (a *fakeAuth) SetupToken(ctx context.Context) (string, error) {
	return "setup-token", nil
}

type fakeUsers struct {
	core.Users
	got core.NewUser
}

func (u *fakeUsers) Bootstrap(ctx context.Context, in core.NewUser) (*core.User, error) {
	u.got = in
	return &core.User{ID: "usr_1", Username: in.Username, Role: in.Role}, nil
}

type fakeBackups struct {
	core.Backups
	err error
}

func (b *fakeBackups) GenerateIdentity(ctx context.Context, by *core.Principal) (string, string, error) {
	if b.err != nil {
		return "", "", b.err
	}
	return "age1recipient", "AGE-SECRET-KEY-1TEST", nil
}

type world struct {
	d       *app.Deps
	keys    *fakeKeys
	certs   *fakeCerts
	net     *fakeNet
	set     *fakeSettings
	auth    *fakeAuth
	users   *fakeUsers
	backups *fakeBackups
}

func newWorld(t *testing.T) *world {
	h, _ := home.New(t.TempDir())
	w := &world{keys: &fakeKeys{}, certs: &fakeCerts{}, set: &fakeSettings{}, auth: &fakeAuth{}, users: &fakeUsers{},
		backups: &fakeBackups{},
		net: &fakeNet{ifaces: []core.NetInterface{
			{Name: "lo", Kind: core.IfLoopback, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
			{Name: "eth2", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24"),
				netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("2001:db8:1:2::6/64")}},
		}}}
	env := &core.Env{Home: h, Keys: w.keys, Settings: w.set}
	w.d = &app.Deps{Env: env, Certs: w.certs, Network: w.net, Auth: w.auth, Users: w.users, Backups: w.backups}
	return w
}

// ---------- tests ----------

func TestProvisionDefaults(t *testing.T) {
	w := newWorld(t)
	res, err := Provision(context.Background(), w.d, Options{Admin: "admin", AdminEmail: "a@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Owner != "admin" || !res.PasswordGenerated || res.Password == "" || res.KeyMode != core.KeyModePlain ||
		res.RecoveryKey != "" || res.CAFingerprint != "AA:BB" || res.BackupIdentity != "AGE-SECRET-KEY-1TEST" ||
		res.BackupRecipient != "age1recipient" || res.AccessMode != "allowlist" || len(res.URLs) != 1 || res.SetupToken != "" {
		t.Fatalf("%+v", res)
	}
	if !w.certs.inited || w.keys.sealed {
		t.Fatal("keys/certs")
	}
	if len(res.Interfaces) != 2 || res.Tailscale != nil {
		t.Fatalf("interfaces %v tailscale %v", res.Interfaces, res.Tailscale)
	}
	if w.users.got.Role != core.RoleOwner || !w.users.got.MustChangePassword || w.users.got.PasswordHash != "$argon2id$"+res.Password ||
		w.users.got.Email != "a@example.org" || w.users.got.Password != "" {
		t.Fatalf("bootstrap %+v", w.users.got)
	}
	var allow []string
	json.Unmarshal(w.set.set["network.allow_cidrs"], &allow)
	if strings.Join(allow, ",") != "192.168.1.0/24,2001:db8:1:2::/64" || string(w.set.set["network.access_mode"]) != `"allowlist"` {
		t.Fatalf("policy %s %s", w.set.set["network.allow_cidrs"], w.set.set["network.access_mode"])
	}
}

func TestProvisionVariants(t *testing.T) {
	// Sealed, explicit password, extra CIDRs, any mode.
	w := newWorld(t)
	res, err := Provision(context.Background(), w.d, Options{Admin: "boss", AdminPassword: "correct horse battery", Sealed: true,
		Passphrase: []byte("pp"), Access: "any", Allow: []string{"10.0.0.0/8", "203.0.113.7", "192.168.1.9/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.PasswordGenerated || res.Password != "" || w.users.got.MustChangePassword || res.RecoveryKey != "FPRK-TEST" ||
		res.KeyMode != core.KeyModeSealed || string(w.keys.pass) != "pp" || res.AccessMode != "any" {
		t.Fatalf("%+v", res)
	}
	if got := strings.Join(res.AllowCIDRs, ","); got != "192.168.1.0/24,2001:db8:1:2::/64,10.0.0.0/8,203.0.113.7/32" {
		t.Fatal(got)
	}
	w = newWorld(t)
	w.net.ifaces = append(w.net.ifaces, core.NetInterface{Name: "tailscale0", Kind: core.IfTailscale, Up: true})
	w.net.ts = &core.TailscaleInfo{Running: true, DNSName: "box.tail.ts.net"}
	if res, _ := Provision(context.Background(), w.d, Options{Admin: "admin"}); res.Tailscale == nil || res.Tailscale.DNSName != "box.tail.ts.net" {
		t.Fatalf("tailscale %+v", res.Tailscale)
	}
	// The role-aware default allowlist (netinfo.DefaultAllowlist): the
	// tailnet ranges and a mesh VPN's subnet, never an exit VPN's.
	w = newWorld(t)
	w.net.ifaces = append(w.net.ifaces,
		core.NetInterface{Name: "tailscale0", Kind: core.IfTailscale, Up: true, IsVPN: true, Role: core.VPNRoleMesh,
			Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")}},
		core.NetInterface{Name: "wg0-mullvad", Kind: core.IfExitVPN, Provider: "mullvad", Up: true, IsVPN: true, Role: core.VPNRoleEgress,
			Addrs: []netip.Prefix{netip.MustParsePrefix("10.64.1.2/24")}},
		core.NetInterface{Name: "zt0", Kind: core.IfZeroTier, Up: true, IsVPN: true, Role: core.VPNRoleMesh,
			Addrs: []netip.Prefix{netip.MustParsePrefix("10.147.17.5/24")}})
	res, err = Provision(context.Background(), w.d, Options{Admin: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res.AllowCIDRs, ","); got != "10.147.17.0/24,100.64.0.0/10,192.168.1.0/24,2001:db8:1:2::/64,fd7a:115c:a1e0::/48" {
		t.Fatalf("role-aware allowlist %s", got)
	}
	// Userspace networking: no Tailscale interface, tailscaled running.
	w = newWorld(t)
	w.net.ts = &core.TailscaleInfo{Running: true, Userspace: true, DNSName: "box.tail.ts.net"}
	if res, _ := Provision(context.Background(), w.d, Options{Admin: "admin"}); res.Tailscale == nil || !res.Tailscale.Userspace {
		t.Fatalf("userspace tailscale %+v", res.Tailscale)
	}

	// No owner → setup token; settings failure falls back to Network.SetPolicy; backup failure is a warning.
	w = newWorld(t)
	w.set.err = errors.New("unknown setting")
	w.backups.err = core.ErrNotImplemented
	res, err = Provision(context.Background(), w.d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Owner != "" || res.SetupToken != "setup-token" || w.net.policy == nil || w.net.policy.Mode != "allowlist" ||
		len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "backup identity") {
		t.Fatalf("%+v %+v", res, w.net.policy)
	}

	// Weak password and fatal failures abort.
	w = newWorld(t)
	if _, err := Provision(context.Background(), w.d, Options{Admin: "admin", AdminPassword: "admin123456789"}); err == nil ||
		!strings.Contains(err.Error(), "admin password") {
		t.Fatalf("weak password: %v", err)
	}
	w = newWorld(t)
	w.keys.err = core.ErrConflict
	if _, err := Provision(context.Background(), w.d, Options{Admin: "admin"}); !errors.Is(err, core.ErrConflict) {
		t.Fatal(err)
	}
	w = newWorld(t)
	w.certs.err = errors.New("ca failed")
	if _, err := Provision(context.Background(), w.d, Options{Admin: "admin"}); err == nil || !strings.Contains(err.Error(), "certificates") {
		t.Fatal(err)
	}
	for _, o := range []Options{{Access: "public"}, {Allow: []string{"nope"}}, {Sealed: true}} {
		if _, err := Provision(context.Background(), newWorld(t).d, o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8": "10.0.0.0/8", "10.1.2.3/8": "10.0.0.0/8", " 192.168.1.1 ": "192.168.1.1/32", "::1": "::1/128",
		"::ffff:10.0.0.0/104": "10.0.0.0/8", "fe80::1%eth0": "fe80::1/128",
	} {
		p, err := ParseCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("%q → %v %v", in, p, err)
		}
	}
	for _, bad := range []string{"", "x", "10.0.0.0/33", "::ffff:10.0.0.0/8"} {
		if _, err := ParseCIDR(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	re := regexp.MustCompile(`^[a-km-np-zA-HJ-NP-Z2-9]{5}(-[a-km-np-zA-HJ-NP-Z2-9]{5}){3}$`)
	seen := map[string]bool{}
	for range 200 {
		p, err := GeneratePassword()
		if err != nil || !re.MatchString(p) || seen[p] {
			t.Fatalf("%q %v", p, err)
		}
		seen[p] = true
	}
}

func TestPrepareHome(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new", "home")
	p, err := PrepareHome(dir, ConfigOptions{Name: "box", HTTPSPort: 9443, HTTPPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Created || !p.Home.Exists() {
		t.Fatal("not created")
	}
	cfg, err := config.Load(p.Home)
	if err != nil || cfg.Server.Name != "box" || cfg.Server.HTTPSPort != 9443 || cfg.Server.HTTPPort != 0 || len(cfg.InstallID) != 32 {
		t.Fatalf("%+v %v", cfg, err)
	}
	for sub, mode := range map[string]os.FileMode{"": 0o750, "data": 0o700, "keys": 0o700, "logs": 0o750} {
		if fi, err := os.Stat(p.Home.Path(sub)); err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", sub, fi.Mode(), err)
		}
	}
	if _, err := PrepareHome(dir, ConfigOptions{}); !errors.Is(err, ErrExists) {
		t.Fatalf("second prepare: %v", err)
	}
	if err := p.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("created dir not removed")
	}

	// A pre-existing directory with installer files: only our additions are removed.
	pre := t.TempDir()
	os.MkdirAll(filepath.Join(pre, "bin"), 0o755)
	os.WriteFile(filepath.Join(pre, "bin", "fileparcel"), []byte("bin"), 0o755)
	os.MkdirAll(filepath.Join(pre, "keys"), 0o700) // empty data dir from a failed attempt
	p, err = PrepareHome(pre, ConfigOptions{})
	if err != nil || p.Created {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(pre, "keys", "master.key"), []byte("k"), 0o600)
	if err := p.Remove(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(pre)
	if len(entries) != 1 || entries[0].Name() != "bin" {
		t.Fatalf("left %v", entries)
	}
	if _, err := os.Stat(filepath.Join(pre, "bin", "fileparcel")); err != nil {
		t.Fatal("installer binary removed")
	}

	// Refusals: foreign content, damaged home, bad config values.
	foreign := t.TempDir()
	os.WriteFile(filepath.Join(foreign, "notes.txt"), nil, 0o644)
	if _, err := PrepareHome(foreign, ConfigOptions{}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatal(err)
	}
	damaged := t.TempDir()
	os.MkdirAll(filepath.Join(damaged, "data"), 0o700)
	os.WriteFile(filepath.Join(damaged, "data", "fileparcel.db"), []byte("db"), 0o600)
	if _, err := PrepareHome(damaged, ConfigOptions{}); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatal(err)
	}
	if _, err := PrepareHome(t.TempDir(), ConfigOptions{Name: "Bad Name"}); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := PrepareHome(t.TempDir(), ConfigOptions{HTTPSPort: -1}); err == nil {
		t.Fatal("bad port accepted")
	}
	if _, err := PrepareHome(t.TempDir(), ConfigOptions{HTTPSPort: 8080, HTTPPort: 8080}); err == nil {
		t.Fatal("same ports accepted")
	}
	if err := (*Prepared)(nil).Remove(); err != nil {
		t.Fatal(err)
	}
}
