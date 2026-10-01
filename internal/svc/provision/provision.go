// Package provision initialises a new FileParcel home (the logic behind
// `fileparcel init`, the fresh-install path of `fileparcel install` and
// `serve --init-if-missing`; DESIGN §12, §14.2 step 3, §14.7):
//
//  1. PrepareHome: create the layout (§3 modes) and write fileparcel.toml
//     (config.Default + name/ports) — before any service is built;
//  2. Provision, on services built over that home (wire.Build offline by the
//     caller): master key + keyring (Keys.Init, plain or sealed), local CA,
//     client CA and leaf (Certs.Init), the network access policy
//     (netinfo.DefaultAllowlist: the private LAN/Wi-Fi subnets and the ranges
//     of the VPNs devices come in through — never an exit or corporate VPN),
//     the owner account (Users.Bootstrap with an Auth-hashed
//     password, or a web setup token when no owner is requested) and the
//     backup identity (Backups.GenerateIdentity);
//  3. the Result carries what the summary shows once (generated password,
//     recovery key, backup identity) plus the access URLs and CA fingerprint.
//
// It imports no concrete service package (the caller wires them) except
// netinfo's pure DefaultAllowlist, so it is testable with fakes. Owned by
// unit I.
package provision

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/netip"
	"os"
	"slices"
	"strings"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/netinfo"
)

// Defaults (DESIGN §14.2, §11.1).
const (
	DefaultAdmin     = "admin"
	DefaultName      = "fileparcel"
	DefaultHTTPSPort = 8443
	DefaultHTTPPort  = 8080
)

// ConfigOptions are the bootstrap values written to fileparcel.toml.
type ConfigOptions struct {
	Name      string // server.name ("" = fileparcel)
	HTTPSPort int    // 0 = 8443
	HTTPPort  int    // 0 = 8080; -1 = no redirect listener
}

// layoutNames are the entries a home may contain before init (the installer
// copies the binary, docs and uninstall.sh first).
var layoutNames = map[string]bool{
	"bin": true, "docs": true, "data": true, "keys": true, "certs": true, "backups": true, "logs": true, "tmp": true,
	"run": true, "service": true, "uninstall.sh": true, "VERSION": true,
}

// ErrExists is returned when the directory is already a FileParcel home.
var ErrExists = errors.New("already a FileParcel home")

// dataDirs are layout directories that must be empty in a directory being
// initialised: content there means a damaged home (fileparcel.toml lost),
// which init must never overwrite or clean up.
var dataDirs = map[string]bool{"data": true, "keys": true, "certs": true, "backups": true}

// Prepared describes a home created by PrepareHome.
type Prepared struct {
	Home   *home.Home
	Config *config.Config
	// Created reports whether the directory itself was created.
	Created bool
	// existed lists the entries that were there before (never removed by Remove).
	existed map[string]bool
}

// PrepareHome creates the home layout in dir and writes fileparcel.toml. It
// refuses a directory that is already a home, one that contains anything but
// FileParcel layout entries (so `init --home ~/Documents` cannot scatter
// files into a user folder), and one whose data/keys/certs/backups
// directories are not empty (a damaged home). Call Remove on the result when
// a later step fails.
func PrepareHome(dir string, o ConfigOptions) (*Prepared, error) {
	h, err := home.New(dir)
	if err != nil {
		return nil, err
	}
	p, err := inspectHome(h, o)
	if err != nil {
		return nil, err
	}
	if err := p.create(); err != nil {
		return nil, err
	}
	return p, nil
}

// inspectHome runs the checks of PrepareHome without changing anything and
// returns the Prepared that create completes.
func inspectHome(h *home.Home, o ConfigOptions) (*Prepared, error) {
	if h.Exists() {
		return nil, fmt.Errorf("%s: %w", h.Dir(), ErrExists)
	}
	p := &Prepared{Home: h, existed: map[string]bool{}}
	entries, err := os.ReadDir(h.Dir())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		p.Created = true
	case err != nil:
		return nil, err
	default:
		for _, e := range entries {
			if !layoutNames[e.Name()] {
				return nil, fmt.Errorf("%s is not empty (found %q); choose an empty or new directory", h.Dir(), e.Name())
			}
			if dataDirs[e.Name()] {
				if !onlyEmptyDirs(h.Path(e.Name())) {
					return nil, fmt.Errorf("%s contains %s/ with data but no fileparcel.toml: this looks like a damaged home; restore its fileparcel.toml instead of running init", h.Dir(), e.Name())
				}
				continue // empty: Remove may delete it again
			}
			p.existed[e.Name()] = true
		}
	}
	cfg := config.Default(config.NewInstallID())
	if o.Name != "" {
		cfg.Server.Name = o.Name
	}
	switch {
	case o.HTTPSPort > 0:
		cfg.Server.HTTPSPort = o.HTTPSPort
	case o.HTTPSPort < 0:
		return nil, errors.New("invalid HTTPS port")
	}
	switch {
	case o.HTTPPort > 0:
		cfg.Server.HTTPPort = o.HTTPPort
	case o.HTTPPort < 0:
		cfg.Server.HTTPPort = 0
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p.Config = cfg
	return p, nil
}

// create makes the layout and writes fileparcel.toml; a failure is undone
// with Remove.
func (p *Prepared) create() error {
	if err := p.Home.EnsureLayout(); err != nil {
		_ = p.Remove()
		return err
	}
	if err := p.Config.SaveTo(p.Home.Config()); err != nil {
		_ = p.Remove()
		return err
	}
	return nil
}

// onlyEmptyDirs reports whether dir contains nothing but (nested) empty directories.
func onlyEmptyDirs(dir string) bool {
	empty := true
	_ = fs.WalkDir(os.DirFS(dir), ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			empty = false
			return fs.SkipAll
		}
		return nil
	})
	return empty
}

// Remove undoes PrepareHome after a failed init: it deletes the directory
// when PrepareHome created it, otherwise only the entries it added (never
// anything that was there before).
func (p *Prepared) Remove() error {
	if p == nil || p.Home == nil {
		return nil
	}
	if p.Created {
		return os.RemoveAll(p.Home.Dir())
	}
	var errs []error
	entries, err := os.ReadDir(p.Home.Dir())
	if err != nil {
		return err
	}
	for _, e := range entries {
		if p.existed[e.Name()] {
			continue
		}
		if layoutNames[e.Name()] || e.Name() == home.ConfigName {
			errs = append(errs, os.RemoveAll(p.Home.Path(e.Name())))
		}
	}
	return errors.Join(errs...)
}

// Options configure Provision.
type Options struct {
	// Admin is the owner's username; "" = no owner (a one-time web setup
	// token is created instead, DESIGN §9.4 POST /auth/setup).
	Admin string
	// AdminPassword is the owner's password; "" generates one (returned in
	// Result.Password, marked must-change).
	AdminPassword string
	AdminEmail    string
	// Sealed creates a passphrase-sealed master key (Passphrase required).
	Sealed     bool
	Passphrase []byte
	// Access is network.access_mode (private | allowlist | any; "" = allowlist).
	Access string
	// Allow are extra CIDRs/IPs for network.allow_cidrs.
	Allow []string
	// SkipBackupIdentity leaves the backup identity for later.
	SkipBackupIdentity bool
}

// Result is what Provision did; secrets in it are shown once.
type Result struct {
	Home              string           `json:"home"`
	Owner             string           `json:"owner,omitempty"`
	Password          string           `json:"password,omitempty"` // generated password (shown once)
	PasswordGenerated bool             `json:"password_generated"`
	SetupToken        string           `json:"setup_token,omitempty"`  // when no owner was created
	RecoveryKey       string           `json:"recovery_key,omitempty"` // sealed mode (shown once)
	KeyMode           string           `json:"key_mode"`
	BackupRecipient   string           `json:"backup_recipient,omitempty"`
	BackupIdentity    string           `json:"backup_identity,omitempty"` // shown once
	CAFingerprint     string           `json:"ca_fingerprint,omitempty"`
	AccessMode        string           `json:"access_mode"`
	AllowCIDRs        []string         `json:"allow_cidrs"`
	URLs              []core.AccessURL `json:"urls,omitempty"`
	Warnings          []string         `json:"warnings,omitempty"`
	// Interfaces and Tailscale describe the network (for firewall and
	// Tailscale hints in the installer summary).
	Interfaces []core.NetInterface `json:"interfaces,omitempty"`
	Tailscale  *core.TailscaleInfo `json:"tailscale,omitempty"`
}

// Validate checks the options before anything is created.
func (o Options) Validate() error {
	switch o.Access {
	case "", core.AccessPrivate, core.AccessAllowlist, core.AccessAny:
	default:
		return fmt.Errorf("access mode must be private, allowlist or any (got %q)", o.Access)
	}
	for _, a := range o.Allow {
		if _, err := ParseCIDR(a); err != nil {
			return err
		}
	}
	if o.Sealed && len(o.Passphrase) == 0 {
		return errors.New("a sealed master key needs a passphrase")
	}
	return nil
}

// ParseCIDR parses a CIDR or a single IP (→ /32 or /128), masked and with
// IPv4-mapped addresses unmapped.
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid CIDR or IP address %q", s)
}

// Provision initialises keys, certificates, the network policy, the owner
// and the backup identity on freshly built services (see the package doc).
// Failures of the optional steps (network policy, backup identity, URLs)
// become Result.Warnings; key, certificate and owner failures abort.
func Provision(ctx context.Context, d *app.Deps, o Options) (*Result, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	sys := core.SystemPrincipal(core.ViaOffline)
	ctx = core.WithPrincipal(ctx, sys)
	res := &Result{KeyMode: core.KeyModePlain}
	if d.Env != nil && d.Home != nil {
		res.Home = d.Home.Dir()
	}
	if o.Sealed {
		res.KeyMode = core.KeyModeSealed
	}

	// 1. Master key + keyring.
	rk, err := d.Keys.Init(ctx, o.Sealed, o.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	res.RecoveryKey = rk

	// 2. Local CA, client CA and leaf.
	if err := d.Certs.Init(ctx); err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	res.CAFingerprint = d.Certs.Fingerprint()

	// 3. Network access policy (fails closed: the catalog default is an
	// allowlist that admits only loopback).
	res.AccessMode = o.Access
	if res.AccessMode == "" {
		res.AccessMode = core.AccessAllowlist
	}
	ifaces, err := d.Network.Interfaces(ctx)
	if err != nil {
		res.Warnings = append(res.Warnings, "could not list network interfaces, so no local network was added to the allow list "+
			"(add yours with `fileparcel network allow add <cidr>`): "+err.Error())
	}
	res.Interfaces = ifaces
	// Tailscale for the allowlist (Headscale's prefixes) and the summary's
	// hints (certificates, Funnel): a Tailscale/Headscale interface, or a
	// running tailscaled without one (userspace networking: Serve and
	// Funnel work there too).
	ts, _ := d.Network.Tailscale(ctx)
	tsIface := slices.ContainsFunc(ifaces, func(in core.NetInterface) bool {
		return in.Up && (in.Kind == core.IfTailscale || in.Kind == core.IfHeadscale)
	})
	if ts != nil && (tsIface || ts.Running) {
		res.Tailscale = ts
	}
	allow, notes := netinfo.DefaultAllowlist(ifaces, res.Tailscale)
	res.Warnings = append(res.Warnings, notes...)
	for _, a := range o.Allow {
		p, _ := ParseCIDR(a)
		if !slices.Contains(allow, p.String()) {
			allow = append(allow, p.String())
		}
	}
	res.AllowCIDRs = allow
	if err := applyPolicy(ctx, d, sys, res.AccessMode, allow); err != nil {
		res.Warnings = append(res.Warnings, "could not store the network policy (only this machine can connect until it is set): "+err.Error())
	}

	// 4. Owner account or web setup token.
	if o.Admin != "" {
		pw := o.AdminPassword
		if pw == "" {
			pw, err = GeneratePassword()
			if err != nil {
				return nil, err
			}
			res.Password, res.PasswordGenerated = pw, true
		}
		u := &core.User{Username: o.Admin, Email: o.AdminEmail, Role: core.RoleOwner}
		if err := d.Auth.CheckPasswordPolicy(pw, u); err != nil {
			return nil, fmt.Errorf("admin password: %w", err)
		}
		phc, err := d.Auth.HashPassword(pw)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
		owner, err := d.Users.Bootstrap(ctx, core.NewUser{Username: o.Admin, Email: o.AdminEmail, Role: core.RoleOwner,
			PasswordHash: phc, MustChangePassword: res.PasswordGenerated})
		if err != nil {
			return nil, fmt.Errorf("owner account: %w", err)
		}
		res.Owner = owner.Username
	} else {
		tok, err := d.Auth.SetupToken(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, "could not create the setup token (it is printed when the server starts): "+err.Error())
		}
		res.SetupToken = tok
	}

	// 5. Backup identity (the recipient is stored for scheduled backups; the
	// identity is shown once for safekeeping).
	if !o.SkipBackupIdentity && d.Backups != nil {
		rcpt, ident, err := d.Backups.GenerateIdentity(ctx, sys)
		if err != nil {
			res.Warnings = append(res.Warnings, "backup identity not created (run \"fileparcel backup identity generate\" later): "+err.Error())
		} else {
			res.BackupRecipient, res.BackupIdentity = rcpt, ident
		}
	}

	// 6. Where to reach the server.
	if urls, err := d.Network.URLs(ctx); err == nil {
		res.URLs = urls
	}
	return res, nil
}

// applyPolicy writes network.access_mode and network.allow_cidrs through the
// settings store, falling back to Network.SetPolicy.
func applyPolicy(ctx context.Context, d *app.Deps, sys *core.Principal, mode string, allow []string) error {
	if allow == nil {
		allow = []string{}
	}
	var errs []error
	if d.Settings != nil {
		m, _ := json.Marshal(mode)
		a, _ := json.Marshal(allow)
		_, err := d.Settings.Set(ctx, sys, map[string]json.RawMessage{"network.access_mode": m, "network.allow_cidrs": a})
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	if d.Network != nil {
		pol := d.Network.Policy()
		pol.Mode, pol.Allow = mode, allow
		if pol.Deny == nil {
			pol.Deny = []string{}
		}
		_, err := d.Network.SetPolicy(ctx, sys, pol, netip.IPv6Loopback(), true)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// passwordAlphabet has no look-alike characters (0/O, 1/l/I).
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GeneratePassword returns a random password of four dash-separated groups
// of five characters from an unambiguous alphabet (≈116 bits).
func GeneratePassword() (string, error) {
	var b strings.Builder
	n := big.NewInt(int64(len(passwordAlphabet)))
	for i := range 20 {
		if i > 0 && i%5 == 0 {
			b.WriteByte('-')
		}
		x, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b.WriteByte(passwordAlphabet[x.Int64()])
	}
	return b.String(), nil
}
