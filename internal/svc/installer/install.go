package installer

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"strconv"
	"strings"

	"fileparcel/internal/auth"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/svc/provision"
)

// InstallOptions are the flags of `fileparcel install` (DESIGN §12, §14.1).
// Zero values mean "default" (asked interactively unless Yes).
type InstallOptions struct {
	Dir              string
	HTTPSPort        int  // 0 = default 8443 (next free port suggested)
	HTTPPort         *int // nil = default 8080; 0 = no redirect listener
	Name             string
	Service          string // user | system | none | "" (root → system, else user)
	Boot             *bool  // nil = yes
	Symlink          string // "" = default
	NoSymlink        bool
	Admin            string // "" = admin
	AdminPassword    string // from --admin-password-file/stdin ("" = generate)
	GeneratePassword bool
	AdminEmail       string
	Sealed           bool
	Passphrase       []byte
	Access           string // private | allowlist | any ("" = allowlist)
	Allow            []string
	Upgrade          bool // require an existing installation
	Force            bool // replace a foreign symlink / another home's service registration
	DryRun           bool
	Yes              bool
	NoStart          bool   // register but do not start the service
	SkipBackup       bool   // upgrade: no pre-upgrade backup
	SourceDir        string // where uninstall.sh and docs/ are ("" = FILEPARCEL_INSTALL_SOURCE / the verified release around the binary)
}

// expandHome turns a leading "~/" into the user's home directory.
func expandHome(p, userHome string) string {
	if p == "~" {
		return userHome
	}
	if strings.HasPrefix(p, "~/") && userHome != "" {
		return filepath.Join(userHome, p[2:])
	}
	return p
}

// absDir validates and cleans an install directory.
func (in *Installer) absDir(dir string) (string, error) {
	dir = expandHome(strings.TrimSpace(dir), in.Host.HomeDir)
	if dir == "" {
		return "", errors.New("empty install directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if svc.DangerousHome(abs, in.Host.HomeDir) {
		return "", fmt.Errorf("refusing to install into %s: choose a dedicated directory such as %s", abs, svc.DefaultHome(in.Host))
	}
	return abs, nil
}

func (in *Installer) askInt(question string, def, min int) (int, error) {
	for range 5 {
		s, err := in.Prompt.Ask(question, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err == nil && n >= min && n <= 65535 {
			return n, nil
		}
		in.infof("Please enter a number between %d and 65535.", min)
	}
	return 0, errors.New("too many invalid answers")
}

// installParams is the resolved install.
type installParams struct {
	h          *home.Home
	kind       svc.Kind
	boot       bool
	start      bool
	https      int
	http       int
	name       string
	symlink    string
	admin      string
	password   string // "" = generate
	email      string
	sealed     bool
	passphrase []byte
	access     string
	allow      []string
	svcUser    string
	notes      []string
}

// Install runs `fileparcel install`: a fresh install, or — when the
// directory already holds a home — an upgrade to the running binary.
func (in *Installer) Install(ctx context.Context, o InstallOptions) error {
	ia := in.interactive(o.Yes)
	dir := o.Dir
	if dir == "" {
		dir = svc.DefaultHome(in.Host)
		if ia {
			var err error
			if dir, err = in.Prompt.Ask("Install directory", dir); err != nil {
				return err
			}
		}
	}
	dir, err := in.absDir(dir)
	if err != nil {
		return err
	}
	h, err := home.New(dir)
	if err != nil {
		return err
	}
	if h.Exists() {
		return in.Upgrade(ctx, UpgradeOptions{Home: h, Binary: in.Executable, SourceDir: o.SourceDir, Force: o.Force,
			DryRun: o.DryRun, Yes: o.Yes, SkipBackup: o.SkipBackup, Install: &o})
	}
	if o.Upgrade {
		return fmt.Errorf("--upgrade: %s does not contain a FileParcel installation", dir)
	}
	p, err := in.resolveFresh(ctx, h, o, ia)
	if err != nil {
		return err
	}
	return in.fresh(ctx, p, o)
}

// resolveFresh applies defaults and asks the interactive questions.
func (in *Installer) resolveFresh(ctx context.Context, h *home.Home, o InstallOptions, ia bool) (*installParams, error) {
	p := &installParams{h: h, name: o.Name, email: o.AdminEmail, sealed: o.Sealed, passphrase: o.Passphrase,
		access: o.Access, allow: o.Allow, start: !o.NoStart}
	kind, why, err := svc.ResolveKind(in.Host, o.Service)
	if errors.Is(err, svc.ErrNeedsRoot) && o.DryRun && svc.SystemKind(in.Host.GOOS) != svc.KindNone {
		// A preview of the system install: say what it needs instead of
		// refusing to show the plan.
		kind, why, err = svc.SystemKind(in.Host.GOOS), "a system install needs root: run the installer with sudo", nil
	}
	if err != nil {
		return nil, err
	}
	p.kind = kind
	if why != "" {
		p.notes = append(p.notes, why)
	}
	if kind.System() {
		p.svcUser = svc.ServiceUser(in.Host)
	}
	if in.Host.Root() && kind == svc.KindNone {
		p.notes = append(p.notes, "installing as root without a service: \"fileparcel serve\" refuses to run as root unless --allow-root is given")
	}
	if pv := (provision.Options{Access: o.Access, Allow: o.Allow}); pv.Validate() != nil {
		return nil, pv.Validate()
	}
	// Everything the initialisation would refuse is checked here, before
	// the plan is shown: a dry run is a reliable preview, and a real run
	// never stops half-way on bad input.
	if p.name != "" && !config.ValidDNSLabel(p.name) {
		return nil, fmt.Errorf("invalid --name %q: use lowercase letters a-z, digits and '-' (1-63 characters, "+
			"not starting or ending with '-')", p.name)
	}
	if p.email != "" {
		if err := checkEmail(p.email); err != nil {
			return nil, fmt.Errorf("invalid --admin-email %q: %v", p.email, err)
		}
	}

	// Ports (DESIGN §14.2: free-port check, suggest the next free one). The
	// note about a replaced default is kept only when the suggestion is
	// what the install uses (not after another port was typed).
	p.https = o.HTTPSPort
	if p.https == 0 {
		def := provision.DefaultHTTPSPort
		note := ""
		if !in.portFree(def) {
			if n := svc.NextFreePort(def+1, in.portFree); n > 0 {
				note = fmt.Sprintf("port %d is in use; using %d instead", def, n)
				def = n
			}
		}
		p.https = def
		if ia {
			if p.https, err = in.askInt("HTTPS port", def, 1); err != nil {
				return nil, err
			}
		}
		if note != "" && p.https == def {
			p.notes = append(p.notes, note)
		}
	}
	if p.https < 1 || p.https > 65535 {
		return nil, fmt.Errorf("invalid HTTPS port %d", p.https)
	}
	if !o.DryRun && !in.portFree(p.https) {
		return nil, fmt.Errorf("port %d is already in use; choose another one with --port", p.https)
	}
	if o.HTTPPort != nil {
		p.http = *o.HTTPPort
	} else {
		def := provision.DefaultHTTPPort
		note := ""
		if def == p.https || !in.portFree(def) {
			if n := svc.NextFreePort(def+1, in.portFree, p.https); n > 0 {
				why := "is in use"
				if def == p.https {
					why = "is the HTTPS port"
				}
				note = fmt.Sprintf("port %d %s; the HTTP redirect uses %d instead", def, why, n)
				def = n
			}
		}
		p.http = def
		if ia {
			if p.http, err = in.askInt("HTTP port that redirects to HTTPS (0 = none)", def, 0); err != nil {
				return nil, err
			}
		}
		if note != "" && p.http == def {
			p.notes = append(p.notes, note)
		}
	}
	switch {
	case p.http < 0 || p.http > 65535:
		return nil, fmt.Errorf("invalid HTTP port %d", p.http)
	case p.http != 0 && p.http == p.https:
		return nil, errors.New("the HTTP and HTTPS ports must differ")
	case p.http != 0 && !o.DryRun && !in.portFree(p.http):
		return nil, fmt.Errorf("port %d is already in use; choose another one with --http-port (0 = none)", p.http)
	}
	if in.Host.GOOS == "linux" && (p.https < 1024 || (p.http > 0 && p.http < 1024)) && !in.Host.Root() {
		return nil, errors.New("ports below 1024 need a system install (root); use --port 8443 --http-port 8080")
	}

	// Boot (meaningless without a service: recorded as no).
	p.boot = kind != svc.KindNone
	if o.Boot != nil && kind != svc.KindNone {
		p.boot = *o.Boot
	} else if ia && kind != svc.KindNone {
		if p.boot, err = in.Prompt.Confirm("Start FileParcel automatically at boot?", true); err != nil {
			return nil, err
		}
	}

	// Admin account.
	p.admin = o.Admin
	if p.admin == "" {
		p.admin = provision.DefaultAdmin
		if ia {
			if p.admin, err = in.Prompt.Ask("Admin username", provision.DefaultAdmin); err != nil {
				return nil, err
			}
		}
	}
	if p.admin = strings.TrimSpace(p.admin); p.admin == "" || strings.ContainsAny(p.admin, " \t\r\n/\\") {
		return nil, fmt.Errorf("invalid admin username %q", p.admin)
	}
	p.password = o.AdminPassword
	owner := &core.User{Username: p.admin, Email: p.email, Role: core.RoleOwner}
	if p.password != "" {
		if err := auth.CheckDefaultPasswordPolicy(p.password, owner); err != nil {
			return nil, fmt.Errorf("the admin password is not accepted: %s", errMessage(err))
		}
	}
	if p.password == "" && !o.GeneratePassword && ia {
		gen, err := in.Prompt.Confirm("Generate a secure password for "+p.admin+"?", true)
		if err != nil {
			return nil, err
		}
		for try := 0; !gen; try++ {
			if p.password, err = in.Prompt.Secret("Password for "+p.admin+": ", true); err != nil {
				return nil, err
			}
			perr := auth.CheckDefaultPasswordPolicy(p.password, owner)
			if perr == nil {
				break
			}
			if try == 2 {
				return nil, fmt.Errorf("the admin password is not accepted: %s", errMessage(perr))
			}
			in.infof("%s; please choose another one.", errMessage(perr))
		}
	}

	// Sealed master key.
	if p.sealed && len(p.passphrase) == 0 {
		if !ia {
			return nil, errors.New("--sealed needs --passphrase-file or --passphrase-stdin (or run interactively)")
		}
		pp, err := in.Prompt.Secret("Master-key passphrase (needed after every restart): ", true)
		if err != nil {
			return nil, err
		}
		p.passphrase = []byte(pp)
	}

	// Command symlink.
	link, notes, err := in.resolveSymlink(h, o)
	if err != nil {
		return nil, err
	}
	p.symlink, p.notes = link, append(p.notes, notes...)
	if p.access == "" {
		p.access = core.AccessAllowlist
	}
	_ = ctx
	return p, nil
}

// resolveSymlink returns the command link of an install into h ("" with
// --no-symlink) and the notes for the plan, refusing what DESIGN §14.2 step
// 4 refuses: a relative path, a path inside the home (EnsureSymlink would
// replace a file of the installation, even with --force) and a foreign file
// or another link without --force. Fresh installs and repairs share it.
func (in *Installer) resolveSymlink(h *home.Home, o InstallOptions) (link string, notes []string, err error) {
	if o.NoSymlink {
		return "", nil, nil
	}
	link = expandHome(o.Symlink, in.Host.HomeDir)
	if link == "" {
		link = svc.DefaultSymlink(in.Host)
	}
	if !filepath.IsAbs(link) {
		return "", nil, fmt.Errorf("--symlink must be an absolute path (got %q)", link)
	}
	if svc.Within(h.Dir(), link) {
		return "", nil, errors.New("--symlink must be outside the install directory")
	}
	switch st, cur := svc.InspectSymlink(link, h.Binary()); st {
	case svc.SymlinkOther:
		if !o.Force {
			return "", nil, fmt.Errorf("%s already links to %s (another installation?); use --force to replace it or --no-symlink", link, cur)
		}
	case svc.SymlinkForeign:
		if !o.Force {
			return "", nil, fmt.Errorf("%s already exists and is not a symlink; use --force to replace it or --no-symlink", link)
		}
	}
	if !svc.OnPath(filepath.Dir(link), in.env("PATH")) {
		notes = append(notes, filepath.Dir(link)+" is not on your PATH; add it (e.g. in ~/.profile) to run \"fileparcel\" directly")
	}
	return link, notes, nil
}

// serviceOptions returns the svc.Options for the resolved install.
func (p *installParams) serviceOptions(force bool) svc.Options {
	return svc.Options{Kind: p.kind, Home: p.h.Dir(), Binary: p.h.Binary(), Boot: p.boot, User: p.svcUser,
		HTTPSPort: p.https, HTTPPort: p.http, Force: force}
}

// fresh builds and runs (or prints) the fresh-install plan.
func (in *Installer) fresh(ctx context.Context, p *installParams, o InstallOptions) error {
	h := p.h
	sf := in.supportFiles(in.Executable, o.SourceDir)
	var mgr svc.Manager
	if p.kind != svc.KindNone {
		host := in.Host
		if o.DryRun && p.kind.System() && !host.Root() {
			// The preview of a system install as a normal user (resolveFresh
			// noted that it needs root): the plan shows what root would do.
			h := *host
			h.UID = 0
			host = &h
		}
		m, err := svc.NewManager(host, p.serviceOptions(o.Force))
		if err != nil {
			return err
		}
		mgr = m
	}

	plan := &svc.Plan{Title: "FileParcel install plan"}
	if o.DryRun {
		plan.Title += " (dry run: nothing will be changed)"
	}
	plan.Fact("Install directory", h.Dir())
	plan.Fact("Version", in.Build.String())
	plan.Fact("Binary", in.Executable+" -> "+h.Binary())
	svcDesc := p.kind.Describe()
	if p.kind != svc.KindNone {
		svcDesc += ", start at boot: " + yesNo(p.boot)
		if p.kind == svc.KindSystemdUser && p.boot {
			svcDesc += " (enables linger for " + in.Host.User + ")"
		}
		if p.svcUser != "" {
			svcDesc += ", runs as " + p.svcUser
		}
	}
	plan.Fact("Service", svcDesc)
	ports := fmt.Sprintf("HTTPS %d", p.https)
	if p.http > 0 {
		ports += fmt.Sprintf(", HTTP redirect %d", p.http)
	}
	plan.Fact("Ports", ports)
	name := p.name
	if name == "" {
		name = provision.DefaultName
	}
	plan.Fact("Server name", name+".local")
	pw := "generated (shown once, must be changed at the first sign-in)"
	if p.password != "" {
		pw = "as provided"
	}
	plan.Fact("Admin", p.admin+", password "+pw)
	keyMode := "plain key file (unlocked automatically)"
	if p.sealed {
		keyMode = "sealed with a passphrase (unlock after every restart)"
	}
	plan.Fact("Master key", keyMode)
	access := p.access
	switch access {
	case core.AccessAllowlist:
		access += " (loopback + detected private LAN/Wi-Fi subnets, tailnet and VPN ranges"
		if len(p.allow) > 0 {
			access += " + " + strings.Join(p.allow, ", ")
		}
		access += ")"
	case core.AccessPrivate:
		access += " (loopback and the private address ranges"
		if len(p.allow) > 0 {
			access += " + " + strings.Join(p.allow, ", ")
		}
		access += ")"
	case core.AccessAny:
		access += " (every address: the server is reachable from the internet if the port is forwarded or the machine has a public address)"
	}
	plan.Fact("Network access", access)
	if p.symlink != "" {
		plan.Fact("Command", p.symlink+" -> "+h.Binary())
	}

	var res *provision.Result
	var rec *svc.Installed
	var createdUser string
	started, healthy := false, false
	var warnings []string

	if p.kind.System() {
		plan.Add("Create the service account "+p.svcUser+" (if missing)", func(ctx context.Context) error {
			created, err := svc.EnsureSystemUser(ctx, in.Host, p.svcUser, h.Dir())
			if created {
				createdUser = p.svcUser
			}
			return err
		})
	}
	plan.Add("Initialise "+h.Dir()+": layout, master key, local CA and certificates, network policy, owner "+p.admin+", backup identity",
		func(ctx context.Context) error {
			var err error
			res, err = in.Hooks.InitHome(ctx, h.Dir(),
				provision.ConfigOptions{Name: p.name, HTTPSPort: p.https, HTTPPort: portOrNone(p.http)},
				provision.Options{Admin: p.admin, AdminPassword: p.password, AdminEmail: p.email, Sealed: p.sealed,
					Passphrase: p.passphrase, Access: p.access, Allow: p.allow})
			return err
		}, "fileparcel.toml, data/, keys/master.key, certs/ (CA, client CA, leaf), owner account, backup identity")
	detail := []string{h.Binary() + " (0755), " + h.VersionFile()}
	if sf.Uninstall != "" {
		detail = append(detail, sf.Uninstall+" -> "+h.UninstallScript())
	}
	if sf.Docs != "" {
		detail = append(detail, sf.Docs+"/ -> "+h.DocsDir()+"/")
	}
	plan.Add("Install the binary and support files", func(ctx context.Context) error {
		return installFiles(h, in.Executable, sf, in.Build)
	}, detail...)
	if p.kind.System() {
		plan.Add("Give "+h.Dir()+" to "+p.svcUser+" (bin/ stays owned by root)", func(ctx context.Context) error {
			return giveHome(h, p.svcUser)
		})
	}
	if p.symlink != "" {
		plan.Add("Link "+p.symlink+" -> "+h.Binary(), func(ctx context.Context) error {
			_, err := svc.EnsureSymlink(p.symlink, h.Binary(), o.Force)
			return err
		})
	}
	lingerOurs := false
	if mgr != nil {
		title := "Register the " + p.kind.Describe()
		if p.boot {
			title += ", enable it at boot"
		}
		if p.start {
			title += " and start it"
		}
		d := []string{"registration: " + mgr.RegistrationPath()}
		if p.kind == svc.KindSystemdUser && p.boot {
			d = append(d, "loginctl enable-linger "+in.Host.User+" (if not enabled yet)")
		}
		plan.Add(title, func(ctx context.Context) error {
			if p.kind == svc.KindSystemdUser && p.boot {
				changed, err := svc.EnableLinger(ctx, in.Host)
				if err != nil {
					warnings = append(warnings, "could not enable linger ("+err.Error()+"): the service stops when you log out and does not start at boot until you run \"loginctl enable-linger "+in.Host.User+"\"")
				}
				lingerOurs = changed
			}
			if err := mgr.Install(ctx, p.start); err != nil {
				return err
			}
			started = p.start
			return nil
		}, d...)
	}
	// record writes installed.json; incomplete marks an install that failed
	// after initialising the home (the rerun repairs it, see Upgrade).
	record := func(incomplete bool) error {
		rec = &svc.Installed{Kind: p.kind, Boot: p.boot, LingerEnabledByUs: lingerOurs, Symlink: p.symlink,
			CreatedUser: createdUser, ServiceUser: p.svcUser, Home: h.Dir(), HTTPSPort: p.https, HTTPPort: p.http,
			Version: in.Build.Version, InstalledAt: in.now(), Incomplete: incomplete}
		if mgr != nil {
			rec.UnitPath = mgr.RegistrationPath()
		}
		if res != nil {
			fi := firewallInput(res, p.https, p.http, h.Binary())
			for _, s := range fi.Subnets {
				rec.FirewallSubnets = append(rec.FirewallSubnets, s.String())
			}
			rec.FirewallIfaces, rec.FirewallAnywhere = fi.VPNIfaces, fi.Anywhere
		}
		return in.writeRecord(h, rec)
	}
	plan.Add("Record the installation in "+svc.InstalledPath(h), func(ctx context.Context) error {
		return record(false)
	})
	if mgr != nil && p.start {
		plan.Add(fmt.Sprintf("Check https://127.0.0.1:%d/healthz (up to %s)", p.https, in.healthTimeout()), func(ctx context.Context) error {
			if err := in.healthWait(ctx, h, p.https); err != nil {
				warnings = append(warnings, "the server did not pass its health check yet: "+err.Error()+
					" (see \"fileparcel logs\" and \"fileparcel doctor\")")
				return nil
			}
			healthy = true
			return nil
		})
	}
	for _, n := range p.notes {
		plan.Note("Note: %s", n)
	}

	if o.DryRun {
		return plan.Print(in.Out)
	}
	if in.interactive(o.Yes) {
		if err := plan.Print(in.Err); err != nil {
			return err
		}
		ok, err := in.Prompt.Confirm("\nInstall now?", true)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("installation cancelled")
		}
	}
	if err := plan.Execute(ctx, in.Err); err != nil {
		ctx := context.WithoutCancel(ctx)
		if res == nil {
			// InitHome failed and removed the home again: the account this
			// run created serves nothing (a rerun would not record it).
			if createdUser != "" {
				if rerr := in.removeSystemUser(ctx, createdUser); rerr != nil {
					in.warnf("the installer created the service account %s and could not remove it again (%v); delete it yourself", createdUser, rerr)
				}
			}
			return err
		}
		// The home stays for the rerun: record it as incomplete, with the
		// linger and account this run created (uninstall must undo them),
		// and show the credentials, recovery key and backup identity, which
		// exist only here.
		if rerr := record(true); rerr != nil {
			in.warnf("could not record the incomplete installation: %v", rerr)
		}
		sum := in.installSummary(ctx, p, res, started, healthy)
		sum.Incomplete = true
		sum.Warnings = append(sum.Warnings, "the installation did not finish: "+err.Error()+
			"; after fixing the problem run the installer again on "+h.Dir()+" to finish (it detects the existing installation)")
		if perr := sum.Print(in.Out, in.JSON); perr != nil {
			in.warnf("%v", perr)
		}
		return err
	}
	warnings = append(warnings, p.notes...)
	if p.access == core.AccessAny {
		warnings = append(warnings, anyAccessWarning)
	}
	sum := in.installSummary(ctx, p, res, started, healthy)
	sum.Warnings = append(sum.Warnings, warnings...)
	return sum.Print(in.Out, in.JSON)
}

// anyAccessWarning is the summary's warning of --access any.
const anyAccessWarning = "network access is \"any\": every address may open the sign-in page, from the internet too if the " +
	"port is forwarded or the machine has a public address; require two-factor authentication, or narrow it later with " +
	"\"fileparcel network mode allowlist\""

// checkEmail validates an admin e-mail address like the user accounts do.
func checkEmail(s string) error {
	if len(s) > 254 {
		return errors.New("too long")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" || strings.ContainsAny(s, "\r\n<>\"") {
		return errors.New("expected an address like name@example.com")
	}
	return nil
}

// errMessage is the user-facing message of err (a core.Error's own text,
// without the field prefix).
func errMessage(err error) string {
	if ce := core.AsError(err); ce != nil && ce.Message != "" {
		return ce.Message
	}
	return err.Error()
}

func portOrNone(p int) int {
	if p == 0 {
		return -1
	}
	return p
}

func (in *Installer) healthTimeout() string {
	if in.HealthTimeout > 0 {
		return in.HealthTimeout.String()
	}
	return "30s"
}

// installSummary builds the summary of a fresh install (res.Warnings are
// included).
func (in *Installer) installSummary(ctx context.Context, p *installParams, res *provision.Result, started, healthy bool) *Summary {
	// The Tailscale hint is for the account the server runs as. A system
	// service runs as the service account, while CertCapable was probed in
	// this root process (root may always fetch certificates): it says
	// nothing about the account, which needs the operator step.
	user, sres := in.Host.User, res
	if p.kind.System() {
		user = p.svcUser
		if res != nil && res.Tailscale != nil && res.Tailscale.CertCapable {
			r, ts := *res, *res.Tailscale
			ts.CertCapable = false
			r.Tailscale = &ts
			sres = &r
		}
	}
	s := ResultSummary("install", in.Build.Version, sres, user)
	s.Home, s.Service, s.Boot, s.Started, s.Healthy, s.Symlink = p.h.Dir(), p.kind, p.boot, started, healthy, p.symlink
	if res != nil {
		fi := firewallInput(res, p.https, p.http, p.h.Binary())
		fi.BuiltinMDNS = svc.BuiltinMDNSLikely(in.Host)
		s.Firewall = firewallAdvice(svc.DetectFirewalls(ctx, in.Host), fi, false)
		s.FirewallAnywhere = fi.Anywhere
	}
	first := "open the recommended URL and sign in"
	if s.Admin != "" {
		first = "open the recommended URL and sign in as " + s.Admin
		if s.Password != "" {
			first += " (you will be asked to choose a new password)"
		}
	}
	s.NextSteps = append(s.NextSteps, first)
	if s.TrustURL != "" {
		s.NextSteps = append(s.NextSteps, "install the local CA on each device from "+s.TrustURL+" to get rid of certificate warnings")
	}
	if p.kind == svc.KindNone {
		s.NextSteps = append(s.NextSteps, "start the server: "+svc.ShellQuote(p.h.Binary())+" serve --home "+svc.ShellQuote(p.h.Dir()))
	}
	if p.sealed {
		s.NextSteps = append(s.NextSteps, "the server starts locked after every restart: unlock it at /unlock or with \"fileparcel keys unlock\"")
	}
	s.NextSteps = append(s.NextSteps, "check everything with \"fileparcel doctor\"; see \"fileparcel --help\" for administration from the command line")
	return s
}

// env reads an environment variable of the host.
func (in *Installer) env(k string) string {
	if in.Host.Getenv == nil {
		return ""
	}
	return in.Host.Getenv(k)
}
