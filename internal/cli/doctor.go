package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/buildinfo"
	"fileparcel/internal/config"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/web/opsapi"
)

func init() { Register(newDoctorCmd) }

// Doctor check statuses (the same values as GET /admin/system/doctor).
const (
	lcOK   = "ok"
	lcWarn = "warn"
	lcFail = "fail"
	lcInfo = "info"
)

// lcCheck is one doctor result.
type lcCheck struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Fixed   bool   `json:"fixed,omitempty"` // repaired by --fix
}

// lcDoctorReport is the output of `fileparcel doctor` (--json).
type lcDoctorReport struct {
	Home     string    `json:"home"`
	OK       bool      `json:"ok"`
	Failures int       `json:"failures"`
	Warnings int       `json:"warnings"`
	Fixed    int       `json:"fixed"`
	Checks   []lcCheck `json:"checks"`
}

// lcDoctor runs the local checks of one home.
type lcDoctor struct {
	h    *home.Home
	host *svc.Host
	fix  bool
	now  time.Time

	cfg     *config.Config
	rec     *svc.Installed
	running bool // the admin socket answers
	checks  []lcCheck
}

func (d *lcDoctor) add(c lcCheck) { d.checks = append(d.checks, c) }

func newDoctorCmd() *cobra.Command {
	var fix bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the installation and fix common problems",
		Long: `Check the FileParcel installation: configuration, directory and key file
permissions, the binary, the running server (admin socket, health check), the
service registration and linger, certificates, the command link, ports and the
firewall. When the server is running its own checks (keys, certificates,
backups, disk, database, jobs, …) are included.

--fix applies the safe repairs: file and directory modes, ownership (as root:
files in the home that its account does not own), stale socket and PID files
of a crashed server, and linger for a start-at-boot user service.

Exit status 1 when a check failed.`,
		Example: `  fileparcel doctor
  fileparcel doctor --fix
  fileparcel doctor --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			d := &lcDoctor{h: h, host: svc.CurrentHost(), fix: fix, now: time.Now()}
			rep := d.run(lcCtx(cmd))
			if err := Print(cmd, rep, func(w io.Writer) error { return lcRenderDoctor(w, rep) }); err != nil {
				return err
			}
			if !rep.OK {
				return &ExitCodeError{Code: ExitFailure}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, "apply the safe fixes")
	return cmd
}

// run performs every check.
func (d *lcDoctor) run(ctx context.Context) *lcDoctorReport {
	rep := &lcDoctorReport{Home: d.h.Dir()}
	if d.checkHome() {
		d.checkPerms()
		d.checkOwner()
		d.checkKeysFile()
		d.checkBinary()
		srv := d.checkServer(ctx)
		d.checkService(ctx)
		d.checkCerts()
		d.checkSymlink()
		d.checkPorts()
		d.checkFirewall(ctx)
		d.checkRestore()
		if srv != nil {
			d.serverChecks(ctx, srv)
			srv.Close()
		} else {
			d.checkIngressOffline(ctx)
		}
	}
	rep.Checks = d.checks
	for _, c := range rep.Checks {
		switch c.Status {
		case lcFail:
			rep.Failures++
		case lcWarn:
			rep.Warnings++
		}
		if c.Fixed {
			rep.Fixed++
		}
	}
	rep.OK = rep.Failures == 0
	return rep
}

func (d *lcDoctor) checkHome() bool {
	c := lcCheck{ID: "home", Name: "Home directory"}
	if !d.h.Exists() {
		c.Status, c.Message = lcFail, d.h.Dir()+" contains no "+home.ConfigName
		c.Hint = "Run \"fileparcel install\" or \"fileparcel init --home DIR\", or point --home at the installation."
		d.add(c)
		return false
	}
	// The service record does not depend on the config: read it first, so a
	// broken fileparcel.toml does not also turn the service, binary, link
	// and linger checks into "no service is registered".
	d.rec, _ = svc.ReadInstalled(d.h)
	cfg, err := config.Load(d.h)
	if err != nil {
		c.Status, c.Message = lcFail, "fileparcel.toml: "+err.Error()
		c.Hint = "Fix the file (\"fileparcel config edit\" validates it)."
		d.add(c)
		return true
	}
	d.cfg = cfg
	c.Status, c.Message = lcOK, d.h.Dir()
	if ws := cfg.Warnings(); len(ws) > 0 {
		c.Status, c.Message = lcWarn, "fileparcel.toml: "+strings.Join(ws, "; ")
	}
	d.add(c)
	return true
}

// lcLayoutModes are the expected modes of the home layout (DESIGN §3).
var lcLayoutModes = []struct {
	rel  string
	mode fs.FileMode
}{
	{"", home.ModeHome}, {"data", home.ModePrivate}, {"data/blobs", home.ModePrivate}, {"keys", home.ModePrivate},
	{"certs", home.ModePrivate}, {"backups", home.ModePrivate}, {"logs", home.ModeLogs}, {"tmp", home.ModePrivate},
	{"run", home.ModePrivate}, {"service", home.ModeService},
}

// checkPerms compares directory modes with the layout and looks for secret
// files readable by group/others; --fix re-applies the modes.
func (d *lcDoctor) checkPerms() {
	c := lcCheck{ID: "permissions", Name: "File permissions"}
	var probs []string
	for _, lm := range lcLayoutModes {
		rel, want := lm.rel, lm.mode
		p := d.h.Path(rel)
		fi, err := os.Stat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			probs = append(probs, lcRel(rel)+" missing")
		case err != nil:
			probs = append(probs, err.Error())
		case rel == "" && home.IsSystemHomeMode(fi.Mode()):
			// A system install's HOME: root:<service group> 01770 (DESIGN §14.4).
		case fi.Mode().Perm() != want:
			probs = append(probs, fmt.Sprintf("%s is %04o (want %04o)", lcRel(rel), fi.Mode().Perm(), want))
		}
	}
	secret := d.secretFiles()
	var loose []string
	for _, p := range secret {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			loose = append(loose, p)
			rel, _ := filepath.Rel(d.h.Dir(), p)
			probs = append(probs, fmt.Sprintf("%s is %04o (want 0600)", rel, fi.Mode().Perm()))
		}
	}
	if fi, err := os.Stat(d.h.Config()); err == nil && fi.Mode().Perm()&0o027 != 0 {
		loose = append(loose, d.h.Config())
		probs = append(probs, fmt.Sprintf("%s is %04o (want 0640)", home.ConfigName, fi.Mode().Perm()))
	}
	if len(probs) == 0 {
		c.Status, c.Message = lcOK, "directory and key file modes are as expected"
		d.add(c)
		return
	}
	c.Status, c.Message = lcWarn, strings.Join(probs, "; ")
	c.Hint = "Run \"fileparcel doctor --fix\"."
	if d.fix {
		err := d.h.EnsureLayout()
		for _, p := range loose {
			mode := fs.FileMode(0o600)
			if p == d.h.Config() {
				mode = home.ModeConfig
			}
			err = errors.Join(err, os.Chmod(p, mode))
		}
		if err == nil {
			c.Status, c.Fixed, c.Hint = lcOK, true, ""
			c.Message = "repaired: " + c.Message
		} else {
			c.Message += " (fix failed: " + err.Error() + ")"
		}
	}
	d.add(c)
}

// checkOwner looks for entries of the home (bin/ and uninstall.sh aside) that
// its account does not own — left by an admin command run as root with an
// older release, or copied in by hand. The server runs as that account and
// cannot read root's 0600 files. --fix, as root, gives them back (checkPerms,
// which runs first, may just have created directories as root).
func (d *lcDoctor) checkOwner() {
	o, ok := lcOwnerOf(d.h)
	if !ok {
		return // a home root owns itself: nothing to compare with
	}
	c := lcCheck{ID: "ownership", Name: "File ownership"}
	n, first, partial := lcForeignEntries(d.h, o)
	switch {
	case n == 0 && partial:
		c.Status, c.Message = lcInfo, "not every directory of the home is readable by this user, so not every owner was checked"
		c.Hint = "Run the doctor as root or as " + o.name + "."
		d.add(c)
		return
	case n == 0:
		c.Status, c.Message = lcOK, "the home belongs to "+o.name
		d.add(c)
		return
	}
	c.Status = lcWarn
	c.Message = fmt.Sprintf("%s in the home not owned by %s, the account the server runs as: %s",
		Plural(n, "entry"), o.name, strings.Join(first, ", "))
	if n > int64(len(first)) {
		c.Message += ", …"
	}
	c.Hint = "Run \"sudo fileparcel doctor --fix\"."
	if d.fix && lcGeteuid() == 0 {
		if err := lcGiveHome(d.h, o); err != nil {
			c.Message += " (fix failed: " + err.Error() + ")"
		} else {
			c.Status, c.Fixed, c.Hint = lcOK, true, ""
			c.Message = "repaired: " + c.Message
		}
	}
	d.add(c)
}

// secretFiles lists the files that must not be readable by others: the
// master key, certificate keys (including the plaintext Tailscale key
// certs/tailscale/key.pem), the database and the restore key. Under keys/
// and certs/ only public certificates are exempt: *.crt and cert.pem
// (custom/, tailscale/), which are written world-readable on purpose.
func (d *lcDoctor) secretFiles() []string {
	var out []string
	for _, dir := range []string{d.h.KeysDir(), d.h.CertsDir()} {
		_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
			public := strings.HasSuffix(p, ".crt") || filepath.Base(p) == "cert.pem"
			if err == nil && e.Type().IsRegular() && !public {
				out = append(out, p)
			}
			return nil
		})
	}
	for _, p := range []string{d.h.DB(), d.h.DB() + "-wal", d.h.DB() + "-shm", filepath.Join(d.h.RunDir(), "restore.key")} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func lcRel(rel string) string {
	if rel == "" {
		return "the home directory"
	}
	return rel + "/"
}

func (d *lcDoctor) checkKeysFile() {
	c := lcCheck{ID: "keys.file", Name: "Master key file"}
	fi, err := os.Stat(d.h.KeysFile())
	switch {
	case err != nil:
		c.Status, c.Message = lcFail, "keys/master.key is missing: the server cannot decrypt anything"
		c.Hint = "Restore the home (including keys/) from a backup; see \"fileparcel backup restore --help\"."
	case fi.Size() == 0:
		c.Status, c.Message = lcFail, "keys/master.key is empty"
	default:
		c.Status, c.Message = lcOK, "present"
	}
	d.add(c)
}

func (d *lcDoctor) checkBinary() {
	c := lcCheck{ID: "binary", Name: "Server binary"}
	fi, err := os.Stat(d.h.Binary())
	switch {
	case err != nil:
		c.Status, c.Message = lcWarn, "bin/fileparcel is missing"
		c.Hint = "The service runs bin/fileparcel; reinstall with install.sh --dir " + svc.ShellQuote(d.h.Dir()) + "."
		if d.rec == nil || d.rec.Kind == svc.KindNone {
			c.Status = lcInfo
			c.Message += " (no service is registered, so it is not needed)"
			c.Hint = ""
		}
	case fi.Mode().Perm()&0o111 == 0:
		c.Status, c.Message = lcFail, "bin/fileparcel is not executable"
		c.Hint = "chmod 755 " + svc.ShellQuote(d.h.Binary())
	default:
		v := lcFirstLine(d.h.VersionFile())
		c.Status, c.Message = lcOK, "installed "+Dash(v)
		if me := buildinfo.Get(); v != "" && !strings.HasPrefix(v, me.Version+" ") && v != me.Version {
			c.Message += "; this command is " + me.Version
		}
	}
	d.add(c)
}

// checkServer reports the running state; it returns a socket client when the
// server answers (for the health check and the server-side checks).
func (d *lcDoctor) checkServer(ctx context.Context) *Client {
	c := lcCheck{ID: "server", Name: "Server process"}
	cl, err := connectSocket(d.h, Options{})
	switch {
	case err == nil:
		d.running = true
		c.Status, c.Message = lcOK, "running (admin socket answers)"
		if G.Offline {
			// doctor's job is to inspect the home as it is, so it never
			// refuses because the server runs; say the flag had no effect.
			c.Hint = "--offline was ignored: doctor always inspects the home locally and asks the running server for its own checks."
		}
		d.add(c)
		d.checkHealth(ctx)
		return cl
	case !errors.Is(err, errNoServer):
		c.Status, c.Message = lcWarn, err.Error()
		d.add(c)
		return nil
	}
	if lcHomeBusy(d.h) {
		c.Status, c.Message = lcWarn, "the home lock is held but the admin socket does not answer"
		c.Hint = "Either an offline admin command is running (wait for it), or the server hangs: restart it (fileparcel service restart)."
		if d.cfg != nil && !d.cfg.AdminSocket.Enabled {
			c.Status, c.Message, c.Hint = lcInfo, "running (the admin socket is disabled in fileparcel.toml)", ""
		}
		d.add(c)
		return nil
	}
	c.Status, c.Message = lcInfo, "not running"
	var stale []string
	for _, p := range []string{d.h.Socket(), d.h.PIDFile()} {
		if _, err := os.Lstat(p); err == nil {
			stale = append(stale, p)
		}
	}
	if len(stale) > 0 {
		c.Status = lcWarn
		c.Message += "; stale files of a crashed server: " + strings.Join(stale, ", ")
		c.Hint = "Run \"fileparcel doctor --fix\" to remove them."
		if d.fix {
			var errs []error
			for _, p := range stale {
				errs = append(errs, os.Remove(p))
			}
			if err := errors.Join(errs...); err == nil {
				c.Status, c.Fixed, c.Hint = lcInfo, true, ""
				c.Message = "not running; removed stale " + strings.Join(stale, ", ")
			} else {
				c.Message += " (fix failed: " + err.Error() + ")"
			}
		}
	}
	d.add(c)
	return nil
}

func (d *lcDoctor) checkHealth(ctx context.Context) {
	c := lcCheck{ID: "health", Name: "HTTPS health check"}
	u, err := svc.HealthCheckURL(ctx, d.h, 0, 5*time.Second)
	if err != nil {
		c.Status, c.Message = lcFail, err.Error()
		c.Hint = "See \"fileparcel logs\"; the listeners may have failed (port in use?)."
	} else {
		c.Status, c.Message = lcOK, u+" answers (certificate verified against the local CA)"
	}
	d.add(c)
}

func (d *lcDoctor) checkService(ctx context.Context) {
	c := lcCheck{ID: "service", Name: "Service"}
	if d.rec == nil || d.rec.Kind == svc.KindNone || d.rec.Kind == "" {
		c.Status, c.Message = lcInfo, "no service is registered"
		c.Hint = "Register one with \"fileparcel service install --start\" to run FileParcel in the background and at boot."
		d.add(c)
		return
	}
	e := &lcSvcEnv{h: d.h, host: d.host, rec: d.rec}
	m, err := e.manager(ctx)
	if err != nil {
		c.Status, c.Message = lcWarn, d.rec.Kind.Describe()+": "+err.Error()
		d.add(c)
		return
	}
	st, err := m.Status(ctx)
	switch {
	case err != nil:
		c.Status, c.Message = lcWarn, err.Error()
	case !st.Installed:
		c.Status, c.Message = lcFail, d.rec.Kind.Describe()+" is recorded but not registered ("+st.Registration+")"
		c.Hint = "Run \"fileparcel service install --start\"."
	case !st.Active:
		c.Status, c.Message = lcWarn, d.rec.Kind.Describe()+" is "+Dash(st.State)
		if st.Detail != "" {
			c.Message += " (" + st.Detail + ")"
		}
		c.Hint = "Start it with \"fileparcel service start\"; see \"fileparcel logs\"."
	default:
		c.Status, c.Message = lcOK, d.rec.Kind.Describe()+" is "+st.State
		if d.rec.Boot && !st.Enabled {
			c.Status, c.Message = lcWarn, c.Message+", but not enabled at boot"
			c.Hint = "Run \"fileparcel service enable-boot\"."
		}
	}
	d.add(c)
	if d.rec.Kind == svc.KindSystemdUser && d.rec.Boot {
		d.checkLinger(ctx)
	}
}

func (d *lcDoctor) checkLinger(ctx context.Context) {
	c := lcCheck{ID: "linger", Name: "Linger (start at boot, keep running after logout)"}
	if svc.LingerEnabled(d.host) {
		c.Status, c.Message = lcOK, "enabled for "+d.host.User
		d.add(c)
		return
	}
	c.Status, c.Message = lcWarn, "disabled: the user service stops at logout and does not start at boot"
	c.Hint = "Run \"loginctl enable-linger " + d.host.User + "\" or \"fileparcel doctor --fix\"."
	if d.fix {
		changed, err := svc.EnableLinger(ctx, d.host)
		if err == nil {
			c.Status, c.Fixed, c.Hint, c.Message = lcOK, true, "", "enabled for "+d.host.User
			if changed {
				rec := *d.rec
				rec.LingerEnabledByUs = true
				_ = svc.WriteInstalled(d.h, &rec)
			}
		} else {
			c.Message += " (fix failed: " + err.Error() + ")"
		}
	}
	d.add(c)
}

// checkCerts reads the CA and leaf certificates from disk.
func (d *lcDoctor) checkCerts() {
	for _, cc := range []struct{ id, name, file string }{
		{"cert.ca", "Local CA", svc.CACertPath(d.h)},
		{"cert.leaf", "Server certificate", filepath.Join(d.h.CertsDir(), "server", "leaf.crt")},
	} {
		c := lcCheck{ID: cc.id, Name: cc.name}
		cert, err := lcReadCert(cc.file)
		switch {
		case err != nil:
			c.Status, c.Message = lcFail, err.Error()
			c.Hint = "Run \"fileparcel cert renew\" (the server recreates missing certificates at start)."
		case d.now.After(cert.NotAfter):
			c.Status, c.Message = lcFail, "expired on "+cert.NotAfter.Local().Format("2006-01-02")
			c.Hint = "Run \"fileparcel cert renew\"."
		case cert.NotAfter.Sub(d.now) < certWarnBefore(cc.id, cert):
			c.Status, c.Message = lcWarn, "expires on "+cert.NotAfter.Local().Format("2006-01-02")
			c.Hint = "The server renews the leaf automatically; \"fileparcel cert renew\" forces it."
		default:
			c.Status, c.Message = lcOK, "valid until "+cert.NotAfter.Local().Format("2006-01-02")
		}
		d.add(c)
	}
}

// certWarnBefore is how close to its expiry a certificate is reported: the
// server doctor's thresholds (opsapi.CertWarnBefore), since serverChecks
// drops the server's cert.ca and cert.leaf in favour of these and the two
// doctors must not disagree about the same certificate. That is 90 days for
// the CA; for the leaf, half its renewal window (min(30 days, a third of its
// lifetime), certs.renewBefore, DESIGN §10.4), at most 14 days, so only an
// overdue renewal shows. A fixed 30 days flagged every healthy short-lived
// leaf (tls.leaf_days may be as low as 7) all the time.
func certWarnBefore(id string, cert *x509.Certificate) time.Duration {
	return opsapi.CertWarnBefore(id == "cert.ca", cert.NotBefore, cert.NotAfter)
}

// lcReadCert parses the first certificate of a PEM file.
func lcReadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s is missing", filepath.Base(path))
		}
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s is not a PEM certificate", filepath.Base(path))
	}
	return x509.ParseCertificate(blk.Bytes)
}

func (d *lcDoctor) checkSymlink() {
	if d.rec == nil || d.rec.Symlink == "" {
		return
	}
	c := lcCheck{ID: "symlink", Name: "Command link"}
	switch st, cur := svc.InspectSymlink(d.rec.Symlink, d.h.Binary()); st {
	case svc.SymlinkOurs:
		c.Status, c.Message = lcOK, d.rec.Symlink+" → "+d.h.Binary()
		if !svc.OnPath(filepath.Dir(d.rec.Symlink), os.Getenv("PATH")) {
			c.Status = lcWarn
			c.Message += "; " + filepath.Dir(d.rec.Symlink) + " is not on PATH"
			c.Hint = "Add it to PATH (e.g. in ~/.profile)."
		}
	case svc.SymlinkMissing:
		c.Status, c.Message = lcWarn, d.rec.Symlink+" is missing"
		c.Hint = "ln -s " + svc.ShellQuote(d.h.Binary()) + " " + svc.ShellQuote(d.rec.Symlink)
	default:
		c.Status, c.Message = lcWarn, d.rec.Symlink+" points elsewhere ("+Dash(cur)+")"
	}
	d.add(c)
}

// lcProbePort binds TCP port p on all interfaces and releases it again; it
// returns the bind error (tests replace it).
var lcProbePort = func(p int) error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
	if err != nil {
		return err
	}
	return ln.Close()
}

// checkPorts verifies that the configured ports are free while the server is
// stopped. Only "address in use" is a failure: a port below 1024 that this
// user may not bind (EACCES; the service unit grants CAP_NET_BIND_SERVICE,
// DESIGN §14.4) cannot be tested here, and says so.
func (d *lcDoctor) checkPorts() {
	if d.running || d.cfg == nil || lcHomeBusy(d.h) {
		return
	}
	c := lcCheck{ID: "ports", Name: "Ports"}
	var busy, denied, other []string
	for _, p := range []int{d.cfg.Server.HTTPSPort, d.cfg.Server.HTTPPort} {
		if p <= 0 {
			continue
		}
		switch err := lcProbePort(p); {
		case err == nil:
		case errors.Is(err, syscall.EADDRINUSE):
			busy = append(busy, fmt.Sprint(p))
		case errors.Is(err, fs.ErrPermission):
			denied = append(denied, fmt.Sprint(p))
		default:
			other = append(other, fmt.Sprintf("%d (%v)", p, err))
		}
	}
	var msgs []string
	switch {
	case len(busy) > 0:
		c.Status = lcFail
		msgs = append(msgs, "in use by another program: "+strings.Join(busy, ", "))
		c.Hint = "Stop that program or change server.https_port / server.http_port (fileparcel config set)."
	case len(other) > 0:
		c.Status = lcWarn
	case len(denied) > 0:
		c.Status = lcInfo
		c.Hint = "Run \"sudo fileparcel doctor\" to test them."
	default:
		c.Status, msgs = lcOK, []string{"free"}
	}
	if len(other) > 0 {
		msgs = append(msgs, "cannot be tested: "+strings.Join(other, ", "))
	}
	if len(denied) > 0 {
		msgs = append(msgs, "cannot be tested as this user: "+strings.Join(denied, ", ")+
			" (binding below 1024 needs root or CAP_NET_BIND_SERVICE, which the service unit grants)")
	}
	c.Message = strings.Join(msgs, "; ")
	d.add(c)
}

// checkFirewall prints the commands that open the ports on an active firewall.
func (d *lcDoctor) checkFirewall(ctx context.Context) {
	fws := svc.DetectFirewalls(ctx, d.host)
	in := svc.HintInput{Binary: d.h.Binary(), BuiltinMDNS: svc.BuiltinMDNSLikely(d.host)}
	if d.cfg != nil {
		in.HTTPSPort, in.HTTPPort = d.cfg.Server.HTTPSPort, d.cfg.Server.HTTPPort
	}
	if d.rec != nil {
		in.VPNIfaces, in.Anywhere = d.rec.FirewallIfaces, d.rec.FirewallAnywhere
		for _, s := range d.rec.FirewallSubnets {
			if p, err := netip.ParsePrefix(s); err == nil {
				in.Subnets = append(in.Subnets, p)
			}
		}
	}
	for _, fw := range fws {
		if !fw.Active {
			continue
		}
		c := lcCheck{ID: "firewall." + fw.Kind, Name: "Firewall (" + fw.Kind + ")", Status: lcInfo,
			Message: "active: other devices can only connect when the ports are allowed"}
		switch cmds := svc.Hints(fw.Kind, in); {
		case in.HTTPSPort == 0: // fileparcel.toml does not load (see the home check)
			c.Hint = "Allow the HTTPS port (server.https_port) from your networks once fileparcel.toml is fixed."
		case len(cmds) > 0:
			c.Hint = "If not done yet: " + strings.Join(cmds, " ; ")
		default:
			c.Hint = fmt.Sprintf("Allow TCP port %d from your networks.", in.HTTPSPort)
		}
		d.add(c)
	}
}

// restoreFailedStale matches opsapi's rule: after this long a failed restore
// nobody retried is a note, not a warning, so "doctor" can go green again.
// Scheduling another restore removes the marker (backup.ScheduleRestore), and
// so does a successful one.
const restoreFailedStale = 30 * 24 * time.Hour

// checkRestore reports a pending and a failed scheduled restore. The IDs
// and names are those of the server's checks (opsapi checkRestart), so
// serverChecks drops the server's copies instead of listing, and counting,
// the same condition twice.
func (d *lcDoctor) checkRestore() {
	if _, err := os.Stat(d.h.RestoreFile()); err == nil {
		d.add(lcCheck{ID: "restore.pending", Name: "Pending restore", Status: lcInfo,
			Message: "a restore is scheduled and is applied at the next start"})
	}
	marker := d.h.RestoreFile() + ".failed"
	if fi, err := os.Stat(marker); err == nil {
		m := readRestoreMarker(marker, fi)
		c := lcCheck{ID: "restore.failed", Name: "Scheduled restore", Status: lcWarn,
			Message: "the last scheduled restore failed (run/restore.json.failed)",
			Hint:    "The server kept its previous data. See the log for the reason; delete the file once handled."}
		if m.err != "" {
			c.Message = "the last scheduled restore failed (" + Dash(m.file) + "): " + m.err
		}
		if !m.failedAt.IsZero() && d.now.Sub(m.failedAt) > restoreFailedStale {
			c.Status = lcInfo
			c.Message += ", " + Ago(m.failedAt)
			c.Hint = "Nothing is wrong with the server. Delete " + marker + " to clear this note."
		}
		d.add(c)
	}
}

// restoreMarker is what doctor shows of run/restore.json.failed.
type restoreMarker struct {
	file, err string
	failedAt  time.Time
}

// readRestoreMarker reads the failed-restore marker. failedAt falls back to
// the file's modification time when failed_at cannot be parsed (older
// versions wrote a different shape, and the age is all that needs).
func readRestoreMarker(path string, fi fs.FileInfo) restoreMarker {
	m := restoreMarker{failedAt: fi.ModTime()}
	fh, err := os.Open(path)
	if err != nil {
		return m
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, 64<<10))
	if err != nil {
		return m
	}
	var f struct {
		Error    string    `json:"error"`
		File     string    `json:"file"`
		FailedAt time.Time `json:"failed_at"`
	}
	if json.Unmarshal(b, &f) != nil {
		return m
	}
	m.file = f.File
	if e := strings.TrimSpace(f.Error); e != "" {
		m.err = Truncate(e, 300)
	}
	if !f.FailedAt.IsZero() {
		m.failedAt = f.FailedAt
	}
	return m
}

// serverChecks adds the running server's own checks (GET /admin/system/doctor).
func (d *lcDoctor) serverChecks(ctx context.Context, c *Client) {
	var raw json.RawMessage
	if err := c.Do(ctx, http.MethodGet, "/api/v1/admin/system/doctor", nil, &raw); err != nil {
		d.add(lcCheck{ID: "server.doctor", Name: "Server checks", Status: lcInfo, Message: "unavailable: " + err.Error()})
		return
	}
	var rep struct {
		Checks []lcCheck `json:"checks"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		d.add(lcCheck{ID: "server.doctor", Name: "Server checks", Status: lcInfo, Message: "unreadable report"})
		return
	}
	have := map[string]bool{}
	for _, c := range d.checks {
		have[c.ID] = true
	}
	for _, sc := range rep.Checks {
		if strings.HasPrefix(sc.ID, "firewall") || have[sc.ID] {
			continue // local checks cover these with the exact commands
		}
		switch sc.Status {
		case lcOK, lcWarn, lcFail, lcInfo:
		default:
			sc.Status = lcInfo
		}
		sc.Fixed = false
		d.add(sc)
	}
}

func lcRenderDoctor(w io.Writer, rep *lcDoctorReport) error {
	marks := map[string]string{lcOK: Green("ok  "), lcWarn: Yellow("warn"), lcFail: Red("FAIL"), lcInfo: Dim("info")}
	for _, c := range rep.Checks {
		mark := marks[c.Status]
		if mark == "" {
			mark = c.Status
		}
		fixed := ""
		if c.Fixed {
			fixed = " " + Green("(fixed)")
		}
		if _, err := fmt.Fprintf(w, "[%s] %s: %s%s\n", mark, c.Name, sanitizeCell(c.Message), fixed); err != nil {
			return err
		}
		if c.Hint != "" {
			if _, err := fmt.Fprintf(w, "       → %s\n", sanitizeCell(c.Hint)); err != nil {
				return err
			}
		}
	}
	summary := fmt.Sprintf("\n%d failed, %d warnings", rep.Failures, rep.Warnings)
	if rep.Fixed > 0 {
		summary += fmt.Sprintf(", %d fixed", rep.Fixed)
	}
	_, err := fmt.Fprintln(w, summary+".")
	return err
}
