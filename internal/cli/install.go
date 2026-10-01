package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/svc/installer"
)

func init() { Register(newInstallCmd) }

type installFlags struct {
	o          installer.InstallOptions
	httpPort   int
	boot       bool
	noBoot     bool
	password   lcSecretFlags
	passphrase lcSecretFlags
	nonInter   bool
}

func newInstallCmd() *cobra.Command {
	var fl installFlags
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install FileParcel or upgrade an existing installation",
		Long: `Install FileParcel into a self-contained directory and register it as a
service. ./install.sh from the release zip runs this for you; it asks its
questions interactively, -y accepts every default (and so does a run without
a terminal, which has nobody to ask).

A fresh install copies this binary to <dir>/bin/fileparcel (plus VERSION,
uninstall.sh and docs/ when found next to it), initialises the home (master
key, certificates, network allowlist, owner account with a generated password,
backup identity), links the "fileparcel" command, registers and starts the
service (systemd user/system unit or launchd agent/daemon; start at boot uses
linger for user units), checks /healthz and prints a summary: the URLs with QR
codes, the CA fingerprint, the credentials (shown only once) and the firewall
commands to allow access from your networks.

When <dir> already contains an installation, install upgrades it to this
binary instead (pre-upgrade backup, binary swap with rollback, health check)
and repairs a missing service registration or command link. The options of
a fresh install (--port, --admin, --sealed, --access, --name, …) are then
ignored with a warning, and a --service other than the installed one is
refused.

--dry-run prints the plan without changing anything.

Defaults: dir ~/.local/share/fileparcel (root: /opt/fileparcel; macOS
~/Library/Application Support/FileParcel or /usr/local/fileparcel), service
user (root: system), ports 8443/8080 (the next free port is suggested), start
at boot, admin "admin", access allowlist (the detected private LAN/Wi-Fi
subnets, tailnet and VPN ranges).`,
		Example: `  fileparcel install
  fileparcel install -y --dir ~/fileparcel --port 9443 --no-boot
  fileparcel install -y --access private --admin alice --admin-email alice@example.org
  sudo fileparcel install -y --service system
  fileparcel install --dry-run -y`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runInstall(cmd, &fl) },
	}
	f := cmd.Flags()
	o := &fl.o
	f.StringVar(&o.Dir, "dir", "", "install directory (default: see above; --home works too)")
	f.IntVar(&o.HTTPSPort, "port", 0, "HTTPS port (default 8443 or the next free port)")
	f.IntVar(&fl.httpPort, "http-port", -1, "HTTP port that redirects to HTTPS, 0 = none (default 8080 or the next free port)")
	f.StringVar(&o.Name, "name", "", "server name: NAME.local via mDNS, CA name (default fileparcel)")
	f.StringVar(&o.Service, "service", "", "service kind: user | system | none (default: user; as root: system)")
	f.BoolVar(&fl.boot, "boot", false, "start at boot (default; user services enable linger)")
	f.BoolVar(&fl.noBoot, "no-boot", false, "do not start at boot")
	f.BoolVar(&o.NoStart, "no-start", false, "register the service but do not start it now")
	f.StringVar(&o.Symlink, "symlink", "", "where to link the fileparcel command (default ~/.local/bin/fileparcel; root: /usr/local/bin/fileparcel)")
	f.BoolVar(&o.NoSymlink, "no-symlink", false, "do not create the command link")
	f.StringVar(&o.Admin, "admin", "", "owner username (default admin)")
	f.BoolVar(&o.GeneratePassword, "generate-password", false, "generate the owner password (default; shown once, must be changed at the first sign-in)")
	f.BoolVar(&fl.password.stdin, "admin-password-stdin", false, "read the owner password from standard input")
	f.StringVar(&fl.password.file, "admin-password-file", "", "read the owner password from a file")
	f.StringVar(&o.AdminEmail, "admin-email", "", "owner e-mail address")
	f.BoolVar(&o.Sealed, "sealed", false, "seal the master key with a passphrase (the server starts locked after every restart)")
	f.BoolVar(&fl.passphrase.stdin, "passphrase-stdin", false, "read the master-key passphrase from standard input (with --sealed)")
	f.StringVar(&fl.passphrase.file, "passphrase-file", "", "read the master-key passphrase from a file (with --sealed)")
	f.StringVar(&o.Access, "access", "", "who may connect: private | allowlist | any (default allowlist)")
	f.StringArrayVar(&o.Allow, "allow", nil, "add a network (CIDR or IP) to the allowlist (repeatable)")
	f.BoolVar(&o.Upgrade, "upgrade", false, "only upgrade an existing installation (fail when there is none)")
	f.BoolVar(&o.Force, "force", false, "replace a foreign command link or another home's service registration; upgrade even when the pre-upgrade backup fails")
	f.BoolVar(&o.SkipBackup, "skip-backup", false, "upgrade without the pre-upgrade backup")
	f.BoolVar(&o.DryRun, "dry-run", false, "print the plan without changing anything")
	f.BoolVar(&fl.nonInter, "non-interactive", false, "never prompt (same as -y)")
	_ = f.MarkHidden("non-interactive") // install.sh passes it; help shows -y
	f.StringVar(&o.SourceDir, "source", "", "directory with uninstall.sh and docs/ to install (default: $"+installer.SourceEnv+" or next to the binary)")
	_ = f.MarkHidden("source")
	cmd.MarkFlagsMutuallyExclusive("boot", "no-boot")
	cmd.MarkFlagsMutuallyExclusive("symlink", "no-symlink")
	cmd.MarkFlagsMutuallyExclusive("admin-password-stdin", "admin-password-file", "generate-password")
	cmd.MarkFlagsMutuallyExclusive("passphrase-stdin", "passphrase-file")
	return cmd
}

func runInstall(cmd *cobra.Command, fl *installFlags) error {
	o := fl.o
	if o.Dir == "" {
		o.Dir = G.Home
	}
	if fl.password.stdin && fl.passphrase.stdin {
		return UsageError("--admin-password-stdin and --passphrase-stdin cannot both read standard input")
	}
	if err := lcCheckAccess(o.Access); err != nil {
		return err
	}
	switch o.Service {
	case "", "user", "system", "none":
	default:
		return UsageError("--service must be user, system or none (got %q)", o.Service)
	}
	if o.HTTPSPort < 0 || o.HTTPSPort > 65535 {
		return UsageError("invalid --port %d", o.HTTPSPort)
	}
	if cmd.Flags().Changed("http-port") {
		if fl.httpPort < 0 || fl.httpPort > 65535 {
			return UsageError("invalid --http-port %d (0 = none)", fl.httpPort)
		}
		p := fl.httpPort
		o.HTTPPort = &p
	}
	o.Boot = onOff(cmd.Flags(), "boot") // --boot=false = --no-boot
	if !o.Sealed && (fl.passphrase.stdin || fl.passphrase.file != "") {
		return UsageError("--passphrase-stdin/--passphrase-file need --sealed")
	}
	var err error
	if o.AdminPassword, err = fl.password.read(cmd); err != nil {
		return err
	}
	pp, err := fl.passphrase.read(cmd)
	if err != nil {
		return err
	}
	if pp != "" {
		o.Passphrase = []byte(pp)
	}
	o.Yes = G.Yes || fl.nonInter
	interactive := lcCanPrompt(cmd, fl.nonInter)
	in := lcNewInstaller(cmd, interactive)
	if err := checkUpgradeFlags(cmd, in, o, interactive && !o.Yes); err != nil {
		return err
	}
	return in.Install(lcCtx(cmd), o)
}

// freshOnlyFlags are the install flags only a fresh install uses: an
// upgrade keeps the ports, owner, sealing, access policy and name of the
// installation.
var freshOnlyFlags = []string{"port", "http-port", "name", "admin", "generate-password", "admin-password-stdin",
	"admin-password-file", "admin-email", "sealed", "passphrase-stdin", "passphrase-file", "access", "allow"}

// checkUpgradeFlags speaks up when install is about to upgrade an existing
// installation (its directory is known: given, or the default without a
// question): the fresh-install flags that were given are named as ignored,
// and a --service other than the installation's is refused (an upgrade
// keeps the registered service; only the repair of a home without a
// complete registration uses it).
func checkUpgradeFlags(cmd *cobra.Command, in *installer.Installer, o installer.InstallOptions, asksDir bool) error {
	dir := strings.TrimSpace(o.Dir)
	if dir == "" {
		if asksDir {
			return nil
		}
		dir = svc.DefaultHome(in.Host)
	}
	if rest, ok := strings.CutPrefix(dir, "~"); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
		dir = in.Host.HomeDir + rest
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil // the installer reports it
	}
	h, err := home.New(abs)
	if err != nil || !h.Exists() {
		return nil
	}
	f := cmd.Flags()
	if f.Changed("service") {
		rec, err := svc.ReadInstalled(h)
		want, _, kerr := svc.ResolveKind(in.Host, o.Service)
		repair := rec == nil || rec.Incomplete || rec.Home != "" && filepath.Clean(rec.Home) != h.Dir()
		if err == nil && kerr == nil && !repair && want != rec.Kind {
			change := `"fileparcel service uninstall"`
			if want != svc.KindNone {
				flag := "--user"
				if want.System() {
					flag = "--system"
				}
				change = fmt.Sprintf(`"fileparcel service install %s"`, flag)
				if rec.Kind != svc.KindNone {
					change = `"fileparcel service uninstall", then ` + change
				}
			}
			return UsageError("%s already contains an installation with %s; an upgrade keeps it, so --service %s "+
				"would not apply. To change the service run %s", h.Dir(), rec.Kind.Describe(), o.Service, change)
		}
	}
	var ignored []string
	for _, n := range freshOnlyFlags {
		if f.Changed(n) {
			ignored = append(ignored, "--"+n)
		}
	}
	if len(ignored) > 0 {
		Warnf(cmd, "%s already contains an installation, so this upgrades it and ignores %s; change those settings "+
			`with "fileparcel config", "fileparcel network", "fileparcel keys" or "fileparcel user"`, h.Dir(), joinAnd(ignored))
	}
	return nil
}

// lcNewInstaller returns an installer wired to the terminal, the in-process
// home initialisation and the backup hook.
func lcNewInstaller(cmd *cobra.Command, interactive bool) *installer.Installer {
	backup := func(ctx context.Context, h *home.Home, in core.BackupInput) (*core.Backup, error) {
		return lcBackup(ctx, cmd, h, in)
	}
	in := installer.New(cmd.OutOrStdout(), cmd.ErrOrStderr(), lcPrompter{cmd: cmd, enabled: interactive},
		installer.Hooks{InitHome: lcInitHome, Backup: backup})
	in.JSON = G.JSON
	return in
}

// lcBackup creates a backup of h and waits for it (installer hook for the
// pre-upgrade and final backups): through the running server's admin socket
// (a backup job, followed until it ends), or in-process when the server is
// stopped (Backups.CreateSync). Both act as the system principal, which may
// use the pre-upgrade/final triggers and CopyTo.
//
// The in-process path opens the home like any offline command (wire.Build),
// which migrates the database to this binary's schema. A pre-upgrade backup
// run by the new release (install.sh) would then already hold the new
// schema, which the rolled-back binary refuses, and the database would be
// migrated before the binary swap. So when this is not the installed binary
// and the database is older than this binary's schema, the installed
// binary makes the backup instead (lcDelegateBackup).
//
// A sealed master key is unlocked with the global --passphrase-file /
// --passphrase-stdin, or on the terminal; a backup needs it only in
// passphrase encryption mode, so it may also stay locked.
func lcBackup(ctx context.Context, cmd *cobra.Command, h *home.Home, in core.BackupInput) (*core.Backup, error) {
	pass, err := G.passphraseFunc(cmd)
	if err != nil {
		return nil, err
	}
	opts := Options{Home: h.Dir(), Passphrase: pass}
	c, err := connectSocket(h, opts)
	switch {
	case err == nil:
		defer c.Close()
		var ref core.JobRef
		if err := c.Do(ctx, http.MethodPost, "/api/v1/admin/backups", in, &ref); err != nil {
			return nil, err
		}
		if ref.JobID == "" {
			return nil, errors.New("the server did not start a backup job")
		}
		Infof(cmd, "Waiting for backup job %s (Ctrl-C stops waiting; the job continues in the server) …", ref.JobID)
		return lcWaitBackup(ctx, c, ref.JobID)
	case !errors.Is(err, errNoServer):
		return nil, err
	}
	if in.Trigger == core.TriggerPreUpgrade && lcBackupDelegated(ctx, h) {
		return lcDelegateBackup(ctx, cmd, h, in)
	}
	if c, err = connectOffline(h, opts); err != nil {
		return nil, err
	}
	defer c.Close()
	d := c.Deps()
	if d == nil || d.Backups == nil {
		return nil, errors.New("backups are not available")
	}
	b, err := d.Backups.CreateSync(ctx, core.SystemPrincipal(core.ViaOffline), in)
	var ce *core.Error
	keyErr := errors.Is(err, core.ErrKeysLocked) || (errors.As(err, &ce) && ce.Field == "recipients")
	if keyErr && d.Keys != nil && d.Keys.State() != core.KeyStateUnlocked {
		// The backup needs the master key (passphrase encryption, or no
		// recipient yet); "keys unlock" cannot help: it needs a running
		// server.
		hint := "run it from a terminal to enter the passphrase"
		if cmd.LocalFlags().Lookup("passphrase-file") == nil {
			hint = "pass the global --passphrase-file FILE or --passphrase-stdin, or " + hint
		}
		return nil, fmt.Errorf("%w (the master key is sealed and locked: %s)", err, hint)
	}
	return b, err
}

// lcBackupDelegated reports whether the offline backup of h must be made by
// the installed binary: this process is another binary (the new release run
// by install.sh) whose schema is newer than the database's, so opening the
// home here would migrate it. A database that cannot be read, a missing
// installed binary (a home made with "init") or this process being the
// installed binary keep the in-process path.
func lcBackupDelegated(ctx context.Context, h *home.Home) bool {
	if !fileExists(h.DB()) || !fileExists(h.Binary()) {
		return false
	}
	if exe, err := os.Executable(); err == nil && lcSameFile(exe, h.Binary()) {
		return false
	}
	q, err := sql.Open("sqlite", readOnlyDSN(h.DB()))
	if err != nil {
		return false
	}
	defer q.Close()
	cur, err := schemaVersion(ctx, q)
	return err == nil && cur < db.LatestVersion()
}

// lcSameFile reports whether a and b are the same file (symlinks followed).
func lcSameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// lcDelegateBackup runs `<HOME>/bin/fileparcel backup create` for in, so the
// backup is made by the binary that matches the database schema and nothing
// is migrated before the binary swap. The trigger is passed with the hidden
// --trigger flag when the installed binary knows it (probed with --help,
// which parses the flags and has no side effects); older binaries record a
// manual backup, which is kept until it is deleted by hand as well. A sealed
// key is unlocked by the child: on the terminal (stdin is passed through) or
// with the global passphrase flags given to this command.
func lcDelegateBackup(ctx context.Context, cmd *cobra.Command, h *home.Home, in core.BackupInput) (*core.Backup, error) {
	bin := h.Binary()
	args := []string{"--home", h.Dir(), "--json", "backup", "create", "--scope", in.Scope, "--wait"}
	if in.Note != "" {
		args = append(args, "--note", in.Note)
	}
	if in.Trigger != "" && in.Trigger != core.TriggerManual {
		probe := exec.CommandContext(ctx, bin, "backup", "create", "--trigger", in.Trigger, "--help")
		if probe.Run() == nil {
			args = append(args, "--trigger", in.Trigger)
		}
	}
	stdin := cmd.InOrStdin()
	switch {
	case G.PassphraseFile != "":
		args = append(args, "--passphrase-file", G.PassphraseFile)
	case G.PassphraseStdin:
		pass, err := ReadSecretStdin(cmd)
		if err != nil {
			return nil, err
		}
		args = append(args, "--passphrase-stdin")
		stdin = strings.NewReader(pass + "\n")
	}
	Infof(cmd, "The database is older than this release: the installed %s makes the backup, so nothing is migrated before the upgrade", bin)
	var out bytes.Buffer
	child := exec.CommandContext(ctx, bin, args...)
	child.Stdin, child.Stdout, child.Stderr = stdin, &out, cmd.ErrOrStderr()
	runErr := child.Run()
	var b core.Backup
	if err := json.Unmarshal(out.Bytes(), &b); err != nil || b.ID == "" {
		if runErr != nil {
			return nil, fmt.Errorf("the installed binary could not create the backup: %w", runErr)
		}
		return nil, fmt.Errorf("the installed binary printed no backup: %s", Truncate(strings.TrimSpace(out.String()), 200))
	}
	if runErr != nil && b.State != core.BackupReady {
		return nil, fmt.Errorf("backup %s failed: %s", b.ID, dash(b.Error))
	}
	return &b, nil
}

// lcWaitBackup follows backup job id until it ends and returns its backup.
// It waits as long as the job runs (a full final backup of a large home
// takes hours; a deadline would abandon it, and a retry would queue another
// one behind it); Ctrl-C stops waiting and leaves the job running.
func lcWaitBackup(ctx context.Context, c *Client, id string) (*core.Backup, error) {
	delay := 250 * time.Millisecond
	for {
		var j core.Job
		if err := c.Do(ctx, http.MethodGet, "/api/v1/admin/jobs/"+url.PathEscape(id), nil, &j); err != nil {
			if ctx.Err() != nil {
				return nil, stoppedWaiting(id)
			}
			return nil, err
		}
		switch j.State {
		case core.JobSucceeded:
			return lcBackupOfJob(ctx, c, &j)
		case core.JobFailed, core.JobCanceled:
			msg := j.Error
			if msg == "" {
				msg = j.State
			}
			return nil, fmt.Errorf("backup job %s %s: %s", id, j.State, msg)
		}
		select {
		case <-ctx.Done():
			return nil, stoppedWaiting(id)
		case <-time.After(delay):
		}
		delay = min(delay*2, 2*time.Second)
	}
}

// lcBackupOfJob returns the backup created by a finished backup.create job
// (result {"backup_id": …}; otherwise the backup list is searched by job id).
func lcBackupOfJob(ctx context.Context, c *Client, j *core.Job) (*core.Backup, error) {
	var res struct {
		BackupID string `json:"backup_id"`
	}
	if len(j.Result) > 0 {
		_ = json.Unmarshal(j.Result, &res)
	}
	if res.BackupID != "" {
		var b core.Backup
		if err := c.Do(ctx, http.MethodGet, "/api/v1/admin/backups/"+url.PathEscape(res.BackupID), nil, &b); err != nil {
			return nil, err
		}
		return &b, nil
	}
	var page core.Page[core.Backup]
	if err := c.Do(ctx, http.MethodGet, "/api/v1/admin/backups?limit=50", nil, &page); err != nil {
		return nil, err
	}
	for i := range page.Items {
		if page.Items[i].JobID == j.ID {
			return &page.Items[i], nil
		}
	}
	return nil, fmt.Errorf("backup job %s finished but its backup was not found", j.ID)
}
