package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"fileparcel/internal/app"
	"fileparcel/internal/backup"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/server"
	"fileparcel/internal/svc/provision"
	"fileparcel/internal/web"
	"fileparcel/internal/wire"
)

func init() { Register(newServeCmd) }

// Environment variables of `serve --init-if-missing` (DESIGN §14.7).
const (
	EnvAdminUser         = "FILEPARCEL_ADMIN_USER"
	EnvAdminPasswordFile = "FILEPARCEL_ADMIN_PASSWORD_FILE"
	EnvAdminEmail        = "FILEPARCEL_ADMIN_EMAIL"
)

type serveOptions struct {
	foreground     bool
	dev            bool
	passphraseFile string
	initIfMissing  bool
	allowRoot      bool
}

func newServeCmd() *cobra.Command {
	var o serveOptions
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the server in the foreground",
		Long: `Run the FileParcel server on the home directory: HTTPS (with HTTP→HTTPS
redirects), the local admin socket, background jobs and mDNS.

The process refuses to run as root unless --allow-root is given, and holds the
home lock for its lifetime (only one server per home). A restore scheduled from
the web UI is applied before the database is opened.

When the master key is sealed the server starts locked: --passphrase-file (or
the global --passphrase-stdin) unlocks it at start; otherwise unlock it at
/unlock or with "fileparcel keys unlock". While no account exists the server
prints a one-time setup token for /setup.

--init-if-missing (Docker) initialises an empty home first, with the owner
account from $FILEPARCEL_ADMIN_USER (default admin), its e-mail address from
$FILEPARCEL_ADMIN_EMAIL (optional) and the password from the file named by
$FILEPARCEL_ADMIN_PASSWORD_FILE (default: generated and printed once, to be
changed at the first sign-in).

Exit status 75 asks the service manager for a restart (settings that need a
restart, restores); without a service manager the server re-executes itself.`,
		Example: `  fileparcel serve --home ~/fileparcel
  fileparcel serve --home /srv/fp --passphrase-file /run/secrets/fp-passphrase
  FILEPARCEL_HOME=/data fileparcel serve --init-if-missing`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runServe(cmd, o) },
	}
	f := cmd.Flags()
	f.BoolVar(&o.foreground, "foreground", false, "print a human-readable startup summary (default when stderr is a terminal)")
	f.BoolVar(&o.dev, "dev", false, "development mode: log at debug level")
	f.StringVar(&o.passphraseFile, "passphrase-file", "", "unlock a sealed master key at start with the passphrase in this file")
	f.BoolVar(&o.initIfMissing, "init-if-missing", false, "initialise the home first when it does not exist yet (Docker)")
	f.BoolVar(&o.allowRoot, "allow-root", false, "allow running as root (not recommended)")
	return cmd
}

func runServe(cmd *cobra.Command, o serveOptions) error {
	if os.Geteuid() == 0 && !o.allowRoot {
		return errors.New("refusing to run as root: run FileParcel as an unprivileged user (a system install runs as \"fileparcel\"), or pass --allow-root")
	}
	ctx := lcCtx(cmd)
	stderr := cmd.ErrOrStderr()
	h, err := home.Resolve(G.Home)
	if err != nil {
		return err
	}
	if !h.Exists() {
		if !o.initIfMissing {
			return fmt.Errorf("%s is not a FileParcel home (no %s); run \"fileparcel init --home DIR\" or \"fileparcel install\"", h.Dir(), home.ConfigName)
		}
		if err := serveInitHome(ctx, cmd, h); err != nil {
			return fmt.Errorf("initialise %s: %w", h.Dir(), err)
		}
	}

	unlock, err := h.Lock()
	if err != nil {
		if errors.Is(err, home.ErrLocked) {
			return fmt.Errorf("another FileParcel process is using %s (a running server, or an offline admin command); see \"fileparcel status\"", h.Dir())
		}
		return err
	}
	defer unlock()

	// A restore scheduled through the API is applied under the lock, before
	// the database is opened (DESIGN §12, core.Backups). Under systemd the
	// start timeout runs until READY=1: it is extended while the restore
	// (which takes minutes for a large backup) and then the opening and
	// migration of the database run, and shown in "systemctl status".
	bootLog := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	status := "Starting"
	if fileExists(h.RestoreFile()) {
		status = "Applying the scheduled restore (a large backup takes a while)"
	}
	stopExtend := server.ExtendStartTimeout(ctx, status)
	applied, err := backup.ApplyPendingRestore(ctx, h, bootLog)
	stopExtend()
	if err != nil {
		bootLog.Error("the scheduled restore failed; starting with the existing data", "err", err)
	} else if applied {
		bootLog.Info("the scheduled restore was applied")
	}
	stopExtend = server.ExtendStartTimeout(ctx, "Opening the database")
	defer stopExtend()

	d, cleanup, err := wire.Build(ctx, h, app.ModeNetwork)
	if err != nil {
		return err
	}
	defer cleanup()
	if lim, how := lcApplyMemoryLimit(d.Config); lim > 0 {
		d.Log.Debug("memory limit", "bytes", lim, "source", how)
	}
	if err := wire.Start(ctx, d); err != nil {
		return err
	}

	switch d.Keys.State() {
	case core.KeyStateUninitialized:
		return fmt.Errorf("%s has no master key (%s is missing): restore the home from a backup, or move it away and run \"fileparcel init\"", h.Dir(), h.KeysFile())
	case core.KeyStateLocked:
		serveUnlock(ctx, cmd, d, o.passphraseFile, G.PassphraseStdin)
	}
	stopSetup := serveSetupToken(ctx, d, stderr)
	defer stopSetup()
	stopExtend() // READY=1 (server.Run) ends the start

	fg := o.foreground || (lcIsTerminal(stderr) && !server.Supervised())
	// Run stops the services itself (Cleanup) before it records a clean
	// shutdown; after a failed start the calls below do it.
	err = server.Run(ctx, d, web.NewRouter(d), server.Options{Foreground: fg, Dev: o.dev,
		Cleanup: func() { stopSetup(); cleanup() }})
	stopSetup()
	cleanup()
	unlock()
	if errors.Is(err, server.ErrRestart) {
		if !server.Supervised() {
			fmt.Fprintln(stderr, "fileparcel: restarting …")
			rerr := server.ReExec() // does not return on success
			fmt.Fprintln(stderr, "fileparcel: re-exec failed:", rerr)
		}
		return &ExitCodeError{Code: ExitRestart}
	}
	return err
}

// serveInitHome creates the home for --init-if-missing (DESIGN §14.7). An
// existing home, or one another container is initialising right now (it
// holds the home lock: provision.Initialize then touches nothing), is not an
// error here; the caller's own lock then decides who serves.
func serveInitHome(ctx context.Context, cmd *cobra.Command, h *home.Home) error {
	stderr := cmd.ErrOrStderr()
	o := provision.Options{Admin: strings.TrimSpace(os.Getenv(EnvAdminUser)), AdminEmail: os.Getenv(EnvAdminEmail)}
	if o.Admin == "" {
		o.Admin = provision.DefaultAdmin
	}
	if f := os.Getenv(EnvAdminPasswordFile); f != "" {
		pw, err := ReadSecretFile(cmd, f)
		if err != nil {
			return fmt.Errorf("$%s: %w", EnvAdminPasswordFile, err)
		}
		o.AdminPassword = pw
	}
	fmt.Fprintf(stderr, "fileparcel: %s is not initialised yet; creating a new home …\n", h.Dir())
	res, err := lcInitHome(ctx, h.Dir(), provision.ConfigOptions{}, o)
	if err != nil {
		if lcIsExists(err) || errors.Is(err, home.ErrLocked) {
			return nil
		}
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "fileparcel: initialised %s\n", res.Home)
	if res.CAFingerprint != "" {
		fmt.Fprintf(&b, "  CA fingerprint (SHA-256): %s\n", res.CAFingerprint)
	}
	if res.Owner != "" {
		fmt.Fprintf(&b, "  owner account: %s\n", res.Owner)
	}
	if res.Password != "" {
		// Shown exactly once (stderr only, never the log file); the account
		// must choose a new password at the first sign-in.
		fmt.Fprintf(&b, "  generated password (shown only once; change it at the first sign-in): %s\n", res.Password)
	}
	if res.BackupIdentity != "" {
		fmt.Fprintf(&b, "  backup identity (shown only once; keep it outside this machine): %s\n", res.BackupIdentity)
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(&b, "  warning: %s\n", w)
	}
	_, err = io.WriteString(stderr, b.String())
	return err
}

// serveUnlock unlocks a sealed master key with --passphrase-file or the
// global --passphrase-stdin. Failures are logged and the server starts locked
// (web /unlock and "keys unlock" keep working), so a bad passphrase never
// causes a restart loop.
func serveUnlock(ctx context.Context, cmd *cobra.Command, d *app.Deps, file string, stdin bool) {
	src := "--passphrase-file"
	read := func() (string, error) { return ReadSecretFile(cmd, file) }
	switch {
	case file != "" && stdin:
		d.Log.Error("use only one of --passphrase-file and --passphrase-stdin; starting locked")
		return
	case stdin:
		src, read = "--passphrase-stdin", func() (string, error) { return ReadSecretStdin(cmd) }
	case file == "":
		d.Log.Warn("the master key is sealed: the server is locked until it is unlocked at /unlock or with \"fileparcel keys unlock\"")
		return
	}
	pass, err := read()
	if err == nil {
		err = d.Keys.Unlock(ctx, []byte(pass))
	}
	if err != nil {
		d.Log.Error("could not unlock the master key; starting locked", "source", src, "file", file, "err", err)
		return
	}
	d.Log.Info("master key unlocked", "source", src)
}

// serveSetupToken prints the one-time /setup token while no account exists
// (DESIGN §9.4 POST /auth/setup; "printed in logs"): now, or — when the
// database is not reachable yet because the keys are locked — as soon as the
// keys are unlocked. The token is only valid until the first account exists
// and is replaced at every start. The returned func stops waiting.
func serveSetupToken(ctx context.Context, d *app.Deps, stderr io.Writer) func() {
	emit := func() bool {
		n, err := d.Users.Count(ctx)
		if err != nil {
			return false
		}
		if n > 0 {
			return true
		}
		tok, err := d.Auth.SetupToken(ctx)
		if err != nil {
			d.Log.Warn("could not create the setup token", "err", err)
			return false
		}
		port := d.Config.Server.HTTPSPort
		d.Log.Warn("no account exists yet: create the first one in the browser at /setup with the one-time setup token",
			"setup_url", "https://localhost:"+strconv.Itoa(port)+"/setup", "setup_token", tok)
		if lcIsTerminal(stderr) {
			fmt.Fprintf(stderr, "\nNo account exists yet. Open https://localhost:%d/setup and enter this one-time setup token:\n  %s\n\n", port, tok)
		}
		return true
	}
	if d.Keys.State() != core.KeyStateLocked && emit() {
		return func() {}
	}
	if d.Bus == nil {
		return func() {}
	}
	ch, unsub := d.Bus.Subscribe(events.TopicKeysState)
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-wctx.Done():
				return
			case ev, ok := <-ch:
				if !ok {
					return
				}
				if st, ok := ev.Data.(core.KeysStateEvent); ok && st.State != core.KeyStateUnlocked {
					continue
				}
				if d.Keys.State() == core.KeyStateUnlocked && emit() {
					return
				}
			}
		}
	}()
	stopped := false
	return func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		unsub()
		<-done
	}
}

// lcIsTerminal reports whether w is a terminal (not merely a character
// device such as /dev/null).
func lcIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// ---------- memory limit ----------

// lcApplyMemoryLimit sets the Go soft memory limit from runtime.gomemlimit_mb
// (0 = auto: min(1 GiB, 25 % of the RAM available to the process), DESIGN
// §11.1). An explicit $GOMEMLIMIT wins. It returns the limit set (0 = none)
// and where it came from.
func lcApplyMemoryLimit(cfg *config.Config) (int64, string) {
	if os.Getenv("GOMEMLIMIT") != "" || cfg == nil {
		return 0, "GOMEMLIMIT"
	}
	lim, how := lcMemoryLimit(cfg.Runtime.GOMemLimitMB, lcAvailableMemory())
	debug.SetMemoryLimit(lim)
	return lim, how
}

// lcMemoryLimit computes the limit for configMB (0 = auto) given the
// available memory (0 = unknown).
func lcMemoryLimit(configMB int, available int64) (int64, string) {
	const gib = int64(1) << 30
	if configMB > 0 {
		return int64(configMB) << 20, "runtime.gomemlimit_mb"
	}
	if available > 0 && available/4 < gib {
		return available / 4, "auto (25% of RAM)"
	}
	return gib, "auto (1 GiB)"
}

// lcAvailableMemory returns the RAM available to the process: MemTotal of
// /proc/meminfo, lowered by a cgroup v2/v1 memory limit (containers); 0 when
// unknown (non-Linux).
func lcAvailableMemory() int64 {
	var total int64
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		total = lcParseMemInfo(b)
	}
	for _, p := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 && n < 1<<50 && (total == 0 || n < total) {
			total = n
		}
	}
	return total
}

// lcParseMemInfo returns MemTotal (bytes) from /proc/meminfo content.
func lcParseMemInfo(b []byte) int64 {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "MemTotal:" {
			n, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return 0
			}
			if len(f) >= 3 && strings.EqualFold(f[2], "kB") {
				n *= 1024
			}
			return n
		}
	}
	return 0
}
