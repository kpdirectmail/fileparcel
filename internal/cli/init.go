package cli

// `fileparcel init` (DESIGN §12, §14.2 step 3) and the helpers shared by the
// lifecycle commands (init, install, serve --init-if-missing): the offline
// service builder, secret flags and the terminal prompter used by the
// installer. Helpers of the lifecycle files are prefixed "lc" to keep them
// apart from the other command files of this package.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/app"
	"fileparcel/internal/buildinfo"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/svc/installer"
	"fileparcel/internal/svc/provision"
	"fileparcel/internal/wire"
)

func init() { Register(newInitCmd) }

// lcOfflineBuild builds the services over h in-process (wire.Build in
// ModeOffline + wire.Start, which only starts the network service). It is
// the provision.Builder of init, install and serve --init-if-missing.
func lcOfflineBuild(ctx context.Context, h *home.Home) (*app.Deps, func(), error) {
	d, cleanup, err := wire.Build(ctx, h, app.ModeOffline)
	if err != nil {
		return nil, nil, err
	}
	if err := wire.Start(ctx, d); err != nil {
		cleanup()
		return nil, nil, err
	}
	return d, cleanup, nil
}

// lcInitHome initialises a new home in dir (provision.Initialize with the
// in-process builder).
func lcInitHome(ctx context.Context, dir string, c provision.ConfigOptions, o provision.Options) (*provision.Result, error) {
	return provision.Initialize(ctx, dir, c, o, lcOfflineBuild)
}

// lcSecretFlags are the "--X-stdin | --X-file F" pair of one secret.
type lcSecretFlags struct {
	stdin bool
	file  string
}

// read returns the secret from stdin or the file ("" when neither flag was given).
func (s lcSecretFlags) read(cmd *cobra.Command) (string, error) {
	switch {
	case s.stdin && s.file != "":
		return "", UsageError("use either the -stdin or the -file flag of a secret, not both")
	case s.stdin:
		return ReadSecretStdin(cmd)
	case s.file != "":
		return ReadSecretFile(cmd, s.file)
	}
	return "", nil
}

// lcCanPrompt reports whether the command may ask questions: not with
// -y/--yes (or nonInteractive), and only when stdin is a terminal (or a
// scripted reader in tests).
func lcCanPrompt(cmd *cobra.Command, nonInteractive bool) bool {
	if G.Yes || nonInteractive {
		return false
	}
	_, _, ok := interactive(cmd.InOrStdin())
	return ok
}

// lcPrompter implements installer.Prompter on the command's terminal.
type lcPrompter struct {
	cmd     *cobra.Command
	enabled bool
}

var _ installer.Prompter = lcPrompter{}

// Interactive implements installer.Prompter.
func (p lcPrompter) Interactive() bool { return p.enabled }

// Ask implements installer.Prompter.
func (p lcPrompter) Ask(question, def string) (string, error) { return Prompt(p.cmd, question, def) }

// Confirm implements installer.Prompter.
func (p lcPrompter) Confirm(question string, def bool) (bool, error) {
	return Confirm(p.cmd, question, def)
}

// Secret implements installer.Prompter.
func (p lcPrompter) Secret(prompt string, confirm bool) (string, error) {
	if confirm {
		return PromptNewSecret(p.cmd, prompt)
	}
	return PromptSecret(p.cmd, prompt)
}

// lcAccessModes are the values of --access.
var lcAccessModes = []string{core.AccessPrivate, core.AccessAllowlist, core.AccessAny}

func lcCheckAccess(mode string) error {
	if mode == "" {
		return nil
	}
	for _, m := range lcAccessModes {
		if mode == m {
			return nil
		}
	}
	return UsageError("--access must be private, allowlist or any (got %q)", mode)
}

// lcHomeDir returns the directory named by --home or $FILEPARCEL_HOME ("" when neither is set).
func lcHomeDir() string {
	if G.Home != "" {
		return G.Home
	}
	return os.Getenv(home.EnvVar)
}

type initOptions struct {
	port           int
	httpPort       int
	name           string
	admin          string
	noAdmin        bool
	password       lcSecretFlags
	generate       bool
	email          string
	sealed         bool
	passphrase     lcSecretFlags
	access         string
	allow          []string
	nonInteractive bool
}

func newInitCmd() *cobra.Command {
	var o initOptions
	cmd := &cobra.Command{
		Use:   "init --home DIR",
		Short: "Create a new FileParcel data directory (without a service)",
		Long: `Create and initialise a FileParcel home in DIR (without installing a service):
the directory layout, fileparcel.toml, the database, the master key (plain, or
sealed with a passphrase), the local CA, client CA and server certificate, the
network allowlist (the private subnets of this machine's LAN/Wi-Fi
interfaces, the tailnet ranges and VPN subnets), the owner account and a
backup identity.

The owner password is generated (shown once, must be changed at the first
sign-in) unless one is given with --admin-password-stdin/--admin-password-file.
With --no-admin no account is created; the first account is then set up in the
browser at /setup with the one-time token the server prints when it starts.

Use "fileparcel install" for a complete installation with a service.`,
		Example: `  fileparcel init --home ~/fileparcel
  fileparcel init --home /srv/fp --port 9443 --admin alice --admin-email alice@example.org
  printf '%s\n' "$PASS" | fileparcel init --home /srv/fp --admin-password-stdin -y
  fileparcel init --home /srv/fp --sealed --passphrase-file /run/secrets/fp-passphrase`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runInit(cmd, o) },
	}
	f := cmd.Flags()
	f.IntVar(&o.port, "port", provision.DefaultHTTPSPort, "HTTPS port")
	f.IntVar(&o.httpPort, "http-port", provision.DefaultHTTPPort, "HTTP port that redirects to HTTPS (0 = none)")
	f.StringVar(&o.name, "name", provision.DefaultName, "server name: NAME.local via mDNS, CA name")
	f.StringVar(&o.admin, "admin", provision.DefaultAdmin, "username of the owner account")
	f.BoolVar(&o.noAdmin, "no-admin", false, "create no account; set up the first one in the browser at /setup")
	f.BoolVar(&o.password.stdin, "admin-password-stdin", false, "read the owner password from standard input")
	f.StringVar(&o.password.file, "admin-password-file", "", "read the owner password from a file")
	f.BoolVar(&o.generate, "generate-password", false, "generate the owner password (the default without a terminal)")
	f.StringVar(&o.email, "admin-email", "", "e-mail address of the owner")
	f.BoolVar(&o.sealed, "sealed", false, "seal the master key with a passphrase (unlock after every restart)")
	f.BoolVar(&o.passphrase.stdin, "passphrase-stdin", false, "read the master-key passphrase from standard input (with --sealed)")
	f.StringVar(&o.passphrase.file, "passphrase-file", "", "read the master-key passphrase from a file (with --sealed)")
	f.StringVar(&o.access, "access", core.AccessAllowlist, "who may connect: private | allowlist | any")
	f.StringArrayVar(&o.allow, "allow", nil, "add a network (CIDR or IP) to the allowlist (repeatable)")
	f.BoolVar(&o.nonInteractive, "non-interactive", false, "never prompt (same as -y)")
	_ = f.MarkHidden("non-interactive") // scripts use it; help shows -y
	cmd.MarkFlagsMutuallyExclusive("admin-password-stdin", "admin-password-file", "generate-password")
	cmd.MarkFlagsMutuallyExclusive("passphrase-stdin", "passphrase-file")
	cmd.MarkFlagsMutuallyExclusive("no-admin", "admin-password-stdin")
	cmd.MarkFlagsMutuallyExclusive("no-admin", "admin-password-file")
	return cmd
}

func runInit(cmd *cobra.Command, o initOptions) error {
	dir := lcHomeDir()
	if dir == "" {
		return UsageError("init needs --home DIR (or $%s)", home.EnvVar)
	}
	if o.password.stdin && o.passphrase.stdin {
		return UsageError("--admin-password-stdin and --passphrase-stdin cannot both read standard input")
	}
	if err := lcCheckAccess(o.access); err != nil {
		return err
	}
	if o.port < 1 || o.port > 65535 {
		return UsageError("invalid --port %d", o.port)
	}
	if o.httpPort < 0 || o.httpPort > 65535 || (o.httpPort != 0 && o.httpPort == o.port) {
		return UsageError("invalid --http-port %d (0 = none; must differ from --port)", o.httpPort)
	}
	if !o.sealed && (o.passphrase.stdin || o.passphrase.file != "") {
		return UsageError("--passphrase-stdin/--passphrase-file need --sealed")
	}
	if os.Geteuid() == 0 {
		Warnf(cmd, "running as root: the home will be owned by root, and \"fileparcel serve\" refuses to run as root unless --allow-root is given")
	}
	h, err := home.New(dir)
	if err != nil {
		return err
	}
	if h.Exists() {
		return fmt.Errorf("%s is already a FileParcel home", h.Dir())
	}
	if svc.DangerousHome(h.Dir(), lcUserHomeDir()) {
		return fmt.Errorf("refusing to use %s as a FileParcel home: choose a dedicated directory", h.Dir())
	}
	ask := lcCanPrompt(cmd, o.nonInteractive)

	po := provision.Options{Admin: strings.TrimSpace(o.admin), AdminEmail: o.email, Sealed: o.sealed, Access: o.access,
		Allow: o.allow}
	if o.noAdmin {
		po.Admin = ""
	} else {
		if po.Admin == "" {
			return UsageError("--admin must not be empty (use --no-admin for web setup)")
		}
		if po.AdminPassword, err = o.password.read(cmd); err != nil {
			return err
		}
		if po.AdminPassword == "" && !o.generate && ask {
			gen, err := Confirm(cmd, "Generate a secure password for "+po.Admin+"?", true)
			if err != nil {
				return err
			}
			if !gen {
				if po.AdminPassword, err = PromptNewSecret(cmd, "Password for "+po.Admin+": "); err != nil {
					return err
				}
			}
		}
	}
	if o.sealed {
		pp, err := o.passphrase.read(cmd)
		if err != nil {
			return err
		}
		if pp == "" {
			if !ask {
				return UsageError("--sealed needs --passphrase-stdin or --passphrase-file when not run interactively")
			}
			if pp, err = PromptNewSecret(cmd, "Master-key passphrase (needed after every restart): "); err != nil {
				return err
			}
		}
		po.Passphrase = []byte(pp)
	}
	httpPort := o.httpPort
	if httpPort == 0 {
		httpPort = -1 // ConfigOptions: -1 = no redirect listener
	}
	Infof(cmd, "Initialising %s …", h.Dir())
	res, err := lcInitHome(lcCtx(cmd), h.Dir(), provision.ConfigOptions{Name: o.name, HTTPSPort: o.port, HTTPPort: httpPort}, po)
	if err != nil {
		return err
	}
	s := installer.ResultSummary("init", buildinfo.Get().Version, res, lcUserName())
	s.NextSteps = append(s.NextSteps,
		"start the server: fileparcel serve --home "+svc.ShellQuote(h.Dir()),
		"or register it as a service: fileparcel service install --home "+svc.ShellQuote(h.Dir())+" --start")
	if o.sealed {
		s.NextSteps = append(s.NextSteps, "the server starts locked: unlock it at /unlock or with \"fileparcel keys unlock\"")
	}
	return s.Print(cmd.OutOrStdout(), G.JSON)
}

// lcCtx returns the command context (background when unset).
func lcCtx(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// lcUserHomeDir is os.UserHomeDir without the error.
func lcUserHomeDir() string {
	d, _ := os.UserHomeDir()
	return d
}

// lcUserName returns the login name of this process ("" when unknown).
func lcUserName() string {
	if h := svc.CurrentHost(); h != nil {
		return h.User
	}
	return ""
}

// lcIsExists reports provision.ErrExists.
func lcIsExists(err error) bool { return errors.Is(err, provision.ErrExists) }
