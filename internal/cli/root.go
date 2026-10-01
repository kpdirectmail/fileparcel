// Package cli implements the fileparcel command tree (DESIGN §12) with cobra,
// the client transport (Connect: admin socket | in-process | remote) and the
// output helpers.
//
// # Stable API for command files (do not rename)
//
// Registration — every command lives in its own file and registers a
// constructor from init():
//
//	func init() { Register(newUserCmd) }
//	func newUserCmd() *cobra.Command { … }
//
// NewRootCmd builds a fresh tree on every call (tests may build several), so
// constructors must not keep state in package variables other than flags
// bound inside the constructor.
//
// Global flags — parsed into G (type Globals): --home, --json, -y/--yes,
// --no-color, --offline, --server, --token / --token-file ($FILEPARCEL_TOKEN),
// --ca-file, --fingerprint, --as.
//
// Transport (client.go):
//
//	Connect(opts Options) (*Client, error)         // socket → offline → error; remote with --server
//	G.ConnectOptions() Options
//	WithClient(cmd, func(ctx, c *Client) error) error // Connect + fn + Close
//	(*Client).Do(ctx, method, path, body, out) error  // JSON; API errors are *core.Error
//	(*Client).Stream(ctx, method, path, body io.Reader, hdr) (*http.Response, error)
//	(*Client).Mode() / Home() / Deps() / Close()
//	PromptPassphrase(prompt) ([]byte, error)
//
// Output (output.go):
//
//	Print(cmd, v, human func(io.Writer) error) error // JSON with --json, else human
//	PrintJSON(w, v) / PrintJSONLine(w, v)
//	NewTable(headers...) *Table; (*Table).Add(cells...); Len(); Render(w)
//	NewKV() *KV; (*KV).Add(key, value); Render(w)
//	Cell(v) string
//	HumanBytes(n) / HumanBytesPtr(*n) / ParseSize(s) / ParseQuota(s)
//	HumanTime(t) / HumanTimePtr(*t) / Ago(t) / HumanDuration(d) / ParseDuration("7d")
//	YesNo(b) / Dash(s) / Truncate(s, n) / Plural(n, word)
//	ColorEnabled() / Bold / Dim / Green / Yellow / Red / Cyan
//	Infof(cmd, …) (stderr) / Warnf(cmd, …) (stderr) / Successf(cmd, …) (stdout, not with --json)
//	UsageError(format, …) error                        // exit code 2
//	PrintQR(w, data) error                             // terminal QR (skipped with --json)
//	Confirm(cmd, question, def) (bool, error)          // true with -y; ErrNotInteractive without a TTY
//	Prompt(cmd, question, def) (string, error)         // def with -y
//	PromptSecret(cmd, prompt) / PromptNewSecret(cmd, prompt) (string, error)
//	ReadSecret(r) / ReadSecretStdin(cmd) / ReadSecretFile(cmd, path) (string, error)
//	ErrNotInteractive
//
// Flags (flags.go):
//
//	durationVar(f, &d, name, def, usage)               // 30m, 12h, 7d, 2w; default printed as "2d"
//	addOutputFlag(cmd, &s, usage) / addForceFlag(cmd, &b, usage) // -o/--output, -f/--force (overwrite)
//	addWaitFlags(cmd, def, until) *waitFlags; (*waitFlags).Wait()
//	addSecretFlags(cmd, name, what, secretOpts{…}) *secretInput; Given(); Read(cmd, isNew)
//	addInactiveFlag(cmd, &b, usage) / addAllUsersFlags(cmd, &all, &user, noun)
//	parseExpiry(s, now, allowNever)                    // 7d, 2026-12-31, never
//
// Help (help.go): elevationNote, confirmNote, filesPathNote; groupCmd for
// command groups (cmd_common.go); setListHint(cmd, "fileparcel user list")
// on object groups; unknownCommandError(cmd, word) for a word that is not a
// subcommand. A bool flag that asks for a secret on the terminal carries
// the annotation annSecretPrompt ("fp:secret-prompt").
//
// Rules: top-level groups and help sections are assigned in help.go
// (topLevelGroup, subGroups), never in constructors; a renamed command or
// flag goes through legacy.go; no command sets PersistentPreRun(E) (the
// root's checkInvocation must run for every command); error hints come from
// explainErrorFor, applied once to the whole tree.
//
// Exit codes: return an error from RunE (exit 1; core "invalid" errors exit
// 2), UsageError(…) (exit 2) or &ExitCodeError{Code: n, Err: err} for a
// specific code (serve exits 75 to request a restart).
//
// Commands print human-readable output to stdout (tables by default, JSON
// with --json); prompts, warnings and progress go to stderr.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

// Globals are the global flags (DESIGN §12).
type Globals struct {
	Home        string // --home DIR
	JSON        bool   // --json
	Yes         bool   // -y / --yes
	NoColor     bool   // --no-color
	Offline     bool   // --offline (force in-process)
	Server      string // --server URL (remote)
	Token       string // --token PAT (remote; default $FILEPARCEL_TOKEN)
	TokenFile   string // --token-file F: the token from a file (read into Token)
	CAFile      string // --ca-file F (remote)
	Fingerprint string // --fingerprint SHA256 (remote pinning)
	As          string // --as USER (socket/offline only)
	// Passphrase{Stdin,File} unlock a sealed home in offline mode without a
	// terminal. Commands that bind their own --passphrase-stdin /
	// --passphrase-file (init, install, serve, restore, keys …) shadow these.
	PassphraseStdin bool   // --passphrase-stdin
	PassphraseFile  string // --passphrase-file F
}

// G holds the parsed global flags of the running command.
var G Globals

// TokenEnv is the environment variable read when --token is not given.
const TokenEnv = "FILEPARCEL_TOKEN"

// ConnectOptions converts the global flags into transport options. The
// token (--token, or --token-file read by resolveToken) falls back to
// $FILEPARCEL_TOKEN.
func (g Globals) ConnectOptions() Options {
	tok := g.Token
	if tok == "" {
		tok = os.Getenv(TokenEnv)
	}
	return Options{
		Home: g.Home, Offline: g.Offline, Server: g.Server, Token: tok,
		CAFile: g.CAFile, Fingerprint: g.Fingerprint, As: g.As,
	}
}

// resolveToken reads --token-file into Token. A token given with --token is
// visible to other local users for the whole run (ps, /proc/<pid>/cmdline)
// and lands in the shell history; one in a file or in $FILEPARCEL_TOKEN is
// not. A bad --token-file is a usage error, like a bad --token.
func (g *Globals) resolveToken(cmd *cobra.Command) error {
	if g.TokenFile == "" {
		return nil
	}
	if g.Token != "" {
		return UsageError("use only one of --token and --token-file")
	}
	tok, err := ReadSecretFile(cmd, g.TokenFile)
	if err == nil && strings.TrimSpace(tok) == "" {
		err = fmt.Errorf("%s: empty secret input", g.TokenFile)
	}
	if err != nil {
		return UsageError("--token-file: %v", err)
	}
	g.Token = strings.TrimSpace(tok)
	return nil
}

// passphraseFunc builds Options.Passphrase from the global
// --passphrase-stdin / --passphrase-file flags. It returns nil when neither
// is set, which leaves offline mode with its terminal prompt.
func (g Globals) passphraseFunc(cmd *cobra.Command) (func() ([]byte, error), error) {
	switch {
	case g.PassphraseStdin && g.PassphraseFile != "":
		return nil, UsageError("use only one of --passphrase-stdin and --passphrase-file")
	case g.PassphraseStdin:
		return func() ([]byte, error) {
			s, err := ReadSecretStdin(cmd)
			return []byte(s), err
		}, nil
	case g.PassphraseFile != "":
		return func() ([]byte, error) {
			s, err := ReadSecretFile(cmd, g.PassphraseFile)
			return []byte(s), err
		}, nil
	}
	return nil, nil
}

var registry []func() *cobra.Command

// Register adds a top-level command constructor (call from init()).
func Register(fn func() *cobra.Command) { registry = append(registry, fn) }

// Exit codes.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
	// ExitRestart asks the supervisor to restart the server (same value as
	// server.ExitRestart, DESIGN §11.3).
	ExitRestart = 75
)

// ExitCodeError lets a command choose the process exit code (Err, if non-nil,
// is printed first).
type ExitCodeError struct {
	Code int
	Err  error
}

// Error implements error.
func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e *ExitCodeError) Unwrap() error { return e.Err }

// NewRootCmd builds the command tree (root + registered commands). G is
// reset to its defaults.
func NewRootCmd() *cobra.Command {
	G = Globals{}
	root := &cobra.Command{
		Use:   "fileparcel",
		Short: "FileParcel: self-hosted, encrypted file sharing",
		Long:  rootLong,
		// The root runs only to reject a word that is not a command (with
		// suggestions); alone it prints the help.
		Args:          rootArgs,
		RunE:          func(cmd *cobra.Command, args []string) error { return cmd.Help() },
		SilenceUsage:  true,
		SilenceErrors: true,
		// No command may set a PersistentPreRun(E) of its own: cobra would
		// then skip this one.
		PersistentPreRunE: checkInvocation,
	}
	root.CompletionOptions.HiddenDefaultCmd = true
	root.AddGroup(newRootGroups()...)
	root.SetFlagErrorFunc(flagError)
	pf := root.PersistentFlags()
	pf.StringVar(&G.Home, "home", "", "FileParcel home directory (default: $FILEPARCEL_HOME or the binary's install dir)")
	pf.BoolVar(&G.JSON, "json", false, "print JSON instead of tables")
	pf.BoolVarP(&G.Yes, "yes", "y", false, "assume yes / accept defaults; do not prompt")
	pf.BoolVar(&G.NoColor, "no-color", false, "disable colours")
	pf.BoolVar(&G.Offline, "offline", false,
		"operate in-process on the home (the server must not be running; status, doctor and healthcheck always inspect the home locally)")
	pf.StringVar(&G.Server, "server", "", "remote server URL, https://host:port (with --token; plain http:// only for loopback)")
	pf.StringVar(&G.Token, "token", "", "API token for --server (visible to other local users in the process list: "+
		"prefer $"+TokenEnv+", the default, or --token-file)")
	pf.StringVar(&G.TokenFile, "token-file", "", "API token for --server, first line of this file")
	pf.StringVar(&G.CAFile, "ca-file", "", "CA certificate (PEM) to trust for --server")
	pf.StringVar(&G.Fingerprint, "fingerprint", "", "pin the server certificate chain by SHA-256 fingerprint (for --server)")
	pf.StringVar(&G.As, "as", "", "act as USER (socket/offline only; file, share, request and token commands default to the first owner)")
	pf.BoolVar(&G.PassphraseStdin, "passphrase-stdin", false,
		"master-key passphrase, first line of stdin (for commands that need the key on a sealed home with the server stopped)")
	pf.StringVar(&G.PassphraseFile, "passphrase-file", "",
		"master-key passphrase, first line of this file (for commands that need the key on a sealed home with the server stopped)")

	for _, fn := range registry {
		root.AddCommand(fn())
	}
	finishTree(root)
	return root
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// PrintJSON writes v as indented JSON.
func PrintJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Execute runs the CLI and returns the process exit code. It sets umask 077
// first (DESIGN §3) and cancels the command context on SIGINT/SIGTERM.
func Execute() int {
	setUmask()
	ctx, stop := signalContext()
	defer stop()
	return run(ctx, NewRootCmd(), os.Args[1:], os.Stderr)
}

// signalContext returns a context cancelled by the first SIGINT/SIGTERM.
// The signals are only caught once: after the first, their default action
// is back, so a second Ctrl-C ends a command that does not (or cannot) stop
// on the cancelled context instead of being swallowed for the whole run.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ctx, stop
}

// run executes root with args and maps the result to an exit code.
func run(ctx context.Context, root *cobra.Command, args []string, stderr io.Writer) int {
	invocationArgs = args
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	err = friendlyCobraError(err)
	var ee *ExitCodeError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			printError(stderr, ee.Err, ee.Code)
		}
		return ee.Code
	}
	var uh *usageHintError
	if errors.As(err, &uh) {
		printError(stderr, err, ExitUsage)
		return ExitUsage
	}
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		err = errors.New("interrupted") // Ctrl-C, not a failure to explain
	}
	code := ExitFailure
	if ce := core.AsError(err); ce != nil && ce.Code == core.ErrInvalid.Code {
		code = ExitUsage
	} else if isFlagError(err) {
		code = ExitUsage
	}
	printError(stderr, err, code)
	return code
}

// isFlagError reports cobra/pflag argument errors (unknown flag, bad value,
// wrong number of args, flag groups), which cobra returns as plain errors.
// Every one of them starts with its phrase; matching anywhere in the text
// would also catch runtime failures such as "open …: invalid argument"
// (EINVAL), which are errors (exit 1), not bad usage.
func isFlagError(err error) bool {
	msg := err.Error()
	for _, p := range []string{"unknown flag", "unknown shorthand flag", "unknown command", "invalid argument",
		"bad flag syntax", "flag needs an argument", "accepts ", "requires at least", "required flag",
		"if any flags in the group", "at least one of the flags in the group"} {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}
	return false
}

// printError prints err: "fileparcel: <message>" with its hint lines (and
// the suggestions and usage block of a usageHintError) on a terminal, or
// {"error":{"code","message","field"?,"hint"?}} with --json. The code is
// the API's for server errors, "usage" for other errors that exit with
// status 2, else "error".
func printError(w io.Writer, err error, exitCode int) {
	var uh *usageHintError
	isUsageHint := errors.As(err, &uh)
	if G.JSON {
		code := "error"
		if exitCode == ExitUsage {
			code = "usage"
		}
		msg, hint := splitHints(err.Error())
		if isUsageHint {
			msg, hint = uh.msg, uh.jsonHint()
		}
		out := map[string]any{"code": code, "message": msg}
		if ce := core.AsError(err); ce != nil {
			out["code"], out["message"] = ce.Code, ce.Message
			if ce.Field != "" {
				out["field"] = ce.Field
			}
		}
		if hint != "" {
			out["hint"] = hint
		}
		_ = PrintJSON(w, map[string]any{"error": out})
		return
	}
	text := err.Error()
	if isUsageHint {
		text = uh.text()
	}
	fmt.Fprintln(w, Red("fileparcel:"), text)
}

// splitHints splits an error text into the message and its "hint:" lines
// (hintError appends them as "\n  hint: …").
func splitHints(s string) (msg, hint string) {
	parts := strings.Split(s, "\n  hint: ")
	return parts[0], strings.Join(parts[1:], "\n")
}
