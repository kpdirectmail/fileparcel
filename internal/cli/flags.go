package cli

// Flag conventions shared by every command (DESIGN §12, "Conventions"):
// durations with day and week units, -o/--output and -f/--force, --wait and
// --no-wait, secrets that never travel on the command line, --inactive and
// --all-users on lists, one expiry parser, and the checks every invocation
// passes before a command runs (at most one flag reads standard input, and
// no word follows a flag that asks for a secret on the terminal).

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Flag annotations.
const (
	// annSecretPrompt marks a bool flag that asks for a secret on the
	// terminal (--password on share create). checkInvocation refuses a word
	// right after it, and flagError never echoes a value given to it.
	annSecretPrompt = "fp:secret-prompt"
	// annExample is a sample value, used by "--expires needs a value, e.g.
	// --expires 7d".
	annExample = "fp:example"
)

// invocationArgs are the raw command-line arguments of this run (set by
// run before the tree executes). The secret-prompt guard needs them: after
// parsing, "--password hunter2" and "--password" followed by a path look the
// same.
var invocationArgs []string

// ---------- durations ----------

// durationValue is a pflag.Value that parses ParseDuration syntax ("30m",
// "12h", "7d", "2w", "1d12h") and prints HumanDuration ("2d"), so the default
// in the help reads "(default 2d)" rather than "(default 48h0m0s)".
type durationValue time.Duration

func (d *durationValue) Set(s string) error {
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = durationValue(v)
	return nil
}

func (d *durationValue) String() string {
	if *d == 0 {
		return "0" // pflag leaves a zero default out of the help
	}
	return HumanDuration(time.Duration(*d))
}

func (d *durationValue) Type() string { return "duration" }

// durationVar defines a duration flag that takes ParseDuration syntax.
func durationVar(f *pflag.FlagSet, p *time.Duration, name string, def time.Duration, usage string) {
	*p = def
	f.Var((*durationValue)(p), name, usage)
	_ = f.SetAnnotation(name, annExample, []string{"7d"})
}

// ---------- output and overwrite ----------

// addOutputFlag defines -o/--output FILE.
func addOutputFlag(cmd *cobra.Command, p *string, usage string) {
	cmd.Flags().StringVarP(p, "output", "o", "", usage)
}

// addForceFlag defines -f/--force for "overwrite the output file". A
// --force that overrides a safety check has no shorthand (it must not be
// typed by accident).
func addForceFlag(cmd *cobra.Command, p *bool, usage string) {
	cmd.Flags().BoolVarP(p, "force", "f", false, usage)
}

// ---------- waiting for background work ----------

// waitFlags are --wait and --no-wait of a command that can return before
// its work is done.
type waitFlags struct {
	wait, noWait bool
	def          bool
	flags        *pflag.FlagSet
}

// addWaitFlags defines --wait and --no-wait (mutually exclusive). def is
// what the command does without either; until completes "wait until …"
// ("the job finishes", "the health check passes").
func addWaitFlags(cmd *cobra.Command, def bool, until string) *waitFlags {
	w := &waitFlags{def: def, flags: cmd.Flags()}
	waitUsage, noWaitUsage := "wait until "+until, "return at once"
	if def {
		waitUsage += " (default)"
	} else {
		noWaitUsage += " (default)"
	}
	cmd.Flags().BoolVar(&w.wait, "wait", false, waitUsage)
	cmd.Flags().BoolVar(&w.noWait, "no-wait", false, noWaitUsage)
	cmd.MarkFlagsMutuallyExclusive("wait", "no-wait")
	return w
}

// Wait reports whether the command waits: as --wait or --no-wait say, else
// the default.
func (w *waitFlags) Wait() bool {
	switch {
	case w.flags.Changed("wait"):
		return w.wait
	case w.flags.Changed("no-wait"):
		return !w.noWait
	}
	return w.def
}

// Explicit reports whether --wait or --no-wait was given.
func (w *waitFlags) Explicit() bool { return w.flags.Changed("wait") || w.flags.Changed("no-wait") }

// ---------- on/off pairs ----------

// onOff resolves a pair of bool flags --NAME and --no-NAME: nil when
// neither was given, else the setting. --NAME sends its value, so
// --NAME=false turns the option off like --no-NAME (and --no-NAME=false
// turns it on), as "fileparcel help values" promises. The caller makes the
// two flags mutually exclusive.
func onOff(f *pflag.FlagSet, name string) *bool {
	var v bool
	switch {
	case f.Changed(name):
		v, _ = f.GetBool(name)
	case f.Changed("no-" + name):
		off, _ := f.GetBool("no-" + name)
		v = !off
	default:
		return nil
	}
	return &v
}

// ---------- secrets ----------

// secretOpts selects the flags of addSecretFlags.
type secretOpts struct {
	// Prompt adds --NAME, a bool that asks on the terminal (without it the
	// terminal is asked only when Read finds no flag).
	Prompt bool
	// PromptUsage replaces the help text of --NAME.
	PromptUsage string
	// Generate adds a flag that has the secret generated (by the server or
	// by the caller); GenerateName names it (default "generate-NAME").
	Generate     bool
	GenerateName string
	// GenerateUsage replaces the help text of the generate flag.
	GenerateUsage string
}

// secretInput is a secret given by one of the flags of addSecretFlags:
// --NAME (prompt), --NAME-stdin, --NAME-file FILE or the generate flag. A
// secret is never a flag value itself: values on the command line show up
// in the process list and the shell history.
type secretInput struct {
	Prompt, Stdin, Generate bool
	File                    string

	name, what, genName string
}

// addSecretFlags defines the flags of one secret. name is the flag stem
// ("password"), what names the secret in help texts and prompts ("link
// password"). The flags are mutually exclusive.
func addSecretFlags(cmd *cobra.Command, name, what string, o secretOpts) *secretInput {
	s := &secretInput{name: name, what: what}
	f := cmd.Flags()
	var names []string
	if o.Prompt {
		usage := o.PromptUsage
		if usage == "" {
			usage = "ask for the " + what + " on the terminal (twice)"
		}
		f.BoolVar(&s.Prompt, name, false, usage)
		_ = f.SetAnnotation(name, annSecretPrompt, []string{"true"})
		names = append(names, name)
	}
	f.BoolVar(&s.Stdin, name+"-stdin", false, "read the "+what+" from the first line of standard input")
	f.StringVar(&s.File, name+"-file", "", "read the "+what+" from the first line of `FILE`")
	names = append(names, name+"-stdin", name+"-file")
	if o.Generate {
		s.genName = o.GenerateName
		if s.genName == "" {
			s.genName = "generate-" + name
		}
		usage := o.GenerateUsage
		if usage == "" {
			usage = "generate a strong " + what + " (shown once)"
		}
		f.BoolVar(&s.Generate, s.genName, false, usage)
		names = append(names, s.genName)
	}
	cmd.MarkFlagsMutuallyExclusive(names...)
	return s
}

// Given reports whether any flag of the secret was used.
func (s *secretInput) Given() bool { return s.Prompt || s.Stdin || s.File != "" || s.Generate }

// Read returns the secret from --NAME-stdin, --NAME-file or the terminal
// (asked twice when isNew). Without a terminal the error is
// ErrNotInteractive with a hint naming the -stdin and -file flags. Callers
// handle the generate flag themselves (Generate is true then; Read refuses).
func (s *secretInput) Read(cmd *cobra.Command, isNew bool) (string, error) {
	switch {
	case s.Generate:
		return "", fmt.Errorf("cli: Read called with --%s", s.genName)
	case s.Stdin:
		return ReadSecretStdin(cmd)
	case s.File != "":
		return ReadSecretFile(cmd, s.File)
	}
	// ".zip password" asks "Zip password: ".
	label := strings.TrimPrefix(s.what, ".")
	prompt := strings.ToUpper(label[:1]) + label[1:] + ": "
	var v string
	var err error
	if isNew {
		v, err = PromptNewSecret(cmd, prompt)
	} else {
		v, err = PromptSecret(cmd, prompt)
		if err == nil && v == "" {
			err = fmt.Errorf("empty %s", s.what)
		}
	}
	if errors.Is(err, ErrNotInteractive) {
		return "", &hintError{err, fmt.Sprintf("use --%s-stdin or --%s-file to give the %s without a terminal", s.name, s.name, s.what)}
	}
	return v, err
}

// ---------- list filters ----------

// addInactiveFlag defines --inactive: also list revoked, expired, used or
// closed items (what names them: "tokens").
func addInactiveFlag(cmd *cobra.Command, p *bool, usage string) {
	cmd.Flags().BoolVar(p, "inactive", false, usage)
}

// addAllUsersFlags defines --all-users (admin: every user's items) and
// --user USER (with --all-users: one user's). noun names the items.
func addAllUsersFlags(cmd *cobra.Command, all *bool, user *string, noun string) {
	cmd.Flags().BoolVar(all, "all-users", false, "admin: list the "+noun+" of every user")
	cmd.Flags().StringVar(user, "user", "", "with --all-users: only the "+noun+" of this user")
}

// ---------- expiry ----------

// parseExpiry turns "7d", "12h", "2026-12-31" (until the end of that day,
// local time), an RFC 3339 time or "never" into an expiry. "" gives nil
// (the caller's default); "never" gives nil and never=true, or a usage
// error when allowNever is false (invites and client certificates must
// expire).
func parseExpiry(s string, now time.Time, allowNever bool) (t *time.Time, never bool, err error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "":
		return nil, false, nil
	case "never", "none", "no":
		if !allowNever {
			return nil, false, UsageError("%q is not possible here: it must expire (give a duration such as 7d or a date such as 2026-12-31)", s)
		}
		return nil, true, nil
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		if !ts.After(now) {
			return nil, false, UsageError("the expiry %s is in the past", s)
		}
		u := ts.UTC()
		return &u, false, nil
	}
	if ts, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		u := ts.AddDate(0, 0, 1).Add(-time.Second).UTC() // end of that day
		if !u.After(now) {
			return nil, false, UsageError("the expiry %s is in the past", s)
		}
		return &u, false, nil
	}
	d, err := ParseDuration(s)
	if err != nil || d <= 0 {
		examples := "12h, 7d, 2w, 2026-12-31"
		if allowNever {
			examples += ", never"
		}
		return nil, false, UsageError("invalid expiry %q (examples: %s)", s, examples)
	}
	u := now.Add(d).UTC()
	return &u, false, nil
}

// ---------- invocation checks ----------

// checkInvocation is the root's PersistentPreRunE: it runs before every
// command (no command may set its own PersistentPreRun(E): cobra would then
// skip this one). It refuses a word typed right after a secret-prompt flag
// and a second flag that reads standard input, then reads --token-file.
func checkInvocation(cmd *cobra.Command, args []string) error {
	if err := checkSecretPrompts(cmd, invocationArgs); err != nil {
		return err
	}
	if err := checkStdinReaders(cmd); err != nil {
		return err
	}
	return G.resolveToken(cmd)
}

// checkSecretPrompts fails when a flag of cmd annotated annSecretPrompt is
// followed directly by a word that does not start with "-", or by "--", in
// the raw arguments: "--password hunter2" parses as --password plus an
// argument, and the password would then be used as a path (with "files put
// … --zip-password hunter2", as the name of the file inside the .zip, which
// the password does not hide). The word is never echoed.
func checkSecretPrompts(cmd *cobra.Command, raw []string) error {
	for i, tok := range raw {
		if tok == "--" {
			return nil
		}
		f := secretPromptFlag(cmd, tok)
		if f == nil || i+1 >= len(raw) {
			continue
		}
		if next := raw[i+1]; next == "--" || next != "" && !strings.HasPrefix(next, "-") {
			return secretPromptError(f)
		}
	}
	return nil
}

// secretPromptFlag returns the secret-prompt flag of cmd that tok names
// ("--password", or its shorthand), or nil.
func secretPromptFlag(cmd *cobra.Command, tok string) *pflag.Flag {
	var f *pflag.Flag
	switch {
	case strings.Contains(tok, "="):
		return nil
	case strings.HasPrefix(tok, "--") && len(tok) > 2:
		f = cmd.Flags().Lookup(tok[2:])
	case len(tok) == 2 && tok[0] == '-' && tok[1] != '-':
		f = cmd.Flags().ShorthandLookup(tok[1:])
	}
	if f == nil || f.Annotations[annSecretPrompt] == nil {
		return nil
	}
	return f
}

// setSecretPromptFlag returns a secret-prompt flag of cmd that was given,
// or nil. Argument errors then print no argument values: one of them may be
// a password typed after the flag.
func setSecretPromptFlag(cmd *cobra.Command) *pflag.Flag {
	var set *pflag.Flag
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if set == nil && f.Annotations[annSecretPrompt] != nil {
			set = f
		}
	})
	return set
}

// secretPromptError is the usage error for a value typed after (or into) a
// secret-prompt flag. It never contains the value.
func secretPromptError(f *pflag.Flag) error {
	return UsageError("--%[1]s takes no value: it asks for the password on the terminal. Put it after the paths, "+
		"or use --%[1]s-stdin / --%[1]s-file in scripts. Never type a password on the command line; remove it from "+
		"your shell history.", f.Name)
}

// stdinSwitch reports whether f is a switch that reads standard input
// (--password-stdin, --passphrase-stdin, --credentials-stdin, …): what it
// reads is a secret, so a value typed into it by mistake is one too.
func stdinSwitch(f *pflag.Flag) bool {
	return f.Value.Type() == "bool" && strings.HasSuffix(f.Name, "-stdin")
}

// stdinSwitchError is the usage error for a value typed into a -stdin
// switch ("--password-stdin=hunter2"). It never contains the value.
func stdinSwitchError(f *pflag.Flag) error {
	return UsageError("--%[1]s takes no value: it reads standard input (for example printf '%%s\\n' \"$SECRET\" | "+
		"fileparcel … --%[1]s). Never type a secret on the command line; remove it from your shell history.", f.Name)
}

// secretPromptAdvice is the hint of an argument error while the
// secret-prompt flag f is set.
func secretPromptAdvice(f *pflag.Flag) string {
	return fmt.Sprintf("--%[1]s asks for the password on the terminal and takes no value; use --%[1]s-stdin or "+
		"--%[1]s-file in scripts, and never type a password on the command line", f.Name)
}

// checkStdinReaders refuses two flags that read standard input (the second
// reader would only get EOF, or a secret meant for the first).
func checkStdinReaders(cmd *cobra.Command) error {
	var readers []string
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if strings.HasSuffix(f.Name, "-stdin") && f.Value.String() == "true" {
			readers = append(readers, f.Name)
		}
	})
	if len(readers) < 2 {
		return nil
	}
	slices.Sort(readers)
	var alts []string
	for _, r := range readers {
		if file := strings.TrimSuffix(r, "-stdin") + "-file"; cmd.Flags().Lookup(file) != nil {
			alts = append(alts, "--"+file)
		}
	}
	names := make([]string, len(readers))
	for i, r := range readers {
		names[i] = "--" + r
	}
	fix := "read one of them from a file instead"
	if len(alts) > 0 {
		fix = "use " + joinOr(alts) + " for one of them"
	}
	return UsageError("%s cannot both read standard input; %s", joinAnd(names), fix)
}

// joinAnd joins words as "a", "a and b", "a, b and c".
func joinAnd(words []string) string { return joinWords(words, "and") }

// joinOr joins words as "a", "a or b", "a, b or c".
func joinOr(words []string) string { return joinWords(words, "or") }

func joinWords(words []string, conj string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " " + conj + " " + words[len(words)-1]
}
