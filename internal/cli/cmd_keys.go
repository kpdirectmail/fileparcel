package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newKeysCmd) }

func newKeysCmd() *cobra.Command {
	cmd := groupCmd("keys", "Lock, unlock and rotate the encryption keys",
		`All file contents and secrets are encrypted with keys derived from the master
key (keys/master.key). In "plain" mode the master key file unlocks the server
automatically; in "sealed" mode it is encrypted with a passphrase and the
server starts locked until "fileparcel keys unlock" (or the /unlock page).

Passphrases are read without echo from the terminal, or from
--passphrase-stdin / --passphrase-file for scripts. Keep the recovery key
("keys recovery-key") offline: it unlocks the server if the passphrase is
lost.`,
		`  fileparcel keys status
  fileparcel keys unlock
  fileparcel keys seal
  fileparcel keys rotate --kek`)
	cmd.AddCommand(newKeysStatusCmd(), newKeysUnlockCmd(), newKeysLockCmd(), newKeysSealCmd(true), newKeysSealCmd(false),
		newKeysPassphraseCmd(), newKeysRotateCmd(), newKeysRecoveryKeyCmd(), newKeysVerifyCmd())
	return cmd
}

// passphraseFlags binds --passphrase-stdin and --passphrase-file.
type passphraseFlags struct {
	stdin bool
	file  string
}

func (p *passphraseFlags) bind(cmd *cobra.Command, what string) {
	cmd.Flags().BoolVar(&p.stdin, "passphrase-stdin", false, "read the "+what+" from the first line of stdin")
	cmd.Flags().StringVar(&p.file, "passphrase-file", "", "read the "+what+" from the first line of a file")
}

// read returns the passphrase from the flags or a no-echo prompt (twice for
// a new passphrase).
func (p *passphraseFlags) read(cmd *cobra.Command, prompt string, isNew bool) (string, error) {
	switch {
	case p.stdin && p.file != "":
		return "", UsageError("use only one of --passphrase-stdin and --passphrase-file")
	case p.stdin:
		return ReadSecretStdin(cmd)
	case p.file != "":
		return ReadSecretFile(cmd, p.file)
	case isNew:
		return PromptNewSecret(cmd, prompt)
	}
	s, err := PromptSecret(cmd, prompt)
	if err == nil && s == "" {
		err = errors.New("empty passphrase")
	}
	return s, err
}

func getKeyStatus(ctx context.Context, c *Client) (*core.KeyStatus, error) {
	var st core.KeyStatus
	if err := c.Do(ctx, http.MethodGet, api("/admin/keys"), nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func newKeysStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the keys are locked and which keys exist",
		Long: `Show whether the keys are locked, the master key mode (plain or sealed), the
cipher for new files and the key-encryption keys with their use.`,
		Example: `  fileparcel keys status
  fileparcel keys status --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				st, err := getKeyStatus(ctx, c)
				if err != nil {
					if errors.Is(err, core.ErrKeysLocked) {
						var ss core.SystemStatus
						if err2 := c.Do(ctx, http.MethodGet, api("/system/status"), nil, &ss); err2 == nil {
							return Print(cmd, &ss, func(w io.Writer) error {
								_, err := fmt.Fprintf(w, "State: %s (unlock with \"fileparcel keys unlock\")\n", ss.State)
								return err
							})
						}
					}
					return err
				}
				return Print(cmd, st, func(w io.Writer) error {
					kv := NewKV()
					kv.Add("State", string(st.State))
					kv.Add("Mode", st.Mode)
					kv.Add("Master key", st.MKID)
					kv.Add("Cipher", st.CipherName)
					kv.Add("Recovery key", YesNo(st.RecoveryConfigured))
					kv.Add("Memory locked", st.Mlocked)
					kv.Add("Web unlock", st.WebUnlock)
					if err := kv.Render(w); err != nil {
						return err
					}
					if len(st.KEKs) > 0 {
						fmt.Fprintln(w)
						t := NewTable("KEK", "PURPOSE", "STATE", "CREATED", "RETIRED", "REFS")
						for _, k := range st.KEKs {
							t.Add(k.ID, k.Purpose, k.State, k.CreatedAt, k.RetiredAt, k.Refs)
						}
						return t.Render(w)
					}
					return nil
				})
			})
		},
	}
}

func newKeysUnlockCmd() *cobra.Command {
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock a sealed server with its passphrase or recovery key",
		Long: `Unlock the running server's master key with the passphrase or the recovery
key (FPRK-…). Needed after every start in sealed mode; the /unlock page of the
web app does the same.`,
		Example: `  fileparcel keys unlock
  fileparcel keys unlock --passphrase-file /run/secrets/fileparcel
  printf '%s\n' "$PASS" | fileparcel keys unlock --passphrase-stdin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if c.Mode() == ModeOffline {
					return &hintError{errors.New("the server is not running, so there is no master key in memory to unlock"),
						"offline commands unlock the home themselves: they prompt on a terminal, or take the global " +
							"--passphrase-stdin / --passphrase-file (e.g. \"fileparcel --passphrase-file pp.txt files get …\")"}
				}
				var ss core.SystemStatus
				if err := c.Do(ctx, http.MethodGet, api("/system/status"), nil, &ss); err == nil && ss.State == core.KeyStateUnlocked {
					return done(cmd, &ss, "the server is already unlocked")
				}
				pass, err := pf.read(cmd, "Master key passphrase (or recovery key): ", false)
				if err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/system/unlock"), core.PassphraseInput{Passphrase: pass}, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"state": string(core.KeyStateUnlocked)}, "unlocked")
			})
		},
	}
	pf.bind(cmd, "passphrase or recovery key")
	return cmd
}

func newKeysLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock a sealed server now (wipes the key from memory)",
		Long: `Wipe the master key from the running server's memory (sealed mode only).
The web app and the remote API stop working until "fileparcel keys unlock",
and no encrypted content (file data, shares, encrypted settings) can be read.
The local admin socket keeps working on everything else, so the server can
still be inspected, administered and unlocked.

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel keys lock
  fileparcel keys lock -y`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := requireServer(c, "keys lock"); err != nil {
					return err
				}
				if err := confirmOrAbort(cmd, "Lock the server? Users cannot access anything until it is unlocked."); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/keys/lock"), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"state": string(core.KeyStateLocked)}, "locked; unlock with \"fileparcel keys unlock\"")
			})
		},
	}
}

// withClientUnlocking is WithClient for commands that already hold the
// current master-key secret (keys unseal, keys passphrase). Their own
// --passphrase-* flags shadow the global ones (DESIGN §12), so an offline
// connect to a sealed home unlocks with that secret instead of prompting for
// it a second time — or, without a terminal, staying locked. The secret is
// only used when the home is locked (connectOffline), never over the socket.
func withClientUnlocking(cmd *cobra.Command, secret string, fn func(context.Context, *Client) error) error {
	opts := G.ConnectOptions()
	opts.Passphrase = func() ([]byte, error) { return []byte(secret), nil }
	c, err := Connect(opts)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return fn(ctx, c)
}

func newKeysSealCmd(seal bool) *cobra.Command {
	var pf passphraseFlags
	use, short := "seal", "Protect the master key with a passphrase"
	long := `Switch from plain to sealed mode: the master key file is encrypted with a
passphrase (argon2id). From then on the server starts locked and needs
"fileparcel keys unlock" after every restart (also after reboots).

` + confirmNote + "\n" + elevationNote
	example := `  fileparcel keys seal
  fileparcel keys seal --passphrase-file /secure/new-pass -y`
	if !seal {
		use, short = "unseal", "Remove the passphrase from the master key"
		long = `Switch from sealed to plain mode: the master key is stored unencrypted in
keys/master.key and the server unlocks itself at start. Only do this when the
disk itself is encrypted. It needs the current passphrase.

` + confirmNote + "\n" + elevationNote
		example = `  fileparcel keys unseal
  fileparcel keys unseal --passphrase-file /secure/pass`
	}
	cmd := &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			q := "Seal the master key? The server will need the passphrase after every restart."
			prompt := "New master key passphrase: "
			if !seal {
				q = "Unseal the master key? It will be stored without a passphrase."
				prompt = "Current master key passphrase: "
			}
			if err := confirmOrAbort(cmd, q); err != nil {
				return err
			}
			pass, err := pf.read(cmd, prompt, seal)
			if err != nil {
				return err
			}
			if seal && utf8.RuneCountInString(pass) < 12 {
				Warnf(cmd, "short passphrases are weak; 5+ random words are recommended")
			}
			run := func(ctx context.Context, c *Client) error {
				var raw json.RawMessage
				if err := c.Do(ctx, http.MethodPost, api("/admin/keys/"+use), core.PassphraseInput{Passphrase: pass}, &raw); err != nil {
					return err
				}
				if !seal {
					return done(cmd, rawOrOK(raw), "unsealed; the server unlocks itself at start")
				}
				if err := done(cmd, rawOrOK(raw), "sealed; the server now starts locked (unlock with \"fileparcel keys unlock\")"); err != nil {
					return err
				}
				// Sealing never creates a recovery key, and a plain install has
				// none: without one a forgotten passphrase loses all data. The
				// web UI offers to create one at this point; warn the same way
				// (stderr, so --json stays one document).
				var st core.KeyStatus
				if json.Unmarshal(raw, &st) == nil && st.Mode == core.KeyModeSealed && !st.RecoveryConfigured {
					Warnf(cmd, "no recovery key is configured: if the passphrase is forgotten, all data is lost; "+
						"create one now with \"fileparcel keys recovery-key\" and store it offline")
				}
				return nil
			}
			if seal {
				return WithClient(cmd, run)
			}
			return withClientUnlocking(cmd, pass, run)
		},
	}
	what := "new passphrase"
	if !seal {
		what = "current passphrase"
	}
	pf.bind(cmd, what)
	return cmd
}

// rawOrOK returns raw for --json output, or nil when empty.
func rawOrOK(raw json.RawMessage) any {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	return raw
}

func newKeysPassphraseCmd() *cobra.Command {
	var stdin bool
	var curFile, newFile string
	cmd := &cobra.Command{
		Use:     "passphrase",
		Aliases: []string{"change-passphrase"},
		Short:   "Change the master key passphrase",
		Long: `Change the passphrase of a sealed master key. Both passphrases are asked for
without echo, or read from --current-file/--new-file, or from standard input
with --passphrase-stdin (first line: current, second line: new).

` + elevationNote,
		Example: `  fileparcel keys passphrase
  fileparcel keys passphrase --current-file /secure/old --new-file /secure/new
  printf '%s\n%s\n' "$OLD" "$NEW" | fileparcel keys passphrase --passphrase-stdin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var cur, next string
			var err error
			switch {
			case stdin && (curFile != "" || newFile != ""):
				return UsageError("use either --passphrase-stdin or --current-file/--new-file")
			case stdin:
				sc := bufio.NewScanner(io.LimitReader(cmd.InOrStdin(), maxSecret))
				lines := []string{}
				for sc.Scan() && len(lines) < 2 {
					lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
				}
				if len(lines) < 2 || lines[0] == "" || lines[1] == "" {
					return UsageError("--passphrase-stdin expects two lines: the current and the new passphrase")
				}
				cur, next = lines[0], lines[1]
			default:
				if curFile != "" {
					cur, err = ReadSecretFile(cmd, curFile)
				} else {
					cur, err = PromptSecret(cmd, "Current passphrase: ")
				}
				if err != nil {
					return err
				}
				if newFile != "" {
					next, err = ReadSecretFile(cmd, newFile)
				} else {
					next, err = PromptNewSecret(cmd, "New passphrase: ")
				}
				if err != nil {
					return err
				}
			}
			if cur == next {
				return UsageError("the new passphrase is the same as the current one")
			}
			return withClientUnlocking(cmd, cur, func(ctx context.Context, c *Client) error {
				in := core.PassphraseChangeInput{CurrentPassphrase: cur, NewPassphrase: next}
				if err := c.Do(ctx, http.MethodPost, api("/admin/keys/passphrase"), in, nil); err != nil {
					return err
				}
				return done(cmd, nil, "passphrase changed")
			})
		},
	}
	cmd.Flags().BoolVar(&stdin, "passphrase-stdin", false, "read the current and the new passphrase (two lines) from stdin")
	cmd.Flags().StringVar(&curFile, "current-file", "", "read the current passphrase from a file")
	cmd.Flags().StringVar(&newFile, "new-file", "", "read the new passphrase from a file")
	return cmd
}

func newKeysRotateCmd() *cobra.Command {
	var kek, master, data bool
	var purpose string
	var wait *waitFlags
	cmd := &cobra.Command{
		Use:   "rotate (--kek [--purpose blob|field] | --master | --data)",
		Short: "Replace encryption keys",
		Long: `Rotate keys:

  --kek     new key-encryption key; re-wraps every file key (purpose blob) or
            re-seals every encrypted setting/secret (purpose field). Fast.
  --master  new master key; re-wraps the keyring (the passphrase stays).
  --data    re-encrypt every file with fresh keys (slow; a background job).

A master rotation keeps the passphrase and the recovery key, and an old copy
of the key file still yields both. If the key file may have leaked, also run
"fileparcel keys passphrase" (sealed) or "fileparcel keys seal" (plain) and
"fileparcel keys recovery-key"; if the database may have leaked too, rotate
both key-encryption keys and use --data.

Retired keys nothing uses any more are removed 15 minutes after they were
retired, so "fileparcel keys status" still lists them right after a rotation.
Long operations run as background jobs; the command waits for them unless
--no-wait.

` + elevationNote,
		Example: `  fileparcel keys rotate --kek
  fileparcel keys rotate --kek --purpose field
  fileparcel keys rotate --master
  fileparcel keys rotate --data --no-wait`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var in core.KeysRotateInput
			switch countTrue(kek, master, data) {
			case 0:
				return UsageError("choose one of --kek, --master or --data")
			case 1:
			default:
				return UsageError("use only one of --kek, --master and --data")
			}
			switch {
			case kek:
				if purpose != core.KEKBlob && purpose != core.KEKField {
					return UsageError("invalid --purpose %q (blob or field)", purpose)
				}
				in = core.KeysRotateInput{Target: "kek", Purpose: purpose}
			case master:
				in.Target = "master"
			case data:
				in.Target = "data"
			}
			if cmd.Flags().Changed("purpose") && !kek {
				return UsageError("--purpose only applies to --kek")
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var raw json.RawMessage
				if err := c.Do(ctx, http.MethodPost, api("/admin/keys/rotate"), in, &raw); err != nil {
					return err
				}
				label := "rotated the " + in.Target + " key"
				if kek {
					label = "rotated the " + purpose + " key-encryption key"
				}
				if data {
					label = "re-encrypted all files"
				}
				if id := jobRefFrom(raw); id != "" {
					if offlineJobWarning(cmd, c, id) || !wait.Wait() {
						return done(cmd, &core.JobRef{JobID: id}, "job %s started", id)
					}
					j, err := waitJob(ctx, cmd, c, id, true, "rotating")
					if err != nil {
						return err
					}
					return done(cmd, j, "%s", label)
				}
				return done(cmd, rawOrOK(raw), "%s", label)
			})
		},
	}
	f := cmd.Flags()
	f.BoolVar(&kek, "kek", false, "rotate a key-encryption key")
	f.StringVar(&purpose, "purpose", core.KEKBlob, "with --kek: blob (file keys) or field (settings and secrets)")
	f.BoolVar(&master, "master", false, "rotate the master key")
	f.BoolVar(&data, "data", false, "re-encrypt all file data with new keys (background job)")
	wait = addWaitFlags(cmd, true, "the background jobs finish")
	return cmd
}

// newKeysRecoveryKeyCmd is "keys recovery-key" (and the hidden legacy copy
// "keys export-recovery", legacy.go).
func newKeysRecoveryKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recovery-key",
		Short: "Create a new recovery key (the old one stops working)",
		Long: `Creates a NEW recovery key (FPRK-…) and prints it once; the previous recovery
key stops working. The recovery key unlocks the master key without the
passphrase: store it offline.

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel keys recovery-key
  fileparcel keys recovery-key -y > /secure/fileparcel-recovery.txt`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := confirmOrAbort(cmd, "Create a new recovery key? The previous one stops working."); err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var rk core.RecoveryKey
				if err := c.Do(ctx, http.MethodPost, api("/admin/keys/recovery"), nil, &rk); err != nil {
					return err
				}
				if rk.RecoveryKey == "" {
					return errors.New("the server did not return a recovery key")
				}
				return Print(cmd, &rk, func(w io.Writer) error {
					Warnf(cmd, "the recovery key is shown only once; store it offline")
					_, err := fmt.Fprintln(w, rk.RecoveryKey)
					return err
				})
			})
		},
	}
}

// keyCheck is one finding of keys verify.
type keyCheck struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// verifyKeyStatus checks a KeyStatus for problems (DESIGN §7.6).
func verifyKeyStatus(st *core.KeyStatus) []keyCheck {
	var out []keyCheck
	add := func(check string, ok bool, detail string) {
		out = append(out, keyCheck{Check: check, OK: ok, Detail: detail})
	}
	add("master key unlocked", st.State == core.KeyStateUnlocked, string(st.State))
	for _, p := range []string{core.KEKBlob, core.KEKField, core.KEKMAC} {
		n := 0
		for _, k := range st.KEKs {
			if k.Purpose == p && k.State == core.KEKActive {
				n++
			}
		}
		add("one active "+p+" KEK", n == 1, fmt.Sprintf("%d active", n))
	}
	var pending []string
	for _, k := range st.KEKs {
		if k.State == core.KEKRetired && k.Refs > 0 {
			pending = append(pending, fmt.Sprintf("%s (%s, %d refs)", k.ID, k.Purpose, k.Refs))
		}
	}
	add("no retired KEK still in use", len(pending) == 0, strings.Join(pending, ", "))
	if st.Mode == core.KeyModeSealed {
		add("recovery key configured", st.RecoveryConfigured, "")
	}
	return out
}

func newKeysVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check the keyring for problems",
		Long: `Check the master key state and the keyring: exactly one active key per
purpose, no retired key still in use (an interrupted rotation: run
"fileparcel keys rotate --kek" again) and, in sealed mode, a recovery key.
Exits with status 1 when a check fails.`,
		Example: `  fileparcel keys verify
  fileparcel keys verify --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				st, err := getKeyStatus(ctx, c)
				if err != nil {
					return err
				}
				checks := verifyKeyStatus(st)
				failed := 0
				for _, k := range checks {
					if !k.OK {
						failed++
					}
				}
				err = Print(cmd, checks, func(w io.Writer) error {
					for _, k := range checks {
						mark := Green("ok  ")
						if !k.OK {
							mark = Red("FAIL")
						}
						line := mark + " " + k.Check
						if k.Detail != "" {
							line += Dim(" (" + k.Detail + ")")
						}
						fmt.Fprintln(w, line)
					}
					return nil
				})
				if err != nil {
					return err
				}
				if failed > 0 {
					return &ExitCodeError{Code: ExitFailure, Err: fmt.Errorf("%s failed", Plural(int64(failed), "check"))}
				}
				return nil
			})
		},
	}
}
