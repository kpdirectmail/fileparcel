package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
)

func init() { Register(newConfigCmd) }

func newConfigCmd() *cobra.Command {
	cmd := groupCmd("config", "Show and change settings",
		`Read and change FileParcel's settings: the runtime settings stored in the
database (applied immediately by a running server) and the bootstrap settings
of fileparcel.toml that are also runtime settings (server name, ports, listen
addresses, public URL and trusted proxies, log.level, runtime.gomemlimit_mb;
most need a restart). Change the other keys of fileparcel.toml with
"fileparcel config edit".

Values are parsed as JSON when they are valid JSON (true, 30, ["a","b"]),
otherwise taken as a plain string; list settings also accept "a,b,c". Secret
settings are read from stdin (or a no-echo prompt), never from the command
line.`,
		`  fileparcel config list
  fileparcel config get storage.trash_days
  fileparcel config set storage.trash_days 14
  fileparcel config set smtp.password < smtp-password.txt`, "settings")
	cmd.AddCommand(newConfigListCmd(), newConfigGetCmd(), newConfigSetCmd(), newConfigUnsetCmd(), newConfigPathCmd(), newConfigEditCmd(),
		newConfigTestEmailCmd())
	setListHint(cmd, "fileparcel config list --all")
	return cmd
}

// settingValueText renders a setting value for humans: strings unquoted,
// lists comma-joined, secrets masked.
func settingValueText(s *core.SettingView) string {
	if s.Secret {
		if s.IsSet {
			return "(set)"
		}
		return "(not set)"
	}
	return jsonText(s.Value)
}

// jsonText renders a JSON value compactly for humans.
func jsonText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "" {
			return `""`
		}
		return s
	}
	var list []any
	if json.Unmarshal(raw, &list) == nil {
		parts := make([]string, len(list))
		for i, v := range list {
			parts[i] = fmt.Sprint(v)
		}
		if len(parts) == 0 {
			return "[]"
		}
		return strings.Join(parts, ",")
	}
	var buf bytes.Buffer
	if json.Compact(&buf, raw) == nil {
		return buf.String()
	}
	return string(raw)
}

// parseSettingValue converts a command-line value to JSON for a setting of
// type typ (catalog type names; "" when unknown): JSON when valid, else a
// string; string-like types always become strings; list types accept
// comma-separated values; bool accepts yes/no/on/off.
func parseSettingValue(typ, v string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(v)
	isJSON := json.Valid([]byte(trimmed)) && trimmed != ""
	str := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
	switch typ {
	case "string", "enum", "cron", "color", "email", "url", "duration", "secret":
		if isJSON && strings.HasPrefix(trimmed, `"`) {
			return json.RawMessage(trimmed), nil
		}
		if typ == "string" {
			return str(v), nil // keep the value exactly (spaces may matter)
		}
		return str(trimmed), nil
	case "bool":
		switch strings.ToLower(trimmed) {
		case "true", "yes", "on", "1", "enable", "enabled":
			return json.RawMessage("true"), nil
		case "false", "no", "off", "0", "disable", "disabled":
			return json.RawMessage("false"), nil
		}
		return nil, UsageError("expected a boolean (true/false, yes/no, on/off), got %q", v)
	case "int":
		n, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return nil, UsageError("expected an integer, got %q", v)
		}
		return json.RawMessage(strconv.FormatInt(n, 10)), nil
	case "strings", "cidrs":
		if strings.HasPrefix(trimmed, "[") {
			var list []string
			if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
				return nil, UsageError("expected a JSON list of strings, got %q", v)
			}
			b, _ := json.Marshal(list)
			return b, nil
		}
		list := []string{}
		for _, p := range strings.Split(trimmed, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, p)
			}
		}
		b, _ := json.Marshal(list)
		return b, nil
	}
	if isJSON {
		return json.RawMessage(trimmed), nil
	}
	return str(v), nil
}

// readSecretValue reads a secret setting from stdin: a no-echo prompt on a
// terminal, otherwise the whole input (up to 64 KiB, trailing newlines
// removed; multi-line values such as JSON credentials are kept).
func readSecretValue(cmd *cobra.Command, key string) (string, error) {
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok && isTerminal(f) {
		return PromptNewSecret(cmd, fmt.Sprintf("Value for %s: ", key))
	}
	data, err := io.ReadAll(io.LimitReader(in, maxSecret+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSecret {
		return "", errors.New("secret input too long")
	}
	s := strings.TrimRight(string(data), "\r\n")
	if s == "" {
		return "", errors.New("empty secret on stdin")
	}
	return s, nil
}

func newConfigListCmd() *cobra.Command {
	var section string
	var all bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List settings (changed ones, or --all)",
		Long: `List the settings that differ from their defaults (--all: every setting with
its default, type and whether a change needs a restart). Secrets are never
shown, only whether they are set.`,
		Example: `  fileparcel config list
  fileparcel config list --all --section storage
  fileparcel config list --all --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				list, err := settingsCatalog(ctx, c)
				if err != nil {
					return err
				}
				kept := list[:0]
				for _, s := range list {
					if section != "" && !strings.EqualFold(s.Section, section) {
						continue
					}
					if !all && !s.IsSet && s.OverriddenByEnv == "" {
						continue
					}
					kept = append(kept, s)
				}
				list = kept
				return Print(cmd, list, func(w io.Writer) error {
					if len(list) == 0 {
						if all {
							Infof(cmd, "no settings in section %q", section)
						} else {
							Infof(cmd, "all settings have their default values (use --all to list them)")
						}
						return nil
					}
					var t *Table
					if all {
						t = NewTable("KEY", "VALUE", "DEFAULT", "TYPE", "NOTES")
					} else {
						t = NewTable("KEY", "VALUE", "DEFAULT", "NOTES")
					}
					for i := range list {
						s := &list[i]
						var notes []string
						if s.Restart {
							notes = append(notes, "restart")
						}
						if s.Bootstrap {
							notes = append(notes, "toml")
						}
						if s.OverriddenByEnv != "" {
							notes = append(notes, "env "+s.OverriddenByEnv)
						}
						if s.Managed != "" {
							notes = append(notes, "managed")
						}
						def := jsonText(s.Default)
						if s.Secret {
							def = ""
						}
						if all {
							t.Add(s.Key, Truncate(settingValueText(s), 50), Truncate(def, 30), s.Type, strings.Join(notes, ","))
						} else {
							t.Add(s.Key, Truncate(settingValueText(s), 60), Truncate(def, 30), strings.Join(notes, ","))
						}
					}
					return t.Render(w)
				})
			})
		},
	}
	cmd.Flags().StringVar(&section, "section", "", "only this section (general, network, tls, auth, storage, sharing, backup, …)")
	cmd.Flags().BoolVar(&all, "all", false, "list every setting, including those with default values")
	return cmd
}

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "get <key>",
		Aliases: []string{"show"},
		Short:   "Show one setting",
		Long: `Print the value of a setting (plain text; lists comma-separated) or, with
--json, everything about it: type, default, allowed values and description.`,
		Example: `  fileparcel config get storage.trash_days
  fileparcel config get network.allow_cidrs --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getSetting(ctx, c, args[0])
				if err != nil {
					return err
				}
				return Print(cmd, s, func(w io.Writer) error {
					_, err := fmt.Fprintln(w, settingValueText(s))
					return err
				})
			})
		},
	}
}

func newConfigSetCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "set <key> [value]",
		Short: "Change a setting",
		Long: `Change a setting. A running server applies it immediately (some settings
need a restart, which is reported). Offline, the change takes effect at the
next start. Settings shown as "managed" are changed by their own command
(e.g. funnel.* by "fileparcel network funnel"). Sensitive sections need
elevation remotely.

Values are parsed according to the setting's type: JSON when valid, otherwise a
string; list settings accept "a,b,c"; booleans accept yes/no/on/off. Secret
settings take no value argument: the value is read from stdin (or prompted for
without echo).

Some changes are refused unless confirmed with --force: an access policy
(network.access_mode, network.allow_cidrs, network.deny_cidrs) that would
lock out the client making it, and turning auth.passkeys off or moving the
passkey domain (auth.webauthn_rp_id, mdns.name, server.name) while accounts
have no second factor other than a passkey ("fileparcel user reset-2fa"
lets such a user sign in again).

` + elevationNote,
		Example: `  fileparcel config set storage.trash_days 14
  fileparcel config set sharing.require_password true
  fileparcel config set ui.instance_name "Family Files"
  printf '%s' "$SMTP_PASSWORD" | fileparcel config set smtp.password`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			// Without a value (or with "-") the value comes from standard
			// input, which then cannot also carry the passphrase
			// (checkInvocation's rule for the -stdin flags).
			if (len(args) == 1 || args[1] == "-") && G.PassphraseStdin {
				return UsageError("--passphrase-stdin and the value of %s cannot both read standard input; "+
					"use --passphrase-file for the passphrase", key)
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getSetting(ctx, c, key)
				if err != nil {
					return err
				}
				var raw json.RawMessage
				switch {
				case s.Secret && len(args) == 2 && args[1] != "-":
					return UsageError("%s is a secret: pass the value on stdin, not on the command line (it would end up in your shell history)", key)
				case s.Secret:
					v, err := readSecretValue(cmd, key)
					if err != nil {
						return err
					}
					raw, _ = json.Marshal(v)
				case len(args) == 1:
					return UsageError("missing value for %s (use \"config unset %s\" to restore the default)", key, key)
				default:
					if raw, err = parseSettingValue(s.Type, args[1]); err != nil {
						return err
					}
				}
				res, err := patchSettingsForce(ctx, cmd, c, map[string]any{key: raw}, force)
				if err != nil {
					return settingRefused(s, err, force)
				}
				shown := jsonText(raw)
				if s.Secret {
					shown = "(secret)"
				}
				return done(cmd, res, "%s = %s", key, shown)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, forceUsage)
	return cmd
}

// managedHint is the hint of a refused change of the managed setting key:
// the command that owns it (funnel.serve* belong to Tailscale Serve), or ""
// when the server's message names that command already.
func managedHint(key, msg string) string {
	cmd := "fileparcel network funnel"
	if strings.HasPrefix(key, "funnel.serve") {
		cmd = "fileparcel network tailscale-serve"
	}
	if strings.Contains(msg, "fileparcel network ") {
		return ""
	}
	return fmt.Sprintf("use %q", cmd)
}

// settingRefused explains a refused change of setting s: a managed setting
// has its own command (409 whatever --force says); other conflicts are the
// server's safety guards (see guardHint).
func settingRefused(s *core.SettingView, err error, force bool) error {
	if s.Managed != "" && apiStatus(err) == http.StatusConflict {
		if hint := managedHint(s.Key, core.AsError(err).Message); hint != "" {
			return &hintError{err, hint}
		}
		return err
	}
	return guardHint(err, force)
}

// forceUsage describes --force of config set and unset.
const forceUsage = "apply a change the server refuses as unsafe (an access policy that locks you out; " +
	"turning passkeys off or moving their domain while accounts rely on a passkey alone)"

func newConfigUnsetCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "unset <key>",
		Aliases: []string{"reset"},
		Short:   "Put a setting back to its default",
		Long: `Put a setting back to its default value (secrets are cleared). A reset the
server refuses as unsafe needs --force, as with "fileparcel config set".`,
		Example: `  fileparcel config unset ui.login_message
  fileparcel config unset storage.trash_days`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getSetting(ctx, c, args[0])
				if err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodDelete, api("/admin/settings/"+pathEsc(s.Key), "force", boolParam(force)), nil, nil); err != nil {
					return settingRefused(s, err, force)
				}
				if s.Restart {
					noteRestart(cmd, c, []string{s.Key})
				}
				def := jsonText(s.Default)
				if s.Secret {
					def = "(not set)"
				}
				return done(cmd, map[string]any{"key": s.Key, "value": s.Default}, "%s reset to its default (%s)", s.Key, Dash(def))
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, forceUsage)
	return cmd
}

func newConfigPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the path of fileparcel.toml",
		Long: `Print the full path of fileparcel.toml, the start-up configuration of the
installation (see --home in "fileparcel help flags").`,
		Example: `  fileparcel config path
  $EDITOR "$(fileparcel config path)"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			return Print(cmd, map[string]string{"path": h.Config(), "home": h.Dir()}, func(w io.Writer) error {
				_, err := fmt.Fprintln(w, h.Config())
				return err
			})
		},
	}
}

// editorCommand returns the user's editor ($VISUAL, $EDITOR, vi).
func editorCommand() string {
	for _, k := range []string{"VISUAL", "EDITOR"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return "vi"
}

func newConfigEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Edit fileparcel.toml in your editor",
		Long: `Open fileparcel.toml in $VISUAL/$EDITOR (default vi). The file is edited as a
copy, validated when the editor exits and only then saved (atomically, keeping
its permissions and owner). An invalid copy can be edited again; with -y it is
discarded at once. Restart the server to apply the changes.`,
		Example: `  fileparcel config edit
  VISUAL=nano fileparcel config edit`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			path := h.Config()
			orig, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			st, err := os.Stat(path)
			if err != nil {
				return err
			}
			tmp, err := os.CreateTemp(filepath.Dir(path), ".fileparcel.toml.edit-*")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			defer os.Remove(tmpPath)
			if _, err := tmp.Write(orig); err != nil {
				tmp.Close()
				return err
			}
			if err := tmp.Close(); err != nil {
				return err
			}
			for {
				ed := exec.Command("sh", "-c", editorCommand()+` "$1"`, "sh", tmpPath)
				ed.Stdin, ed.Stdout, ed.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := ed.Run(); err != nil {
					return fmt.Errorf("editor: %w", err)
				}
				if err := ctxErr(cmd.Context()); err != nil {
					return err // Ctrl-C or SIGTERM: the copy is removed on the way out
				}
				data, err := os.ReadFile(tmpPath)
				if err != nil {
					return err
				}
				if bytes.Equal(data, orig) {
					Infof(cmd, "No changes.")
					return nil
				}
				verr := validateTOML(data)
				if verr == nil {
					// The owner first (a chown may clear mode bits); a copy
					// written by sudo would lock the server out of it.
					if err := keepOwner(tmpPath, path); err != nil {
						return err
					}
					if err := os.Chmod(tmpPath, st.Mode().Perm()); err != nil {
						return err
					}
					if err := os.Rename(tmpPath, path); err != nil {
						return err
					}
					Successf(cmd, "saved %s", path)
					Infof(cmd, "Restart the server to apply the changes: fileparcel service restart")
					return nil
				}
				// -y must not answer "edit again" for ever: nobody fixes the
				// file in a non-interactive run (help scripting).
				if G.Yes {
					return fmt.Errorf("the file is not valid, changes discarded: %v", verr)
				}
				Warnf(cmd, "the file is not valid: %v", verr)
				again, err := Confirm(cmd, "Edit again? (no discards your changes)", true)
				if err != nil || !again {
					return errors.New("changes discarded")
				}
			}
		},
	}
}

// validateTOML parses and validates a fileparcel.toml candidate.
func validateTOML(data []byte) error {
	c, err := config.Parse(data)
	if err != nil {
		return err
	}
	if w := c.Warnings(); len(w) > 0 {
		return errors.New(strings.Join(w, "; "))
	}
	return c.Validate()
}
