package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newTokenCmd) }

func newTokenCmd() *cobra.Command {
	cmd := groupCmd("token", "Create API tokens for scripts and remote use",
		`A personal API token ("fpt_…") lets scripts and the fileparcel command on
another computer act as a user: fileparcel --server URL --token-file FILE …,
or the token in $FILEPARCEL_TOKEN. Scopes limit what it may do: files:read,
files:write, shares and admin. Admin tokens made with --elevated count as a
recent identity confirmation for sensitive admin actions (at most 30 days).

On the server, tokens belong to --user (or --as), else to the first owner;
remotely they belong to the token's own user. See "fileparcel help connect".`,
		`  fileparcel token create laptop
  fileparcel token list --user alice
  fileparcel token revoke tok_01j9zq3x4k6m8p0r2t4v6x8z0b`, "tokens")
	cmd.AddCommand(newTokenListCmd(), newTokenCreateCmd(), newTokenRevokeCmd())
	setListHint(cmd, "fileparcel token list --inactive")
	return cmd
}

// withActingUser is withUserClient with an explicit --user override.
func withActingUser(cmd *cobra.Command, user string, fn func(ctx context.Context, c *Client) error) error {
	if user == "" {
		return withUserClient(cmd, fn)
	}
	if G.Server != "" {
		return UsageError("--user only works over the admin socket or offline; a remote token always acts as its own user")
	}
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		setClientActAs(c, user)
		return fn(ctx, c)
	})
}

func parseScopes(list []string) ([]string, error) {
	var out []string
	for _, item := range list {
		for _, s := range strings.Split(item, ",") {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			if !slices.Contains(core.AllScopes, s) {
				return nil, UsageError("unknown scope %q (valid: %s)", s, strings.Join(core.AllScopes, ", "))
			}
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		return nil, UsageError("at least one scope is required (valid: %s)", strings.Join(core.AllScopes, ", "))
	}
	return out, nil
}

func newTokenListCmd() *cobra.Command {
	var user string
	var inactive bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List API tokens",
		Long: `List the API tokens of a user; their secrets are never shown again. Revoked
and expired tokens are left out unless --inactive.`,
		Example: `  fileparcel token list
  fileparcel token list --user alice --inactive`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withActingUser(cmd, user, func(ctx context.Context, c *Client) error {
				tokens, err := listAll[core.APIToken](ctx, c, api("/me/tokens"), 0)
				if err != nil {
					return err
				}
				if !inactive {
					now := time.Now()
					kept := tokens[:0]
					for _, t := range tokens {
						if t.RevokedAt == nil && (t.ExpiresAt == nil || t.ExpiresAt.After(now)) {
							kept = append(kept, t)
						}
					}
					tokens = kept
				}
				return Print(cmd, tokens, func(w io.Writer) error {
					t := NewTable("ID", "NAME", "SCOPES", "ELEVATED", "CREATED", "EXPIRES", "LAST USED")
					for _, tk := range tokens {
						exp := HumanTimePtr(tk.ExpiresAt)
						if tk.ExpiresAt == nil {
							exp = "never"
						}
						if tk.RevokedAt != nil {
							exp = "revoked"
						}
						t.Add(tk.ID, tk.Name, strings.Join(tk.Scopes, ","), tk.Elevated, tk.CreatedAt, exp, HumanTimePtr(tk.LastUsedAt))
					}
					return t.Render(w)
				})
			})
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "list the tokens of this user (admin socket only; default --as or the first owner)")
	addInactiveFlag(cmd, &inactive, "include revoked and expired tokens")
	return cmd
}

func newTokenCreateCmd() *cobra.Command {
	var in core.TokenInput
	var name, user, expires string
	var scopes []string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an API token (the secret is shown once)",
		Long: `Create a personal API token. The name tells you where the token is used. The
secret is printed once; store it safely.

--expires takes a duration (30d, 12h, 2w), a date (2026-12-31) or "never"
(default). --elevated (needs the admin scope) makes the token count as a
recent identity confirmation for sensitive admin actions; such tokens must
expire within 30 days. The admin scope needs an account with server
permissions (an administrator, or a role with such permissions: see
"fileparcel role show <role>").`,
		Example: `  fileparcel token create laptop
  fileparcel token create backup-script --scopes files:read --expires 90d
  fileparcel token create ops --user alice --scopes admin --elevated --expires 7d`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Legacy: "token create --name NAME" (legacy.go).
			if len(args) == 1 {
				if cmd.Flags().Changed("name") && name != args[0] {
					return UsageError("the name is given twice (%q and --name %q); give it once, as the argument", args[0], name)
				}
				name = args[0]
			}
			if in.Name = strings.TrimSpace(name); in.Name == "" {
				return needsArgsError(cmd)
			}
			sc, err := parseScopes(scopes)
			if err != nil {
				return err
			}
			in.Scopes = sc
			now := time.Now()
			exp, _, err := parseExpiry(expires, now, true)
			if err != nil {
				return err
			}
			switch {
			case in.Elevated && exp == nil:
				return UsageError("--elevated tokens must expire within 30 days (e.g. --expires 30d)")
			case in.Elevated && exp.Sub(now) > 30*24*time.Hour:
				return UsageError("--elevated tokens must expire within 30 days")
			}
			in.ExpiresAt = exp
			if in.Elevated && !slices.Contains(in.Scopes, core.ScopeAdmin) {
				return UsageError("--elevated requires the admin scope")
			}
			return withActingUser(cmd, user, func(ctx context.Context, c *Client) error {
				var res core.TokenCreated
				if err := c.Do(ctx, http.MethodPost, api("/me/tokens"), in, &res); err != nil {
					return err
				}
				// A user in scope of auth.require_2fa without a second factor
				// is EnrollRequired (DESIGN §9.3), which refuses their tokens
				// on every remote route but GET /me and /me/mfa, so the token
				// cannot be used until they enrol in the web UI. Best effort:
				// never fail a create whose secret is already minted.
				enroll := false
				var mfa core.MFAStatus
				if err := c.Do(ctx, http.MethodGet, api("/me/mfa"), nil, &mfa); err == nil {
					enroll = mfa.EnrollRequired
				}
				if err := Print(cmd, res, func(w io.Writer) error {
					if res.Token != nil {
						Successf(cmd, "created token %s (%s)", res.Token.ID, strings.Join(res.Token.Scopes, ","))
					}
					fmt.Fprintln(w, res.Secret)
					Infof(cmd, "The token is shown only once. Use it with: fileparcel --server URL --token-file FILE … (or $%s)", TokenEnv)
					return nil
				}); err != nil {
					return err
				}
				if enroll {
					Warnf(cmd, "this account has no second factor yet and auth.require_2fa applies to it: until two-factor "+
						"authentication is set up in the web UI, every remote request with this token fails with "+
						"\"two-factor authentication must be set up first\"")
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "the token's name (use the argument)")
	_ = f.MarkHidden("name")
	f.StringVar(&user, "user", "", "create the token for this user (admin socket only; default --as or the first owner)")
	f.StringSliceVar(&scopes, "scopes", []string{core.ScopeFilesRead, core.ScopeFilesWrite, core.ScopeShares},
		"comma-separated scopes: files:read, files:write, shares, admin")
	f.StringVar(&expires, "expires", "never", "lifetime: a duration (30d, 12h), a date (2026-12-31) or never")
	f.BoolVar(&in.Elevated, "elevated", false, "admin token that counts as step-up elevated (max 30 days)")
	return cmd
}

func newTokenRevokeCmd() *cobra.Command {
	var user string
	cmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an API token right away",
		Long: `Revoke an API token right away; scripts using it stop working. On the server,
pass --user for the tokens of users other than the first owner.`,
		Example: `  fileparcel token revoke tok_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel token revoke tok_01j9zq3x4k6m8p0r2t4v6x8z0b --user alice`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withActingUser(cmd, user, func(ctx context.Context, c *Client) error {
				if err := c.Do(ctx, http.MethodDelete, api("/me/tokens/"+pathEsc(args[0])), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"revoked": args[0]}, "revoked token %s", args[0])
			})
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "the token's owner (admin socket only; default --as or the first owner)")
	return cmd
}
