package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

func init() { Register(newWhoamiCmd) }

// whoamiView is the JSON of "fileparcel whoami".
type whoamiView struct {
	// Via is how the command reached the server: socket, offline or token.
	Via core.AuthVia `json:"via"`
	// System is true for the full rights of the admin socket or of offline
	// mode without --as (no account).
	System bool `json:"system"`
	// FilesAs is the account file, share, request and token commands act
	// as when System is true (the first owner; "" when there is none).
	FilesAs string `json:"files_as,omitempty"`
	// Server is the --server URL (remote only).
	Server string `json:"server,omitempty"`
	// User is the account commands act as (GET /me), with its role and
	// permissions.
	User *core.User `json:"user,omitempty"`
	// Groups are the account's groups (with its role in each); [] rather
	// than null for an account, left out for System (see MarshalJSON).
	Groups []core.Group `json:"groups,omitempty"`
	// Staff reports whether commands can use at least one server permission
	// this way: always for System; for an account, whether its role has one
	// (a token also needs the "admin" scope).
	Staff bool `json:"staff"`
	// ElevatedUntil is the end of the step-up window of an elevated token.
	ElevatedUntil *time.Time `json:"elevated_until,omitempty"`
	// Token is the API token of a remote command, when the server lists it.
	Token *core.APIToken `json:"token,omitempty"`
	// TokenError says why the token could not be listed (GET /me/tokens
	// refused, e.g. because the account must set up two-factor first).
	TokenError string `json:"token_error,omitempty"`
}

// MarshalJSON writes Groups as [] for an account without groups (lists
// are never null, DESIGN §12.1) and leaves it out for System, which has no
// account.
func (v whoamiView) MarshalJSON() ([]byte, error) {
	type plain whoamiView
	out := struct {
		plain
		Groups *[]core.Group `json:"groups,omitempty"`
	}{plain: plain(v)}
	if v.User != nil {
		g := v.Groups
		if g == nil {
			g = []core.Group{}
		}
		out.Groups = &g
	}
	return json.Marshal(out)
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show who you act as, your role and what you may do",
		Long: `Show which account commands act as and what it may do: its role, the
permissions of that role, its groups and whether it signs in with a second
factor. Remotely it also shows the API token in use, its scopes and when it
expires.

On the server, commands without --as have the admin socket's full rights (or,
with the server stopped, work on the data directly with the same rights);
file, share, request and token commands then act as the first owner. With
--as USER they act as that user. Remotely every command acts as the token's
user. See "fileparcel help connect" and "fileparcel help permissions".`,
		Example: `  fileparcel whoami
  fileparcel --as alice whoami
  fileparcel --server https://files.example.lan:8443 --token-file ~/.fileparcel-token whoami`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				v := whoamiView{Via: core.ViaToken}
				switch c.Mode() {
				case ModeSocket:
					v.Via = core.ViaSocket
				case ModeOffline:
					v.Via = core.ViaOffline
				default:
					v.Server = G.Server
				}
				if c.Mode() != ModeRemote && G.As == "" {
					v.System, v.Staff = true, true
					if owner, err := firstOwner(ctx, c); err == nil {
						v.FilesAs = owner
					}
					return Print(cmd, v, func(w io.Writer) error { return renderSystemWhoami(w, &v) })
				}
				var me core.Me
				if err := c.Do(ctx, http.MethodGet, api("/me"), nil, &me); err != nil {
					return err
				}
				v.User, v.Groups, v.Staff, v.ElevatedUntil = me.User, me.Groups, me.Staff, me.ElevatedUntil
				if v.Groups == nil {
					v.Groups = []core.Group{}
				}
				if c.Mode() == ModeRemote {
					tok, err := currentToken(ctx, c, G.ConnectOptions().Token)
					if err != nil {
						// whoami is the diagnostic command: say why rather
						// than leave the token lines out.
						v.TokenError = err.Error()
						if ce := core.AsError(err); ce != nil && ce.Message != "" {
							v.TokenError = ce.Message
						}
					}
					v.Token = tok
				}
				return Print(cmd, v, func(w io.Writer) error {
					if err := renderWhoami(w, &v); err != nil {
						return err
					}
					if hint := tokenScopeHint(&v); hint != "" {
						Infof(cmd, "%s", hint)
					}
					return nil
				})
			})
		},
	}
}

// renderSystemWhoami prints the full rights of the admin socket or of
// offline mode, and whom file commands act as.
func renderSystemWhoami(w io.Writer, v *whoamiView) error {
	what := "admin socket"
	if v.Via == core.ViaOffline {
		what = "offline (server stopped)"
	}
	if _, err := fmt.Fprintf(w, "%s (system): full rights\n", what); err != nil {
		return err
	}
	if v.FilesAs == "" {
		return nil
	}
	_, err := fmt.Fprintf(w, "File, share, request and token commands act as %s, the first owner (--as USER for someone else).\n",
		v.FilesAs)
	return err
}

// renderWhoami prints the account a command acts as.
func renderWhoami(w io.Writer, v *whoamiView) error {
	kv := NewKV()
	if u := v.User; u != nil {
		account := u.Username
		if d := strings.TrimSpace(u.DisplayName); d != "" && d != u.Username {
			account += " (" + d + ")"
		}
		kv.Add("Account", account)
		kv.Add("ID", u.ID)
		kv.Add("Role", userRoleDetail(u))
		if perms, ok := userPermissionsText(u); ok {
			kv.Add("Permissions", perms)
		}
		var groups []string
		for _, g := range v.Groups {
			name := g.Name
			if g.MyRole == core.GroupRoleManager {
				name += " (manager)"
			}
			groups = append(groups, name)
		}
		kv.Add("Groups", strings.Join(groups, ", "))
		kv.Add("Two-factor", u.MFAEnabled)
	}
	switch v.Via {
	case core.ViaSocket:
		kv.Add("Acting via", "the admin socket (--as "+G.As+")")
	case core.ViaOffline:
		kv.Add("Acting via", "offline, the server is stopped (--as "+G.As+")")
	default:
		kv.Add("Acting via", "an API token on "+v.Server)
		if v.TokenError != "" {
			kv.Add("Token", "not shown ("+v.TokenError+")")
		}
		if t := v.Token; t != nil {
			kv.Add("Token", fmt.Sprintf("%s (%s)", t.Name, t.ID))
			kv.Add("Scopes", tokenScopesText(t))
			expires := "never"
			if t.ExpiresAt != nil {
				expires = HumanTime(*t.ExpiresAt)
			}
			kv.Add("Expires", expires)
		}
		if v.ElevatedUntil != nil {
			kv.Add("Elevated until", *v.ElevatedUntil)
		}
	}
	return kv.Render(w)
}

// tokenScopesText lists a token's scopes; an elevated token says so.
func tokenScopesText(t *core.APIToken) string {
	var scopes []string
	for _, s := range t.Scopes {
		if s != core.ScopeElevated {
			scopes = append(scopes, s)
		}
	}
	text := strings.Join(scopes, ", ")
	if t.Elevated {
		text += " (elevated)"
	}
	return text
}

// tokenScopeHint explains why admin commands fail with a token of an
// account whose role has server permissions but which lacks the "admin"
// scope ("" otherwise).
func tokenScopeHint(v *whoamiView) string {
	t, u := v.Token, v.User
	if t == nil || u == nil || slices.Contains(t.Scopes, core.ScopeAdmin) {
		return ""
	}
	if !u.Role.IsAdmin() && u.Permissions.Server() == 0 {
		return ""
	}
	return `this token has no "admin" scope, so admin commands are refused; ` +
		`make one with "fileparcel token create NAME --scopes admin"`
}

// currentToken returns the API token a remote command authenticates with
// (the id is part of the secret: fpt_<id suffix>_<secret>), or nil when the
// secret names no token id or the server does not list it; err when the
// server refused the list.
func currentToken(ctx context.Context, c *Client, secret string) (*core.APIToken, error) {
	id := tokenIDOf(secret)
	if id == "" {
		return nil, nil
	}
	tokens, err := listAll[core.APIToken](ctx, c, api("/me/tokens"), 0)
	if err != nil {
		return nil, err
	}
	for i := range tokens {
		if tokens[i].ID == id {
			return &tokens[i], nil
		}
	}
	return nil, nil
}

// tokenIDOf returns the id ("tok_…") of an API token secret, or "".
func tokenIDOf(secret string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(secret), "fpt_")
	if !ok {
		return ""
	}
	suffix, _, ok := strings.Cut(rest, "_")
	if !ok {
		return ""
	}
	id := ids.PrefixToken + "_" + suffix
	if !ids.Valid(ids.PrefixToken, id) {
		return ""
	}
	return id
}
