package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newUserCmd) }

func newUserCmd() *cobra.Command {
	cmd := groupCmd("user", "Create and manage user accounts",
		`User accounts sign in to the web app and have their own files ("/My files").
Every account has one role that decides what it may do on the server: owner,
admin, member (the default), guest, or a custom role ("fileparcel role").
Guests have no personal files; they only see what is shared with them.

Name users by username or by id (usr_…). Access to more folders comes from
groups ("fileparcel group") and access grants ("fileparcel access").`,
		`  fileparcel user list
  fileparcel user create alice --email alice@example.com --generate-password
  fileparcel user set-role alice admin
  fileparcel user set-quota alice 50G`, "users")
	cmd.SuggestFor = []string{"account", "accounts", "people"}
	cmd.AddCommand(
		newUserListCmd(), newUserCreateCmd(), newUserShowCmd(), newUserEditCmd(), newUserResetPasswordCmd(),
		newUserSetRoleCmd(), newUserSetQuotaCmd(), newUserStatusCmd("disable"), newUserStatusCmd("enable"),
		newUserDeleteCmd(), newUserUnlockCmd(), newUserReset2FACmd(), newUserSessionsCmd(), newUserRevokeSessionsCmd(),
	)
	setListHint(cmd, "fileparcel user list")
	return cmd
}

func renderUsers(w io.Writer, users []core.User) error {
	t := NewTable("USERNAME", "NAME", "ROLE", "STATUS", "2FA", "QUOTA", "LAST LOGIN", "ID")
	// locked_until stays set after the lock expires (until the next
	// successful login or "user unlock"), so compare it with now.
	now := time.Now()
	for _, u := range users {
		status := u.Status
		if u.Locked(now) {
			status += " (locked)"
		}
		t.Add(u.Username, u.DisplayName, userRoleText(&u), status, YesNo(u.MFAEnabled), quotaText(u.QuotaBytes), HumanTimePtr(u.LastLoginAt), u.ID)
	}
	return t.Render(w)
}

// quotaText renders a user quota (nil = server default, 0 = unlimited).
func quotaText(q *int64) string {
	switch {
	case q == nil:
		return "default"
	case *q == 0:
		return "unlimited"
	}
	return HumanBytes(*q)
}

// parseUserQuota parses "default" (nil opt = null), "unlimited" (0) or a size.
// Only the words (and a bare "0") mean unlimited: a size that comes out below
// one byte ("0.5", "0K") is an error rather than silently unlimited.
func parseUserQuota(s string) (core.Opt[int64], error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "default":
		return core.Null[int64](), nil
	case "unlimited", "none", "0":
		return core.Some[int64](0), nil
	}
	n, err := ParseSize(s)
	if err != nil {
		return core.Opt[int64]{}, UsageError("%v", err)
	}
	if n <= 0 {
		return core.Opt[int64]{}, UsageError("quota %q is less than 1 byte; use \"unlimited\" for no limit", s)
	}
	return core.Some(n), nil
}

// userRoleText is the role of an account in lists: the built-in word, or
// the name of a custom role.
func userRoleText(u *core.User) string {
	if core.IsCustomRoleID(u.RoleID) && u.RoleName != "" {
		return u.RoleName
	}
	return string(u.Role)
}

// roleFields returns the body fields that give role r: "role" for a
// built-in word (servers without roles understand it; on a server with
// roles it also takes a custom role away), "role_id" for a custom role.
func roleFields(r *roleRef) (role core.Role, roleID string) {
	if r.Builtin {
		return core.Role(r.ID), ""
	}
	return "", r.ID
}

// roleHelp ends the help text of --role on the user and invite commands.
const roleHelp = `a built-in role or a custom one (see "fileparcel role list")`

func newUserListCmd() *cobra.Command {
	var role, status, query string
	var limit int
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List user accounts",
		Long: `List user accounts with their role, status, two-factor state, quota and last
sign-in. The flags narrow the list; -q searches usernames, display names and
e-mail addresses.`,
		Example: `  fileparcel user list
  fileparcel user list --role admin
  fileparcel user list --status disabled --json
  fileparcel user list -q ali`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				// role (the base) keeps a built-in filter right on servers
				// without roles, which ignore role_id.
				var base, roleID string
				if role != "" {
					r, err := resolveRole(ctx, c, role)
					if err != nil {
						return err
					}
					if roleID = r.ID; r.Builtin {
						base = r.ID
					}
				}
				users, err := listAll[core.User](ctx, c, api("/admin/users", "q", query, "role", base, "role_id", roleID,
					"status", status, "limit", limitParam(limit)), limit)
				if err != nil {
					return err
				}
				return Print(cmd, users, func(w io.Writer) error { return renderUsers(w, users) })
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&role, "role", "", `only users with this role (see "fileparcel role list")`)
	f.StringVar(&status, "status", "", "only users with this status (active, disabled)")
	f.StringVarP(&query, "query", "q", "", "search username, display name and e-mail")
	f.IntVar(&limit, "limit", 0, "maximum number of users (0 = all)")
	return cmd
}

func newUserCreateCmd() *cobra.Command {
	var in core.NewUser
	var role, quota string
	var groups []string
	var pw *secretInput
	cmd := &cobra.Command{
		Use:     "create <user>",
		Aliases: []string{"add"},
		Short:   "Create a user account",
		Long: `Create a user account and its personal files ("/My files"; guests have
none).

The password is read from --password-stdin or --password-file, generated with
--generate-password (printed once), or asked for on a terminal. Generated
passwords and --must-change make the user choose a new password at the first
sign-in.

` + elevationNoteFor("Creating an owner or admin account"),
		Example: `  fileparcel user create alice --email alice@example.com --generate-password
  echo 'correct horse battery staple' | fileparcel user create bob --password-stdin --role admin
  fileparcel user create carol --generate-password --quota 20G --group Design --group Marketing
  fileparcel user create visitor --role guest --generate-password`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in.Username = args[0]
			if quota != "" {
				q, err := parseUserQuota(quota)
				if err != nil {
					return err
				}
				if q.Set && !q.Null {
					v := q.V
					in.QuotaBytes = &v
				}
			}
			if pw.Generate {
				in.GeneratePassword = true
			} else {
				p, err := pw.Read(cmd, true)
				if err != nil {
					return err
				}
				in.Password = p
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				r, err := resolveRole(ctx, c, role)
				if err != nil {
					return err
				}
				in.Role, in.RoleID = roleFields(r)
				for _, g := range groups {
					grp, err := resolveGroup(ctx, c, g)
					if err != nil {
						return err
					}
					in.GroupIDs = append(in.GroupIDs, grp.ID)
				}
				var res core.UserCreated
				if err := c.Do(ctx, http.MethodPost, api("/admin/users"), in, &res); err != nil {
					return err
				}
				return Print(cmd, res, func(w io.Writer) error {
					name := in.Username
					if res.User != nil {
						name = res.User.Username
					}
					Successf(cmd, "created %s user %q", r.label(), name)
					if res.Password != "" {
						fmt.Fprintf(w, "Password: %s\n", res.Password)
						Infof(cmd, "The password is shown only once; the user must change it at the first login.")
					}
					return nil
				})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&role, "role", "member", "role of the account: "+roleHelp)
	f.StringVar(&in.Email, "email", "", "e-mail address")
	f.StringVar(&in.DisplayName, "display-name", "", "display name (default: the username)")
	pw = addSecretFlags(cmd, "password", "password", secretOpts{Generate: true,
		GenerateUsage: "generate a strong password (printed once; must be changed at the first sign-in)"})
	f.BoolVar(&in.MustChangePassword, "must-change", false, "require a password change at the first login")
	f.StringVar(&quota, "quota", "", "storage quota (e.g. 10G, 500M, unlimited; default: storage.default_quota_gb)")
	f.StringArrayVar(&groups, "group", nil, "add the user to this group (repeatable)")
	return cmd
}

func renderUser(w io.Writer, u *core.User) error {
	kv := NewKV()
	kv.Add("Username", u.Username)
	kv.Add("Display name", u.DisplayName)
	kv.Add("E-mail", u.Email)
	kv.Add("Role", userRoleDetail(u))
	if perms, ok := userPermissionsText(u); ok {
		kv.Add("Permissions", perms)
	}
	kv.Add("Status", u.Status)
	kv.Add("ID", u.ID)
	kv.Add("Two-factor", YesNo(u.MFAEnabled))
	kv.Add("Quota", quotaText(u.QuotaBytes))
	kv.Add("Must change password", u.MustChangePassword)
	kv.Add("Password changed", u.PasswordChangedAt)
	kv.Add("Failed logins", u.FailedLogins)
	if u.Locked(time.Now()) {
		kv.Add("Locked until", u.LockedUntil)
	}
	kv.Add("Last login", u.LastLoginAt)
	kv.Add("Last login IP", u.LastLoginIP)
	kv.Add("Personal space", u.SpaceID)
	kv.Add("Created", u.CreatedAt)
	return kv.Render(w)
}

// userRoleDetail is the Role line of an account: the built-in word, or
// "Helpdesk (rol_…), based on member" for a custom role.
func userRoleDetail(u *core.User) string {
	if core.IsCustomRoleID(u.RoleID) {
		return fmt.Sprintf("%s (%s), based on %s", Dash(u.RoleName), u.RoleID, u.Role)
	}
	return string(u.Role)
}

// userPermissionsText is the Permissions line of an account: "all" for
// owners and admins, "none", or the names its role gives. ok is false for
// servers without roles, which send neither role_id nor permissions.
func userPermissionsText(u *core.User) (text string, ok bool) {
	if u.RoleID == "" {
		return "", false
	}
	switch perms := u.Permissions.String(); {
	case u.Role.IsAdmin():
		return "all", true
	case perms == "":
		return "none", true
	default:
		return perms, true
	}
}

func newUserShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <user>",
		Short: "Show everything about one account",
		Long: `Show every detail of a user account: role and the permissions it gives,
status, quota, two-factor state, lockout, last sign-in and the id of their
personal files.`,
		Example: `  fileparcel user show alice
  fileparcel user show usr_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				return Print(cmd, u, func(w io.Writer) error { return renderUser(w, u) })
			})
		},
	}
}

// patchUser sends PATCH /admin/users/{id} and prints the result (msg names
// the user with %q).
func patchUser(cmd *cobra.Command, ref string, in core.UserUpdate, msg string) error {
	return patchUserRole(cmd, ref, "", in, func(user, _ string) string { return fmt.Sprintf(msg, user) })
}

// patchUserRole is patchUser that also gives the role named role when it is
// not "" (resolved first, see roleFields); msg builds the success line from
// the username and the role.
func patchUserRole(cmd *cobra.Command, ref, role string, in core.UserUpdate, msg func(user, role string) string) error {
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		label := ""
		if role != "" {
			r, err := resolveRole(ctx, c, role)
			if err != nil {
				return err
			}
			base, id := roleFields(r)
			if base != "" {
				in.Role = &base
			} else {
				in.RoleID = &id
			}
			label = r.label()
		}
		u, err := resolveUser(ctx, c, ref)
		if err != nil {
			return err
		}
		var out core.User
		if err := c.Do(ctx, http.MethodPatch, api("/admin/users/"+u.ID), in, &out); err != nil {
			return err
		}
		if out.ID == "" {
			out = *u
		}
		return done(cmd, &out, "%s", msg(u.Username, label))
	})
}

func newUserEditCmd() *cobra.Command {
	var displayName, email, role, quota string
	var mustChange bool
	cmd := &cobra.Command{
		Use:   "edit <user>",
		Short: "Change a user's name, e-mail, role, quota or password rule",
		Long: `Change one or more attributes of a user account; only the flags you pass are
changed. For one attribute there are shortcuts: "fileparcel user set-role" and
"fileparcel user set-quota".

` + elevationNoteFor("Changing the role"),
		Example: `  fileparcel user edit alice --display-name "Alice Liddell" --email alice@example.org
  fileparcel user edit bob --role admin --quota unlimited
  fileparcel user edit carol --must-change`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var in core.UserUpdate
			f := cmd.Flags()
			changed := false
			if f.Changed("display-name") {
				in.DisplayName, changed = &displayName, true
			}
			if f.Changed("email") {
				in.Email, changed = &email, true
			}
			newRole := ""
			if f.Changed("role") {
				if newRole = strings.TrimSpace(role); newRole == "" {
					return UsageError("--role must not be empty")
				}
				changed = true
			}
			if f.Changed("quota") {
				q, err := parseUserQuota(quota)
				if err != nil {
					return err
				}
				in.QuotaBytes, changed = q, true
			}
			if f.Changed("must-change") {
				in.MustChangePassword, changed = &mustChange, true
			}
			if !changed {
				return UsageError("nothing to change; pass at least one of --display-name, --email, --role, --quota, --must-change")
			}
			return patchUserRole(cmd, args[0], newRole, in, func(user, _ string) string {
				return fmt.Sprintf("updated user %q", user)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&displayName, "display-name", "", "new display name")
	f.StringVar(&email, "email", "", `new e-mail address ("" clears it)`)
	f.StringVar(&role, "role", "", "new role: "+roleHelp)
	f.StringVar(&quota, "quota", "", "new quota: a size (10G), unlimited, or default")
	f.BoolVar(&mustChange, "must-change", false, "require (or with =false, stop requiring) a password change at the next login")
	return cmd
}

func newUserSetRoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-role <user> <role>",
		Short: "Change a user's role",
		Long: `Give a user a built-in role (owner, admin, member, guest) or a custom role
made with "fileparcel role create". The role decides what the user may do on
the server; which folders they can open comes from their own files, their
groups and access grants. Only owners can make someone an owner.

` + elevationNote,
		Example: `  fileparcel user set-role alice admin
  fileparcel user set-role bob member
  fileparcel user set-role carol contractors`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(args[1]) == "" {
				return UsageError("the role must not be empty")
			}
			return patchUserRole(cmd, args[0], args[1], core.UserUpdate{}, func(user, role string) string {
				return fmt.Sprintf("changed the role of %q to %q", user, role)
			})
		},
	}
}

func newUserSetQuotaCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "set-quota <user> <size|unlimited|default>",
		Aliases: []string{"quota"},
		Short:   "Set how much storage a user may use",
		Long: `Set the storage quota of a user's personal files. Sizes use binary units
(500M, 10G, 1.5T). "unlimited" removes the limit; "default" falls back to the
server-wide default (storage.default_quota_gb).`,
		Example: `  fileparcel user set-quota alice 50G
  fileparcel user set-quota bob unlimited
  fileparcel user set-quota carol default`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := parseUserQuota(args[1])
			if err != nil {
				return err
			}
			return patchUser(cmd, args[0], core.UserUpdate{QuotaBytes: q}, "updated the quota of %q")
		},
	}
}

func newUserResetPasswordCmd() *cobra.Command {
	var in core.PasswordResetInput
	var pw *secretInput
	cmd := &cobra.Command{
		Use:     "reset-password <user>",
		Aliases: []string{"passwd", "set-password"},
		Short:   "Set a new password for a user",
		Long: `Set a new password for a user, for example when they forgot theirs. The new
password is read from --password-stdin or --password-file, generated with
--generate-password (printed once), or asked for twice on a terminal. The
user's sessions and API tokens are revoked, so anything signed in as them has
to sign in again.

` + elevationNote,
		Example: `  fileparcel user reset-password alice
  fileparcel user reset-password alice --generate-password --must-change
  printf '%s\n' "$NEW_PASSWORD" | fileparcel user reset-password bob --password-stdin`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in.Generate = pw.Generate
			if !pw.Generate {
				p, err := pw.Read(cmd, true)
				if err != nil {
					return err
				}
				in.Password = p
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				var res core.PasswordReset
				if err := c.Do(ctx, http.MethodPost, api("/admin/users/"+u.ID+"/password"), in, &res); err != nil {
					return err
				}
				return Print(cmd, res, func(w io.Writer) error {
					Successf(cmd, "reset the password of %q", u.Username)
					if res.Password != "" {
						fmt.Fprintf(w, "Password: %s\n", res.Password)
						Infof(cmd, "The password is shown only once.")
					}
					return nil
				})
			})
		},
	}
	pw = addSecretFlags(cmd, "password", "new password", secretOpts{Generate: true,
		GenerateUsage: "generate a strong password (printed once)"})
	cmd.Flags().BoolVar(&in.MustChange, "must-change", false, "require a password change at the next login")
	return cmd
}

func newUserStatusCmd(action string) *cobra.Command {
	short, long := "Stop a user from signing in (their files stay)", `Stop a user from signing in: they are signed out everywhere, their API tokens
and share links stop working and the invitations they created are revoked.
Their files, groups and settings stay; "fileparcel user enable" lets them back
in.`
	if action == "enable" {
		short, long = "Let a disabled user sign in again", `Let a disabled user sign in again. Disabling signed them out everywhere, so
they sign in anew; their files, groups and share links are as before.`
	}
	example := fmt.Sprintf(`  fileparcel user %[1]s mallory
  fileparcel user %[1]s usr_01j9zq3x4k6m8p0r2t4v6x8z0b`, action)
	return &cobra.Command{
		Use:     action + " <user>",
		Short:   short,
		Long:    long,
		Example: example,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/users/"+u.ID+"/"+action), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"id": u.ID, "username": u.Username, "action": action}, "%sd user %q", action, u.Username)
			})
		},
	}
}

func newUserDeleteCmd() *cobra.Command {
	var transferTo string
	cmd := &cobra.Command{
		Use:   "delete <user>",
		Short: "Delete an account and its files",
		Long: `Delete a user account for good. Without --transfer-to the user's personal
files are deleted too; with --transfer-to they are moved into the other user's
files. To keep someone out for a while, use "fileparcel user disable" instead.

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel user delete mallory
  fileparcel user delete bob --transfer-to alice -y`,
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				var to *core.User
				if transferTo != "" {
					if to, err = resolveUser(ctx, c, transferTo); err != nil {
						return err
					}
					if to.ID == u.ID {
						return UsageError("--transfer-to must name a different user")
					}
				}
				q := fmt.Sprintf("Delete user %q and ALL of their files?", u.Username)
				if to != nil {
					q = fmt.Sprintf("Delete user %q and move their files to %q?", u.Username, to.Username)
				}
				if err := confirmOrAbort(cmd, q); err != nil {
					return err
				}
				path := api("/admin/users/" + u.ID)
				if to != nil {
					path = api("/admin/users/"+u.ID, "transfer_to", to.ID)
				}
				if err := c.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"deleted": u.ID}, "deleted user %q", u.Username)
			})
		},
	}
	cmd.Flags().StringVar(&transferTo, "transfer-to", "", "move the user's files to this user instead of deleting them")
	return cmd
}

func newUserUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock <user>",
		Short: "Clear the lockout after too many failed sign-ins",
		Long: `Clear the lockout that follows too many failed sign-ins
(auth.lockout_threshold) and reset the failure counter, so the user can try
again at once.`,
		Example: `  fileparcel user unlock alice
  fileparcel user unlock usr_01j9zq3x4k6m8p0r2t4v6x8z0b`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/users/"+u.ID+"/unlock"), nil, nil); err != nil {
					return err
				}
				return done(cmd, nil, "unlocked %q", u.Username)
			})
		},
	}
}

func newUserReset2FACmd() *cobra.Command {
	return &cobra.Command{
		Use:     "reset-2fa <user>",
		Aliases: []string{"reset-mfa"},
		Short:   "Remove a user's second factors (lost phone or key)",
		Long: `Remove a user's authenticator app secret, recovery codes and passkeys, for
example after they lost their phone or security key. Their sessions and API
tokens are revoked as well. If two-factor sign-in is required, the user sets
it up again at the next sign-in.

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel user reset-2fa alice
  fileparcel user reset-2fa alice -y`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				if err := confirmOrAbort(cmd, fmt.Sprintf("Remove all second factors (TOTP, recovery codes, passkeys) of %q?", u.Username)); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/users/"+u.ID+"/reset-mfa"), nil, nil); err != nil {
					return err
				}
				return done(cmd, nil, "removed the second factors of %q", u.Username)
			})
		},
	}
}

func newUserSessionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sessions <user>",
		Short: "List where a user is signed in",
		Long: `List a user's active browser sessions with IP address, browser and expiry.
"fileparcel user revoke-sessions" signs them out everywhere.`,
		Example: `  fileparcel user sessions alice
  fileparcel user sessions alice --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				sessions, err := listAll[core.Session](ctx, c, api("/admin/users/"+u.ID+"/sessions"), 0)
				if err != nil {
					return err
				}
				return Print(cmd, sessions, func(w io.Writer) error {
					t := NewTable("ID", "CREATED", "LAST SEEN", "EXPIRES", "IP", "2FA", "USER AGENT")
					for _, s := range sessions {
						t.Add(s.ID, s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.IP, s.MFAMethod, Truncate(s.UserAgent, 50))
					}
					return t.Render(w)
				})
			})
		},
	}
}

func newUserRevokeSessionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "revoke-sessions <user>",
		Aliases: []string{"sign-out"},
		Short:   "Sign a user out everywhere",
		Long: `Revoke all of a user's browser sessions, so they have to sign in again. API
tokens are not affected (see "fileparcel token revoke").`,
		Example: `  fileparcel user revoke-sessions alice
  fileparcel user revoke-sessions alice --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodDelete, api("/admin/users/"+u.ID+"/sessions"), nil, nil); err != nil {
					return err
				}
				return done(cmd, nil, "revoked all sessions of %q", u.Username)
			})
		},
	}
}
