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

func init() { Register(newInviteCmd) }

func newInviteCmd() *cobra.Command {
	cmd := groupCmd("invite", "Invite people to create their own account",
		`An invitation link lets someone create their own account: they choose the
username and password, you choose the role, groups and quota beforehand.
Links expire (after 7 days unless --expires) and can be limited to a number of
uses. Sending them by e-mail needs the SMTP settings.`,
		`  fileparcel invite create --role member --group Design --expires 3d
  fileparcel invite list
  fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b`, "invites")
	cmd.AddCommand(newInviteCreateCmd(), newInviteListCmd(), newInviteRevokeCmd())
	setListHint(cmd, "fileparcel invite list --inactive")
	return cmd
}

func newInviteCreateCmd() *cobra.Command {
	var in core.InviteInput
	var role, expires, quota string
	var groups []string
	var showQR bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an invitation link",
		Long: `Create an invitation link and print it. The link of an active invitation is
also shown by "fileparcel invite list". --send e-mails it to --email (needs the
SMTP settings); --qr prints a QR code for phones.

--note is a message to the invited person: it is shown on the sign-up page to
anyone who opens the link and included in the invitation e-mail, so do not put
private remarks in it.

` + elevationNoteFor("Inviting an admin"),
		Example: `  fileparcel invite create
  fileparcel invite create --role guest --expires 1d --qr
  fileparcel invite create --email bob@example.com --send --group Design --uses 1
  fileparcel invite create --uses 10 --expires 14d --quota 5G --note "Welcome to the workshop"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.EqualFold(strings.TrimSpace(role), string(core.RoleOwner)) {
				return UsageError("invites cannot create owners; invite an admin and promote them with \"fileparcel user set-role\"")
			}
			exp, _, err := parseExpiry(expires, time.Now(), false)
			if err != nil {
				return err
			}
			in.ExpiresAt = exp
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
			if in.Send && in.Email == "" {
				return UsageError("--send needs --email")
			}
			if in.MaxUses < 0 {
				return UsageError("--uses must be at least 1")
			}
			// An invitation addressed to an e-mail creates one account with
			// that address, so the server refuses more than one use; say so
			// here rather than after a round trip.
			if in.Email != "" && in.MaxUses > 1 {
				return UsageError("--uses must be 1 with --email: an invitation addressed to an e-mail address creates a single account with that address")
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
				var res core.InviteCreated
				if err := c.Do(ctx, http.MethodPost, api("/admin/invites"), in, &res); err != nil {
					return err
				}
				abs := newURLResolver(c)
				res.URL = abs.abs(ctx, res.URL)
				if res.Invite != nil && res.Invite.URL != "" {
					res.Invite.URL = abs.abs(ctx, res.Invite.URL)
				}
				return Print(cmd, res, func(w io.Writer) error {
					if res.Invite != nil {
						Successf(cmd, "created invite %s (%s, %s, expires %s)", res.Invite.ID, inviteRoleText(res.Invite),
							Plural(int64(res.Invite.MaxUses), "use"), HumanTime(res.Invite.ExpiresAt))
						if res.Invite.EmailError != "" {
							Warnf(cmd, "the invitation e-mail was not sent (%s); pass the link on yourself", res.Invite.EmailError)
						}
					}
					fmt.Fprintln(w, res.URL)
					if showQR && res.URL != "" {
						return PrintQR(w, res.URL)
					}
					return nil
				})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&role, "role", "member", `role of the new account (default member; any role except owner, see "fileparcel role list")`)
	f.StringArrayVar(&groups, "group", nil, "add the new account to this group (repeatable)")
	f.StringVar(&expires, "expires", "7d", "validity: a duration (12h, 7d, 2w) or a date (2026-12-31)")
	f.IntVar(&in.MaxUses, "uses", 1, "how many accounts the link may create (must be 1 with --email)")
	f.StringVar(&in.Email, "email", "", "e-mail address of the invitee")
	f.BoolVar(&in.Send, "send", false, "e-mail the link to --email (needs SMTP)")
	f.StringVar(&quota, "quota", "", "storage quota of the new account (e.g. 10G, unlimited)")
	f.StringVar(&in.Note, "note", "", "message to the invited person, shown on the sign-up page and in the invitation e-mail (not private)")
	f.BoolVar(&showQR, "qr", false, "also print the link as a QR code")
	return cmd
}

// inviteRoleText is the role of an invitation: the built-in word, or the
// name of a custom role ("Deleted role" once it is gone).
func inviteRoleText(inv *core.Invite) string {
	if core.IsCustomRoleID(inv.RoleID) && inv.RoleName != "" {
		return inv.RoleName
	}
	return string(inv.Role)
}

func newInviteListCmd() *cobra.Command {
	var inactive bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List invitation links",
		Long: `List invitation links. Only active ones are shown unless --inactive, which
adds used, expired and revoked ones. Active invitations show their link, except
while the server's keys are locked and, remotely without an elevated token, for
admin invitations.`,
		Example: `  fileparcel invite list
  fileparcel invite list --inactive --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				invites, err := listAll[core.Invite](ctx, c, api("/admin/invites", "limit", limitParam(0)), 0)
				if err != nil {
					return err
				}
				if !inactive {
					kept := invites[:0]
					for _, inv := range invites {
						if inv.Status == "" || inv.Status == core.InviteActive {
							kept = append(kept, inv)
						}
					}
					invites = kept
				}
				abs := newURLResolver(c)
				for i := range invites {
					if invites[i].URL != "" {
						invites[i].URL = abs.abs(ctx, invites[i].URL)
					}
				}
				return Print(cmd, invites, func(w io.Writer) error {
					// Active invites carry their link; the column is left out
					// when no row has one (only inactive invites, the keys are
					// locked, admin invites without step-up) rather than
					// printed as a column of dashes.
					urls := slices.ContainsFunc(invites, func(i core.Invite) bool { return i.URL != "" })
					headers := []string{"ID", "ROLE", "STATUS", "USES", "EXPIRES", "E-MAIL", "NOTE"}
					if urls {
						headers = append(headers, "URL")
					}
					t := NewTable(headers...)
					for _, inv := range invites {
						row := []any{inv.ID, inviteRoleText(&inv), inv.Status, fmt.Sprintf("%d/%d", inv.Uses, inv.MaxUses), inv.ExpiresAt, inv.Email, inv.Note}
						if urls {
							row = append(row, inv.URL)
						}
						t.Add(row...)
					}
					return t.Render(w)
				})
			})
		},
	}
	addInactiveFlag(cmd, &inactive, "include used, expired and revoked invites")
	return cmd
}

func newInviteRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Stop an invitation link from working",
		Long: `Revoke an invitation link so it can no longer be used. Accounts already
created with it stay.`,
		Example: `  fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := c.Do(ctx, http.MethodDelete, api("/admin/invites/"+pathEsc(args[0])), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"revoked": args[0]}, "revoked invite %s", args[0])
			})
		},
	}
}
