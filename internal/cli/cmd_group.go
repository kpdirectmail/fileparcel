package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newGroupCmd) }

func newGroupCmd() *cobra.Command {
	cmd := groupCmd("group", "Manage groups and their team folders",
		`A group bundles users. Every group has a team folder, "/Team/<group>", that
all its members can open; managers of the group can also share it and change
who has access to it. Name groups by name or by id (grp_…).

To let another group or single users into a team folder without making them
members, see "fileparcel access".`,
		`  fileparcel group create Design --description "Design team"
  fileparcel group add-member Design alice bob
  fileparcel group show Design`, "groups")
	cmd.AddCommand(newGroupListCmd(), newGroupShowCmd(), newGroupCreateCmd(), newGroupEditCmd(), newGroupDeleteCmd(),
		newGroupRenameCmd(), newGroupMembersCmd(), newGroupAddMemberCmd(), newGroupRemoveMemberCmd())
	setListHint(cmd, "fileparcel group list")
	return cmd
}

func newGroupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List groups",
		Long:    "List all groups with their number of members and their description.",
		Example: `  fileparcel group list
  fileparcel group list --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				groups, err := listAll[core.Group](ctx, c, api("/admin/groups", "limit", limitParam(0)), 0)
				if err != nil {
					return err
				}
				return Print(cmd, groups, func(w io.Writer) error {
					t := NewTable("NAME", "MEMBERS", "DESCRIPTION", "CREATED", "ID")
					for _, g := range groups {
						t.Add(g.Name, g.MemberCount, Truncate(g.Description, 50), g.CreatedAt, g.ID)
					}
					return t.Render(w)
				})
			})
		},
	}
}

// groupDetails is the --json output of "group show".
type groupDetails struct {
	Group   *core.Group        `json:"group"`
	Members []core.GroupMember `json:"members"`
}

func newGroupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <group>",
		Short: "Show a group, its team folder and its members",
		Long: `Show a group: its description, its team folder and everyone who is a member
of it, with their role in the group (member or manager).`,
		Example: `  fileparcel group show Design
  fileparcel group show grp_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				g, err := resolveGroup(ctx, c, args[0])
				if err != nil {
					return err
				}
				// The list entry lacks the details (the roles that make
				// people members); the group itself has them.
				var full core.Group
				if err := c.Do(ctx, http.MethodGet, api("/admin/groups/"+g.ID), nil, &full); err != nil {
					return err
				}
				members, err := listAll[core.GroupMember](ctx, c, api("/admin/groups/"+g.ID+"/members"), 0)
				if err != nil {
					return err
				}
				if members == nil {
					members = []core.GroupMember{}
				}
				out := groupDetails{Group: &full, Members: members}
				return Print(cmd, out, func(w io.Writer) error { return renderGroup(w, &full, members) })
			})
		},
	}
}

// renderGroup prints a group and its members.
func renderGroup(w io.Writer, g *core.Group, members []core.GroupMember) error {
	kv := NewKV()
	kv.Add("Name", g.Name)
	kv.Add("ID", g.ID)
	kv.Add("Description", g.Description)
	kv.Add("Team folder", "/Team/"+g.Name)
	kv.Add("Members", g.MemberCount)
	if len(g.Roles) > 0 {
		var roles []string
		for _, r := range g.Roles {
			roles = append(roles, fmt.Sprintf("%s (%s)", r.RoleName, r.MemberRole))
		}
		kv.Add("Roles that make people members", strings.Join(roles, ", "))
	}
	kv.Add("Created", g.CreatedAt)
	if err := kv.Render(w); err != nil {
		return err
	}
	if len(members) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	return renderMembers(w, members)
}

// renderMembers prints the members of a group. SOURCE says why someone is
// a member: "direct" (added to the group) and "role:<name>" for each custom
// role that makes them one; ROLE is the effective one (manager wins).
func renderMembers(w io.Writer, members []core.GroupMember) error {
	t := NewTable("USERNAME", "NAME", "ROLE", "SOURCE", "ADDED")
	for _, m := range members {
		t.Add(m.Username, m.DisplayName, m.Role, memberSource(&m), m.AddedAt)
	}
	return t.Render(w)
}

// memberSource is the SOURCE of a member. Servers without roles send no
// source at all: every member is a direct one there.
func memberSource(m *core.GroupMember) string {
	var src []string
	if m.Direct || len(m.ViaRoles) == 0 {
		src = append(src, "direct")
	}
	for _, r := range m.ViaRoles {
		src = append(src, "role:"+r.Name)
	}
	return strings.Join(src, ", ")
}

func newGroupCreateCmd() *cobra.Command {
	var desc string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a group and its team folder",
		Long: `Create a group. Its team folder is created at the same time and appears as
"/Team/<name>". Add people with "fileparcel group add-member".`,
		Example: `  fileparcel group create Design
  fileparcel group create "Finance 2026" --description "Accounting and invoices"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in := core.GroupInput{Name: args[0]}
			if cmd.Flags().Changed("description") {
				in.Description = &desc
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var g core.Group
				if err := c.Do(ctx, http.MethodPost, api("/admin/groups"), in, &g); err != nil {
					return err
				}
				return done(cmd, &g, "created group %q", args[0])
			})
		},
	}
	cmd.Flags().StringVar(&desc, "description", "", "description of the group")
	return cmd
}

func newGroupEditCmd() *cobra.Command {
	var name, desc string
	cmd := &cobra.Command{
		Use:   "edit <group>",
		Short: "Change a group's name or description",
		Long: `Change a group's name, its description or both; only the flags you pass are
changed. A new name also renames the team folder; its files stay where they
are.`,
		Example: `  fileparcel group edit Design --description "Product design team"
  fileparcel group edit Design --name "Product Design"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var in core.GroupInput
			f := cmd.Flags()
			if f.Changed("name") {
				if strings.TrimSpace(name) == "" {
					return UsageError("--name must not be empty")
				}
				in.Name = name
			}
			if f.Changed("description") {
				in.Description = &desc
			}
			if !anyChanged(f, "name", "description") {
				return UsageError("nothing to change; pass --name, --description or both")
			}
			return patchGroup(cmd, args[0], in)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new name of the group (its team folder follows)")
	cmd.Flags().StringVar(&desc, "description", "", `new description ("" clears it)`)
	return cmd
}

// patchGroup sends PATCH /admin/groups/{id} for the group ref and prints
// the result.
func patchGroup(cmd *cobra.Command, ref string, in core.GroupInput) error {
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		g, err := resolveGroup(ctx, c, ref)
		if err != nil {
			return err
		}
		var out core.Group
		if err := c.Do(ctx, http.MethodPatch, api("/admin/groups/"+g.ID), in, &out); err != nil {
			return err
		}
		if in.Name != "" && in.Name != g.Name {
			return done(cmd, &out, "renamed group %q to %q", g.Name, in.Name)
		}
		return done(cmd, &out, "updated group %q", g.Name)
	})
}

func newGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <group>",
		Aliases: []string{"rm"},
		Short:   "Delete a group and its team folder with all files",
		Long: `Delete a group, its memberships and its team folder with all files in it.
The members keep their accounts and their own files.

` + confirmNote,
		Example: `  fileparcel group delete Design
  fileparcel group delete Design -y`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				g, err := resolveGroup(ctx, c, args[0])
				if err != nil {
					return err
				}
				if err := confirmOrAbort(cmd, fmt.Sprintf("Delete group %q and its team folder with ALL files?", g.Name)); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodDelete, api("/admin/groups/"+g.ID), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"deleted": g.ID}, "deleted group %q", g.Name)
			})
		},
	}
}

func newGroupRenameCmd() *cobra.Command {
	var desc string
	cmd := &cobra.Command{
		Use:   "rename <group> <new-name>",
		Short: "Rename a group (its team folder follows)",
		Long: `Rename a group. Its team folder keeps its contents and appears under the new
name. "fileparcel group edit" changes the description too.`,
		Example: `  fileparcel group rename Design "Product Design"
  fileparcel group rename grp_01j9zq3x4k6m8p0r2t4v6x8z0b Design`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(args[1]) == "" {
				return UsageError("the new name must not be empty")
			}
			in := core.GroupInput{Name: args[1]}
			if cmd.Flags().Changed("description") {
				in.Description = &desc
			}
			return patchGroup(cmd, args[0], in)
		},
	}
	// Kept for old scripts; "group edit --description" is the documented way.
	cmd.Flags().StringVar(&desc, "description", "", "also set a new description")
	_ = cmd.Flags().MarkHidden("description")
	return cmd
}

func newGroupMembersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "members <group>",
		Short: "List the members of a group",
		Long: `List the members of a group with their role in the group: member, or
manager (may also share the team folder and change who has access to it).
SOURCE says how they became members: "direct" when they were added, and
"role:<name>" when a role makes its people members ("fileparcel role
add-group").`,
		Example: `  fileparcel group members Design
  fileparcel group members Design --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				g, err := resolveGroup(ctx, c, args[0])
				if err != nil {
					return err
				}
				members, err := listAll[core.GroupMember](ctx, c, api("/admin/groups/"+g.ID+"/members"), 0)
				if err != nil {
					return err
				}
				return Print(cmd, members, func(w io.Writer) error { return renderMembers(w, members) })
			})
		},
	}
}

// memberResult is the --json output of one "group add-member" user.
type memberResult struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
	Role    string `json:"role"`
}

// forEachMember resolves the group ref, then resolves and handles the users
// in order. It stops at the first error; when some users were handled
// already, the error says which ones ("added", "removed"); nothing is rolled
// back.
func forEachMember(ctx context.Context, cmd *cobra.Command, c *Client, ref string, users []string, past string,
	fn func(g *core.Group, u *core.User) error) error {
	g, err := resolveGroup(ctx, c, ref)
	if err != nil {
		return err
	}
	var handled []string
	for _, name := range users {
		u, err := resolveUser(ctx, c, name)
		if err == nil {
			err = fn(g, u)
		}
		if err != nil {
			if len(handled) == 0 {
				return err
			}
			verb := "were"
			if len(handled) == 1 {
				verb = "was"
			}
			return &hintError{explainErrorFor(cmd, err), fmt.Sprintf("%s %s %s before this error; the users after it were not",
				joinAnd(quoteAll(handled)), verb, past)}
		}
		handled = append(handled, u.Username)
	}
	return nil
}

// quoteAll returns the words quoted.
func quoteAll(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = fmt.Sprintf("%q", w)
	}
	return out
}

func newGroupAddMemberCmd() *cobra.Command {
	var manager bool
	cmd := &cobra.Command{
		Use:   "add-member <group> <user>...",
		Short: "Add users to a group (or make them managers)",
		Long: `Add users to a group as members, or as managers with --manager (managers may
also share the team folder and change who has access to it). Running it again
for someone already in the group changes their role in it.

The users are added in order; at the first error it stops and says which
users were added before it.`,
		Example: `  fileparcel group add-member Design alice
  fileparcel group add-member Design alice bob carol
  fileparcel group add-member Design bob --manager`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := core.GroupRoleMember
			if manager {
				role = core.GroupRoleManager
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var added []memberResult
				err := forEachMember(ctx, cmd, c, args[0], args[1:], "added", func(g *core.Group, u *core.User) error {
					if err := c.Do(ctx, http.MethodPut, api("/admin/groups/"+g.ID+"/members/"+u.ID), core.RoleInput{Role: role}, nil); err != nil {
						return err
					}
					added = append(added, memberResult{GroupID: g.ID, UserID: u.ID, Role: role})
					if !G.JSON {
						Successf(cmd, "%q is now a %s of %q", u.Username, role, g.Name)
					}
					return nil
				})
				if err != nil {
					return err
				}
				if !G.JSON {
					return nil
				}
				// One user prints the object of old versions; several an
				// array of them.
				if len(added) == 1 {
					return PrintJSON(cmd.OutOrStdout(), added[0])
				}
				return PrintJSON(cmd.OutOrStdout(), added)
			})
		},
	}
	cmd.Flags().BoolVar(&manager, "manager", false, "make the users managers of the group")
	return cmd
}

func newGroupRemoveMemberCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-member <group> <user>...",
		Short: "Remove users from a group",
		Long: `Remove users from a group. Files they created in the team folder stay there.

This removes their own membership. Someone whose custom role makes them a
member ("role:<name>" in "fileparcel group members") stays a member through
the role: the command says so, and "fileparcel role remove-group ROLE GROUP"
or another role ("fileparcel user set-role") ends that.

The users are removed in order; at the first error it stops and says which
users were removed before it.`,
		Example: `  fileparcel group remove-member Design alice
  fileparcel group remove-member Design alice bob`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				// Memberships through a role are not removed here; the
				// member list (read once) tells who keeps one.
				var members []core.GroupMember
				listed := false
				err := forEachMember(ctx, cmd, c, args[0], args[1:], "removed", func(g *core.Group, u *core.User) error {
					if err := c.Do(ctx, http.MethodDelete, api("/admin/groups/"+g.ID+"/members/"+u.ID), nil, nil); err != nil {
						return err
					}
					if !listed {
						members, _ = listAll[core.GroupMember](ctx, c, api("/admin/groups/"+g.ID+"/members"), 0)
						listed = true
					}
					var via []string
					if i := slices.IndexFunc(members, func(m core.GroupMember) bool { return m.UserID == u.ID }); i >= 0 {
						for _, r := range members[i].ViaRoles {
							via = append(via, strconv.Quote(r.Name))
						}
					}
					if !G.JSON {
						if len(via) > 0 {
							Successf(cmd, "removed %q's own membership of %q", u.Username, g.Name)
						} else {
							Successf(cmd, "removed %q from %q", u.Username, g.Name)
						}
					}
					if len(via) > 0 {
						// Also in JSON mode: the membership is not gone.
						role := "role"
						if len(via) > 1 {
							role = "roles"
						}
						Warnf(cmd, "%q is still a member of %q through the %s %s; \"fileparcel role remove-group ROLE %s\" or "+
							"\"fileparcel user set-role %s ROLE\" ends that", u.Username, g.Name, role, joinAnd(via),
							shellArg(g.Name), shellArg(u.Username))
					}
					return nil
				})
				if err != nil || !G.JSON {
					return err
				}
				return done(cmd, nil, "")
			})
		},
	}
}
