package cli

// "fileparcel role" (DESIGN §6a, §12): what the users of a role may do on the
// server. The four built-in roles (owner, admin, member, guest) are fixed;
// custom roles ("rol_…") start from the permissions of another role
// (copy_from) and add or remove some, and can make their people members of
// groups. Every command uses the admin API: GET/POST /admin/roles,
// GET/PATCH/DELETE /admin/roles/{id}, GET/PUT/DELETE
// /admin/roles/{id}/groups[/{groupId}], GET /admin/capabilities, GET
// /admin/users?role_id= and GET /admin/grants?subject_type=role. Changes
// need an administrator, remotely with an elevated token.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newRoleCmd) }

func newRoleCmd() *cobra.Command {
	cmd := groupCmd("role", "Create roles and choose what they may do",
		`A role decides what its users may do on the server. There are four built-in
roles (owner, admin, member, guest) and you can create your own, starting
from a copy of another role and adding or removing permissions. Every user
has exactly one role ("fileparcel user set-role"). Built-in roles cannot be
renamed or deleted.

Which folders people can open is not part of the permissions: see
"fileparcel group" and "fileparcel access", and "fileparcel help permissions"
for the big picture. Changing roles needs an admin; remotely also an elevated
token.`,
		`  fileparcel role list
  fileparcel role create contractors --from member --remove shares.links
  fileparcel role show contractors
  fileparcel role members contractors`, "roles", "class", "classes")
	cmd.AddCommand(newRoleListCmd(), newRoleShowCmd(), newRolePermissionsCmd(), newRoleCreateCmd(), newRoleEditCmd(),
		newRoleDeleteCmd(), newRoleMembersCmd(), newRoleGroupCmd(true), newRoleGroupCmd(false))
	setListHint(cmd, "fileparcel role list")
	return cmd
}

// roleView is a role as the API sends it (core.RoleDef). The permission
// names are kept as sent: core.CapSet would drop names this build does not
// know, and a role copied or edited from it would lose them.
type roleView struct {
	core.RoleDef
	Permissions []core.Capability `json:"permissions"`
}

// getRole reads one role (GET /admin/roles/{id}; built-in words work).
func getRole(ctx context.Context, c *Client, r *roleRef) (*roleView, error) {
	var v roleView
	if err := c.Do(ctx, http.MethodGet, api("/admin/roles/"+pathEsc(r.ID)), nil, &v); err != nil {
		if r.Builtin {
			return nil, withNoRolesHint(err) // every server with roles has the built-in ones
		}
		return nil, err
	}
	if v.Permissions == nil {
		v.Permissions = []core.Capability{}
	}
	return &v, nil
}

// label is how messages name a role: the built-in word or the custom name.
func (v *roleView) label() string { return roleRefOf(&v.RoleDef).label() }

// people is "1 person" / "3 people".
func people(n int) string {
	if n == 1 {
		return "1 person"
	}
	return fmt.Sprintf("%d people", n)
}

// permNames joins permission names ("none" for an empty list).
func permNames(ps []core.Capability) string {
	if len(ps) == 0 {
		return "none"
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return strings.Join(out, ", ")
}

// roleKind is "built-in" or "custom, based on <base>".
func roleKind(v *roleView) string {
	if v.Builtin {
		return "built-in"
	}
	if v.Base == "" {
		return "custom"
	}
	return "custom, based on " + string(v.Base)
}

// ---------- list, show, permissions ----------

func newRoleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List roles and how many people have each",
		Long: `List the built-in roles and the custom roles with how many people have each
(for a built-in role: the people without a custom role), how many permissions
it gives and what it is based on.`,
		Example: `  fileparcel role list
  fileparcel role list --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				roles, err := listAll[roleView](ctx, c, api("/admin/roles"), 0)
				if err != nil {
					return withNoRolesHint(err)
				}
				for i := range roles {
					if roles[i].Permissions == nil {
						roles[i].Permissions = []core.Capability{}
					}
				}
				return Print(cmd, roles, func(w io.Writer) error {
					t := NewTable("ROLE", "KIND", "PEOPLE", "PERMISSIONS", "DESCRIPTION", "ID")
					for _, r := range roles {
						perms := fmt.Sprint(len(r.Permissions))
						if r.Base.IsAdmin() {
							perms = "all"
						}
						t.Add(r.Name, roleKind(&r), r.UserCount, perms, Truncate(r.Description, 40), r.ID)
					}
					return t.Render(w)
				})
			})
		},
	}
}

func newRoleShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <role>",
		Short: "Show a role: permissions, people, groups and folders",
		Long: `Show everything about a role: its permissions (with a warning for each one
that has a high impact), how many people have it, whether account managers
may give it (delegable), the groups it makes its people members of and the
folders it has access to. Name roles by name or by id (rol_…).`,
		Example: `  fileparcel role show admin
  fileparcel role show contractors --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				ref, err := resolveRole(ctx, c, args[0])
				if err != nil {
					return err
				}
				v, err := getRole(ctx, c, ref)
				if err != nil {
					return err
				}
				return Print(cmd, v, func(w io.Writer) error { return renderRole(ctx, c, w, v) })
			})
		},
	}
}

// renderRole prints a role. Groups and folders are read for custom roles
// only (built-in roles have none); a refusal leaves their line out. The
// warnings come from the server's permission catalog (roleCatalog).
func renderRole(ctx context.Context, c *Client, w io.Writer, v *roleView) error {
	kv := NewKV()
	head := v.Name
	if v.ID != "" && !strings.EqualFold(v.ID, v.Name) {
		head += " (" + v.ID + ")"
	}
	kv.Add("Role", head+", "+roleKind(v))
	kv.Add("Description", v.Description)
	kv.Add("Delegable", v.Delegable)
	kv.Add("People", fmt.Sprintf("%d (fileparcel role members %s)", v.UserCount, shellArg(v.label())))
	perms := permNames(v.Permissions)
	if v.Base.IsAdmin() {
		perms = "all"
	}
	kv.Add("Permissions", perms)
	if !v.Builtin {
		if groups, err := listAll[core.RoleGroup](ctx, c, api("/admin/roles/"+pathEsc(v.ID)+"/groups"), 0); err == nil {
			var gs []string
			for _, g := range groups {
				gs = append(gs, fmt.Sprintf("%s (%s)", g.GroupName, g.MemberRole))
			}
			kv.Add("Groups", Dash(strings.Join(gs, ", ")))
		}
		var sg core.SubjectGrants
		if err := c.Do(ctx, http.MethodGet, api("/admin/grants", "subject_type", core.SubjectRole, "subject_id", v.ID), nil, &sg); err == nil {
			var fs []string
			for _, g := range sg.Items {
				fs = append(fs, fmt.Sprintf("%s (%s)", grantNodePath(g), levelWord(g.Role)))
			}
			if sg.Hidden > 0 {
				fs = append(fs, fmt.Sprintf("%d more you may not see", sg.Hidden))
			}
			kv.Add("Folders", Dash(strings.Join(fs, ", ")))
		}
	}
	if cat, _, err := roleCatalog(ctx, c); err == nil && !v.Base.IsAdmin() {
		for _, info := range cat.Items {
			if slices.Contains(v.Permissions, info.Name) && info.HighImpact && info.Warning != "" {
				kv.Add("Warning", info.Warning)
			}
		}
	}
	return kv.Render(w)
}

// grantNodePath is the path of the node of a grant from GET /admin/grants
// ("/Team/Design/Briefs", "/My files/Taxes (alice)").
func grantNodePath(g core.Grant) string {
	rel := strings.TrimSuffix(g.NodePath, "/")
	switch {
	case g.SpaceKind == core.SpaceGroup:
		return "/" + teamName + "/" + g.SpaceName + rel
	case g.SpaceKind == core.SpaceUser:
		return displayIn("/"+myFilesName, g.SpaceName, rel)
	case g.NodeName != "":
		return g.NodeName
	}
	return g.NodeID
}

func newRolePermissionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "permissions",
		Aliases: []string{"perms", "caps"},
		Short:   "List every permission a role can have",
		Long: `List every permission a role can have, grouped as in the web app, with what it
allows and a warning for those with a high impact. Server permissions open
parts of the Admin area (API tokens need the "admin" scope to use them). Some
permissions need another one, which a role then gets as well.`,
		Example: `  fileparcel role permissions
  fileparcel role permissions --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cat, compiled, err := roleCatalog(ctx, c)
				if err != nil {
					return err
				}
				if compiled {
					Infof(cmd, "(catalog of this program; the server may differ)")
				}
				return Print(cmd, cat, func(w io.Writer) error { return renderCatalog(w, cat) })
			})
		},
	}
}

// renderCatalog prints the permissions by group: name and label, then the
// description and the warning, indented and wrapped.
func renderCatalog(w io.Writer, cat core.CapabilityCatalog) error {
	width := 0
	for _, p := range cat.Items {
		width = max(width, len(p.Name))
	}
	indent := strings.Repeat(" ", width+4)
	groups := slices.Clone(cat.Groups)
	for _, p := range cat.Items { // a group the list does not name comes last
		if !slices.ContainsFunc(groups, func(g core.CapabilityGroup) bool { return g.ID == p.Group }) {
			groups = append(groups, core.CapabilityGroup{ID: p.Group, Label: p.Group})
		}
	}
	for gi, g := range groups {
		if gi > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, Bold(g.Label))
		for _, p := range cat.Items {
			if p.Group != g.ID {
				continue
			}
			var notes []string
			if p.Server {
				notes = append(notes, "server")
			}
			if len(p.Implies) > 0 {
				notes = append(notes, "includes "+permNames(p.Implies))
			}
			head := sanitizeCell(p.Label)
			if len(notes) > 0 {
				head += " (" + strings.Join(notes, "; ") + ")"
			}
			fmt.Fprintf(w, "  %-*s  %s\n", width, p.Name, head)
			for _, l := range wrapWords(sanitizeCell(p.Description), 78-len(indent)) {
				fmt.Fprintln(w, indent+l)
			}
			if p.Warning != "" {
				for _, l := range wrapWords("Warning: "+sanitizeCell(p.Warning), 78-len(indent)) {
					fmt.Fprintln(w, indent+l)
				}
			}
		}
	}
	return nil
}

// wrapWords breaks s into lines of at most width runes (a longer word keeps
// its own line).
func wrapWords(s string, width int) []string {
	var lines []string
	var cur strings.Builder
	n := 0
	for _, word := range strings.Fields(s) {
		wl := len([]rune(word))
		if n > 0 && n+1+wl > width {
			lines = append(lines, cur.String())
			cur.Reset()
			n = 0
		}
		if n > 0 {
			cur.WriteByte(' ')
			n++
		}
		cur.WriteString(word)
		n += wl
	}
	if n > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

// ---------- create, edit, delete ----------

// permFlags are --add, --remove and --set of role create and edit.
type permFlags struct{ add, remove, set []string }

func (p *permFlags) define(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringArrayVar(&p.add, "add", nil, "give this permission too (repeatable; a,b works)")
	f.StringArrayVar(&p.remove, "remove", nil, "take this permission away (repeatable; a,b works)")
	f.StringArrayVar(&p.set, "set", nil, "exactly these permissions, instead of --add/--remove (comma-separated)")
	cmd.MarkFlagsMutuallyExclusive("set", "add")
	cmd.MarkFlagsMutuallyExclusive("set", "remove")
}

func (p *permFlags) given() bool { return len(p.add)+len(p.remove)+len(p.set) > 0 }

// parsed checks the names against the catalog (usage errors before any
// change is sent).
func (p *permFlags) parsed(cat core.CapabilityCatalog) (add, remove, set []core.Capability, err error) {
	if add, err = parsePermList(p.add, cat.Items); err != nil {
		return
	}
	if remove, err = parsePermList(p.remove, cat.Items); err != nil {
		return
	}
	if set, err = parsePermList(p.set, cat.Items); err != nil {
		return
	}
	if len(p.set) > 0 && set == nil {
		set = []core.Capability{} // --set "" gives no permission
	}
	if both := slices.DeleteFunc(slices.Clone(add), func(c core.Capability) bool { return !slices.Contains(remove, c) }); len(both) > 0 {
		err = UsageError("%s is both added and removed", permNames(both))
	}
	return
}

// delegableFlags are --delegable and --no-delegable.
type delegableFlags struct{ cmd *cobra.Command }

func (d *delegableFlags) define(cmd *cobra.Command) {
	d.cmd = cmd
	cmd.Flags().Bool("delegable", false, "account managers who are not administrators may give this role and manage its people")
	cmd.Flags().Bool("no-delegable", false, "only administrators may give this role and manage its people")
	cmd.MarkFlagsMutuallyExclusive("delegable", "no-delegable")
}

// value is the flags' setting (--delegable=false clears it like
// --no-delegable), or nil when neither was given.
func (d *delegableFlags) value() *bool { return onOff(d.cmd.Flags(), "delegable") }

// sortPerms orders names like the catalog (unknown names last).
func sortPerms(ps []core.Capability, cat core.CapabilityCatalog) []core.Capability {
	idx := func(p core.Capability) int {
		if i := slices.IndexFunc(cat.Items, func(c core.CapabilityInfo) bool { return c.Name == p }); i >= 0 {
			return i
		}
		return len(cat.Items)
	}
	slices.SortStableFunc(ps, func(a, b core.Capability) int { return idx(a) - idx(b) })
	return ps
}

// reportImplied names the permissions the server added because a requested
// one needs them ("also allowed: users.view (needed by users.manage)").
func reportImplied(cmd *cobra.Command, before, requested, got []core.Capability, cat core.CapabilityCatalog) {
	for _, p := range got {
		if slices.Contains(requested, p) || slices.Contains(before, p) {
			continue
		}
		var by []string
		for _, r := range requested {
			i := slices.IndexFunc(cat.Items, func(c core.CapabilityInfo) bool { return c.Name == r })
			if i >= 0 && slices.Contains(cat.Items[i].Implies, p) {
				by = append(by, string(r))
			}
		}
		if len(by) > 0 {
			Infof(cmd, "also allowed: %s (needed by %s)", p, strings.Join(by, ", "))
		}
	}
}

// printRole prints the role a change returned: the API object with --json,
// else a success line.
func printRole(cmd *cobra.Command, raw json.RawMessage, format string, a ...any) error {
	if G.JSON {
		return PrintJSON(cmd.OutOrStdout(), raw)
	}
	Successf(cmd, format, a...)
	return nil
}

func newRoleCreateCmd() *cobra.Command {
	var from, base, desc string
	var perms permFlags
	var deleg delegableFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a custom role",
		Long: `Create a custom role. It starts with the permissions of another role (--from;
default: the role of --base, else member; owner or admin give every
permission), which --add and --remove change, or --set replaces. Permissions
go by name ("fileparcel role permissions"); several at once with commas.

--base is the kind of account its people have: member (their own files) or
guest (no own files, only what is shared with them). Without it the role gets
the base of --from (member when --from is owner or admin, or not given), so
--from guest also makes a guest-based role. It cannot be changed later.
--delegable lets account managers who are not administrators
give the role and manage its people.

` + elevationNote,
		Example: `  fileparcel role create contractors --from member --remove shares.links
  fileparcel role create helpdesk --from admin --set users.view,users.manage --description "Resets passwords"
  fileparcel role create auditors --from guest --add audit.view`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return UsageError("the role name must not be empty")
			}
			if core.Role(strings.ToLower(name)).Valid() {
				return UsageError("%q is the name of a built-in role; choose another name", name)
			}
			b := core.Role(strings.ToLower(strings.TrimSpace(base)))
			if b != "" && b != core.RoleMember && b != core.RoleGuest {
				return UsageError("--base must be member or guest (got %q)", base)
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cat, _, err := roleCatalog(ctx, c)
				if err != nil {
					return err
				}
				add, remove, set, err := perms.parsed(cat)
				if err != nil {
					return err
				}
				src := from
				if src == "" {
					src = string(core.RoleMember)
					if b != "" {
						src = string(b)
					}
				}
				srcRef, err := resolveRole(ctx, c, src)
				if err != nil {
					return err
				}
				in := core.RoleDefInput{Name: name, Base: b, CopyFrom: srcRef.ID}
				if cmd.Flags().Changed("description") {
					in.Description = desc
				}
				if d := deleg.value(); d != nil {
					in.Delegable = *d
				}
				var start, requested []core.Capability
				if perms.given() {
					if set != nil {
						requested = set
					} else {
						sv, err := getRole(ctx, c, srcRef)
						if err != nil {
							return err
						}
						start = sv.Permissions
						requested = slices.DeleteFunc(slices.Clone(start), func(p core.Capability) bool { return slices.Contains(remove, p) })
						for _, p := range add {
							if !slices.Contains(requested, p) {
								requested = append(requested, p)
							}
						}
					}
					requested = sortPerms(requested, cat)
					in.Permissions = &requested
				}
				var raw json.RawMessage
				if err := c.Do(ctx, http.MethodPost, api("/admin/roles"), in, &raw); err != nil {
					return withNoRolesHint(err)
				}
				var got roleView
				if err := json.Unmarshal(raw, &got); err != nil {
					return fmt.Errorf("decode response: %w", err)
				}
				if requested != nil {
					reportImplied(cmd, nil, requested, got.Permissions, cat)
				}
				return printRole(cmd, raw, "created role %q (%s, %s): %s", got.Name, got.ID, roleKind(&got), permNames(got.Permissions))
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "start with the permissions of this role (default: --base, else member)")
	f.StringVar(&base, "base", "", "member (own files) or guest (no own files); default: the base of --from, else member")
	f.StringVar(&desc, "description", "", "what the role is for")
	perms.define(cmd)
	deleg.define(cmd)
	return cmd
}

func newRoleEditCmd() *cobra.Command {
	var name, desc string
	var perms permFlags
	var deleg delegableFlags
	cmd := &cobra.Command{
		Use:   "edit <role>",
		Short: "Change a custom role's name, description or permissions",
		Long: `Change a custom role; only the flags you pass are changed. --add and --remove
change its permissions, --set replaces them all. The people who have the role
get the change at once (their open sessions and tokens included).

` + elevationNote,
		Example: `  fileparcel role edit contractors --add shares.links
  fileparcel role edit helpdesk --remove users.manage
  fileparcel role edit contractors --name freelancers`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var in core.RoleDefUpdate
			f := cmd.Flags()
			if f.Changed("name") {
				n := strings.TrimSpace(name)
				if n == "" {
					return UsageError("--name must not be empty")
				}
				in.Name = &n
			}
			if f.Changed("description") {
				in.Description = &desc
			}
			in.Delegable = deleg.value()
			if in.Name == nil && in.Description == nil && in.Delegable == nil && !perms.given() {
				return UsageError("nothing to change; pass --name, --description, --add, --remove, --set, --delegable or --no-delegable")
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cat, _, err := roleCatalog(ctx, c)
				if err != nil {
					return err
				}
				add, remove, set, err := perms.parsed(cat)
				if err != nil {
					return err
				}
				ref, err := resolveRole(ctx, c, args[0])
				if err != nil {
					return err
				}
				old, err := getRole(ctx, c, ref)
				if err != nil {
					return err
				}
				requested, before := add, old.Permissions
				if set != nil {
					in.Permissions, requested, before = &set, set, nil
				} else {
					in.AddPermissions, in.RemovePermissions = add, remove
				}
				var raw json.RawMessage
				if err := c.Do(ctx, http.MethodPatch, api("/admin/roles/"+pathEsc(ref.ID)), in, &raw); err != nil {
					return err
				}
				var got roleView
				if err := json.Unmarshal(raw, &got); err != nil {
					return fmt.Errorf("decode response: %w", err)
				}
				reportImplied(cmd, before, requested, got.Permissions, cat)
				return printRole(cmd, raw, "updated role %q: %s", got.Name, permNames(got.Permissions))
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "new name of the role")
	f.StringVar(&desc, "description", "", `new description ("" clears it)`)
	perms.define(cmd)
	deleg.define(cmd)
	return cmd
}

// roleDeleted is the --json output of "role delete".
type roleDeleted struct {
	Deleted      string `json:"deleted"`
	ReassignedTo string `json:"reassigned_to,omitempty"`
	Moved        int    `json:"moved"`
}

func newRoleDeleteCmd() *cobra.Command {
	var reassign string
	cmd := &cobra.Command{
		Use:     "delete <role>",
		Aliases: []string{"rm"},
		Short:   "Delete a custom role (its people move to another role)",
		Long: `Delete a custom role. Its access grants and group memberships go with it. The
people who have the role get the role of --reassign-to, which you must choose
while anyone has the role: nothing is picked for you, because another role can
give them more rights.

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel role delete contractors --reassign-to member
  fileparcel role delete interns --reassign-to guest -y`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				ref, err := resolveRole(ctx, c, args[0])
				if err != nil {
					return err
				}
				if ref.Builtin {
					return UsageError("%q is a built-in role; built-in roles cannot be deleted", ref.ID)
				}
				v, err := getRole(ctx, c, ref)
				if err != nil {
					return err
				}
				var to *roleRef
				switch {
				case reassign != "":
					if to, err = resolveRole(ctx, c, reassign); err != nil {
						return err
					}
					if to.ID == v.ID {
						return UsageError("--reassign-to must name another role")
					}
				case v.UserCount > 0:
					return UsageError("%s the role %q: say which role they get instead with --reassign-to ROLE "+
						"(nothing is chosen for you: another role can give them more rights)", hasHave(v.UserCount), v.Name)
				}
				q := fmt.Sprintf("Delete role %q?", v.Name)
				if to != nil && v.UserCount > 0 {
					q += fmt.Sprintf(" Its %s get the role %q.", people(v.UserCount), to.label())
				}
				if err := confirmOrAbort(cmd, q); err != nil {
					return err
				}
				out := roleDeleted{Deleted: v.ID, Moved: v.UserCount}
				path := api("/admin/roles/" + pathEsc(v.ID))
				if to != nil {
					out.ReassignedTo = to.ID
					path = api("/admin/roles/"+pathEsc(v.ID), "reassign_to", to.ID)
				}
				if err := c.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
					return err
				}
				if to != nil && v.UserCount > 0 {
					return done(cmd, out, "deleted role %q; the role of its %s is now %q", v.Name, people(v.UserCount), to.label())
				}
				return done(cmd, out, "deleted role %q", v.Name)
			})
		},
	}
	cmd.Flags().StringVar(&reassign, "reassign-to", "", "the role its people get instead (needed while anyone has the role)")
	return cmd
}

// hasHave is "1 person has" / "3 people have".
func hasHave(n int) string {
	if n == 1 {
		return "1 person has"
	}
	return people(n) + " have"
}

// ---------- members and groups ----------

func newRoleMembersCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:     "members <role>",
		Aliases: []string{"people"},
		Short:   "List the people who have a role",
		Long: `List the accounts that have a role. For a built-in role these are the accounts
without a custom role.`,
		Example: `  fileparcel role members contractors
  fileparcel role members admin --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				ref, err := resolveRole(ctx, c, args[0])
				if err != nil {
					return err
				}
				// role (the base) keeps the filter right on servers
				// without roles, which ignore role_id.
				base := ""
				if ref.Builtin {
					base = ref.ID
				}
				users, err := listAll[core.User](ctx, c, api("/admin/users", "role", base, "role_id", ref.ID,
					"limit", limitParam(limit)), limit)
				if err != nil {
					return err
				}
				return Print(cmd, users, func(w io.Writer) error {
					if len(users) == 0 {
						Infof(cmd, "nobody has the role %q", ref.label())
						return nil
					}
					return renderUsers(w, users)
				})
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of people (0 = all)")
	return cmd
}

// newRoleGroupCmd is "role add-group" (add) or "role remove-group".
func newRoleGroupCmd(add bool) *cobra.Command {
	var manager bool
	cmd := &cobra.Command{
		Use:   "add-group <role> <group>",
		Short: "Make everyone with a role a member of a group",
		Long: `Make everyone who has a custom role a member of a group (or, with --manager, a
manager of it), now and whoever gets the role later. Their memberships through
the role show as "role:<name>" in "fileparcel group members".`,
		Example: `  fileparcel role add-group contractors Design
  fileparcel role add-group leads Design --manager`,
		Args: cobra.ExactArgs(2),
	}
	if !add {
		cmd.Use = "remove-group <role> <group>"
		cmd.Short = "Stop a role from making its people members of a group"
		cmd.Long = `Stop a custom role from making its people members of a group. People who are
also members on their own stay members.`
		cmd.Example = `  fileparcel role remove-group contractors Design
  fileparcel role remove-group leads Design --json`
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return WithClient(cmd, func(ctx context.Context, c *Client) error {
			ref, err := resolveRole(ctx, c, args[0])
			if err != nil {
				return err
			}
			g, err := resolveGroup(ctx, c, args[1])
			if err != nil {
				return err
			}
			path := api("/admin/roles/" + pathEsc(ref.ID) + "/groups/" + pathEsc(g.ID))
			if !add {
				if err := c.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
					// Both exist (resolved above): what is missing is the
					// role's membership, which "role show" lists.
					if apiStatus(err) == http.StatusNotFound {
						return &hintError{err, fmt.Sprintf("see the groups of the role with %q",
							"fileparcel role show "+shellArg(ref.label()))}
					}
					return err
				}
				return done(cmd, nil, "the role %q no longer makes its people members of %q", ref.label(), g.Name)
			}
			in := core.RoleGroupInput{MemberRole: core.GroupRoleMember}
			if manager {
				in.MemberRole = core.GroupRoleManager
			}
			var rg core.RoleGroup
			if err := c.Do(ctx, http.MethodPut, path, in, &rg); err != nil {
				return err
			}
			if rg.RoleID == "" {
				rg = core.RoleGroup{RoleID: ref.ID, RoleName: ref.Name, GroupID: g.ID, GroupName: g.Name, MemberRole: in.MemberRole}
			}
			return done(cmd, &rg, "everyone with the role %q is now a %s of %q", ref.label(), in.MemberRole, g.Name)
		})
	}
	if add {
		cmd.Flags().BoolVar(&manager, "manager", false, "make them managers of the group")
	}
	return cmd
}
