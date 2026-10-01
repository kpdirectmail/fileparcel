package cli

// "fileparcel access" (DESIGN §12): access grants on files and folders. A
// grant gives a user, a group or everyone with a custom role view, edit or
// manage access to one file or folder and everything in it (GET, POST and
// DELETE /nodes/{id}/grants; the caller needs manage access to the node).
//
// Acting identity: over the admin socket or offline, without --as, the
// commands use the socket's system principal, which sees every space, so
// team folders and ids resolve for an administrator who is no manager of
// them; "/My files" names nobody then and is refused. With --as USER they
// act as that user; remotely as the token's user. "access check" asks the
// server as the user in question (X-FP-As), so it needs the admin socket or
// offline mode.

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

func init() { Register(newAccessCmd) }

func newAccessCmd() *cobra.Command {
	cmd := groupCmd("access", "Give users, groups or roles access to folders",
		`An access grant lets a user, a group or everyone with a role open a folder (or
a single file) they would not see otherwise, for example another group's team
folder or a folder in someone's own files. Levels: view (see and download),
edit (also add, change, move and delete) or manage (also share it and change
who has access). A grant on a folder covers everything in it. Grants only add
access; they never take away what someone has through their own files or their
groups.

On the server, access commands have full rights over team folders and ids;
for someone's "/My files" name them with --as USER. Remotely you need to
manage the folder yourself. Paths work like in "fileparcel files" (see
"fileparcel help paths").`,
		`  fileparcel access grant /Team/Design --group Marketing
  fileparcel access list /Team/Design
  fileparcel access revoke /Team/Design --group Marketing
  fileparcel access check bob /Team/Design`, "acl")
	cmd.SuggestFor = []string{"permission", "permissions", "grant", "grants", "sharing"}
	check := newAccessCheckCmd()
	cmd.AddCommand(newAccessListCmd(), newAccessGrantCmd(), newAccessRevokeCmd(), check)
	// A missing path is the usual not-found: list the folder it should be in.
	setListHint(cmd, "fileparcel files ls {parent}")
	setListHint(check, "fileparcel files ls {parent:last}")
	return cmd
}

// ---------- levels ----------

// grantLevel is one access level: the word the CLI shows and accepts, and
// the value of the API (core.Grant*).
type grantLevel struct{ Word, API string }

// grantLevels are the levels of access grants, lowest first (the core.Grant*
// constants of the server model).
var grantLevels = []grantLevel{
	{"view", core.GrantViewer},
	{"edit", core.GrantEditor},
	{"manage", core.GrantManager},
}

// parseGrantLevel turns a --level value (view|viewer, edit|editor,
// manage|manager) into the API value.
func parseGrantLevel(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	var words []string
	for _, l := range grantLevels {
		if s == l.Word || s == l.API {
			return l.API, nil
		}
		words = append(words, l.Word)
	}
	return "", UsageError("invalid level %q (%s)", s, joinOr(words))
}

// levelWord is the word of an API level ("viewer" → "view").
func levelWord(api string) string {
	for _, l := range grantLevels {
		if l.API == api {
			return l.Word
		}
	}
	return api
}

// ---------- subjects ----------

// grantSubject is a resolved --user, --group or --role value.
type grantSubject struct {
	Type  string // core.SubjectUser | core.SubjectGroup | core.SubjectRole
	ID    string
	Name  string // username, group name or role name
	Given string // the flag value as typed
}

// label names the subject in messages: "bob", "group Marketing", "role
// contractors".
func (s grantSubject) label() string {
	switch s.Type {
	case core.SubjectGroup:
		return "group " + s.Name
	case core.SubjectRole:
		return "role " + s.Name
	}
	return s.Name
}

// who names the subject as the one who can do something: "bob", "group
// Marketing", "everyone with the role contractors".
func (s grantSubject) who() string {
	if s.Type == core.SubjectRole {
		return "everyone with the role " + s.Name
	}
	return s.label()
}

// flag is the subject as a flag of a printed command ("--user bob").
func (s grantSubject) flag() string { return "--" + s.Type + " " + shellArg(s.Given) }

// matches reports whether grant g is to this subject.
func (s grantSubject) matches(g core.Grant) bool {
	return g.SubjectType == s.Type && g.SubjectID == s.ID
}

// grantSubjectFlags are the --user, --group and --role flags of grant and
// revoke.
type grantSubjectFlags struct{ users, groups, roles []string }

func (f *grantSubjectFlags) add(cmd *cobra.Command, verb string) {
	fl := cmd.Flags()
	fl.StringArrayVar(&f.users, "user", nil, verb+" this user (repeatable)")
	fl.StringArrayVar(&f.groups, "group", nil, verb+" this group (repeatable)")
	fl.StringArrayVar(&f.roles, "role", nil, verb+" everyone with this custom role (repeatable)")
}

func (f *grantSubjectFlags) given() bool { return len(f.users)+len(f.groups)+len(f.roles) > 0 }

// resolve resolves the subjects, users first, then groups, then roles.
// Callers without the admin API (a folder manager's token) find users in the
// directory, groups among their own and roles through GET /roles.
func (f *grantSubjectFlags) resolve(ctx context.Context, c *Client) ([]grantSubject, error) {
	var out []grantSubject
	for _, ref := range f.users {
		s, err := resolveGrantUser(ctx, c, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	for _, ref := range f.groups {
		s, err := resolveGrantGroup(ctx, c, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	for _, ref := range f.roles {
		r, err := resolveRole(ctx, c, ref)
		if err != nil {
			return nil, err
		}
		if r.Builtin {
			return nil, UsageError("%q is a built-in role: access grants go to users, groups and custom roles "+
				"(give everyone with a built-in role access through a group)", ref)
		}
		out = append(out, grantSubject{Type: core.SubjectRole, ID: r.ID, Name: r.Name, Given: ref})
	}
	return out, nil
}

func resolveGrantUser(ctx context.Context, c *Client, ref string) (*grantSubject, error) {
	u, err := resolveUser(ctx, c, ref)
	if err == nil {
		return &grantSubject{Type: core.SubjectUser, ID: u.ID, Name: u.Username, Given: ref}, nil
	}
	if apiStatus(err) != http.StatusForbidden {
		return nil, err
	}
	// No admin API: an id is taken as it is (the server checks it), a name
	// must match a directory entry exactly.
	ref = strings.TrimSpace(ref)
	if ids.Valid(ids.PrefixUser, ref) {
		return &grantSubject{Type: core.SubjectUser, ID: ref, Name: ref, Given: ref}, nil
	}
	found, lerr := listAll[core.UserRef](ctx, c, api("/users/lookup", "q", ref), 0)
	if lerr != nil {
		return nil, err // the refusal of the admin API says more
	}
	for _, r := range found {
		if strings.EqualFold(r.Username, ref) {
			return &grantSubject{Type: core.SubjectUser, ID: r.ID, Name: r.Username, Given: ref}, nil
		}
	}
	return nil, core.NotFoundf("user %q not found", ref)
}

func resolveGrantGroup(ctx context.Context, c *Client, ref string) (*grantSubject, error) {
	g, err := resolveGroup(ctx, c, ref)
	if err == nil {
		return &grantSubject{Type: core.SubjectGroup, ID: g.ID, Name: g.Name, Given: ref}, nil
	}
	if apiStatus(err) != http.StatusForbidden {
		return nil, err
	}
	// No admin API: one of the caller's own groups.
	mine, lerr := listAll[core.Group](ctx, c, api("/groups"), 0)
	if lerr != nil {
		return nil, err
	}
	key := names.Key(ref)
	for _, g := range mine {
		if g.ID == ref || g.Name == ref || names.Key(g.Name) == key {
			return &grantSubject{Type: core.SubjectGroup, ID: g.ID, Name: g.Name, Given: ref}, nil
		}
	}
	return nil, core.NotFoundf("group %q not found among your groups", ref)
}

// ---------- paths ----------

// refuseOwnFilesWithoutAs refuses "/My files" (and a relative path) over the
// admin socket or offline without --as: the system principal has no files
// of its own, and whose "/My files" is meant is not guessed.
func refuseOwnFilesWithoutAs(raw string) error {
	if G.Server != "" || G.As != "" {
		return nil
	}
	p, err := parseRemotePath(raw)
	if err != nil {
		return err
	}
	if p.Root == rootMy {
		return UsageError("%q is somebody's own folder: say whose with --as USER", "/"+myFilesName)
	}
	return nil
}

// resolveAccessNode resolves the path of an access command to a file or
// folder.
func resolveAccessNode(ctx context.Context, r *resolver, raw string) (*target, error) {
	t, err := r.resolve(ctx, raw)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, accessNotFound(ctx, r, raw, err)
		}
		return nil, err
	}
	if t.Node == nil {
		return nil, UsageError("%s is not a file or folder: name a team folder, a folder in it or an id", t.Path)
	}
	return t, nil
}

// accessNotFound adds to the not-found error of an access command's path
// where to look, with the rights the path was resolved with (without --as
// those of the admin socket, which "fileparcel files ls" does not have: it
// acts as the first owner): the groups for a missing team folder, else
// what the nearest existing folder of the path holds.
func accessNotFound(ctx context.Context, r *resolver, raw string, err error) error {
	p, perr := parseRemotePath(raw)
	if perr != nil {
		return err
	}
	if p.Root == rootTeam && p.Group != "" {
		if _, terr := r.teamRoot(ctx, p.Group); terr != nil {
			return &hintError{err, `team folders are "/Team/<group>"; list the groups with "fileparcel group list"`}
		}
	}
	for q := p; len(q.Segs) > 0; {
		q.Segs = q.Segs[:len(q.Segs)-1]
		t, terr := r.resolveParsed(ctx, q)
		if terr != nil || t.Node == nil || !t.Node.IsDir() {
			continue
		}
		kids, lerr := r.list(ctx, t.Node.ID)
		if lerr != nil {
			return err
		}
		if len(kids) == 0 {
			return &hintError{err, fmt.Sprintf("%s exists and is empty", t.Path)}
		}
		const show = 8
		var shown []string
		for _, n := range kids[:min(len(kids), show)] {
			name := n.Name
			if n.IsDir() {
				name += "/"
			}
			shown = append(shown, strconv.Quote(name))
		}
		more := ""
		if len(kids) > show {
			more = fmt.Sprintf(" and %d more", len(kids)-show)
		}
		return &hintError{err, fmt.Sprintf("%s holds %s%s", t.Path, strings.Join(shown, ", "), more)}
	}
	return err
}

// spacePrefix is how the paths of a space start: "/My files" (the acting
// user's), "/Team/<group>", or "/My files" with owner set for somebody
// else's personal files. Both are "" when the space is not visible.
func spacePrefix(ctx context.Context, r *resolver, spaceID string) (prefix, owner string) {
	if r.load(ctx) != nil {
		return "", ""
	}
	sp := r.space(spaceID)
	switch {
	case spaceID == r.me.SpaceID && spaceID != "":
		return "/" + myFilesName, ""
	case sp == nil:
		return "", ""
	case sp.Kind == core.SpaceGroup:
		return r.prefixes[sp.ID], ""
	}
	return "/" + myFilesName, sp.Name
}

// displayIn renders the path rel ("/Docs", "/" for the root) of a space.
func displayIn(prefix, owner, rel string) string {
	p := prefix + strings.TrimSuffix(rel, "/")
	if owner != "" {
		p += " (" + owner + ")"
	}
	return p
}

// nodePaths maps n and each of its ancestors (by id) to the path the access
// commands print. shown is n's path as resolved from the command line; it
// is kept unless it starts with a node id.
func nodePaths(ctx context.Context, r *resolver, n *core.Node, shown string) map[string]string {
	out := map[string]string{n.ID: shown}
	crumbs, err := doList[core.Node](ctx, r.c, http.MethodGet, api("/nodes/"+pathEsc(n.ID)+"/breadcrumbs"), nil)
	if err != nil {
		return out
	}
	prefix, owner := spacePrefix(ctx, r, n.SpaceID)
	var segs []string
	for i, cr := range crumbs {
		if i > 0 || cr.ParentID != "" || prefix == "" {
			segs = append(segs, cr.Name)
		}
		p := "…/" + strings.Join(segs, "/")
		if prefix != "" {
			p = displayIn(prefix, owner, "/"+strings.Join(segs, "/"))
		}
		if cr.ID != n.ID || ids.Valid(ids.PrefixNode, strings.SplitN(shown, "/", 2)[0]) {
			out[cr.ID] = p
		}
	}
	return out
}

// spaceLine describes the space of n for "access list": whose personal
// files, or which group's team folder. "" when the space is not visible.
func spaceLine(ctx context.Context, r *resolver, n *core.Node) string {
	if r.load(ctx) != nil {
		return ""
	}
	sp := r.space(n.SpaceID)
	switch {
	case sp == nil:
		return ""
	case sp.Kind == core.SpaceGroup:
		return fmt.Sprintf("%q (team folder of %s: its members can edit, managers manage)", r.prefixes[sp.ID], sp.Name)
	case sp.ID == r.me.SpaceID && r.me.User != nil:
		return fmt.Sprintf("%q of %s (owner)", "/"+myFilesName, r.me.User.Username)
	}
	return fmt.Sprintf("%q of %s (owner)", "/"+myFilesName, sp.Name)
}

// listGrants returns the live grants on n and its ancestors (inherited
// ones first).
func listGrants(ctx context.Context, c *Client, n *core.Node) ([]core.Grant, error) {
	return doList[core.Grant](ctx, c, http.MethodGet, api("/nodes/"+pathEsc(n.ID)+"/grants"), nil)
}

// ---------- list ----------

func newAccessListCmd() *cobra.Command {
	var direct bool
	cmd := &cobra.Command{
		Use:     "list <path>",
		Aliases: []string{"ls"},
		Short:   "Show who has access to a file or folder, and why",
		Long: `Show the access grants on a file or folder, including the grants on the folders
above it (FROM names the folder a grant is on), and the space it belongs to:
someone's own files, or a group's team folder whose members can edit it.
--direct shows only the grants on this item.

` + filesPathNote,
		Example: `  fileparcel access list /Team/Design
  fileparcel --as alice access list "/My files/Taxes"
  fileparcel access list nod_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseOwnFilesWithoutAs(args[0]); err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := resolveAccessNode(ctx, r, args[0])
				if err != nil {
					return err
				}
				grants, err := listGrants(ctx, c, t.Node)
				if err != nil {
					return err
				}
				if direct {
					grants = slices.DeleteFunc(grants, func(g core.Grant) bool { return g.NodeID != t.Node.ID })
				}
				return Print(cmd, grants, func(w io.Writer) error {
					if line := spaceLine(ctx, r, t.Node); line != "" {
						kv := NewKV()
						kv.Add("Space", line)
						if err := kv.Render(w); err != nil {
							return err
						}
					}
					if len(grants) == 0 {
						Infof(cmd, "no access grants on %s", t.Path)
						return nil
					}
					paths := nodePaths(ctx, r, t.Node, t.Path)
					tb := NewTable("WHO", "TYPE", "ACCESS", "FROM", "EXPIRES", "ID")
					for _, g := range grants {
						from := "this item"
						if g.NodeID != t.Node.ID {
							from = cmp.Or(paths[g.NodeID], g.NodeID)
						}
						tb.Add(cmp.Or(g.SubjectName, g.SubjectID), g.SubjectType, levelWord(g.Role), from, expiryText(g.ExpiresAt), g.ID)
					}
					return tb.Render(w)
				})
			})
		},
	}
	cmd.Flags().BoolVar(&direct, "direct", false, "only the grants on this item, not those on the folders above it")
	return cmd
}

// ---------- grant ----------

func newAccessGrantCmd() *cobra.Command {
	var subj grantSubjectFlags
	var level, expires string
	cmd := &cobra.Command{
		Use:   "grant <path>",
		Short: "Give users, groups or roles access to a file or folder",
		Long: `Give users (--user), groups (--group) or everyone with a custom role (--role)
access to a file or folder and everything in it. --level is view (see and
download; the default), edit (also add, change, move and delete) or manage
(also share it and change who has access). --expires ends the access after a
time (30d), at the end of a date (2026-12-31) or never (the default for a new
grant). Granting again changes the level; the expiry stays as it was unless
--expires is given.

` + filesPathNote,
		Example: `  fileparcel access grant /Team/Design --group Marketing
  fileparcel --as alice access grant "/My files/Taxes" --user bob --level edit --expires 30d
  fileparcel access grant /Team/Finance --role auditors`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !subj.given() {
				return UsageError("say who gets access: --user, --group or --role (each repeatable)")
			}
			role, err := parseGrantLevel(level)
			if err != nil {
				return err
			}
			exp, _, err := parseExpiry(expires, time.Now(), true)
			if err != nil {
				return err
			}
			keepExpiry := !cmd.Flags().Changed("expires")
			if err := refuseOwnFilesWithoutAs(args[0]); err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := resolveAccessNode(ctx, r, args[0])
				if err != nil {
					return err
				}
				subjects, err := subj.resolve(ctx, c)
				if err != nil {
					return err
				}
				// The server replaces a subject's grant as a whole: without
				// --expires, send the expiry of an existing grant again so
				// a time-limited grant does not become permanent when only
				// its level changes (as the web UI does).
				var existing []core.Grant
				if keepExpiry {
					if existing, err = listGrants(ctx, c, t.Node); err != nil {
						return err
					}
				}
				out := []core.Grant{}
				for _, s := range subjects {
					var g core.Grant
					in := core.GrantInput{SubjectType: s.Type, SubjectID: s.ID, Role: role, ExpiresAt: exp}
					if keepExpiry {
						in.ExpiresAt = keptExpiry(existing, t.Node.ID, s, time.Now())
					}
					if err := c.Do(ctx, http.MethodPost, api("/nodes/"+pathEsc(t.Node.ID)+"/grants"), in, &g); err != nil {
						return grantedBefore(cmd, err, out, subjects)
					}
					out = append(out, g)
					what := ""
					if t.Node.IsDir() {
						what = " (and everything in it)"
					}
					until := ""
					if g.ExpiresAt != nil {
						until = ", until " + HumanTime(*g.ExpiresAt)
					}
					Successf(cmd, "%s can now %s %s%s%s", s.who(), levelWord(g.Role), t.Path, what, until)
				}
				if G.JSON {
					return PrintJSON(cmd.OutOrStdout(), out)
				}
				return nil
			})
		},
	}
	subj.add(cmd, "give access to")
	f := cmd.Flags()
	f.StringVar(&level, "level", "view", "view, edit or manage")
	f.StringVar(&expires, "expires", "", "when the access ends: a duration (30d), a date (2026-12-31) or never "+
		"(default: never for a new grant, unchanged for an existing one)")
	return cmd
}

// keptExpiry is the expiry of subject s's own grant on the node nodeID
// among grants, when it has one that has not passed yet (nil otherwise: a
// new grant, or one that never expires).
func keptExpiry(grants []core.Grant, nodeID string, s grantSubject, now time.Time) *time.Time {
	for _, g := range grants {
		if g.NodeID == nodeID && s.matches(g) && g.ExpiresAt != nil && g.ExpiresAt.After(now) {
			t := *g.ExpiresAt
			return &t
		}
	}
	return nil
}

// grantedBefore adds to the error of one subject which subjects got access
// before it (nothing is rolled back).
func grantedBefore(cmd *cobra.Command, err error, done []core.Grant, subjects []grantSubject) error {
	if len(done) == 0 {
		return err
	}
	var who []string
	for _, s := range subjects[:len(done)] {
		who = append(who, s.label())
	}
	return &hintError{explainErrorFor(cmd, err), joinAnd(who) + " got access before this error; the others did not"}
}

// ---------- revoke ----------

func newAccessRevokeCmd() *cobra.Command {
	var subj grantSubjectFlags
	cmd := &cobra.Command{
		Use:   "revoke <path> [gnt_…]",
		Short: "Take back access to a file or folder",
		Long: `Take back the access grants of users, groups or roles on a file or folder, or
one grant by its id (as "fileparcel access list" shows it). A grant on a folder
above the path is taken back on that folder: name it instead. Access through
someone's own files or their groups is not a grant. It does not ask first: a
grant can be made again at any time.

` + filesPathNote,
		Example: `  fileparcel access revoke /Team/Design --group Marketing
  fileparcel --as alice access revoke "/My files/Taxes" --user bob
  fileparcel access revoke /Team/Design gnt_01j9zq3x4k6m8p0r2t4v6x8z0b`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			byID := len(args) == 2
			if byID == subj.given() {
				return UsageError("name the access to take back: --user, --group or --role, or a grant id (gnt_…), not both")
			}
			if byID && !ids.Valid(ids.PrefixGrant, args[1]) {
				return UsageError("%q is not a grant id (gnt_…; see \"fileparcel access list %s\")", args[1], shellArg(args[0]))
			}
			if err := refuseOwnFilesWithoutAs(args[0]); err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := resolveAccessNode(ctx, r, args[0])
				if err != nil {
					return err
				}
				grants, err := listGrants(ctx, c, t.Node)
				if err != nil {
					return err
				}
				var pick []core.Grant
				var who []string
				if byID {
					i := slices.IndexFunc(grants, func(g core.Grant) bool { return g.ID == args[1] })
					if i < 0 {
						return &hintError{core.NotFoundf("grant %s is not on %s or a folder above it", args[1], t.Path),
							fmt.Sprintf("list them with %q", "fileparcel access list "+shellArg(args[0]))}
					}
					g := grants[i]
					pick, who = append(pick, g), append(who, grantWho(g))
				} else {
					subjects, err := subj.resolve(ctx, c)
					if err != nil {
						return err
					}
					for _, s := range subjects {
						g, err := directGrant(ctx, r, t, grants, s)
						if err != nil {
							return err
						}
						pick, who = append(pick, *g), append(who, s.label())
					}
				}
				paths := nodePaths(ctx, r, t.Node, t.Path)
				revoked := []string{}
				for i, g := range pick {
					if err := c.Do(ctx, http.MethodDelete, api("/nodes/"+pathEsc(g.NodeID)+"/grants/"+pathEsc(g.ID)), nil, nil); err != nil {
						if len(revoked) > 0 {
							return &hintError{explainErrorFor(cmd, err), fmt.Sprintf("revoked before this error: %s", strings.Join(revoked, ", "))}
						}
						return err
					}
					revoked = append(revoked, g.ID)
					on := cmp.Or(paths[g.NodeID], t.Path)
					Successf(cmd, "took back the %s access of %s to %s (%s)", levelWord(g.Role), who[i], on, g.ID)
				}
				if G.JSON {
					return PrintJSON(cmd.OutOrStdout(), map[string][]string{"revoked": revoked})
				}
				return nil
			})
		},
	}
	subj.add(cmd, "take back the access of")
	return cmd
}

// grantWho names the subject of a grant in messages.
func grantWho(g core.Grant) string {
	return grantSubject{Type: g.SubjectType, Name: cmp.Or(g.SubjectName, g.SubjectID)}.label()
}

// directGrant returns the grant of s on t itself. A subject whose grant sits
// on a folder above is told to revoke it there; one without any grant is
// pointed at "access check".
func directGrant(ctx context.Context, r *resolver, t *target, grants []core.Grant, s grantSubject) (*core.Grant, error) {
	var inherited *core.Grant
	for i := range grants {
		g := &grants[i]
		if !s.matches(*g) {
			continue
		}
		if g.NodeID == t.Node.ID {
			return g, nil
		}
		inherited = g
	}
	if inherited != nil {
		parent := cmp.Or(nodePaths(ctx, r, t.Node, t.Path)[inherited.NodeID], inherited.NodeID)
		// The command names the folder by a path the command line resolves:
		// somebody else's "/My files" only has its id.
		arg := parent
		if prefix, owner := spacePrefix(ctx, r, t.Node.SpaceID); prefix == "" || owner != "" {
			arg = inherited.NodeID
		}
		return nil, &ExitCodeError{Code: ExitFailure, Err: fmt.Errorf(
			"%s's access comes from a grant on %q (a parent folder); revoke it there: fileparcel access revoke %s %s",
			s.label(), parent, shellArg(arg), s.flag())}
	}
	hint := fmt.Sprintf("list them with %q", "fileparcel access list "+shellArg(t.Path))
	if s.Type == core.SubjectUser {
		hint = fmt.Sprintf("see %q", "fileparcel access check "+shellArg(s.Given)+" "+shellArg(t.Path))
	}
	return nil, &hintError{fmt.Errorf("%s has no access grant on %s", s.label(), t.Path), hint}
}

// ---------- check ----------

// accessCheck is the --json output of "access check".
type accessCheck struct {
	User     string         `json:"user"`
	Username string         `json:"username"`
	Path     string         `json:"path"`
	NodeID   string         `json:"node_id"`
	Access   string         `json:"access"` // none | view | edit | manage | owner
	Reasons  []accessReason `json:"reasons"`
}

// accessReason is one reason of an access check.
type accessReason struct {
	Kind    string `json:"kind"` // space | group | grant | admin
	Detail  string `json:"detail"`
	Access  string `json:"access"`
	GrantID string `json:"grant_id,omitempty"`

	perm core.Perm
}

func newAccessCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <user> <path>",
		Short: "Explain what a user may do with a file or folder",
		Long: `Show what a user may do with a file or folder (nothing, view, edit or manage)
and why: their own files, the team folders of their groups, access grants to
them, their groups or their role, and administrators' access to all files.
"/My files" means the user's own files here, unless --as names somebody else.
It asks the server as that user, so it needs the admin socket or offline mode:
run it on the server.

` + filesPathNote,
		Example: `  fileparcel access check bob /Team/Design
  fileparcel --as alice access check bob "/My files/Taxes/2026.pdf" --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if G.Server != "" {
				return UsageError("access check needs the admin socket: run it on the server")
			}
			p, err := parseRemotePath(args[1])
			if err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				actAs := c.as
				defer setClientActAs(c, actAs)
				setClientActAs(c, "")
				u, err := resolveUser(ctx, c, args[0])
				if err != nil {
					return err
				}
				// The path: as --as USER when given, "/My files" as the user
				// checked, team folders and ids with full rights.
				pathAs := actAs
				if pathAs == "" && p.Root == rootMy {
					pathAs = u.Username
				}
				setClientActAs(c, pathAs)
				t, err := resolveAccessNode(ctx, newResolver(c), args[1])
				if err != nil {
					return err
				}
				setClientActAs(c, "")
				res, err := checkAccess(ctx, c, u, t)
				if err != nil {
					return err
				}
				return Print(cmd, res, func(w io.Writer) error { return renderAccessCheck(cmd, w, res) })
			})
		},
	}
}

// checkAccess asks the server what u may do with t (GET /nodes/{id} as u)
// and collects the reasons with full rights: the space of the node, u's
// groups (GET /groups as u) and the grants on the node and above it.
func checkAccess(ctx context.Context, c *Client, u *core.User, t *target) (*accessCheck, error) {
	res := &accessCheck{User: u.ID, Username: u.Username, Path: t.Path, NodeID: t.Node.ID, Reasons: []accessReason{}}
	setClientActAs(c, u.Username)
	perm := core.PermNone
	var n core.Node
	switch err := c.Do(ctx, http.MethodGet, api("/nodes/"+pathEsc(t.Node.ID)), nil, &n); {
	case err == nil:
		perm = n.Perm
	case apiStatus(err) != http.StatusNotFound && apiStatus(err) != http.StatusForbidden:
		setClientActAs(c, "")
		return nil, err
	}
	groups, err := listAll[core.Group](ctx, c, api("/groups"), 0)
	setClientActAs(c, "")
	if err != nil && apiStatus(err) != http.StatusForbidden {
		return nil, err
	}
	res.Access = perm.String()

	r := newResolver(c)
	if err := r.load(ctx); err != nil {
		return nil, err
	}
	if sp := r.space(t.Node.SpaceID); sp != nil {
		switch {
		case sp.Kind == core.SpaceUser && sp.OwnerUserID == u.ID:
			res.Reasons = append(res.Reasons, accessReason{Kind: "space", Detail: "their own files (owner)", perm: core.PermOwner})
		case sp.Kind == core.SpaceGroup:
			for _, g := range groups {
				if g.ID != sp.GroupID && (g.SpaceID == "" || g.SpaceID != sp.ID) {
					continue
				}
				gp := core.PermEdit
				if g.MyRole == core.GroupRoleManager {
					gp = core.PermManage
				}
				role := g.MyRole
				if role == "" {
					role = core.GroupRoleMember
				}
				// A membership only through the user's custom role says so
				// ("direct" also when they are a member both ways).
				through := ""
				if g.Via == "role" {
					through = " through the role " + cmp.Or(u.RoleName, u.RoleID)
				}
				res.Reasons = append(res.Reasons, accessReason{Kind: "group",
					Detail: fmt.Sprintf("%s of group %s%s (team folder: %s)", role, g.Name, through, gp), perm: gp})
			}
		}
	}
	grants, err := listGrants(ctx, c, t.Node)
	if err != nil {
		return nil, err
	}
	paths := nodePaths(ctx, r, t.Node, t.Path)
	inGroup := map[string]string{}
	for _, g := range groups {
		inGroup[g.ID] = g.Name
	}
	for _, g := range grants {
		why := ""
		switch g.SubjectType {
		case core.SubjectUser:
			if g.SubjectID != u.ID {
				continue
			}
		case core.SubjectGroup:
			name, ok := inGroup[g.SubjectID]
			if !ok {
				continue
			}
			why = fmt.Sprintf(" (%s is in %s)", u.Username, name)
		case core.SubjectRole:
			if g.SubjectID != u.RoleID {
				continue
			}
			why = fmt.Sprintf(" (%s has this role)", u.Username)
		default:
			continue
		}
		on := cmp.Or(paths[g.NodeID], g.NodeID)
		gp := grantPerm(g.Role)
		res.Reasons = append(res.Reasons, accessReason{Kind: "grant", GrantID: g.ID, perm: gp,
			Detail: fmt.Sprintf("grant %s on %s: %s → %s%s", g.ID, on, grantWho(g), levelWord(g.Role), why)})
	}
	best := core.PermNone
	for _, rs := range res.Reasons {
		best = max(best, rs.perm)
	}
	if perm > best && u.Role.IsAdmin() {
		res.Reasons = append(res.Reasons, accessReason{Kind: "admin", perm: perm,
			Detail: "admin access to all files (auth.admin_can_access_files is on)"})
	}
	for i := range res.Reasons {
		res.Reasons[i].Access = res.Reasons[i].perm.String()
	}
	return res, nil
}

// grantPerm is the permission an API grant level gives.
func grantPerm(api string) core.Perm {
	switch api {
	case core.GrantManager:
		return core.PermManage
	case core.GrantEditor:
		return core.PermEdit
	case core.GrantViewer:
		return core.PermView
	}
	return core.PermNone
}

// renderAccessCheck prints "bob can EDIT /Team/Design" and the reasons.
func renderAccessCheck(cmd *cobra.Command, w io.Writer, res *accessCheck) error {
	if res.Access == core.PermNone.String() {
		if _, err := fmt.Fprintf(w, "%s cannot open %s\n", res.Username, res.Path); err != nil {
			return err
		}
		Infof(cmd, "hint: give access with %q", fmt.Sprintf("fileparcel access grant %s --user %s", shellArg(res.Path), shellArg(res.Username)))
		return nil
	}
	can := strings.ToUpper(res.Access)
	if res.Access == core.PermOwner.String() {
		can = "MANAGE (owner)"
	}
	if _, err := fmt.Fprintf(w, "%s can %s %s\n", res.Username, can, res.Path); err != nil {
		return err
	}
	for i, rs := range res.Reasons {
		lead := "           "
		if i == 0 {
			lead = "  because: "
		}
		if _, err := fmt.Fprintln(w, lead+sanitizeCell(rs.Detail)); err != nil {
			return err
		}
	}
	return nil
}
