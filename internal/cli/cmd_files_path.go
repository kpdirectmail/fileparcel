package cli

// Remote path resolution for the files, share and request commands
// (DESIGN §12): "/My files/…" (the acting user's personal space),
// "/Team/<group>/…" (a group's team folder), node ids ("nod_…", optionally
// followed by "/sub/path") and paths relative to "/My files". Resolution
// uses only the REST API: GET /me, GET /spaces, GET /nodes/{id},
// GET /nodes/{id}/children and GET /nodes/{id}/breadcrumbs.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/text/unicode/norm"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// Top-level names of the virtual remote file system.
const (
	myFilesName = "My files"
	teamName    = "Team"
)

// Virtual (non-node) folders.
const (
	virtualTop  = "top"  // "/"
	virtualTeam = "team" // "/Team"
)

// Roots of a parsed remote path.
const (
	rootTop  = "top"
	rootMy   = "my"
	rootTeam = "team"
	rootID   = "id"
)

// remotePath is a parsed, normalized remote path.
type remotePath struct {
	Root  string   // rootTop, rootMy, rootTeam or rootID
	ID    string   // rootID: the start node id
	Group string   // rootTeam: the group name ("" = the /Team listing)
	Segs  []string // names below the root
}

// parseRemotePath parses p. Relative paths (and "~/…") are relative to
// "/My files"; "." segments are dropped and ".." goes up (never above "/").
func parseRemotePath(p string) (remotePath, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return remotePath{}, core.Invalid("path", "empty remote path")
	}
	first, rest, _ := strings.Cut(p, "/")
	if ids.Valid(ids.PrefixNode, first) {
		segs, err := normalizeSegs(rest, false)
		if err != nil {
			return remotePath{}, err
		}
		return remotePath{Root: rootID, ID: first, Segs: segs}, nil
	}
	switch {
	case p == "~":
		p = "/" + myFilesName
	case strings.HasPrefix(p, "~/"):
		p = "/" + myFilesName + p[1:]
	case !strings.HasPrefix(p, "/"):
		p = "/" + myFilesName + "/" + p
	}
	segs, err := normalizeSegs(p, true)
	if err != nil {
		return remotePath{}, err
	}
	if len(segs) == 0 {
		return remotePath{Root: rootTop}, nil
	}
	switch {
	case isMyFiles(segs[0]):
		return remotePath{Root: rootMy, Segs: segs[1:]}, nil
	case isTeam(segs[0]):
		if len(segs) == 1 {
			return remotePath{Root: rootTeam}, nil
		}
		return remotePath{Root: rootTeam, Group: segs[1], Segs: segs[2:]}, nil
	}
	return remotePath{}, core.Invalid("path", fmt.Sprintf(
		"unknown top-level folder %q: remote paths start with %q or %q (or are relative to %q, or a node id)",
		segs[0], "/"+myFilesName, "/"+teamName+"/<group>", "/"+myFilesName))
}

// normalizeSegs splits a slash path and resolves "." and "..". With
// clampAtRoot, ".." at the top is ignored; otherwise (paths below a node id)
// it is an error.
func normalizeSegs(p string, clampAtRoot bool) ([]string, error) {
	var out []string
	for _, s := range strings.Split(p, "/") {
		switch s {
		case "", ".":
		case "..":
			if len(out) == 0 {
				if !clampAtRoot {
					return nil, core.Invalid("path", `".." cannot go above the start node`)
				}
				continue
			}
			out = out[:len(out)-1]
		default:
			out = append(out, s)
		}
	}
	return out, nil
}

func isMyFiles(s string) bool {
	switch strings.ToLower(s) {
	case "my files", "my-files", "myfiles", "~":
		return true
	}
	return false
}

func isTeam(s string) bool {
	switch strings.ToLower(s) {
	case "team", "teams", "team folders", "team-folders":
		return true
	}
	return false
}

// String renders the canonical display form.
func (p remotePath) String() string {
	var parts []string
	switch p.Root {
	case rootTop:
		return "/"
	case rootMy:
		parts = []string{"", myFilesName}
	case rootTeam:
		parts = []string{"", teamName}
		if p.Group != "" {
			parts = append(parts, p.Group)
		}
	case rootID:
		parts = []string{p.ID}
	}
	return strings.Join(append(parts, p.Segs...), "/")
}

// parent returns the path of the parent folder and the last name. It fails
// for roots ("/", "/My files", "/Team/<group>", a bare node id).
func (p remotePath) parent() (remotePath, string, error) {
	if len(p.Segs) == 0 {
		return remotePath{}, "", core.Invalid("path", fmt.Sprintf("%s is a root folder", p))
	}
	q := p
	q.Segs = slices.Clone(p.Segs[:len(p.Segs)-1])
	return q, p.Segs[len(p.Segs)-1], nil
}

// ---------- resolver ----------

// target is a resolved remote path: a node, or a virtual folder ("/" or
// "/Team") when Node is nil.
type target struct {
	Node    *core.Node
	Virtual string // virtualTop | virtualTeam when Node is nil
	Path    string // display path
}

// IsDir reports whether the target can hold children.
func (t *target) IsDir() bool { return t.Node == nil || t.Node.IsDir() }

// resolver resolves remote paths for one command run (results are cached).
type resolver struct {
	c        *Client
	me       *core.Me
	spaces   []core.Space
	loaded   bool
	children map[string][]core.Node
	prefixes map[string]string // space id → display prefix
	shared   *[]teamSpace      // sharedTeams, once read
}

func newResolver(c *Client) *resolver {
	return &resolver{c: c, children: map[string][]core.Node{}}
}

// load fetches GET /me and GET /spaces once.
func (r *resolver) load(ctx context.Context) error {
	if r.loaded {
		return nil
	}
	var me core.Me
	if err := r.c.Do(ctx, http.MethodGet, api("/me"), nil, &me); err != nil {
		return fmt.Errorf("look up the acting user: %w", err)
	}
	spaces, err := listAll[core.Space](ctx, r.c, api("/spaces"), 0)
	if err != nil {
		return fmt.Errorf("list spaces: %w", err)
	}
	r.me, r.spaces, r.loaded = &me, spaces, true
	r.prefixes = map[string]string{}
	for _, s := range spaces {
		r.prefixes[s.ID] = "/" + s.Name
	}
	for _, s := range spaces {
		if s.Kind == core.SpaceGroup {
			r.prefixes[s.ID] = "/" + teamName + "/" + s.Name
		}
	}
	for _, g := range me.Groups {
		if sid := r.groupSpaceID(g); sid != "" {
			r.prefixes[sid] = "/" + teamName + "/" + g.Name
		}
	}
	if me.SpaceID != "" {
		r.prefixes[me.SpaceID] = "/" + myFilesName
	}
	return nil
}

func (r *resolver) groupSpaceID(g core.Group) string {
	if sid := r.me.GroupSpaceIDs[g.ID]; sid != "" {
		return sid
	}
	return g.SpaceID
}

func (r *resolver) space(id string) *core.Space {
	for i := range r.spaces {
		if r.spaces[i].ID == id {
			return &r.spaces[i]
		}
	}
	return nil
}

// personalRoot returns the root folder id of "/My files".
func (r *resolver) personalRoot(ctx context.Context) (string, error) {
	if err := r.load(ctx); err != nil {
		return "", err
	}
	if r.me.SpaceID == "" {
		return "", core.Errorf(core.ErrNotFound, "%s has no personal space (guest accounts only see folders shared with them)", r.actor())
	}
	sp := r.space(r.me.SpaceID)
	if sp == nil || sp.RootID == "" {
		return "", core.Errorf(core.ErrNotFound, "the personal space of %s is not visible", r.actor())
	}
	return sp.RootID, nil
}

func (r *resolver) actor() string {
	switch {
	case r.system():
		return "the admin socket (no --as)"
	case r.me != nil && r.me.User != nil && r.me.User.Username != "":
		return fmt.Sprintf("user %q", r.me.User.Username)
	}
	return "this account"
}

// system reports whether paths resolve with the admin socket's (or offline
// mode's) full rights: no --as, so no account ("system" is not a user).
func (r *resolver) system() bool {
	return r.me != nil && r.me.User != nil && r.me.User.ID == "" && r.me.User.Role == core.RoleSystem
}

// teamSpaces lists the team folders visible to the acting user as
// (group name, space) pairs, sorted by name.
func (r *resolver) teamSpaces(ctx context.Context) ([]teamSpace, error) {
	if err := r.load(ctx); err != nil {
		return nil, err
	}
	var out []teamSpace
	seen := map[string]bool{}
	for _, g := range r.me.Groups {
		sid := r.groupSpaceID(g)
		if sp := r.space(sid); sp != nil && !seen[sid] {
			seen[sid] = true
			out = append(out, teamSpace{Name: g.Name, Space: *sp})
		}
	}
	for _, sp := range r.spaces {
		if sp.Kind == core.SpaceGroup && !seen[sp.ID] {
			seen[sp.ID] = true
			out = append(out, teamSpace{Name: sp.Name, Space: sp})
		}
	}
	slices.SortFunc(out, func(a, b teamSpace) int { return strings.Compare(names.Key(a.Name), names.Key(b.Name)) })
	return out, nil
}

type teamSpace struct {
	Name  string
	Space core.Space
	// Shared: the user is not a member; a grant on the whole team folder
	// lets them open it (Space then holds only ids and the name).
	Shared bool
}

// teamRoot returns the root folder id of "/Team/<group>": the exact (NFC)
// group name wins, else the one that matches by names.Key. Several key
// matches (groups from before the server made names unique by casefold) are
// refused rather than guessed, like resolveGroup does.
func (r *resolver) teamRoot(ctx context.Context, group string) (string, error) {
	teams, err := r.teamSpaces(ctx)
	if err != nil {
		return "", err
	}
	exact, key := norm.NFC.String(group), names.Key(group)
	var folded []teamSpace
	for _, t := range teams {
		switch {
		case t.Space.RootID == "":
		case t.Name == exact:
			return t.Space.RootID, nil
		case names.Key(t.Name) == key:
			folded = append(folded, t)
		}
	}
	switch len(folded) {
	case 1:
		return folded[0].Space.RootID, nil
	case 0:
	default:
		var cands []string
		for _, t := range folded {
			cands = append(cands, fmt.Sprintf("%q (%s)", t.Name, t.Space.RootID))
		}
		return "", core.Invalid("path", fmt.Sprintf("team folder %q matches several groups (%s); use the exact name or the folder id",
			group, strings.Join(cands, ", ")))
	}
	if id := r.sharedTeamRoot(ctx, exact, key); id != "" {
		return id, nil
	}
	var avail []string
	for _, t := range teams {
		avail = append(avail, t.Name)
	}
	msg := fmt.Sprintf("no team folder %q for %s", group, r.actor())
	if r.system() {
		msg = fmt.Sprintf("no team folder %q", group) // every team folder is visible
	}
	if len(avail) > 0 {
		msg += " (available: " + strings.Join(avail, ", ") + ")"
	}
	return "", core.Errorf(core.ErrNotFound, "%s", msg)
}

// sharedTeamRoot finds "/Team/<group>" among the folders shared with the
// acting user (GET /shared-with-me) when the user is not a member of the
// group but holds a grant on its whole team folder — directly, through a
// group or through a role (so "access check bob /Team/Design" and
// "--as bob files ls /Team/Design" agree). Only space roots count (a team
// folder's root carries the group's name); the exact name wins over a
// casefold match, and several matches are left unresolved.
func (r *resolver) sharedTeamRoot(ctx context.Context, exact, key string) string {
	var folded []string
	for _, t := range r.sharedTeams(ctx) {
		if t.Name == exact {
			return t.Space.RootID
		}
		if names.Key(t.Name) == key {
			folded = append(folded, t.Space.RootID)
		}
	}
	if len(folded) == 1 {
		return folded[0]
	}
	return ""
}

// sharedTeams lists the team folders the acting user reaches through a
// grant on the whole folder rather than as a member (the roots
// sharedTeamRoot accepts), sorted by name; Shared is set and Space holds
// only the root and space ids and the name. It is read once per run. Errors
// (an older server, a token without files:read) give no folders: the
// caller then reports the usual "no team folder".
func (r *resolver) sharedTeams(ctx context.Context) []teamSpace {
	if r.shared != nil {
		return *r.shared
	}
	out := []teamSpace{}
	r.shared = &out
	if err := r.load(ctx); err != nil {
		return out
	}
	shared, err := listAll[core.Node](ctx, r.c, api("/shared-with-me", "limit", limitParam(0)), 0)
	if err != nil {
		return out
	}
	for _, n := range shared {
		// A root outside the spaces the user sees; "My files" is someone's
		// personal space, not a team folder.
		if n.ParentID != "" || n.Kind != core.KindFolder || r.space(n.SpaceID) != nil || n.Name == myFilesName {
			continue
		}
		out = append(out, teamSpace{Name: n.Name, Shared: true,
			Space: core.Space{ID: n.SpaceID, Kind: core.SpaceGroup, Name: n.Name, RootID: n.ID}})
	}
	slices.SortFunc(out, func(a, b teamSpace) int { return strings.Compare(names.Key(a.Name), names.Key(b.Name)) })
	r.shared = &out
	return out
}

// allTeams lists every team folder the acting user can open, as "files ls
// /Team" shows them: those of the groups (teamSpaces), then those shared
// as a whole (sharedTeams), sorted by name.
func (r *resolver) allTeams(ctx context.Context) ([]teamSpace, error) {
	teams, err := r.teamSpaces(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range r.sharedTeams(ctx) {
		if !slices.ContainsFunc(teams, func(m teamSpace) bool { return m.Space.RootID == t.Space.RootID }) {
			teams = append(teams, t)
		}
	}
	slices.SortStableFunc(teams, func(a, b teamSpace) int { return strings.Compare(names.Key(a.Name), names.Key(b.Name)) })
	return teams, nil
}

// getNode fetches one node.
func (r *resolver) getNode(ctx context.Context, id string) (*core.Node, error) {
	var n core.Node
	if err := r.c.Do(ctx, http.MethodGet, api("/nodes/"+pathEsc(id)), nil, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

// list returns every child of a folder (all pages; cached per run).
func (r *resolver) list(ctx context.Context, folderID string) ([]core.Node, error) {
	if kids, ok := r.children[folderID]; ok {
		return kids, nil
	}
	kids, err := listAll[core.Node](ctx, r.c, api("/nodes/"+pathEsc(folderID)+"/children", "limit", limitParam(0)), 0)
	if err != nil {
		return nil, err
	}
	r.children[folderID] = kids
	return kids, nil
}

// forget drops cached listings (after a change).
func (r *resolver) forget(folderID string) { delete(r.children, folderID) }

// child finds name in a folder: an exact match first, then the
// case-insensitive, normalization-insensitive match the server uses for
// uniqueness (names.Key). nil when absent.
func (r *resolver) child(ctx context.Context, folderID, name string) (*core.Node, error) {
	kids, err := r.list(ctx, folderID)
	if err != nil {
		return nil, err
	}
	for i := range kids {
		if kids[i].Name == name {
			return &kids[i], nil
		}
	}
	key := names.Key(name)
	for i := range kids {
		if names.Key(kids[i].Name) == key {
			return &kids[i], nil
		}
	}
	return nil, nil
}

// resolve resolves a remote path to a node or a virtual folder. Missing
// entries are core.ErrNotFound errors naming the path.
func (r *resolver) resolve(ctx context.Context, raw string) (*target, error) {
	p, err := parseRemotePath(raw)
	if err != nil {
		return nil, err
	}
	return r.resolveParsed(ctx, p)
}

func (r *resolver) resolveParsed(ctx context.Context, p remotePath) (*target, error) {
	var start *core.Node
	switch p.Root {
	case rootTop:
		if err := r.load(ctx); err != nil {
			return nil, err
		}
		return &target{Virtual: virtualTop, Path: "/"}, nil
	case rootTeam:
		if p.Group == "" {
			if err := r.load(ctx); err != nil {
				return nil, err
			}
			return &target{Virtual: virtualTeam, Path: "/" + teamName}, nil
		}
		rootID, err := r.teamRoot(ctx, p.Group)
		if err != nil {
			return nil, err
		}
		if start, err = r.getNode(ctx, rootID); err != nil {
			return nil, err
		}
	case rootMy:
		rootID, err := r.personalRoot(ctx)
		if err != nil {
			return nil, err
		}
		if start, err = r.getNode(ctx, rootID); err != nil {
			return nil, err
		}
	case rootID:
		n, err := r.getNode(ctx, p.ID)
		if err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return nil, core.Errorf(core.ErrNotFound, "%s: no such file or folder", p.ID)
			}
			return nil, err
		}
		start = n
	default:
		return nil, core.Invalid("path", "invalid path")
	}
	cur := start
	for i, seg := range p.Segs {
		if !cur.IsDir() {
			sub := p
			sub.Segs = p.Segs[:i]
			return nil, core.Invalid("path", fmt.Sprintf("%s is a file, not a folder", sub))
		}
		next, err := r.child(ctx, cur.ID, seg)
		if err != nil {
			return nil, err
		}
		if next == nil {
			sub := p
			sub.Segs = p.Segs[:i+1]
			return nil, core.Errorf(core.ErrNotFound, "%s: no such file or folder", sub)
		}
		cur = next
	}
	return &target{Node: cur, Path: p.String()}, nil
}

// resolveFolder resolves a path that must be a real folder node.
func (r *resolver) resolveFolder(ctx context.Context, raw string) (*target, error) {
	t, err := r.resolve(ctx, raw)
	if err != nil {
		return nil, err
	}
	if t.Node == nil {
		return nil, core.Invalid("path", fmt.Sprintf("%s is not a folder you can put files in; use %q or %q",
			t.Path, "/"+myFilesName+"/…", "/"+teamName+"/<group>/…"))
	}
	if !t.Node.IsDir() {
		return nil, core.Invalid("path", fmt.Sprintf("%s is a file, not a folder", t.Path))
	}
	return t, nil
}

// resolveNode resolves a path that must be a real node (file or folder).
func (r *resolver) resolveNode(ctx context.Context, raw string) (*target, error) {
	t, err := r.resolve(ctx, raw)
	if err != nil {
		return nil, err
	}
	if t.Node == nil {
		return nil, core.Invalid("path", fmt.Sprintf("%s is a virtual folder, not a file or folder", t.Path))
	}
	return t, nil
}

// resolveNew resolves a path whose last element may not exist yet: it
// returns the parent folder and the last name, plus the existing node (nil
// when absent).
func (r *resolver) resolveNew(ctx context.Context, raw string) (parent *target, name string, existing *core.Node, err error) {
	p, err := parseRemotePath(raw)
	if err != nil {
		return nil, "", nil, err
	}
	pp, name, err := p.parent()
	if err != nil {
		return nil, "", nil, err
	}
	parent, err = r.resolveParsed(ctx, pp)
	if err != nil {
		return nil, "", nil, err
	}
	if parent.Node == nil || !parent.Node.IsDir() {
		return nil, "", nil, core.Invalid("path", fmt.Sprintf("%s is not a folder", parent.Path))
	}
	existing, err = r.child(ctx, parent.Node.ID, name)
	if err != nil {
		return nil, "", nil, err
	}
	return parent, name, existing, nil
}

// mkdirAll creates the missing folders of a path (like mkdir -p) and
// returns the final folder.
func (r *resolver) mkdirAll(ctx context.Context, raw string) (*target, []string, error) {
	p, err := parseRemotePath(raw)
	if err != nil {
		return nil, nil, err
	}
	base := p
	base.Segs = nil
	t, err := r.resolveParsed(ctx, base)
	if err != nil {
		return nil, nil, err
	}
	if t.Node == nil {
		return nil, nil, core.Invalid("path", fmt.Sprintf("cannot create folders in %s", t.Path))
	}
	cur := t.Node
	var created []string
	for i, seg := range p.Segs {
		sub := p
		sub.Segs = p.Segs[:i+1]
		next, err := r.child(ctx, cur.ID, seg)
		if err != nil {
			return nil, nil, err
		}
		if next == nil {
			var n core.Node
			if err := r.c.Do(ctx, http.MethodPost, api("/nodes/"+pathEsc(cur.ID)+"/folders"), core.NameInput{Name: seg}, &n); err != nil {
				return nil, nil, fmt.Errorf("create %s: %w", sub, err)
			}
			r.forget(cur.ID)
			next = &n
			created = append(created, sub.String())
		} else if !next.IsDir() {
			return nil, nil, core.Invalid("path", fmt.Sprintf("%s is a file, not a folder", sub))
		}
		cur = next
	}
	return &target{Node: cur, Path: p.String()}, created, nil
}

// displayPath renders a node's full path ("/My files/Docs/a.txt") from its
// space and Node.Path (as filled by search and trash listings), falling
// back to the breadcrumbs.
func (r *resolver) displayPath(ctx context.Context, n *core.Node) string {
	if err := r.load(ctx); err != nil {
		return n.Name
	}
	prefix, ok := r.prefixes[n.SpaceID]
	if !ok {
		prefix = "/" + n.SpaceID
	}
	if n.Path != "" {
		p := n.Path
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return prefix + p
	}
	if n.ParentID == "" {
		return prefix
	}
	crumbs, err := doList[core.Node](ctx, r.c, http.MethodGet, api("/nodes/"+pathEsc(n.ID)+"/breadcrumbs"), nil)
	if err != nil {
		return prefix + "/…/" + n.Name
	}
	var parts []string
	for _, c := range crumbs {
		if c.ParentID == "" || c.ID == n.ID {
			continue
		}
		parts = append(parts, c.Name)
	}
	parts = append(parts, n.Name)
	return prefix + "/" + strings.Join(parts, "/")
}
