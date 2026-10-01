package cli

// Shared plumbing for the command groups of unit I2 (user, invite, group,
// token, files, share, request, backup, cert, ca, client-cert, config,
// network, keys, audit, jobs, db, gc, maintenance, completion, docs) and of
// role and access: API list pagination, name → id resolution of users,
// groups and roles, the permission catalog, the default acting user, job
// polling, absolute share/invite URLs and error hints.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"golang.org/x/text/unicode/norm"

	"fileparcel/internal/cli/clikit"
	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// apiPrefix is the REST API mount point.
const apiPrefix = "/api/v1"

// api returns apiPrefix+path with the query built from kv pairs (empty
// values are skipped): api("/admin/users", "role", "owner").
func api(path string, kv ...string) string {
	return withQuery(apiPrefix+path, kv...)
}

// withQuery appends kv pairs (key, value, …) to path's query, skipping empty
// values.
func withQuery(path string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Add(kv[i], kv[i+1])
		}
	}
	if len(q) == 0 {
		return path
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + q.Encode()
}

// pathEsc escapes one path segment (ids never need it, names might).
func pathEsc(s string) string { return url.PathEscape(s) }

// listAll GETs a list endpoint and follows next_cursor until the last page or
// until max items were collected (max <= 0: all). The endpoint may answer
// with a core.Page or a bare JSON array. The result is never nil (so --json
// prints [] rather than null).
func listAll[T any](ctx context.Context, c *Client, path string, max int) ([]T, error) {
	out := []T{}
	cursor := ""
	for page := 0; ; page++ {
		p := path
		if cursor != "" {
			p = withQuery(path, "cursor", cursor)
		}
		var raw json.RawMessage
		if err := c.Do(ctx, http.MethodGet, p, nil, &raw); err != nil {
			return nil, err
		}
		items, next, err := decodeList[T](raw)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if max > 0 && len(out) >= max {
			return out[:max], nil
		}
		if next == "" || next == cursor || page > 100000 {
			return out, nil
		}
		cursor = next
	}
}

// doList sends one request whose response is a list: a bare JSON array, a
// core.Page[T] or an empty body (204). The result is never nil.
func doList[T any](ctx context.Context, c *Client, method, path string, body any) ([]T, error) {
	var raw json.RawMessage
	if err := c.Do(ctx, method, path, body, &raw); err != nil {
		return nil, err
	}
	items, _, err := decodeList[T](raw)
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []T{}
	}
	return items, nil
}

// decodeList decodes a core.Page[T] or a bare []T.
func decodeList[T any](raw json.RawMessage) ([]T, string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, "", nil
	}
	if raw[0] == '[' {
		var items []T
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, "", fmt.Errorf("decode response: %w", err)
		}
		return items, "", nil
	}
	var pg core.Page[T]
	if err := json.Unmarshal(raw, &pg); err != nil {
		return nil, "", fmt.Errorf("decode response: %w", err)
	}
	return pg.Items, pg.NextCursor, nil
}

// limitParam renders a --limit value for a list request (the server caps it
// at core.MaxPageLimit).
func limitParam(n int) string {
	if n <= 0 || n > core.MaxPageLimit {
		return fmt.Sprint(core.MaxPageLimit)
	}
	return fmt.Sprint(n)
}

// ---------- users & groups ----------

// resolveUser finds a user by id ("usr_…") or username (case-insensitive).
func resolveUser(ctx context.Context, c *Client, ref string) (*core.User, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, core.Invalid("user", "user name must not be empty")
	}
	if ids.Valid(ids.PrefixUser, ref) {
		var u core.User
		if err := c.Do(ctx, http.MethodGet, api("/admin/users/"+ref), nil, &u); err != nil {
			return nil, withListHint(err, "fileparcel user list")
		}
		return &u, nil
	}
	users, err := listAll[core.User](ctx, c, api("/admin/users", "q", ref, "limit", limitParam(0)), 0)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if strings.EqualFold(users[i].Username, ref) {
			return &users[i], nil
		}
	}
	return nil, withListHint(core.NotFoundf("user %q not found", ref), "fileparcel user list")
}

// resolveGroup finds a group by id ("grp_…") or name. The exact (NFC) name
// wins; otherwise the name matches case-insensitively the way the server
// compares group names (names.Key, casefold(NFC)). A name that folds to
// several groups ("Équipe" and "équipe", possible in databases from before
// the server enforced that) is refused rather than guessed: `-y group
// delete` must never pick the other group.
func resolveGroup(ctx context.Context, c *Client, ref string) (*core.Group, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, core.Invalid("group", "group name must not be empty")
	}
	if ids.Valid(ids.PrefixGroup, ref) {
		var g core.Group
		if err := c.Do(ctx, http.MethodGet, api("/admin/groups/"+ref), nil, &g); err != nil {
			return nil, withListHint(err, "fileparcel group list")
		}
		return &g, nil
	}
	groups, err := listAll[core.Group](ctx, c, api("/admin/groups", "limit", limitParam(0)), 0)
	if err != nil {
		return nil, err
	}
	exact, key := norm.NFC.String(ref), names.Key(ref)
	var folded []*core.Group
	for i := range groups {
		switch {
		case groups[i].Name == exact:
			return &groups[i], nil
		case names.Key(groups[i].Name) == key:
			folded = append(folded, &groups[i])
		}
	}
	switch len(folded) {
	case 0:
		return nil, withListHint(core.NotFoundf("group %q not found", ref), "fileparcel group list")
	case 1:
		return folded[0], nil
	}
	var cands []string
	for _, g := range folded {
		cands = append(cands, fmt.Sprintf("%s %q", g.ID, g.Name))
	}
	return nil, core.Invalid("group", fmt.Sprintf("group name %q matches several groups (%s); use the group id or the exact name",
		ref, strings.Join(cands, ", ")))
}

// ---------- roles ----------

// roleRef is a resolved --role / <role> value.
type roleRef struct {
	ID      string    // "owner", "admin", "member", "guest" or "rol_…"
	Name    string    // display name
	Builtin bool      // one of the four built-in roles
	Base    core.Role // the built-in role it is based on ("" when unknown: a role found through GET /roles)
}

// label is how messages name the role: the built-in word or the custom
// name.
func (r *roleRef) label() string {
	if r.Builtin {
		return r.ID
	}
	return r.Name
}

// noRolesHint is the hint of a server that answers 404 on the roles API.
const noRolesHint = "this server has no custom roles (upgrade it)"

// withNoRolesHint adds noRolesHint to a not-found error of a roles route
// that exists on every server with roles (the list, a built-in role).
func withNoRolesHint(err error) error {
	if apiStatus(err) == http.StatusNotFound {
		return &hintError{err, noRolesHint}
	}
	return err
}

// listRoles returns the roles the caller may see: GET /admin/roles (every
// role, built-in first), or GET /roles (custom roles only, for callers who
// may search the directory but not view people) when that is refused.
func listRoles(ctx context.Context, c *Client) ([]core.RoleDef, error) {
	roles, err := listAll[core.RoleDef](ctx, c, api("/admin/roles"), 0)
	if apiStatus(err) == http.StatusForbidden {
		refs, rerr := listAll[core.RoleRef](ctx, c, api("/roles"), 0)
		if rerr != nil {
			return nil, withNoRolesHint(rerr)
		}
		roles = make([]core.RoleDef, len(refs))
		for i, r := range refs {
			roles[i] = core.RoleDef{ID: r.ID, Name: r.Name, Description: r.Description}
		}
		return roles, nil
	}
	if err != nil {
		return nil, withNoRolesHint(err)
	}
	return roles, nil
}

// resolveRole finds a role by id (a built-in word or "rol_…") or by name
// (the exact name first, then case-insensitively) via listRoles. Built-in
// words resolve without a request, so --role member keeps working against
// servers without roles.
func resolveRole(ctx context.Context, c *Client, ref string) (*roleRef, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, core.Invalid("role", "role name must not be empty")
	}
	if r := core.Role(strings.ToLower(ref)); r.Valid() {
		return &roleRef{ID: string(r), Name: core.BuiltinRoleName(r), Builtin: true, Base: r}, nil
	}
	roles, err := listRoles(ctx, c)
	if err != nil {
		return nil, err
	}
	key := names.Key(ref)
	var folded []*core.RoleDef
	for i := range roles {
		switch {
		case roles[i].ID == ref || roles[i].Name == ref:
			return roleRefOf(&roles[i]), nil
		case names.Key(roles[i].Name) == key:
			folded = append(folded, &roles[i])
		}
	}
	switch len(folded) {
	case 0:
		return nil, withListHint(core.NotFoundf("role %q not found", ref), "fileparcel role list")
	case 1:
		return roleRefOf(folded[0]), nil
	}
	var cands []string
	for _, r := range folded {
		cands = append(cands, fmt.Sprintf("%s %q", r.ID, r.Name))
	}
	return nil, core.Invalid("role", fmt.Sprintf("role name %q matches several roles (%s); use the role id or the exact name",
		ref, strings.Join(cands, ", ")))
}

// roleRefOf is the roleRef of a role from the API.
func roleRefOf(r *core.RoleDef) *roleRef {
	return &roleRef{ID: r.ID, Name: r.Name, Builtin: r.Builtin || core.Role(r.ID).Valid(), Base: r.Base}
}

// roleCatalog returns the permission catalog for validating --add,
// --remove and --set: GET /admin/capabilities, or the catalog compiled into
// this program when the server has no such route or refuses it (compiled is
// then true, and the server's own list may differ).
func roleCatalog(ctx context.Context, c *Client) (cat core.CapabilityCatalog, compiled bool, err error) {
	err = c.Do(ctx, http.MethodGet, api("/admin/capabilities"), nil, &cat)
	if st := apiStatus(err); st == http.StatusNotFound || st == http.StatusForbidden {
		return core.Catalog(), true, nil
	}
	if err != nil {
		return core.CapabilityCatalog{}, false, err
	}
	if len(cat.Items) == 0 {
		return core.Catalog(), true, nil
	}
	return cat, false, nil
}

// parsePermList splits repeatable and comma-separated permission names,
// lower-cases and de-duplicates them and checks each against the catalog:
// an unknown name is a usage error with the closest names.
func parsePermList(vals []string, cat []core.CapabilityInfo) ([]core.Capability, error) {
	known := make(map[core.Capability]bool, len(cat))
	for _, c := range cat {
		known[c.Name] = true
	}
	var out []core.Capability
	for _, v := range vals {
		for _, s := range strings.Split(v, ",") {
			name := core.Capability(strings.ToLower(strings.TrimSpace(s)))
			if name == "" || slices.Contains(out, name) {
				continue
			}
			if !known[name] {
				return nil, &usageHintError{
					msg:         fmt.Sprintf("unknown permission %q", string(name)),
					suggestions: closestPerms(string(name), cat, 3),
					help:        `Run "fileparcel role permissions" to see them all.`,
				}
			}
			out = append(out, name)
		}
	}
	return out, nil
}

// closestPerms returns the n catalog names closest to name (edit distance,
// then catalog order).
func closestPerms(name string, cat []core.CapabilityInfo, n int) []string {
	type cand struct {
		name string
		d, i int
	}
	cands := make([]cand, len(cat))
	for i, c := range cat {
		cands[i] = cand{string(c.Name), levenshtein(name, string(c.Name)), i}
	}
	slices.SortFunc(cands, func(a, b cand) int {
		if a.d != b.d {
			return a.d - b.d
		}
		return a.i - b.i
	})
	var out []string
	for _, c := range cands[:min(n, len(cands))] {
		out = append(out, c.name)
	}
	return out
}

// firstOwner returns the username of the oldest owner account (the default
// acting user of files/share commands on the admin socket, DESIGN §12).
func firstOwner(ctx context.Context, c *Client) (string, error) {
	users, err := listAll[core.User](ctx, c, api("/admin/users", "role", string(core.RoleOwner), "limit", limitParam(0)), 0)
	if err != nil {
		return "", fmt.Errorf("find the owner account: %w", err)
	}
	var owners []core.User
	for _, u := range users {
		// A disabled owner cannot act, so acting as one would fail later with a
		// confusing error; pick the oldest owner that is still active.
		if u.Role == core.RoleOwner && u.Status != core.UserDisabled {
			owners = append(owners, u)
		}
	}
	if len(owners) == 0 {
		return "", errors.New(`there is no active owner account; create one with "fileparcel user create NAME --role owner", enable an existing one, or pass --as USER`)
	}
	slices.SortStableFunc(owners, func(a, b core.User) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return owners[0].Username, nil
}

// setClientActAs makes c send X-FP-As: username on every request (socket
// and offline transports only).
func setClientActAs(c *Client, username string) { c.as = username }

// withUserClient is WithClient for commands that act on a user's own data
// (files, share, request, token): over the admin socket or offline, the
// requests act as --as USER, defaulting to the first owner; remotely they act
// as the token's user.
func withUserClient(cmd *cobra.Command, fn func(ctx context.Context, c *Client) error) error {
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		if c.Mode() != ModeRemote && G.As == "" {
			owner, err := firstOwner(ctx, c)
			if err != nil {
				return err
			}
			setClientActAs(c, owner)
		}
		return fn(ctx, c)
	})
}

// ---------- jobs ----------

// jobTerminal reports whether a job state is final.
func jobTerminal(state string) bool {
	return state == core.JobSucceeded || state == core.JobFailed || state == core.JobCanceled
}

// jobPath returns the endpoint to poll a job: /admin/jobs/{id} for admin
// commands, /jobs/{id} (own jobs) for user-scoped ones.
func jobPath(id string, admin bool) string {
	if admin {
		return api("/admin/jobs/" + pathEsc(id))
	}
	return api("/jobs/" + pathEsc(id))
}

// waitJob polls a job until it finishes, drawing a progress line on a
// terminal. A failed or canceled job is an error. Interrupting (ctx done)
// leaves the job running and says how to check on it.
func waitJob(ctx context.Context, cmd *cobra.Command, c *Client, id string, admin bool, label string) (*core.Job, error) {
	prog := clikit.NewProgress(cmd.ErrOrStderr(), stderrIsTerminal(cmd) && !G.JSON, label, 0)
	prog.SetFormat(clikit.Count)
	prog.Start(250 * time.Millisecond)
	defer prog.Finish()
	delay := 300 * time.Millisecond
	for {
		var j core.Job
		if err := c.Do(ctx, http.MethodGet, jobPath(id, admin), nil, &j); err != nil {
			if ctx.Err() != nil {
				return nil, stoppedWaiting(id)
			}
			return nil, err
		}
		if j.ProgressTotal > 0 {
			prog.SetTotal(j.ProgressTotal)
			prog.Add(j.ProgressDone - prog.Done())
		}
		prog.SetNote(strings.TrimSpace(j.State + " " + j.Note))
		if jobTerminal(j.State) {
			prog.Finish()
			switch j.State {
			case core.JobFailed:
				return &j, fmt.Errorf("job %s (%s) failed: %s", j.ID, j.Kind, dash(j.Error))
			case core.JobCanceled:
				return &j, fmt.Errorf("job %s (%s) was canceled", j.ID, j.Kind)
			}
			return &j, nil
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, stoppedWaiting(id)
		case <-t.C:
		}
		delay = min(delay*2, 2*time.Second)
	}
}

func stoppedWaiting(id string) error {
	return fmt.Errorf("stopped waiting; job %s continues in the background (check it with \"fileparcel jobs show %s\")", id, id)
}

// stderrIsTerminal reports whether progress output makes sense.
func stderrIsTerminal(cmd *cobra.Command) bool {
	f, ok := cmd.ErrOrStderr().(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool { return f != nil && term.IsTerminal(int(f.Fd())) }

// ---------- URLs ----------

// absoluteURL turns a root-relative URL returned by the API ("/s/<token>",
// "/invite/<token>") into an absolute one: remote mode uses --server, the
// socket/offline modes the recommended access URL (GET /network/urls). On
// failure the relative URL is returned unchanged. Use a urlResolver when
// converting many URLs.
func absoluteURL(ctx context.Context, c *Client, rel string) string {
	return newURLResolver(c).abs(ctx, rel)
}

// urlResolver makes root-relative URLs absolute, looking the server origin
// up at most once.
type urlResolver struct {
	c      *Client
	origin string
	looked bool
}

func newURLResolver(c *Client) *urlResolver { return &urlResolver{c: c} }

func (u *urlResolver) abs(ctx context.Context, rel string) string {
	if rel == "" || !strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "//") {
		return rel
	}
	if !u.looked {
		u.looked = true
		if u.c.Mode() == ModeRemote && G.Server != "" {
			if p, err := url.Parse(strings.TrimRight(G.Server, "/")); err == nil && p.Host != "" {
				u.origin = p.Scheme + "://" + p.Host
			}
		} else {
			u.origin = serverOrigin(ctx, u.c)
		}
	}
	if u.origin == "" {
		return rel
	}
	return u.origin + rel
}

// serverOrigin returns "https://host:port" of the recommended access URL,
// or "" when unknown.
func serverOrigin(ctx context.Context, c *Client) string {
	urls, err := doList[core.AccessURL](ctx, c, http.MethodGet, api("/network/urls"), nil)
	if err != nil || len(urls) == 0 {
		return ""
	}
	pick := urls[0]
	for _, u := range urls {
		if u.Recommended {
			pick = u
			break
		}
	}
	u, err := url.Parse(pick.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// ---------- errors ----------

// hintError decorates an error with advice for the user; errors.Is/As see
// through it (so exit codes and --json codes are unchanged).
type hintError struct {
	err  error
	hint string
}

func (e *hintError) Error() string { return e.err.Error() + "\n  hint: " + e.hint }
func (e *hintError) Unwrap() error { return e.err }

// stepUpTokenCmd is the command the step-up hint suggests; it must pass
// "token create" validation as written (an --elevated token must expire
// within 30 days).
const stepUpTokenCmd = `"fileparcel token create ops --scopes admin --elevated --expires 7d"`

// explainError adds a hint to well-known API error codes.
func explainError(err error) error {
	if err == nil {
		return nil
	}
	var he *hintError
	var ee *ExitCodeError
	if errors.As(err, &he) || errors.As(err, &ee) {
		return err
	}
	ce := core.AsError(err)
	if ce == nil {
		if errors.Is(err, ErrNotInteractive) {
			return &hintError{err, "re-run in a terminal, pass -y/--yes to confirm, or use the --*-stdin / --*-file flags for secrets"}
		}
		return err
	}
	remote := G.Server != ""
	var hint string
	switch ce.Code {
	case core.ErrElevationRequired.Code:
		hint = "this action needs a recent identity confirmation (step-up). Run the command on the server host " +
			"without --server: the local admin socket is always elevated. Remotely, use an elevated admin token, " +
			"created on the server host with " + stepUpTokenCmd + " (add --user NAME for another admin)."
	case core.ErrKeysLocked.Code:
		// "keys unlock" needs a running server; an offline command on a
		// sealed home unlocks it itself, given the passphrase.
		hint = `the master key is locked; unlock the running server with "fileparcel keys unlock", or, with the ` +
			`server stopped, pass the passphrase to the command itself (--passphrase-stdin / --passphrase-file)`
	case core.ErrUnauthorized.Code:
		if remote {
			hint = "the API token is missing, invalid, revoked or expired ($" + TokenEnv + ", --token-file or --token)"
		}
	case core.ErrForbidden.Code:
		if remote {
			hint = `the token's user or scopes do not allow this (see "fileparcel token list"); admin commands need an admin token with the "admin" scope`
		}
	case core.ErrEnrollRequired.Code:
		hint = "the account must set up two-factor authentication (sign in to the web UI) before it can do this"
	case core.ErrMFARequired.Code:
		hint = "the session still needs its second factor"
	case core.ErrNotImplemented.Code:
		hint = "this feature is not available in this build of the server"
	case core.ErrRateLimited.Code:
		hint = "too many requests; wait a minute and try again"
	case core.ErrQuota.Code:
		// The same code refuses work when the server's disk is nearly full
		// ("not enough free disk space …"); a quota does not help there.
		if strings.Contains(ce.Message, "disk space") {
			hint = `the server's disk is nearly full; free disk space on the server ("fileparcel gc" removes data of deleted files)`
		} else if strings.Contains(ce.Message, "unfinished uploads hold") {
			// A killed upload or a closed tab still holds its reservation.
			hint = `cancel the unfinished uploads you no longer need in the upload panel of the web interface, or wait ` +
				`until they expire; otherwise free some space or raise the quota ("fileparcel user set-quota USER SIZE")`
		} else {
			hint = `the storage quota is exhausted; free some space or raise the quota ("fileparcel user set-quota USER SIZE")`
		}
	case core.ErrUnavailable.Code:
		hint = `the server is busy or a required service is unavailable; check "fileparcel status"`
	case core.ErrCorrupt.Code:
		hint = `stored data failed its integrity check; run "fileparcel doctor" and consider restoring a backup`
	}
	if hint == "" {
		return err
	}
	return &hintError{err, hint}
}

// reSettingKey matches a setting key ("storage.trash_days") in an error's
// Field.
var reSettingKey = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// explainErrorFor is explainError plus hints that depend on the command:
// where to list the objects of a not-found error (the annList annotation of
// the command or its nearest parent), what limits the caller of a refusal,
// the allowed values of a setting and an object that already exists.
func explainErrorFor(cmd *cobra.Command, err error) error {
	var he *hintError
	var ee *ExitCodeError
	var uh *usageHintError
	if err == nil || errors.As(err, &he) || errors.As(err, &ee) || errors.As(err, &uh) {
		return err
	}
	if hint := commandHint(cmd, core.AsError(err)); hint != "" {
		return &hintError{err, hint}
	}
	return explainError(err)
}

// commandHint is the hint of explainErrorFor for the API error ce of cmd,
// or "" (explainError then decides).
func commandHint(cmd *cobra.Command, ce *core.Error) string {
	if ce == nil {
		return ""
	}
	root := cmd.Root()
	switch ce.Code {
	case core.ErrNotFound.Code:
		// The server refuses every request of an --as user that does not
		// exist (mw.actAs) before the command's own objects are looked at.
		if G.As != "" && ce.Message == fmt.Sprintf("user %q not found", G.As) {
			return fmt.Sprintf(`--as %s names no user; list them with "fileparcel user list"`, G.As)
		}
		if l := listHint(cmd); l != "" && !strings.Contains(ce.Message, l) {
			return fmt.Sprintf("list them with %q", l)
		}
	case core.ErrForbidden.Code:
		switch {
		case G.Server != "":
			var see []string
			for _, c := range []string{"whoami", "role show <role>"} {
				if commandExists(root, c) {
					see = append(see, strconv.Quote("fileparcel "+c))
				}
			}
			if len(see) == 0 {
				see = []string{`"fileparcel token list"`}
			}
			return fmt.Sprintf(`the token's account or scopes do not allow this; admin commands need an account with the `+
				`matching permission and a token with the "admin" scope (see %s)`, joinOr(see))
		case G.As != "":
			hint := fmt.Sprintf("%s's role or access does not allow this; drop --as to use the admin socket's full rights", G.As)
			// Only a refusal on a file or folder is about access; the
			// others need a permission of the role ("fileparcel whoami").
			if commandExists(root, "access check") && takesRemotePath(cmd) {
				hint += fmt.Sprintf(`, or see "fileparcel access check %s <path>"`, G.As)
			} else if commandExists(root, "whoami") {
				hint += fmt.Sprintf(`, or see what the role allows with "fileparcel --as %s whoami"`, G.As)
			}
			return hint
		}
	case core.ErrInvalid.Code:
		if reSettingKey.MatchString(ce.Field) {
			return fmt.Sprintf(`see "fileparcel config get %s --json" for allowed values`, ce.Field)
		}
	case core.ErrConflict.Code:
		if strings.HasPrefix(ce.Field, "funnel.") { // a managed setting (network funnel/tailscale-serve own them)
			return managedHint(ce.Field, ce.Message)
		}
		if l := listHint(cmd); l != "" && cmd.Name() == "create" {
			return fmt.Sprintf("it already exists; see %q", l)
		}
	}
	return ""
}

// takesRemotePath reports whether cmd takes a remote file or folder path
// (a command of the files, share, request or access groups whose use line
// has a path, folder or remote placeholder).
func takesRemotePath(cmd *cobra.Command) bool {
	if !slices.Contains(remoteGroups, topCommand(cmd)) {
		return false
	}
	return slices.ContainsFunc(placeholders(cmd), func(ph string) bool {
		return strings.Contains(ph, "path") || strings.Contains(ph, "folder") || strings.Contains(ph, "remote")
	})
}

// withListHint adds "list them with …" to a not-found error of an object
// the command resolved by name, where the command's own list hint would
// name the wrong objects (the user of "group add-member").
func withListHint(err error, list string) error {
	if ce := core.AsError(err); ce != nil && ce.Code == core.ErrNotFound.Code {
		return &hintError{err, fmt.Sprintf("list them with %q", list)}
	}
	return err
}

// setListHint records the command that lists the objects of cmd (a group,
// or one command whose objects differ from its group's): not-found errors
// of cmd and the commands below it point at it ("fileparcel user list").
// "{parent}" stands for the parent folder of the first argument,
// "{parent:last}" for that of the last one.
func setListHint(cmd *cobra.Command, list string) {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[annList] = list
}

// listHint returns the list command of cmd or its nearest parent, or "".
func listHint(cmd *cobra.Command) string {
	for c := cmd; c != nil; c = c.Parent() {
		l := c.Annotations[annList]
		if l == "" {
			continue
		}
		args := cmd.Flags().Args()
		for placeholder, pick := range map[string]func() string{
			"{parent}":      func() string { return args[0] },
			"{parent:last}": func() string { return args[len(args)-1] },
		} {
			if !strings.Contains(l, placeholder) {
				continue
			}
			parent := ""
			if len(args) > 0 {
				if d := path.Dir(strings.TrimRight(pick(), "/")); d != "." {
					parent = d
				}
			}
			l = strings.TrimSpace(strings.ReplaceAll(l, placeholder, shellArg(parent)))
		}
		return l
	}
	return ""
}

// shellArg quotes s for a command line printed in a hint (single quotes
// when it holds spaces or quotes; "" stays empty).
func shellArg(s string) string {
	if strings.ContainsAny(s, " \t'\"$`\\;&|<>()*?!#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// apiStatus is the HTTP status of an API error (0 when err is none). A
// server that answers a route it does not have with plain text gives the
// status only.
func apiStatus(err error) int {
	ce := core.AsError(err)
	switch {
	case ce == nil:
		return 0
	case ce.Status != 0:
		return ce.Status
	}
	return ce.HTTPStatus()
}

// wrapTreeErrors wraps the RunE of c and all its descendants with
// explainErrorFor, so every command reports helpful hints. finishTree
// applies it once to the whole tree.
func wrapTreeErrors(c *cobra.Command) *cobra.Command {
	if run := c.RunE; run != nil {
		c.RunE = func(cmd *cobra.Command, args []string) error { return explainErrorFor(cmd, run(cmd, args)) }
	}
	for _, s := range c.Commands() {
		wrapTreeErrors(s)
	}
	return c
}

// groupCmd returns a parent command whose RunE prints its help and rejects
// a word that is not one of its subcommands (with suggestions, exit 2).
func groupCmd(use, short, long, example string, aliases ...string) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Aliases: aliases,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return unknownCommandError(cmd, args[0])
			}
			return cmd.Help()
		},
	}
}

// done prints a success message (human) or v as JSON (--json). v nil prints
// {"ok":true}.
func done(cmd *cobra.Command, v any, format string, a ...any) error {
	if G.JSON {
		if v == nil {
			v = map[string]bool{"ok": true}
		}
		return PrintJSON(cmd.OutOrStdout(), v)
	}
	Successf(cmd, format, a...)
	return nil
}

// anyChanged reports whether any of the named flags was set on the command
// line (unlike FlagSet.NFlag, inherited global flags such as --server do not
// count).
func anyChanged(f interface{ Changed(string) bool }, names ...string) bool {
	for _, n := range names {
		if f.Changed(n) {
			return true
		}
	}
	return false
}

// confirmOrAbort asks question (default no) and returns an error when the
// user declines.
func confirmOrAbort(cmd *cobra.Command, question string) error {
	ok, err := Confirm(cmd, question, false)
	if errors.Is(err, io.EOF) {
		fmt.Fprintln(cmd.ErrOrStderr())
		return &ExitCodeError{Code: ExitFailure, Err: errors.New("aborted (no answer; pass -y to confirm)")}
	}
	if err != nil {
		return err
	}
	if !ok {
		return &ExitCodeError{Code: ExitFailure, Err: errors.New("aborted")}
	}
	return nil
}

// readStreamBody reads a small response body (e.g. a PEM) into memory.
func readStreamBody(resp *http.Response, max int64) ([]byte, error) {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("response larger than %s", HumanBytes(max))
	}
	return data, nil
}

// secretFlags reads a secret from --X-stdin, --X-file or an interactive
// prompt (twice when isNew). what names the secret in prompts ("password").
func secretFrom(cmd *cobra.Command, fromStdin bool, file, what string, isNew bool) (string, error) {
	switch {
	case fromStdin && file != "":
		return "", UsageError("use only one of --%s-stdin and --%s-file", what, what)
	case fromStdin:
		return ReadSecretStdin(cmd)
	case file != "":
		return ReadSecretFile(cmd, file)
	case isNew:
		return PromptNewSecret(cmd, "New "+what+": ")
	}
	s, err := PromptSecret(cmd, strings.ToUpper(what[:1])+what[1:]+": ")
	if err == nil && s == "" {
		err = fmt.Errorf("empty %s", what)
	}
	return s, err
}

// ---------- transport helpers ----------

// transferBackoff is the retry policy of upload and download requests
// (DESIGN §8.1: 1 s → 30 s, 6 tries); tests shorten it.
var transferBackoff = clikit.TransferBackoff

// isRetryable reports whether a transfer error is worth retrying: network
// failures, 429 and 5xx responses, except errors that will not go away by
// themselves (quota, locked keys, integrity failures, not implemented).
func isRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ee *ExitCodeError
	if errors.As(err, &ee) {
		return false
	}
	if ce := core.AsError(err); ce != nil {
		switch ce.Code {
		case core.ErrQuota.Code, core.ErrKeysLocked.Code, core.ErrCorrupt.Code, core.ErrNotImplemented.Code:
			return false
		}
		s := ce.HTTPStatus()
		return s == http.StatusTooManyRequests || s == http.StatusRequestTimeout || (s >= 500 && s != http.StatusNotImplemented)
	}
	var fatal *fatalError
	return !errors.As(err, &fatal)
}

// fatalError marks a local error that must not be retried (e.g. a local file
// that changed during an upload).
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

func fatalf(format string, a ...any) error { return &fatalError{fmt.Errorf(format, a...)} }

// inlineJobRunner is implemented by the jobs service (jobs.Service.RunInline):
// it runs a job synchronously in the calling goroutine, which is how the
// offline CLI executes jobs (no job runner is started in offline mode).
type inlineJobRunner interface {
	RunInline(ctx context.Context, kind string, params any, by *core.Principal) (*core.Job, error)
}

// runJobInline runs a job of kind in-process (offline mode only) and reports
// a failed or canceled job as an error, like waitJob. ok is false when the
// client is not offline or the jobs service cannot run jobs inline; the
// caller then uses the API.
func runJobInline(ctx context.Context, cmd *cobra.Command, c *Client, kind string, params any) (j *core.Job, ok bool, err error) {
	if c.Mode() != ModeOffline || c.Deps() == nil {
		return nil, false, nil
	}
	r, isRunner := c.Deps().Jobs.(inlineJobRunner)
	if !isRunner {
		return nil, false, nil
	}
	Infof(cmd, "The server is not running; running %s in-process…", kind)
	j, err = r.RunInline(ctx, kind, params, core.SystemPrincipal(core.ViaOffline))
	if err != nil {
		return nil, true, err
	}
	switch j.State {
	case core.JobFailed:
		return j, true, fmt.Errorf("job %s (%s) failed: %s", j.ID, j.Kind, dash(j.Error))
	case core.JobCanceled:
		return j, true, fmt.Errorf("job %s (%s) was canceled", j.ID, j.Kind)
	}
	return j, true, nil
}

// offlineJobWarning tells the user that a job enqueued in offline mode only
// runs once the server is started (the in-process mode never runs jobs).
func offlineJobWarning(cmd *cobra.Command, c *Client, jobID string) bool {
	if c.Mode() != ModeOffline {
		return false
	}
	Warnf(cmd, "the server is not running: job %s was queued and runs when the server starts (fileparcel service start)", jobID)
	return true
}

// requireServer fails in offline mode for operations that need background
// jobs or live services of a running server.
func requireServer(c *Client, what string) error {
	if c.Mode() == ModeOffline {
		return fmt.Errorf("%s needs the running server (background jobs do not run in offline mode); start it with \"fileparcel service start\"", what)
	}
	return nil
}

// fileExists reports whether path exists (any type).
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// jobResultBackupID extracts a backup id from a job result: a core.Backup,
// {"backup_id": …} or {"backup": {…}}.
func jobResultBackupID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var probe struct {
		ID       string       `json:"id"`
		BackupID string       `json:"backup_id"`
		Backup   *core.Backup `json:"backup"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return ""
	}
	switch {
	case probe.BackupID != "":
		return probe.BackupID
	case probe.Backup != nil && probe.Backup.ID != "":
		return probe.Backup.ID
	case ids.Valid(ids.PrefixBackup, probe.ID):
		return probe.ID
	}
	return ""
}

// jobRefFrom extracts {"job_id": …} from a generic JSON response.
func jobRefFrom(raw json.RawMessage) string {
	var ref core.JobRef
	if len(raw) == 0 || json.Unmarshal(raw, &ref) != nil {
		return ""
	}
	return ref.JobID
}
