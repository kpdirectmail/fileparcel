package docs_test

// The v4 contract sections of docs/DESIGN.md (§5.3 events, §6 migrations,
// §9.4 route guards, §9.6 audit actions) are what the feature packages, the
// web UI and the CLI code against. The names they list are derived from the
// code here, so a new audit action, event topic or migration cannot land
// without its line in the design document, and a route guard cannot name a
// permission that does not exist.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// designSection returns the text of the docs/DESIGN.md section whose heading
// line starts with prefix (e.g. "### 9.6 "), so the tests survive a reworded
// heading.
func designSection(t *testing.T, design, prefix string) string {
	t.Helper()
	fenced := false
	for _, l := range strings.Split(design, "\n") {
		if strings.HasPrefix(l, "```") {
			fenced = !fenced
			continue
		}
		if !fenced && strings.HasPrefix(l, prefix) {
			return section(t, design, l)
		}
	}
	t.Fatalf("docs/DESIGN.md has no heading starting with %q", prefix)
	return ""
}

// stringConsts parses the Go file rel and returns its string constants whose
// names start with prefix (name → value).
func stringConsts(t *testing.T, rel, prefix string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRoot(t), rel), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if !strings.HasPrefix(n.Name, prefix) || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: %s: %v", rel, n.Name, err)
				}
				out[n.Name] = v
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("found no %s* string constants in %s", prefix, rel)
	}
	return out
}

// TestV4AuditActionsDocumented: every audit action is in the list that opens
// DESIGN §9.6 — the seven v4 actions by name (a compile-time link to the
// constants), and every Act* constant of internal/core/audit.go as a sweep —
// and §9.6 states that details never contain passwords.
func TestV4AuditActionsDocumented(t *testing.T) {
	sec := designSection(t, read(t, "docs/DESIGN.md"), "### 9.6 ")
	list, _, _ := strings.Cut(strings.TrimSpace(sec), "\n\n")
	v4 := []string{
		core.ActRoleCreate, core.ActRoleUpdate, core.ActRoleDelete,
		core.ActGroupRoleSet, core.ActGroupRoleRemove,
		core.ActNetworkFunnel, core.ActNetworkServe,
	}
	for _, a := range v4 {
		mustContain(t, "docs/DESIGN.md §9.6 (list)", list, "`"+a+"`", "every v4 audit action is listed in DESIGN §9.6.")
	}
	all := stringConsts(t, "internal/core/audit.go", "Act")
	for _, name := range slices.Sorted(maps.Keys(all)) {
		mustContain(t, "docs/DESIGN.md §9.6 (list)", list, "`"+all[name]+"`",
			"core."+name+" is an audit action; the list of DESIGN §9.6 names every one.")
	}
	values := slices.Collect(maps.Values(all))
	for _, a := range v4 {
		if !slices.Contains(values, a) {
			t.Errorf("internal/core/audit.go was not parsed completely: %q is missing", a)
		}
	}
	mustContain(t, "docs/DESIGN.md §9.6", oneLine(sec), "Details never contain passwords",
		"the zip password (and every other password) must never reach the audit log.")
}

// TestV4EventTopicsDocumented: every topic of internal/events is listed in the
// events paragraph of DESIGN §5.3, the two v4 topics included.
func TestV4EventTopicsDocumented(t *testing.T) {
	sec := designSection(t, read(t, "docs/DESIGN.md"), "### 5.3 ")
	topics := stringConsts(t, "internal/events/events.go", "Topic")
	values := slices.Collect(maps.Values(topics))
	for _, v4 := range []string{events.TopicAuthzChanged, events.TopicIngressChanged} {
		if !slices.Contains(values, v4) {
			t.Errorf("internal/events/events.go was not parsed completely: %q is missing", v4)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(topics)) {
		v := topics[name]
		// Listed as `topic` or with its payload fields, `topic{a,b}`.
		if !strings.Contains(sec, "`"+v+"`") && !strings.Contains(sec, "`"+v+"{") {
			t.Errorf("docs/DESIGN.md §5.3 does not list the event topic %q (events.%s)", v, name)
		}
	}
}

// sqlStatements splits a migration into its statements with the comments
// removed and whitespace collapsed (a trigger body yields its parts).
func sqlStatements(sql string) []string {
	var b strings.Builder
	for _, l := range strings.Split(sql, "\n") {
		if i := strings.Index(l, "--"); i >= 0 {
			l = l[:i]
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	var out []string
	for _, st := range strings.Split(b.String(), ";") {
		if st = oneLine(st); st != "" {
			out = append(out, st)
		}
	}
	return out
}

// TestV4MigrationsDocumented: DESIGN §6 names every embedded migration in its
// "Migration numbering" paragraph and lists the SQL of every migration
// verbatim, except that the 0001 listing shows the search index (nodes_fts)
// as 0004 rebuilds it.
func TestV4MigrationsDocumented(t *testing.T) {
	sec := designSection(t, read(t, "docs/DESIGN.md"), "## 6. ")
	_, numbering, ok := strings.Cut(sec, "**Migration numbering.**")
	if !ok {
		t.Fatal(`docs/DESIGN.md §6 has no "Migration numbering" paragraph`)
	}
	numbering, _, _ = strings.Cut(numbering, "\n\n")
	listing := oneLine(strings.Join(sqlStatements(sec), ";"))

	dir := filepath.Join(repoRoot(t), "internal", "db", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		base, isSQL := strings.CutSuffix(e.Name(), ".sql")
		if e.IsDir() || !isSQL {
			continue
		}
		n++
		mustContain(t, `docs/DESIGN.md §6 "Migration numbering"`, numbering, "`"+base+"`",
			"the paragraph lists every migration by its file name.")
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range sqlStatements(string(body)) {
			if strings.HasPrefix(base, "0001_") && strings.Contains(st, "nodes_fts") {
				continue // superseded by 0004_fts_name_key, which the listing shows
			}
			if !strings.Contains(listing, st) {
				t.Errorf("docs/DESIGN.md §6 does not list this statement of %s:\n%s", e.Name(), st)
			}
		}
	}
	if n < 4 {
		t.Fatalf("found %d migrations in %s, want at least 4", n, dir)
	}
}

// capGuard matches the route-guard notation of DESIGN §9.4: Cap(users.view)
// or Cap(settings.manage|network.manage) (the notation's own "Cap(x|y)" has
// no dotted names and is not matched).
var capGuard = regexp.MustCompile(`\bCap\(([a-z_]+\.[a-z_]+(?:\|[a-z_]+\.[a-z_]+)*)\)`)

// TestV4RouteGuardsNamePermissions: every Cap(…) in docs/DESIGN.md names a
// permission of the catalog, and every server permission guards at least one
// route of §9.4 (a server permission opens an Admin-area surface by
// definition).
func TestV4RouteGuardsNamePermissions(t *testing.T) {
	design := read(t, "docs/DESIGN.md")
	for _, m := range capGuard.FindAllStringSubmatch(design, -1) {
		for _, name := range strings.Split(m[1], "|") {
			if !core.Capability(name).Valid() {
				t.Errorf("docs/DESIGN.md: %s names %q, which is not a permission of core.Capabilities", m[0], name)
			}
		}
	}
	guarded := map[core.Capability]bool{}
	for _, m := range capGuard.FindAllStringSubmatch(designSection(t, design, "### 9.4 "), -1) {
		for _, name := range strings.Split(m[1], "|") {
			guarded[core.Capability(name)] = true
		}
	}
	for _, c := range core.Capabilities {
		if c.Server && !guarded[c.Name] {
			t.Errorf("docs/DESIGN.md §9.4: no route is guarded by the server permission %s (Cap(%s))", c.Name, c.Name)
		}
	}
}
