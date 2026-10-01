package docs_test

// Roles and permissions (rbac-final §18, DESIGN §6a, §13.2, §13.5): the manual's chapter, the web app's route guards
// and the design document must say what internal/core, web/static/js and the services do. Package B (web UI and
// the manual's chapter) owns this file.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// rolesChapter is the "Roles and permissions" chapter of the manual (all its subsections).
func rolesChapter(t *testing.T) string {
	t.Helper()
	return section(t, manualProse(t), "### Roles and permissions")
}

// tableRows returns the cells of the markdown table rows in text whose first cell matches first (a regexp), with
// every cell trimmed and its whitespace collapsed.
func tableRows(text, first string) [][]string {
	var rows [][]string
	re := regexp.MustCompile(`^\| ` + first + ` \|`)
	for _, line := range strings.Split(text, "\n") {
		if !re.MatchString(line) {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), " | ")
		for i, c := range cells {
			cells[i] = oneLine(c)
		}
		rows = append(rows, cells)
	}
	return rows
}

// TestPermissionTableDocumented: the permission table of the manual has one row per core.Capabilities entry, in
// catalog order, with the label the web app shows, the description, the permissions it comes with and — for the
// high-impact ones — the warning, all verbatim from the catalog (the texts GET /admin/capabilities serves).
func TestPermissionTableDocumented(t *testing.T) {
	table := section(t, rolesChapter(t), "#### Permissions")
	rows := tableRows(table, "`[a-z]+\\.[a-z]+`")
	var got, want []string
	byName := map[string][]string{}
	for _, r := range rows {
		if len(r) != 4 {
			t.Errorf("permission table row %q: want 4 cells (permission, label, allows, opens), got %d", r[0], len(r))
			continue
		}
		name := strings.Trim(r[0], "`")
		got = append(got, name)
		byName[name] = r
	}
	for _, c := range core.Capabilities {
		want = append(want, string(c.Name))
		r, ok := byName[string(c.Name)]
		if !ok {
			continue
		}
		if r[1] != c.Label {
			t.Errorf("%s: the manual labels it %q; the web app shows %q", c.Name, r[1], c.Label)
		}
		allows := r[2]
		if !strings.HasPrefix(allows, oneLine(c.Description)) {
			t.Errorf("%s: the \"Allows\" cell does not start with the catalog description %q\n(got %q)", c.Name, c.Description, allows)
		}
		for _, imp := range c.Implies {
			if want := "Comes with *" + imp.Label() + "*."; !strings.Contains(allows, want) {
				t.Errorf("%s implies %s: the row does not say %q", c.Name, imp, want)
			}
		}
		if n := strings.Count(allows, "Comes with"); n != len(c.Implies) {
			t.Errorf("%s implies %v, but the row says \"Comes with\" %d times", c.Name, c.Implies, n)
		}
		warn := "**High impact:** " + oneLine(c.Warning)
		switch {
		case c.HighImpact && !strings.Contains(allows, warn):
			t.Errorf("%s is high impact: the row must end its \"Allows\" cell with %q", c.Name, warn)
		case !c.HighImpact && strings.Contains(allows, "High impact"):
			t.Errorf("%s is not high impact, but the row says so", c.Name)
		}
		if r[3] == "" {
			t.Errorf("%s: the \"Opens\" cell is empty", c.Name)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("the permission table lists %q;\ncore.Capabilities (catalog order) is %q", got, want)
	}

	// The groups the chapter names are the web app's (core.CapabilityGroups), and the first one is exactly the four
	// permissions the chapter calls "the first four" and Member's.
	for _, g := range core.CapabilityGroups {
		mustContain(t, "docs/FILEPARCEL.md (#### Permissions)", oneLine(table), "*"+g.Label+"*", "the chapter names every permission group")
	}
	var sharing core.CapSet
	for _, c := range core.Capabilities {
		if c.Group == core.CapabilityGroups[0].ID {
			sharing = sharing.With(c.Name)
		}
		if c.Server != (c.Group != core.CapabilityGroups[0].ID) {
			t.Errorf("%s: the chapter says the %q group holds exactly the permissions that are not server permissions", c.Name, core.CapabilityGroups[0].Label)
		}
	}
	if sharing != core.MemberCaps || len(sharing.List()) != 4 {
		t.Errorf("the chapter says Member has \"the four %s permissions\"; core.MemberCaps is %v, the group holds %v",
			core.CapabilityGroups[0].Label, core.MemberCaps.Names(), sharing.Names())
	}
}

// TestBuiltinRolesDocumented: the built-in roles table lists core.BuiltinRoles in order with their permissions as
// the chapter words them, and the chapter mentions the "classes" synonym the owner used.
func TestBuiltinRolesDocumented(t *testing.T) {
	chapter := rolesChapter(t)
	rows := tableRows(section(t, chapter, "#### Built-in roles"), `\*\*[A-Z][a-z]+\*\*`)
	var names []string
	for _, r := range rows {
		names = append(names, strings.Trim(r[0], "*"))
	}
	var want []string
	perms := map[string]string{}
	for _, r := range core.BuiltinRoles(false) {
		want = append(want, r.Name)
		switch {
		case r.Base.IsAdmin():
			perms[r.Name] = "every permission, plus what only administrators can do"
		case r.Permissions == core.MemberCaps:
			perms[r.Name] = "the four *" + core.CapabilityGroups[0].Label + "* permissions"
		case r.Permissions == 0:
			perms[r.Name] = "none"
		default:
			t.Fatalf("built-in role %s has permissions %v, which the chapter's wording does not cover", r.ID, r.Permissions.Names())
		}
	}
	if !slices.Equal(names, want) {
		t.Fatalf("the built-in roles table lists %q; core.BuiltinRoles is %q", names, want)
	}
	for _, r := range rows {
		name := strings.Trim(r[0], "*")
		if len(r) < 3 || r[1] != perms[name] {
			t.Errorf("built-in roles table, %s: the permissions cell should read %q (got %q)", name, perms[name], r[1:])
		}
	}
	// Guests share only while the setting allows it (core.BuiltinCaps).
	share := core.NewCapSet(core.CapShareLinks, core.CapShareRequests)
	if core.BuiltinCaps(core.RoleGuest, true) != share {
		t.Errorf("core.BuiltinCaps(guest, allow_guests_share) = %v; the Guest row says links and file requests", core.BuiltinCaps(core.RoleGuest, true).Names())
	}
	mustContain(t, "docs/FILEPARCEL.md (roles)", oneLine(chapter), "(also called *classes*)",
		"the owner calls roles \"classes\"; the chapter names the synonym once")
}

// TestRoleExamplesUseRealPermissions: every permission a `fileparcel role create|edit … --add/--remove/--set` example
// of the manual names exists, and every `access grant … --level` is a level the CLI accepts.
func TestRoleExamplesUseRealPermissions(t *testing.T) {
	prose := manualProse(t)
	flags := regexp.MustCompile(`--(?:add|remove|set)[ =]([a-z.,]+)`)
	n := 0
	for _, cmd := range regexp.MustCompile(`fileparcel (?:role|class|classes) (?:create|edit) [^\n`+"`"+`]*`).FindAllString(prose, -1) {
		for _, m := range flags.FindAllStringSubmatch(cmd, -1) {
			for _, name := range strings.Split(m[1], ",") {
				n++
				if !core.Capability(name).Valid() {
					t.Errorf("docs/FILEPARCEL.md: %q names the permission %q, which core.Capabilities does not have", cmd, name)
				}
			}
		}
	}
	if n == 0 {
		t.Error("docs/FILEPARCEL.md has no \"fileparcel role create … --add\" example (the roles chapter shows one)")
	}
	for _, m := range regexp.MustCompile(`fileparcel access grant [^\n`+"`"+`]*--level ([a-z]+)`).FindAllStringSubmatch(prose, -1) {
		if !slices.Contains([]string{"view", "edit", "manage"}, m[1]) {
			t.Errorf("docs/FILEPARCEL.md: %q uses the level %q (view, edit or manage)", m[0], m[1])
		}
	}
}

// uiQuotes are texts the manual quotes from the web app (file, text) and from the roles backend. The backend ones
// are checked only when the roles backend is in the tree (package A's internal/core/escalation.go): before that
// the manual already describes it.
var uiQuotes = []struct {
	file, text string
	backend    bool
}{
	{"web/static/js/routes.js", "Your role does not include this page", false},
	{"web/static/js/app.js", "Your access was changed by an administrator.", false},
	{"web/static/js/pages/admin/dashboard.js", "Your admin areas", false},
	{"web/static/js/pages/admin/invites.js", "Link hidden: only administrators can see it", false},
	{"web/static/js/pages/admin/user.js", "Nothing on the server — a regular account.", false},
	{"web/static/js/pages/admin/role.js", "Account managers can give this role and manage its accounts", false},
	{"web/static/js/pages/admin/role.js", "Give folder access", false},
	{"web/static/js/pages/admin/role.js", "Add to a group", false},
	{"web/static/js/pages/admin/group.js", "Roles in this group", false},
	{"web/static/js/pages/settings/profile.js", "What can I do?", false},
	{"web/static/js/components/share-dialog.js", "Role · everyone with this role", false},
	{"web/static/js/components/share-dialog.js", "Add people, groups or roles", false},
	{"internal/web/mw/guards.go", "this needs the “%s” permission", false},
	{"internal/core/escalation.go", "administrators have not allowed account managers to give the role “%s”", true},
	{"internal/core/escalation.go", "you can only give roles whose server permissions you have yourself (missing: %s)", true},
	{"internal/core/escalation.go", "this account has server permissions you do not have (%s)", true},
	{"internal/core/escalation.go", "accounts with the role “%s” can only be managed by an administrator", true},
	{"internal/core/escalation.go", "ask an administrator to change this on your own account", true},
	{"internal/users/roles.go", "1 account has this role: choose a role to move it to", true},
	{"internal/users/roles.go", "personal files (%s): move or delete them first, or reassign to a member-based role", true},
	{"internal/users/groups.go", "“%s” is a member through the role “%s”; remove the role from the group or change their role", true},
	{"internal/users/invites.go", "invitations for roles with server permissions can be used once", true},
	{"internal/users/invites.go", "invitations for roles with server permissions expire within 7 days", true},
}

// TestRolesManualQuotesTheApp: the texts the roles chapter and the people sections quote are what the web app and
// the server say. %s in a code text stands for a name the manual fills in with an example.
func TestRolesManualQuotesTheApp(t *testing.T) {
	prose := oneLine(manualProse(t))
	root := repoRoot(t)
	_, err := os.Stat(filepath.Join(root, "internal", "core", "escalation.go"))
	backend := err == nil
	for _, q := range uiQuotes {
		if q.backend && !backend {
			t.Logf("roles backend not in this tree: not checking %q", q.text)
			continue
		}
		if code := read(t, q.file); !strings.Contains(code, q.text) {
			t.Errorf("%s no longer says %q; update the manual's quote of it and this list", q.file, q.text)
		}
		parts := strings.Split(q.text, "%s")
		pattern := make([]string, len(parts))
		for i, p := range parts {
			pattern[i] = regexp.QuoteMeta(p)
		}
		if !regexp.MustCompile(strings.Join(pattern, `[^"]{1,40}?`)).MatchString(prose) {
			t.Errorf("docs/FILEPARCEL.md does not quote %q (from %s)", q.text, q.file)
		}
	}
	// The permission in the example message is a real label.
	mustContain(t, "docs/FILEPARCEL.md", prose, "this needs the “"+core.CapAuditView.Label()+"” permission",
		"the troubleshooting example quotes mw.RequireCap with the label of audit.view")
}

// TestRouteGuardsDocumented: the guard table of DESIGN §13.2 gives every admin route of the web app
// (web/static/js/routes.js) the guard routes.js gives it, and lists no other route.
func TestRouteGuardsDocumented(t *testing.T) {
	js := read(t, "web/static/js/routes.js")
	settings := regexp.MustCompile(`const SETTINGS_PERMS = \[([^\]]*)\]`).FindStringSubmatch(js)
	if settings == nil {
		t.Fatal("could not find SETTINGS_PERMS in web/static/js/routes.js")
	}
	guards := map[string]string{} // route → the guard as DESIGN writes it
	for _, m := range regexp.MustCompile(`\{ path: '(/admin[^']*)', nav: '[^']*', (admin: true|staff: true|perm: '[a-z.]+'|perm: SETTINGS_PERMS),`).FindAllStringSubmatch(js, -1) {
		g := m[2]
		if g == "perm: SETTINGS_PERMS" {
			g = "perm: [" + strings.Join(strings.Fields(settings[1]), " ") + "]"
		}
		guards[m[1]] = "`" + g + "`"
	}
	if len(guards) < 15 || guards["/admin/roles"] == "" {
		t.Fatalf("could not parse the admin routes of web/static/js/routes.js (%d: %v)", len(guards), guards)
	}
	table := section(t, read(t, "docs/DESIGN.md"), "### 13.2 Route map")
	documented := map[string]string{}
	for _, r := range tableRows(table, "`(?:admin: true|staff: true|perm: [^`]+)`[^|]*") {
		if len(r) != 2 {
			t.Errorf("DESIGN §13.2 guard table: row %q has %d cells, want 2", r[0], len(r))
			continue
		}
		guard := regexp.MustCompile("^`[^`]+`").FindString(r[0])
		for _, p := range regexp.MustCompile("`(/admin[^`]*)`").FindAllStringSubmatch(r[1], -1) {
			if prev, dup := documented[p[1]]; dup {
				t.Errorf("DESIGN §13.2 lists %s twice (%s and %s)", p[1], prev, guard)
			}
			documented[p[1]] = guard
		}
	}
	for route, want := range guards {
		switch got, ok := documented[route]; {
		case !ok:
			t.Errorf("DESIGN §13.2's guard table does not list %s (routes.js: %s)", route, want)
		case got != want:
			t.Errorf("DESIGN §13.2 guards %s with %s; routes.js with %s", route, got, want)
		}
	}
	for route := range documented {
		if _, ok := guards[route]; !ok {
			t.Errorf("DESIGN §13.2's guard table lists %s, which is not an admin route of routes.js", route)
		}
	}
}
