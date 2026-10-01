package static

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	webassets "fileparcel/web"

	"fileparcel/internal/core"
)

// jsCode returns the lines of a JS module that are code: whole-line comments
// ("// …", JSDoc and other block comments that start a line) are dropped, so
// the prose of a doc comment ("can('…')") is not mistaken for a check.
func jsCode(src string) string {
	var b strings.Builder
	inBlock := false
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if inBlock {
			if strings.Contains(t, "*/") {
				inBlock = false
			}
			continue
		}
		if strings.HasPrefix(t, "/*") {
			inBlock = !strings.Contains(t[2:], "*/")
			continue
		}
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

var (
	// perm: 'x' and perm: ['x', 'y'] (routes), can('x'[, me]), canAny(['x', …]) and const X_PERMS = ['x', …].
	jsPermSingle = regexp.MustCompile(`\bperm:\s*['"]([^'"]*)['"]|\bcan\(\s*['"]([^'"]*)['"]`)
	jsPermList   = regexp.MustCompile(`\bperm:\s*\[([^\]]*)\]|\bcanAny\(\s*\[([^\]]*)\]|\b[A-Z][A-Z_]*_PERMS\s*=\s*\[([^\]]*)\]`)
	jsString     = regexp.MustCompile(`['"]([^'"]*)['"]`)
	// one PERMISSION_LABELS entry: 'name': 'Label' (or "Label" when it has an apostrophe)
	jsLabel = regexp.MustCompile(`(?m)^\s*'([a-z]+\.[a-z]+)':\s*(?:'([^']*)'|"([^"]*)"),?\s*$`)
	// one BUILTIN_ROLE_DESCRIPTIONS entry: role: 'Text' (or "Text")
	jsRoleText = regexp.MustCompile(`(?m)^\s*([a-z]+):\s*(?:'([^']*)'|"([^"]*)"),?\s*$`)
	// an audit action key of an ACTIONS table: 'area.verb':
	jsActionKey = regexp.MustCompile(`'([a-z_]+\.[a-z_]+)':`)
)

// readJS returns the source of static/js/<name>.
func readJS(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(webassets.FS, "static/js/"+name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// jsBlock returns the text of src between the first start marker and the
// first end marker after it.
func jsBlock(t *testing.T, src, file, start, end string) string {
	t.Helper()
	_, rest, ok := strings.Cut(src, start)
	if !ok {
		t.Fatalf("%s has no %q", file, start)
	}
	block, _, ok := strings.Cut(rest, end)
	if !ok {
		t.Fatalf("%s: no %q after %q", file, end, start)
	}
	return block
}

// TestJSPermissionNamesMatchCore pins the permission names of the web UI to
// the catalog in internal/core/roles.go (DESIGN §6a, §13.5): every permission
// a route, the navigation or a page checks is a core.Capabilities name — a
// typo would only hide a page or a button, silently — and core/perms.js labels
// all of them with the catalog labels, in catalog order, and lists exactly the
// server permissions.
func TestJSPermissionNamesMatchCore(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := fs.ReadFile(webassets.FS, "static/js/"+name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	known := map[string]core.CapabilityInfo{}
	var order, server []string
	for _, c := range core.Catalog().Items {
		known[string(c.Name)] = c
		order = append(order, string(c.Name))
		if c.Server {
			server = append(server, string(c.Name))
		}
	}

	t.Run("perms.js", func(t *testing.T) {
		js := read("core/perms.js")
		labels, rest, ok := strings.Cut(js, "export const SERVER_PERMISSIONS")
		if !ok {
			t.Fatal("core/perms.js has no SERVER_PERMISSIONS")
		}
		_, labels, ok = strings.Cut(labels, "export const PERMISSION_LABELS")
		if !ok {
			t.Fatal("core/perms.js has no PERMISSION_LABELS")
		}
		var names []string
		for _, m := range jsLabel.FindAllStringSubmatch(labels, -1) {
			names = append(names, m[1])
			label := m[2] + m[3]
			c, ok := known[m[1]]
			switch {
			case !ok:
				t.Errorf("PERMISSION_LABELS names %q, which is not a permission of core.Capabilities", m[1])
			case label != c.Label:
				t.Errorf("PERMISSION_LABELS[%q] = %q; the catalog label is %q", m[1], label, c.Label)
			}
		}
		if !slices.Equal(names, order) {
			t.Errorf("PERMISSION_LABELS keys = %q\nwant every catalog name in catalog order %q", names, order)
		}
		list, _, _ := strings.Cut(rest, "]);")
		var got []string
		for _, m := range jsString.FindAllStringSubmatch(list, -1) {
			got = append(got, m[1])
		}
		if !slices.Equal(got, server) {
			t.Errorf("SERVER_PERMISSIONS = %q\nwant the server permissions of the catalog, in order: %q", got, server)
		}
	})

	t.Run("checks", func(t *testing.T) {
		files := []string{"routes.js", "nav.js", "app.js"}
		err := fs.WalkDir(webassets.FS, "static/js", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel := strings.TrimPrefix(p, "static/js/")
			if !d.IsDir() && path.Ext(p) == ".js" && !slices.Contains(files, rel) {
				files = append(files, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		uses := map[string]int{} // file → permission names found
		check := func(file, name string) {
			uses[file]++
			if _, ok := known[name]; !ok {
				t.Errorf("%s checks the permission %q, which is not in core.Capabilities", file, name)
			}
		}
		for _, f := range files {
			code := jsCode(read(f))
			for _, m := range jsPermSingle.FindAllStringSubmatch(code, -1) {
				check(f, m[1]+m[2])
			}
			for _, m := range jsPermList.FindAllStringSubmatch(code, -1) {
				for _, s := range jsString.FindAllStringSubmatch(m[1]+m[2]+m[3], -1) {
					check(f, s[1])
				}
			}
		}
		// Not vacuous: the admin routes and the pages that gate controls are seen.
		if uses["routes.js"] < 12 {
			t.Errorf("found only %d permission checks in routes.js; the scan patterns no longer match the route table", uses["routes.js"])
		}
		for _, f := range []string{"nav.js", "app.js", "pages/admin/role.js", "pages/admin/dashboard.js"} {
			if uses[f] == 0 {
				t.Errorf("found no permission check in %s; the scan patterns no longer match its code", f)
			}
		}
	})
}

func TestJSCode(t *testing.T) {
	src := strings.Join([]string{
		"/**",
		" * can('…') in a doc comment",
		" */",
		"// can('x') in a line comment",
		"/* one-line block */ ",
		"const a = can('users.view'); /* trailing */",
		"  /* multi",
		"   can('y') */",
		"const b = 1;",
	}, "\n")
	got := jsCode(src)
	want := "const a = can('users.view'); /* trailing */\nconst b = 1;\n"
	if got != want {
		t.Fatalf("jsCode:\n%q\nwant\n%q", got, want)
	}
}

// TestJSRoleTextsMatchCore pins the role facts the web UI keeps for the
// cases without the roles API: core/perms.js MEMBER_PERMISSIONS (what a
// member holds when the /me payload carries no role, core.MemberCaps) and the
// built-in role descriptions of pages/admin/common.js, which role pickers show
// when GET /admin/roles cannot be read (core.BuiltinRoles).
func TestJSRoleTextsMatchCore(t *testing.T) {
	t.Run("MEMBER_PERMISSIONS", func(t *testing.T) {
		list := jsBlock(t, readJS(t, "core/perms.js"), "core/perms.js", "export const MEMBER_PERMISSIONS", "]);")
		var got []string
		for _, m := range jsString.FindAllStringSubmatch(list, -1) {
			got = append(got, m[1])
		}
		if want := core.MemberCaps.Names(); !slices.Equal(got, want) {
			t.Errorf("MEMBER_PERMISSIONS = %q; core.MemberCaps is %q", got, want)
		}
	})
	t.Run("BUILTIN_ROLE_DESCRIPTIONS", func(t *testing.T) {
		block := jsBlock(t, readJS(t, "pages/admin/common.js"), "pages/admin/common.js", "export const BUILTIN_ROLE_DESCRIPTIONS", "});")
		got := map[string]string{}
		for _, m := range jsRoleText.FindAllStringSubmatch(block, -1) {
			got[m[1]] = m[2] + m[3]
		}
		roles := core.BuiltinRoles(false)
		if len(got) != len(roles) {
			t.Errorf("BUILTIN_ROLE_DESCRIPTIONS has %d entries %q; want one per built-in role (%d)", len(got), got, len(roles))
		}
		for _, r := range roles {
			if got[r.ID] != r.Description {
				t.Errorf("BUILTIN_ROLE_DESCRIPTIONS[%q] = %q\nwant core.BuiltinRoles' %q", r.ID, got[r.ID], r.Description)
			}
		}
	})
}

// TestJSAuditActionsLabelled: every audit action of internal/core/audit.go
// has a readable label in the admin pages (pages/admin/common.js ACTIONS:
// audit log, dashboard), and the actions v4 added also in the personal
// Activity page (components/activity.js), so no entry shows a raw
// "role.update".
func TestJSAuditActionsLabelled(t *testing.T) {
	keys := func(file, start, end string) map[string]bool {
		out := map[string]bool{}
		for _, m := range jsActionKey.FindAllStringSubmatch(jsBlock(t, readJS(t, file), file, start, end), -1) {
			out[m[1]] = true
		}
		return out
	}
	admin := keys("pages/admin/common.js", "const ACTIONS =", "});")
	activity := keys("components/activity.js", "const ACTIONS =", "});")

	f, err := parser.ParseFile(token.NewFileSet(), "../../core/audit.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Act") || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					actions = append(actions, v)
				}
			}
		}
	}
	// Not vacuous: the parse sees the v1 actions and the v4 ones.
	for _, a := range []string{core.ActAuthLogin, core.ActRoleCreate, core.ActNetworkFunnel} {
		if !slices.Contains(actions, a) {
			t.Fatalf("parsed %d actions from internal/core/audit.go, not %q; the parser no longer matches the file", len(actions), a)
		}
	}
	for _, a := range actions {
		if !admin[a] {
			t.Errorf("pages/admin/common.js ACTIONS has no label for the audit action %q", a)
		}
	}
	for _, a := range []string{
		core.ActRoleCreate, core.ActRoleUpdate, core.ActRoleDelete, core.ActGroupRoleSet, core.ActGroupRoleRemove,
		core.ActNetworkFunnel, core.ActNetworkServe,
	} {
		if !activity[a] {
			t.Errorf("components/activity.js ACTIONS has no entry for the v4 audit action %q", a)
		}
	}
}
