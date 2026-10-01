package cli

// Regression tests of the v4 QA pass on the command line: each test names
// the defect it pins down.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/svc"
	"fileparcel/internal/svc/installer"
)

// --zip-generate-password makes a password as long as the server's
// storage.zip_password_min (up to 64) asks for: the refused batch is not
// created, so the command asks once more with a longer one and prints that.
func TestZipGeneratedPasswordMeetsServerMinimum(t *testing.T) {
	for _, n := range []int{0, 8, 22, 23, 30, 64} {
		pw := generateZipPassword(n)
		if want := max(n, 22); len(pw) != want || strings.Trim(pw, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != "" {
			t.Errorf("generateZipPassword(%d) = %q (want %d base62 characters)", n, pw, want)
		}
	}

	f := newFakeAPI(t)
	src := zipSource(t)
	f.zipMin = 30
	before := f.requested("POST /api/v1/upload-batches")
	res := f.run(t, "", "files", "put", src, "/My files", "--zip", "long.zip", "--zip-generate-password")
	in, _ := batchInput(t, f)
	pw := in.ZipPassword.Reveal()
	if res.code != 0 || len(pw) != 30 || !strings.HasPrefix(res.stdout, "Zip password: "+pw+"\n") || strings.Count(res.stdout, pw) != 1 {
		t.Fatalf("storage.zip_password_min 30: %+v (password %q)", res, pw)
	}
	if n := f.requested("POST /api/v1/upload-batches") - before; n != 2 {
		t.Errorf("%d batch creations, want 2 (refused, then accepted)", n)
	}
	onlyBatchCarries(t, f, pw)

	f.zipMin = 64
	res = f.run(t, "", "--json", "files", "put", src, "/My files", "--zip", "longest.zip", "--zip-generate-password")
	var gen struct {
		ZipPassword string `json:"zip_password"`
	}
	if in, _ = batchInput(t, f); res.code != 0 || json.Unmarshal([]byte(res.stdout), &gen) != nil || len(gen.ZipPassword) != 64 ||
		gen.ZipPassword != in.ZipPassword.Reveal() {
		t.Fatalf("storage.zip_password_min 64 --json: %+v", res)
	}

	// A password the user chose is never replaced.
	f.zipMin = 30
	res = f.run(t, "typed-password-12\n", "files", "put", src, "/My files", "--zip", "typed.zip", "--zip-password-stdin")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "zip password rejected by the server: the password must be at least 30") {
		t.Fatalf("a typed short password: %+v", res)
	}
}

// "network vpn role IFACE auto" removes an entry typed with spaces around
// "=", which the server reads as the same interface.
func TestVPNRoleAutoTrimsEntryNames(t *testing.T) {
	f := newFakeAPI(t)
	addIngressRoutes(f)
	store := addSettingsRoutes(f, core.SettingView{Key: "network.iface_roles", Section: "network", Type: "strings",
		Value: json.RawMessage(`["wg0 = egress"," eth1=local"]`), Default: json.RawMessage(`[]`), IsSet: true})
	res := f.run(t, "", "network", "vpn", "role", "wg0", "auto")
	if res.code != 0 || stored(store, "network.iface_roles") != `[" eth1=local"]` {
		t.Fatalf("role wg0 auto: %+v %s", res, stored(store, "network.iface_roles"))
	}
	res = f.run(t, "", "network", "vpn", "role", "eth1", "mesh")
	if res.code != 0 || stored(store, "network.iface_roles") != `["wg0 = egress","eth1=mesh"]` {
		t.Fatalf("role eth1 mesh: %+v %s", res, stored(store, "network.iface_roles"))
	}
}

// fakeFunnel is addIngressRoutes with a PUT that stores allow_admin and
// require_2fa like the server, which keeps them while Funnel is off or in
// shares mode.
func fakeFunnel(t *testing.T) (*fakeAPI, *fakeIngress, func() core.FunnelInput) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	fi.st.Require2FA = true
	fi.put = func(in core.FunnelInput) error {
		if in.AllowAdmin != nil {
			fi.st.AllowAdmin = *in.AllowAdmin
		}
		if in.Require2FA != nil {
			fi.st.Require2FA = *in.Require2FA
		}
		return nil
	}
	body := func() core.FunnelInput {
		var in core.FunnelInput
		_ = json.Unmarshal(f.body("PUT /api/v1/admin/network/funnel"), &in)
		return in
	}
	return f, fi, body
}

// --allow-admin=false and --require-2fa=false send false like the --no-
// flags (they were dropped: admin pages stayed reachable over Funnel while
// the command said it worked).
func TestFunnelFlagsFalseValues(t *testing.T) {
	f, fi, body := fakeFunnel(t)
	if res := f.run(t, "", "-y", "network", "funnel", "enable", "--mode", "app", "--require-2fa", "--allow-admin"); res.code != 0 ||
		!fi.st.AllowAdmin {
		t.Fatalf("enable --allow-admin: %+v", res)
	}
	res := f.run(t, "", "-y", "network", "funnel", "enable", "--allow-admin=false")
	if in := body(); res.code != 0 || in.AllowAdmin == nil || *in.AllowAdmin || fi.st.AllowAdmin {
		t.Fatalf("--allow-admin=false: %+v %+v", res, in)
	}
	// --no-allow-admin=false opens them again, after the question.
	res = f.run(t, "y\n", "network", "funnel", "enable", "--no-allow-admin=false")
	if in := body(); res.code != 0 || in.AllowAdmin == nil || !*in.AllowAdmin || !fi.st.AllowAdmin ||
		!strings.Contains(res.stderr, "Admin pages will be reachable over Funnel. Continue?") {
		t.Fatalf("--no-allow-admin=false: %+v %+v", res, in)
	}
	if res := f.run(t, "", "-y", "network", "funnel", "enable", "--no-allow-admin"); res.code != 0 || fi.st.AllowAdmin {
		t.Fatalf("--no-allow-admin: %+v", res)
	}
	// --require-2fa=false lifts the requirement after the same question.
	res = f.run(t, "n\n", "network", "funnel", "enable", "--require-2fa=false")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "Accounts without two-factor sign-in will be able to sign in over Funnel. Continue?") {
		t.Fatalf("--require-2fa=false asks: %+v", res)
	}
	res = f.run(t, "y\n", "network", "funnel", "enable", "--require-2fa=false")
	if in := body(); res.code != 0 || in.Require2FA == nil || *in.Require2FA || in.Confirm != "public" ||
		!strings.Contains(res.stderr, "anyone who guesses a password can sign in over Funnel") {
		t.Fatalf("--require-2fa=false: %+v %+v", res, in)
	}
	if v := onOff(newFunnelEnableCmd().Flags(), "allow-admin"); v != nil {
		t.Errorf("no flag given: %v", *v)
	}
}

// Switching back to app mode asks about (and warns of) the admin pages and
// the sign-in without two-factor that the stored settings bring back.
func TestFunnelAppModeAsksAboutStoredSettings(t *testing.T) {
	f, fi, body := fakeFunnel(t)
	if res := f.run(t, "", "-y", "network", "funnel", "enable", "--mode", "app", "--require-2fa", "--allow-admin"); res.code != 0 {
		t.Fatalf("app mode: %+v", res)
	}
	if res := f.run(t, "", "-y", "network", "funnel", "enable", "--mode", "shares", "--port", "10000"); res.code != 0 ||
		fi.st.Funnel.Mode != core.FunnelShares || !fi.st.AllowAdmin {
		t.Fatalf("shares mode: %+v %+v", res, fi.st)
	}
	res := f.run(t, "y\nn\n", "network", "funnel", "enable", "--mode", "app")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "sign-in page will be reachable from the whole internet") ||
		!strings.Contains(res.stderr, "Admin pages will be reachable over Funnel. Continue?") || fi.st.Funnel.Mode != core.FunnelShares {
		t.Fatalf("shares → app with admin pages stored: %+v", res)
	}
	res = f.run(t, "y\ny\n", "network", "funnel", "enable", "--mode", "app")
	if in := body(); res.code != 0 || in.Confirm != "public" || !strings.Contains(res.stderr, "admin pages are reachable from the internet") {
		t.Fatalf("confirmed: %+v %+v", res, in)
	}
	// Already in app mode with admin pages open: nothing new to ask.
	if res := f.run(t, "", "network", "funnel", "enable", "--port", "8443"); res.code != 0 || strings.Contains(res.stderr, "Admin pages") {
		t.Errorf("port change in app mode: %+v", res)
	}
	// The same for a stored "no two-factor".
	fi.st.AllowAdmin, fi.st.Require2FA, fi.st.Funnel.Mode = false, false, core.FunnelOff
	res = f.run(t, "y\nn\n", "network", "funnel", "enable", "--mode", "app")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "Accounts without two-factor sign-in will be able to sign in over Funnel") {
		t.Errorf("off → app with 2FA not required: %+v", res)
	}
}

// The --port help of Funnel and Serve says what omitting it does: the
// current port stays (443 the first time); nothing claims "(default 443)".
func TestIngressPortHelp(t *testing.T) {
	for _, cmd := range []string{"network funnel enable", "network tailscale-serve enable"} {
		fl := findCommand(NewRootCmd(), cmd).Flags().Lookup("port")
		if fl == nil || fl.DefValue != "0" || !strings.Contains(fl.Usage, "default: the current port, 443 the first time") {
			t.Errorf("%s --port: %+v", cmd, fl)
		}
	}
	f, fi, body := fakeFunnel(t)
	fi.st.Funnel.Port = 8443
	if res := f.run(t, "", "-y", "network", "funnel", "enable"); res.code != 0 || body().Port != 0 || fi.st.Funnel.Port != 8443 {
		t.Errorf("enable without --port: %+v %+v", res, body())
	}
}

// --delegable=false clears delegable (it was "nothing to change").
func TestRoleDelegableFalse(t *testing.T) {
	f := newFakeAPI(t)
	st := addRoleRoutes(f)
	if res := f.run(t, "", "role", "edit", "Helpdesk", "--delegable"); res.code != 0 || !st.find("rol_01k5z8r3m9d4q7w2x6c1v0b5na").Delegable {
		t.Fatalf("--delegable: %+v", res)
	}
	res := f.run(t, "", "role", "edit", "Helpdesk", "--delegable=false")
	if res.code != 0 || st.find("rol_01k5z8r3m9d4q7w2x6c1v0b5na").Delegable {
		t.Fatalf("--delegable=false: %+v", res)
	}
	res = f.run(t, "", "role", "edit", "Helpdesk", "--no-delegable=false")
	if res.code != 0 || !st.find("rol_01k5z8r3m9d4q7w2x6c1v0b5na").Delegable {
		t.Fatalf("--no-delegable=false: %+v", res)
	}
	var in core.RoleDefInput
	res = f.run(t, "", "role", "create", "auditors", "--delegable=false")
	if _ = json.Unmarshal(f.body("POST /api/v1/admin/roles"), &in); res.code != 0 || in.Delegable {
		t.Fatalf("create --delegable=false: %+v %+v", res, in)
	}
}

// A value typed into a -stdin switch is a secret too: never echoed, in
// text or in --json.
func TestStdinSwitchValueNotEchoed(t *testing.T) {
	for _, args := range [][]string{
		{"user", "create", "dave2", "--password-stdin=Hunter2Secret"},
		{"--json", "user", "create", "dave2", "--password-stdin=Hunter2Secret"},
		{"files", "put", "a.txt", "/My files", "--zip", "q.zip", "--zip-password-stdin=Hunter2Secret"},
		{"backup", "restore", "x.fpbak", "--passphrase-stdin=Hunter2Secret"},
		{"--passphrase-stdin=Hunter2Secret", "status"},
		{"cert", "acme", "enable", "--credentials-stdin=Hunter2Secret"},
	} {
		res := runArgs(t, "", args...)
		if res.code != ExitUsage || strings.Contains(res.stdout+res.stderr, "Hunter2Secret") || !strings.Contains(res.stderr, "takes no value") {
			t.Errorf("%v: %+v", args, res)
		}
	}
	// Other switches still show what was typed (it helps, and is no secret).
	if res := runArgs(t, "", "files", "ls", "--long=maybe"); res.code != ExitUsage || !strings.Contains(res.stderr, `(got "maybe")`) {
		t.Errorf("--long=maybe: %+v", res)
	}
	// The old argument order of share create is refused on purpose (§12.4).
	if res := runArgs(t, "", "share", "create", "--password", "/My files/a.txt"); res.code != ExitUsage ||
		!strings.Contains(res.stderr, "--password takes no value") || strings.Contains(res.stderr, "a.txt") {
		t.Errorf("share create --password PATH: %+v", res)
	}
}

// "/Team" and "/" list the team folders shared with the user as a whole
// (the ones "/Team/<group>" resolves through a grant), and completion
// offers them.
func TestTeamListingIncludesSharedTeamFolders(t *testing.T) {
	f := newFakeAPI(t)
	// A guest: no personal space, no groups.
	f.me.SpaceID, f.me.Groups, f.me.GroupSpaceIDs = "", nil, nil
	f.spaces = nil
	spaceID := ids.New(ids.PrefixSpace)
	root := &fakeNode{Node: core.Node{ID: ids.New(ids.PrefixNode), SpaceID: spaceID, Kind: core.KindFolder, Name: "Finance",
		Perm: core.PermView}}
	personal := &fakeNode{Node: core.Node{ID: ids.New(ids.PrefixNode), SpaceID: ids.New(ids.PrefixSpace), Kind: core.KindFolder,
		Name: myFilesName, Perm: core.PermView}}
	f.mu.Lock()
	f.nodes[root.ID], f.nodes[personal.ID] = root, personal
	f.mu.Unlock()
	f.handle(http.MethodGet, "/api/v1/shared-with-me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, core.Page[core.Node]{Items: []core.Node{root.Node, personal.Node}})
	})
	res := f.run(t, "", "files", "ls", "/Team")
	if res.code != 0 || !strings.Contains(res.stdout, "Finance/") || !strings.Contains(res.stdout, "shared with you") ||
		strings.Contains(res.stdout, myFilesName) || strings.Contains(res.stderr, "join a group") {
		t.Fatalf("files ls /Team: %+v", res)
	}
	res = f.run(t, "", "--json", "files", "ls", "/Team")
	var out []virtualEntry
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &out) != nil || len(out) != 1 || !out[0].Shared || out[0].RootID != root.ID {
		t.Fatalf("files ls /Team --json: %+v", res)
	}
	if res := f.run(t, "", "files", "ls", "/"); res.code != 0 || !strings.Contains(res.stdout, "Team/") {
		t.Fatalf("files ls /: %+v", res)
	}
	if got := strings.Join(completeFor(t, f, "files", "ls", "/Team/"), " "); !strings.Contains(got, "/Team/Finance/") {
		t.Errorf("completion of /Team/: %q", got)
	}
}

// completeFor runs the shell completion of the last word of args against f.
func completeFor(t *testing.T, f *fakeAPI, args ...string) []string {
	t.Helper()
	res := f.run(t, "", append([]string{"__complete"}, args...)...)
	var out []string
	for _, l := range strings.Split(res.stdout, "\n") {
		if l != "" && !strings.HasPrefix(l, ":") {
			out = append(out, strings.SplitN(l, "\t", 2)[0])
		}
	}
	return out
}

// whoami --json always has "groups" for an account ([] without groups), and
// a token that cannot be listed says why instead of leaving the lines out.
func TestWhoamiGroupsAndTokenError(t *testing.T) {
	f := newFakeAPI(t)
	me := f.me
	me.Groups = nil
	f.handle("GET", "/api/v1/me", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, me) })
	res := f.run(t, "", "--json", "whoami")
	var raw map[string]json.RawMessage
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &raw) != nil || string(raw["groups"]) != "[]" {
		t.Fatalf("whoami --json: %+v", res)
	}
	// The system view has no account and no "groups".
	addUserRoutes(f)
	res = f.runSocket(t, f.socketHome(t), "", "--json", "whoami")
	var sys map[string]json.RawMessage
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &sys) != nil || sys["groups"] != nil || string(sys["system"]) != "true" {
		t.Fatalf("socket whoami --json: %+v", res)
	}

	// A refused token list is an error, and whoami shows its message.
	f.handle("GET", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, &core.Error{Code: core.ErrEnrollRequired.Code, Status: core.ErrEnrollRequired.Status,
			Message: "two-factor authentication must be set up first"})
	})
	c, err := connectRemote(Options{Server: f.srv.URL, Token: fakeToken})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id := ids.New(ids.PrefixToken)
	if tok, err := currentToken(t.Context(), c, "fpt_"+strings.TrimPrefix(id, "tok_")+"_secret"); tok != nil ||
		core.AsError(err) == nil || core.AsError(err).Message != "two-factor authentication must be set up first" {
		t.Fatalf("currentToken: %+v %v", tok, err)
	}
	v := whoamiView{Via: core.ViaToken, Server: f.srv.URL, User: me.User, TokenError: "two-factor authentication must be set up first"}
	var b strings.Builder
	if err := renderWhoami(&b, &v); err != nil || !strings.Contains(b.String(), "Token:") ||
		!strings.Contains(b.String(), "not shown (two-factor authentication must be set up first)") {
		t.Fatalf("render: %v\n%s", err, b.String())
	}
	out, _ := json.Marshal(v)
	if !strings.Contains(string(out), `"token_error":"two-factor authentication must be set up first"`) || !strings.Contains(string(out), `"groups":[]`) {
		t.Errorf("JSON: %s", out)
	}
}

// The 403 hint of --as suggests "access check" only for commands on a
// file or folder; the --as help says it applies to every command.
func TestAsForbiddenHint(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("GET", "/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.Errorf(core.ErrForbidden, "this needs the “View people” permission"))
	})
	dir := f.socketHome(t)
	res := f.runSocket(t, dir, "", "--as", "bob", "user", "list")
	if res.code != ExitFailure || strings.Contains(res.stderr, "access check") || !strings.Contains(res.stderr, `"fileparcel --as bob whoami"`) {
		t.Fatalf("user list as bob: %+v", res)
	}
	f.handle("GET", "/api/v1/nodes/{id}/children", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.Errorf(core.ErrForbidden, "no access"))
	})
	res = f.runSocket(t, dir, "", "--as", "bob", "files", "ls", "/Team/Design")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `"fileparcel access check bob <path>"`) {
		t.Fatalf("files ls as bob: %+v", res)
	}
	if u := NewRootCmd().PersistentFlags().Lookup("as").Usage; strings.Contains(u, "for files/share commands") {
		t.Errorf("--as usage: %q", u)
	}
}

// Missing paths of access commands point at something that exists: the
// groups for a team folder, else what the nearest existing folder holds;
// the admin socket is not called user "system". role remove-group of a role
// that is not in the group points at "role show".
func TestAccessAndRoleNotFoundHints(t *testing.T) {
	f := newFakeAPI(t)
	addGrantRoutes(f, nil)
	f.addFolder(f.teamRoot(), "Briefs")
	dir := f.socketHome(t)
	res := f.runSocket(t, dir, "", "access", "list", "/Team/Nope")
	if res.code != ExitFailure || strings.Contains(res.stderr, `"system"`) || !strings.Contains(res.stderr, `no team folder "Nope" (available: Design)`) ||
		!strings.Contains(res.stderr, `"fileparcel group list"`) || strings.Contains(res.stderr, "files ls") {
		t.Fatalf("access list /Team/Nope: %+v", res)
	}
	res = f.runSocket(t, dir, "", "access", "check", "bob", "/Team/Design/Nope/x")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `hint: /Team/Design holds "Briefs/"`) {
		t.Fatalf("access check deeper: %+v", res)
	}

	g := newFakeAPI(t)
	addRoleRoutes(g)
	gid := ids.New(ids.PrefixGroup)
	g.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{{ID: gid, Name: "Marketing"}}})
	})
	g.handle("DELETE", "/api/v1/admin/roles/{id}/groups/{gid}", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.NotFoundf("the role is not a member of this group"))
	})
	res = g.run(t, "", "role", "remove-group", "Helpdesk", "Marketing")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `see the groups of the role with "fileparcel role show Helpdesk"`) ||
		strings.Contains(res.stderr, "role list") {
		t.Fatalf("role remove-group: %+v", res)
	}
}

// group remove-member says when the user stays a member through a role.
func TestGroupRemoveMemberKeptThroughRole(t *testing.T) {
	f := newFakeAPI(t)
	gid, bob, carol := ids.New(ids.PrefixGroup), ids.New(ids.PrefixUser), ids.New(ids.PrefixUser)
	users := map[string]string{"bob": bob, "carol": carol}
	f.handle("GET", "/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		out := []core.User{}
		if id := users[r.URL.Query().Get("q")]; id != "" {
			out = append(out, core.User{ID: id, Username: r.URL.Query().Get("q")})
		}
		writeJSON(w, 200, core.Page[core.User]{Items: out})
	})
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{{ID: gid, Name: "Design"}}})
	})
	f.handle("DELETE", "/api/v1/admin/groups/{id}/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	f.handle("GET", "/api/v1/admin/groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.GroupMember]{Items: []core.GroupMember{{GroupID: chi.URLParam(r, "id"), UserID: bob,
			Username: "bob", Role: core.GroupRoleMember, ViaRoles: []core.RoleRef{{ID: "rol_x", Name: "contractors"}}}}})
	})
	res := f.run(t, "", "group", "remove-member", "Design", "bob", "carol")
	if res.code != 0 || !strings.Contains(res.stdout, `removed "bob"'s own membership of "Design"`) ||
		!strings.Contains(res.stderr, `"bob" is still a member of "Design" through the role "contractors"`) ||
		!strings.Contains(res.stderr, `"fileparcel role remove-group ROLE Design"`) || !strings.Contains(res.stdout, `removed "carol" from "Design"`) ||
		strings.Contains(res.stderr, "carol") {
		t.Fatalf("remove-member: %+v", res)
	}
	if n := f.requested("GET /api/v1/admin/groups/" + gid + "/members"); n != 1 {
		t.Errorf("members listed %d times, want once", n)
	}
}

// Env-overridden settings: one message without the key twice, no --force
// hint and no "stored value" warning; the managed hint sends Serve keys to
// tailscale-serve.
func TestConfigSetEnvOverride(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []core.SettingView{{Key: "log.level", Section: "log", Type: "enum", Value: json.RawMessage(`"debug"`),
			Default: json.RawMessage(`"info"`), OverriddenByEnv: "FILEPARCEL_LOG_LEVEL", Bootstrap: true}})
	})
	f.handle("PATCH", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, &core.Error{Code: core.ErrConflict.Code, Status: 409, Field: "log.level",
			Message: "log.level is set by the environment variable FILEPARCEL_LOG_LEVEL; change it there"})
	})
	for _, args := range [][]string{{"config", "set", "log.level", "warn"}, {"config", "set", "log.level", "warn", "--force"}} {
		res := f.run(t, "", args...)
		if res.code != ExitFailure || strings.Contains(res.stderr, "log.level: log.level") || strings.Contains(res.stderr, "--force if") ||
			strings.Contains(res.stderr, "stored value") || !strings.Contains(res.stderr, "FILEPARCEL_LOG_LEVEL") ||
			!strings.Contains(res.stderr, "--force does not help") {
			t.Errorf("%v: %+v", args, res)
		}
	}
}

// put onto an existing file with --conflict replace adds a version to it
// (it was refused with advice to use --conflict replace); without
// --conflict the refusal says which flag to add.
func TestPutOntoExistingFileWithConflict(t *testing.T) {
	f := newFakeAPI(t)
	f.addFile(f.myRoot(), "notes.md", []byte("v0"))
	src := filepath.Join(t.TempDir(), "v1.md")
	if err := os.WriteFile(src, []byte("version one"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := f.run(t, "", "files", "put", src, "/My files/notes.md")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "add --conflict replace to upload v1.md as a new version of it") {
		t.Fatalf("no --conflict: %+v", res)
	}
	res = f.run(t, "", "files", "put", src, "/My files/notes.md", "--conflict", "replace")
	in, _ := decodeBatch(t, f)
	if res.code != 0 || in.Conflict != core.ConflictReplace || len(in.Files) != 1 || in.Files[0].RelPath != "notes.md" ||
		in.FolderID != f.myRoot() || !strings.Contains(res.stdout, "as /My files/notes.md") {
		t.Fatalf("--conflict replace: %+v %+v", res, in)
	}
	// A folder source onto a file is still not possible.
	if res := f.run(t, "", "files", "put", t.TempDir(), "/My files/notes.md", "--conflict", "replace"); res.code != ExitUsage ||
		!strings.Contains(res.stderr, "is not a folder") {
		t.Errorf("folder onto a file: %+v", res)
	}
}

// decodeBatch decodes the last batch creation.
func decodeBatch(t *testing.T, f *fakeAPI) (core.BatchInput, string) {
	t.Helper()
	return batchInput(t, f)
}

// A missing team folder in put: team folders come from groups (mkdir and
// -p cannot make one).
func TestPutMissingTeamFolderHint(t *testing.T) {
	f := newFakeAPI(t)
	src := filepath.Join(t.TempDir(), "small")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := f.run(t, "", "files", "put", src, "/Team/x")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `team folders come from groups; list yours with "fileparcel files ls /Team"`) ||
		strings.Contains(res.stderr, "mkdir") {
		t.Fatalf("put into /Team/x: %+v", res)
	}
}

// The disk-space refusal (ErrQuota) gets its own hint, not "raise the quota".
func TestDiskSpaceHint(t *testing.T) {
	err := explainError(core.Errorf(core.ErrQuota, "not enough free disk space: this upload needs 381.5 MiB of disk space and "+
		"the server always keeps 1.0 GiB free"))
	if msg := err.Error(); !strings.Contains(msg, "the server's disk is nearly full") || strings.Contains(msg, "set-quota") {
		t.Errorf("disk: %s", msg)
	}
	if msg := explainError(core.Errorf(core.ErrQuota, "quota exceeded")).Error(); !strings.Contains(msg, "set-quota") {
		t.Errorf("quota: %s", msg)
	}
}

// System files inside folders are left out like in the web UI (and
// counted); a file named on the command line is uploaded anyway.
func TestScanLocalSkipsJunk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "junk")
	writeTree(t, dir, map[string]int{".DS_Store": 1, "Thumbs.db": 1, "sub/keep.txt": 3, "only/desktop.ini": 1})
	var warned []string
	entries, err := scanLocal([]string{dir}, "", func(format string, a ...any) { warned = append(warned, format) })
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, e := range entries {
		rels = append(rels, e.Rel+":"+e.Kind)
	}
	got := strings.Join(rels, " ")
	if strings.Contains(got, "DS_Store") || strings.Contains(got, "Thumbs") || strings.Contains(got, "desktop.ini") ||
		!strings.Contains(got, "junk/sub/keep.txt:file") || !strings.Contains(got, "junk/only:dir") || len(warned) != 1 {
		t.Errorf("entries %s, warnings %v", got, warned)
	}
	if entries, err := scanLocal([]string{filepath.Join(dir, ".DS_Store")}, "", func(string, ...any) {}); err != nil || len(entries) != 1 {
		t.Errorf("a system file named on the command line: %v %v", entries, err)
	}
}

// A closed file request shows as "closed", as request close and the web UI
// say.
func TestRequestStatusClosed(t *testing.T) {
	req := &core.Share{Kind: core.ShareRequest, Status: core.ShareDisabled}
	link := &core.Share{Kind: core.ShareLink, Status: core.ShareDisabled}
	if shareStatusText(req) != "closed" || shareStatusText(link) != core.ShareDisabled {
		t.Errorf("request %q, link %q", shareStatusText(req), shareStatusText(link))
	}
}

// config edit -y with a file that stays invalid stops at once (it re-ran
// the editor for ever) and leaves no copy behind.
func TestConfigEditYesInvalidStops(t *testing.T) {
	h := lcBareHome(t)
	ed := filepath.Join(t.TempDir(), "ed.sh")
	if err := os.WriteFile(ed, []byte("#!/bin/sh\necho 'this is [not toml' >> \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", ed)
	done := make(chan lcResult, 1)
	go func() { done <- lcRun(t, "", "--home", h.Dir(), "-y", "config", "edit") }()
	select {
	case res := <-done:
		if res.code != ExitFailure || !strings.Contains(res.err, "changes discarded") {
			t.Fatalf("config edit -y: %+v", res)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("config edit -y did not stop")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(h.Config()), ".fileparcel.toml.edit-*"))
	if len(left) != 0 {
		t.Errorf("copies left behind: %v", left)
	}
}

// cert acme enable waits for the first certificate: a refusal of the CA
// fails the command (it printed ✓), a certificate succeeds, --no-wait and
// a slow CA leave it to the background.
func TestCertACMEEnableWaits(t *testing.T) {
	oldPoll, oldTimeout := acmePoll, acmeWaitTimeout
	acmePoll, acmeWaitTimeout = 10*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { acmePoll, acmeWaitTimeout = oldPoll, oldTimeout })
	f := newFakeAPI(t)
	addSettingsRoutes(f)
	f.handle("POST", "/api/v1/admin/certs/acme/apply", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	var status core.CertStatus
	polls := 0
	f.handle("GET", "/api/v1/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		polls++
		st := status
		if polls < 3 {
			st.ACMEError = "" // the request is still running
		}
		writeJSON(w, 200, st)
	})
	enable := []string{"cert", "acme", "enable", "--email", "a@example.com", "--domain", "files.example.com", "--credentials-stdin"}
	creds := `{"api_token":"x"}`

	status = core.CertStatus{ACMEEnabled: true, ACMEError: "files.example.com: dial tcp 127.0.0.1:1: connection refused"}
	res := f.run(t, creds, enable...)
	if res.code != ExitFailure || !strings.Contains(res.stderr, "the certificate request failed: files.example.com: dial tcp") ||
		strings.Contains(res.stdout, "✓") {
		t.Fatalf("CA refused: %+v", res)
	}
	polls, status = 0, core.CertStatus{ACMEEnabled: true, ACME: []core.CertInfo{{DNSNames: []string{"FILES.example.com"}}}}
	if res := f.run(t, creds, enable...); res.code != 0 || !strings.Contains(res.stdout, "certificate issued") {
		t.Fatalf("issued: %+v", res)
	}
	polls, status = 0, core.CertStatus{ACMEEnabled: true}
	if res := f.run(t, creds, enable...); res.code != 0 || !strings.Contains(res.stderr, "no certificate yet") {
		t.Fatalf("slow CA: %+v", res)
	}
	before := f.requested("GET /api/v1/admin/certs")
	if res := f.run(t, creds, append(enable, "--no-wait")...); res.code != 0 || !strings.Contains(res.stdout, "in the background") ||
		f.requested("GET /api/v1/admin/certs") != before {
		t.Fatalf("--no-wait: %+v", res)
	}
}

// backup restore: an unknown bak_ id is not a path, a damaged archive is
// not "stored data", and the start hint follows the service registration.
func TestRestoreMessages(t *testing.T) {
	h := lcBareHome(t)
	res := lcRun(t, "", "--home", h.Dir(), "backup", "restore", "bak_nonexistent", "--dry-run")
	if res.code != ExitFailure || !strings.Contains(res.err, "no backup with id bak_nonexistent") ||
		!strings.Contains(res.err, `"fileparcel backup list"`) || strings.Contains(res.err, "stat ") {
		t.Fatalf("unknown id: %+v", res)
	}
	if startCommand(h) != "fileparcel serve" {
		t.Errorf("no service: %q", startCommand(h))
	}
	err := archiveError(core.Errorf(core.ErrCorrupt, "not a FileParcel backup"))
	if msg := explainError(err).Error(); strings.Contains(msg, "doctor") || !strings.Contains(msg, "not a FileParcel backup") ||
		!strings.Contains(msg, "the archive itself is at fault") {
		t.Errorf("damaged archive: %s", msg)
	}
}

// jobs run backup.verify without the backup is a usage error naming the
// parameter; a job's result, not its last progress label, ends the line.
func TestJobsRunMessages(t *testing.T) {
	res := runArgs(t, "", "jobs", "run", "backup.verify")
	if res.code != ExitUsage || !strings.Contains(res.stderr, `--params '{"id":"bak_…"}'`) || !strings.Contains(res.stderr, "backup list") {
		t.Fatalf("backup.verify without id: %+v", res)
	}
	j := &core.Job{Note: "archive tickets", Result: json.RawMessage(`{"sessions":3,"tickets":0,"items":[1],"skipped":""}`)}
	if got := jobResultSuffix(j); got != ": sessions 3, tickets 0" {
		t.Errorf("result suffix %q", got)
	}
	if got := jobResultSuffix(&core.Job{Note: "done"}); got != ": done" {
		t.Errorf("note fallback %q", got)
	}
}

// Bare backup groups show their state like "maintenance"; the recipients
// are labelled.
func TestBackupBareGroupsShow(t *testing.T) {
	f := newFakeAPI(t)
	cfg := core.BackupConfig{Enabled: true, Encryption: core.BackupX25519, Recipients: []string{"age1abc", "age1def"}, HasIdentity: true,
		ScheduleMeta: "0 3 * * *", ScheduleFull: "0 4 * * 0"}
	f.handle("GET", "/api/v1/admin/backups/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, cfg) })
	for cmd, want := range map[string]string{"schedule": "Metadata backups:", "config": "Encryption", "identity": "Recipients:                age1abc"} {
		res := f.run(t, "", "backup", cmd)
		if res.code != 0 || !strings.Contains(res.stdout, want) || strings.Contains(res.stdout, "Available Commands") {
			t.Errorf("backup %s: %+v", cmd, res)
		}
	}
	// The second recipient is a continuation row under the first.
	if res := f.run(t, "", "backup", "identity"); !strings.Contains(res.stdout, "\n"+strings.Repeat(" ", 27)+"age1def\n") {
		t.Errorf("second recipient: %q", res.stdout)
	}
}

// install on an existing installation names the fresh-install flags it
// ignores and refuses a different --service.
func TestInstallExistingWarnsAboutIgnoredFlags(t *testing.T) {
	h := lcBareHome(t)
	in := lcNewInstaller(NewRootCmd(), false)
	cmd := newInstallCmd()
	if err := cmd.ParseFlags([]string{"--dir", h.Dir(), "--port", "19999", "--admin", "bob", "--sealed"}); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.SetErr(&stderr)
	if err := checkUpgradeFlags(cmd, in, installer.InstallOptions{Dir: h.Dir()}, false); err != nil {
		t.Fatal(err)
	}
	if s := stderr.String(); !strings.Contains(s, "already contains an installation") || !strings.Contains(s, "--port, --admin and --sealed") {
		t.Errorf("warning: %q", s)
	}
	// A fresh directory: nothing to say.
	stderr.Reset()
	if err := checkUpgradeFlags(cmd, in, installer.InstallOptions{Dir: filepath.Join(t.TempDir(), "new")}, false); err != nil || stderr.Len() != 0 {
		t.Errorf("fresh: %v %q", err, stderr.String())
	}
	// Another service kind than the installation's is refused.
	if err := svc.WriteInstalled(h, &svc.Installed{Kind: svc.KindNone, Home: h.Dir()}); err != nil {
		t.Fatal(err)
	}
	cmd = newInstallCmd()
	if err := cmd.ParseFlags([]string{"--dir", h.Dir(), "--service", "user"}); err != nil {
		t.Fatal(err)
	}
	err := checkUpgradeFlags(cmd, in, installer.InstallOptions{Dir: h.Dir(), Service: "user"}, false)
	if !isUsage(err) || !strings.Contains(err.Error(), "--service user would not apply") ||
		!strings.Contains(err.Error(), `"fileparcel service install --user"`) {
		t.Errorf("--service user on a home without a service: %v", err)
	}
	// The same kind is fine.
	if err := checkUpgradeFlags(cmd, in, installer.InstallOptions{Dir: h.Dir(), Service: "none"}, false); err != nil {
		t.Errorf("--service none: %v", err)
	}
}
