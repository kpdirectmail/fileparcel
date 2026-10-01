package wire

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/auth"
	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/settings"
	"fileparcel/internal/web"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/settingsapi"
)

// routeGuard is the guard an /api/v1/admin/* route is mounted with (DESIGN
// §6a, §9.4): mw.RequireCap(caps...) — any of them opens the route; owners
// and admins hold every permission — or, with caps nil, mw.RequireAdmin (the
// administrators-only surfaces); elevated adds mw.RequireElevated.
type routeGuard struct {
	caps     []core.Capability
	elevated bool
}

func capG(caps ...core.Capability) routeGuard { return routeGuard{caps: caps} }
func capE(caps ...core.Capability) routeGuard { return routeGuard{caps: caps, elevated: true} }

var (
	adm  = routeGuard{}
	admE = routeGuard{elevated: true}
)

// routeCaps declares the guard of every /api/v1/admin/* route. A route the
// router mounts must be listed (TestEveryAdminRouteDeclared), and
// TestAdminRouteGuards proves each one is mounted with exactly this guard.
var routeCaps = map[string]routeGuard{
	// usersapi
	"GET /api/v1/admin/users":                           capG(core.CapUsersView),
	"POST /api/v1/admin/users":                          capG(core.CapUsersManage),
	"GET /api/v1/admin/users/{id}":                      capG(core.CapUsersView),
	"PATCH /api/v1/admin/users/{id}":                    capG(core.CapUsersManage),
	"DELETE /api/v1/admin/users/{id}":                   capE(core.CapUsersManage),
	"POST /api/v1/admin/users/{id}/password":            capE(core.CapUsersCredentials),
	"POST /api/v1/admin/users/{id}/unlock":              capG(core.CapUsersManage),
	"POST /api/v1/admin/users/{id}/reset-mfa":           capE(core.CapUsersCredentials),
	"POST /api/v1/admin/users/{id}/disable":             capG(core.CapUsersManage),
	"POST /api/v1/admin/users/{id}/enable":              capG(core.CapUsersManage),
	"GET /api/v1/admin/users/{id}/sessions":             capG(core.CapUsersCredentials),
	"DELETE /api/v1/admin/users/{id}/sessions":          capG(core.CapUsersCredentials),
	"GET /api/v1/admin/users/{id}/access":               capG(core.CapUsersView),
	"GET /api/v1/admin/invites":                         capG(core.CapInvitesManage),
	"POST /api/v1/admin/invites":                        capG(core.CapInvitesManage),
	"DELETE /api/v1/admin/invites/{id}":                 capG(core.CapInvitesManage),
	"GET /api/v1/admin/groups":                          capG(core.CapUsersView),
	"POST /api/v1/admin/groups":                         capG(core.CapGroupsManage),
	"GET /api/v1/admin/groups/{id}":                     capG(core.CapUsersView),
	"PATCH /api/v1/admin/groups/{id}":                   capG(core.CapGroupsManage),
	"DELETE /api/v1/admin/groups/{id}":                  capG(core.CapGroupsManage),
	"GET /api/v1/admin/groups/{id}/members":             capG(core.CapUsersView),
	"PUT /api/v1/admin/groups/{id}/members/{userId}":    capG(core.CapGroupsManage),
	"DELETE /api/v1/admin/groups/{id}/members/{userId}": capG(core.CapGroupsManage),
	"GET /api/v1/admin/roles":                           capG(core.CapUsersView),
	"POST /api/v1/admin/roles":                          admE,
	"GET /api/v1/admin/roles/{id}":                      capG(core.CapUsersView),
	"PATCH /api/v1/admin/roles/{id}":                    admE,
	"DELETE /api/v1/admin/roles/{id}":                   admE,
	"GET /api/v1/admin/roles/{id}/groups":               capG(core.CapUsersView),
	"PUT /api/v1/admin/roles/{id}/groups/{groupId}":     capG(core.CapGroupsManage),
	"DELETE /api/v1/admin/roles/{id}/groups/{groupId}":  capG(core.CapGroupsManage),
	"GET /api/v1/admin/capabilities":                    capG(core.CapUsersView),

	// filesapi
	"GET /api/v1/admin/grants": capG(core.CapUsersView),

	// sharesapi
	"GET /api/v1/admin/shares": capG(core.CapSharesManage),

	// securityapi
	"GET /api/v1/admin/certs":                  capG(core.CapCertsManage),
	"POST /api/v1/admin/certs/renew":           capG(core.CapCertsManage),
	"POST /api/v1/admin/certs/ca/regenerate":   capE(core.CapCertsManage),
	"PUT /api/v1/admin/certs/custom":           admE,
	"DELETE /api/v1/admin/certs/custom":        admE,
	"POST /api/v1/admin/certs/acme/apply":      capE(core.CapCertsManage),
	"POST /api/v1/admin/certs/tailscale/fetch": capG(core.CapCertsManage),
	"GET /api/v1/admin/client-certs":           capG(core.CapCertsManage),
	"POST /api/v1/admin/client-certs":          capE(core.CapCertsManage),
	"GET /api/v1/admin/client-certs/download":  capG(core.CapCertsManage),
	"DELETE /api/v1/admin/client-certs/{id}":   capG(core.CapCertsManage),
	"GET /api/v1/admin/keys":                   adm,
	"POST /api/v1/admin/keys/lock":             admE,
	"POST /api/v1/admin/keys/seal":             admE,
	"POST /api/v1/admin/keys/unseal":           admE,
	"POST /api/v1/admin/keys/passphrase":       admE,
	"POST /api/v1/admin/keys/rotate":           admE,
	"POST /api/v1/admin/keys/recovery":         admE,

	// settingsapi (the keys a caller may change are checked one by one)
	"GET /api/v1/admin/settings": capG(core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage,
		core.CapSystemManage),
	"PATCH /api/v1/admin/settings": capG(core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage,
		core.CapSystemManage),
	"DELETE /api/v1/admin/settings/{key}": capG(core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage,
		core.CapSystemManage),
	"POST /api/v1/admin/settings/email/test":       adm,
	"GET /api/v1/admin/network":                    capG(core.CapNetworkManage),
	"PUT /api/v1/admin/network/policy":             capE(core.CapNetworkManage),
	"GET /api/v1/admin/mdns":                       capG(core.CapNetworkManage),
	"POST /api/v1/admin/mdns/republish":            capG(core.CapNetworkManage),
	"GET /api/v1/admin/network/tailscale":          capG(core.CapNetworkManage),
	"PUT /api/v1/admin/network/funnel":             capE(core.CapNetworkManage),
	"PUT /api/v1/admin/network/serve":              capE(core.CapNetworkManage),
	"POST /api/v1/admin/network/tailscale/reapply": capE(core.CapNetworkManage),

	// opsapi (job run/cancel also need the permission of the job's kind)
	"GET /api/v1/admin/backups":                  capG(core.CapBackupsRun),
	"POST /api/v1/admin/backups":                 capG(core.CapBackupsRun),
	"GET /api/v1/admin/backups/config":           capG(core.CapBackupsRun),
	"GET /api/v1/admin/backups/{id}":             capG(core.CapBackupsRun),
	"POST /api/v1/admin/backups/{id}/verify":     capG(core.CapBackupsRun),
	"DELETE /api/v1/admin/backups/{id}":          admE,
	"GET /api/v1/admin/backups/{id}/download":    admE,
	"POST /api/v1/admin/backups/{id}/restore":    admE,
	"PUT /api/v1/admin/backups/config":           admE,
	"POST /api/v1/admin/backups/identity":        admE,
	"POST /api/v1/admin/backups/identity/export": admE,
	"POST /api/v1/admin/backups/import":          admE,
	"GET /api/v1/admin/jobs":                     capG(core.CapSystemView),
	"GET /api/v1/admin/jobs/{id}":                capG(core.CapSystemView),
	"GET /api/v1/admin/jobs/kinds":               capG(core.CapSystemView),
	"GET /api/v1/admin/jobs/schedules":           capG(core.CapSystemView),
	"POST /api/v1/admin/jobs/run":                capG(core.CapSystemManage, core.CapBackupsRun),
	"POST /api/v1/admin/jobs/{id}/cancel":        capG(core.CapSystemManage, core.CapBackupsRun),
	"GET /api/v1/admin/system":                   capG(core.CapSystemView),
	"POST /api/v1/admin/system/restart":          capE(core.CapSystemManage),
	"GET /api/v1/admin/system/doctor":            capG(core.CapSystemView),
	"GET /api/v1/admin/system/logs":              capG(core.CapAuditView),
	"GET /api/v1/admin/dashboard":                capG(core.CapSystemView),
	"GET /api/v1/admin/audit":                    capG(core.CapAuditView),
	"GET /api/v1/admin/audit/verify":             capG(core.CapAuditView),
	"GET /api/v1/admin/audit/export":             capG(core.CapAuditView),
}

// Every mounted /api/v1/admin/* route declares its guard in routeCaps, and
// every declaration names a mounted route (so that a typo in routeCaps
// cannot hide a route).
func TestEveryAdminRouteDeclared(t *testing.T) {
	mounted := mountedRoutes(t, buildForAudit(t))
	for _, r := range mounted {
		_, path, _ := strings.Cut(r, " ")
		if !strings.HasPrefix(path, "/api/v1/admin/") {
			continue
		}
		if _, ok := routeCaps[r]; !ok {
			t.Errorf("admin route without a declared guard (add it to routeCaps): %s", r)
		}
	}
	for r, g := range routeCaps {
		if _, path, _ := strings.Cut(r, " "); !strings.HasPrefix(path, "/api/v1/admin/") {
			t.Errorf("routeCaps lists a route outside /api/v1/admin/: %s", r)
		}
		if !slices.Contains(mounted, r) {
			t.Errorf("routeCaps declares a route that is not mounted: %s", r)
		}
		for _, c := range g.caps {
			if !c.Valid() || !c.Server() {
				t.Errorf("%s: %q is not a server permission", r, c)
			}
		}
	}
}

// ---------- the guard harness ----------

// guardEnv is a wired deployment (wire.Build on a temp home) with real
// accounts, sessions and API tokens: the built-in roles, and a "probe"
// account whose custom role gets whatever permissions a check needs (a role
// edit applies to the next request of an existing session or token).
type guardEnv struct {
	t     *testing.T
	d     *app.Deps
	probe string // the probe account's custom role id
	creds map[string]cred
	calls int
}

// cred authenticates a request: a session cookie (with its CSRF token) or a
// bearer token.
type cred struct{ cookie, csrf, bearer string }

const guardPassword = "correct horse battery staple"

func newGuardEnv(t *testing.T) *guardEnv {
	t.Helper()
	defer authtest.FastHashing()()
	ctx := context.Background()
	d, cleanup, err := Build(ctx, newTestHome(t), app.ModeNetwork)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	if _, err := d.Keys.Init(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
	sys := core.SystemPrincipal(core.ViaOffline)
	// Sessions of owners, admins and staff roles would otherwise have to
	// enrol a second factor first (mw answers mfa_enroll_required); and one
	// access-log line per request would bury a failure.
	if _, err := d.Settings.Set(ctx, sys, map[string]json.RawMessage{"auth.require_2fa": json.RawMessage(`"off"`),
		"log.level": json.RawMessage(`"warn"`)}); err != nil {
		t.Fatal(err)
	}
	g := &guardEnv{t: t, d: d, creds: map[string]cred{}}
	g.probe = g.addRole("Probe", core.RoleMember, core.AllCaps)
	users := map[string]core.Role{"olive": core.RoleOwner, "adam": core.RoleAdmin, "mel": core.RoleMember,
		"gus": core.RoleGuest, "pat": core.RoleMember}
	userIDs := map[string]string{}
	for i, name := range []string{"olive", "adam", "mel", "gus", "pat"} {
		userIDs[name] = g.addUser(name, users[name])
		if name == "pat" {
			g.setRole(userIDs[name], g.probe)
		}
		meta := core.ReqMeta{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), UserAgent: "routecaps-test"}
		for _, elevated := range []bool{true, false} {
			res, err := d.Auth.Login(ctx, core.LoginInput{Username: name, Password: guardPassword}, meta)
			if err != nil {
				t.Fatalf("login %s: %v", name, err)
			}
			key := name
			p := g.principal(cred{cookie: res.Token})
			if elevated {
				if err := d.Auth.Elevate(ctx, p, core.ElevateInput{Password: guardPassword}); err != nil {
					t.Fatalf("elevate %s: %v", name, err)
				}
			} else {
				key += " (not elevated)"
			}
			g.creds[key] = cred{cookie: res.Token, csrf: d.Auth.CSRFToken(p)}
		}
	}
	exp := time.Now().Add(24 * time.Hour)
	for key, in := range map[string]core.TokenInput{
		"adam admin token": {Scopes: []string{core.ScopeAdmin}, Elevated: true, ExpiresAt: &exp, UserID: userIDs["adam"]},
		"adam files token": {Scopes: []string{core.ScopeFilesRead, core.ScopeShares}, UserID: userIDs["adam"]},
		"pat admin token":  {Scopes: []string{core.ScopeAdmin}, Elevated: true, ExpiresAt: &exp, UserID: userIDs["pat"]},
		"pat files token":  {Scopes: []string{core.ScopeFilesRead, core.ScopeShares}, UserID: userIDs["pat"]},
	} {
		in.Name = key
		_, secret, err := d.Auth.CreateToken(ctx, sys, in)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		g.creds[key] = cred{bearer: secret}
	}
	return g
}

// addRole stores a custom role straight into the roles table and returns
// its id: the guard checks rewrite the probe role's permissions hundreds of
// times, which through the roles API would mean as many audit entries and
// events.
func (g *guardEnv) addRole(name string, base core.Role, perms core.CapSet) string {
	g.t.Helper()
	id := ids.New(ids.PrefixRole)
	now := db.Ms(time.Now())
	if _, err := g.d.DB.Exec(context.Background(), `INSERT INTO roles (id, name, base, permissions, created_at,
		updated_at) VALUES (?, ?, ?, ?, ?, ?)`, id, name, string(base), core.EncodeCaps(perms), now, now); err != nil {
		g.t.Fatalf("add role %s: %v", name, err)
	}
	return id
}

// setPerms replaces the permissions of the custom role id.
func (g *guardEnv) setPerms(id string, perms core.CapSet) {
	g.t.Helper()
	if _, err := g.d.DB.Exec(context.Background(), `UPDATE roles SET permissions = ? WHERE id = ?`,
		core.EncodeCaps(perms), id); err != nil {
		g.t.Fatal(err)
	}
}

// addUser creates an account with guardPassword.
func (g *guardEnv) addUser(name string, role core.Role) string {
	g.t.Helper()
	phc, err := g.d.Auth.HashPassword(guardPassword)
	if err != nil {
		g.t.Fatal(err)
	}
	u, err := g.d.Users.Create(context.Background(), core.SystemPrincipal(core.ViaOffline),
		core.NewUser{Username: name, Role: role, PasswordHash: phc})
	if err != nil {
		g.t.Fatalf("create %s: %v", name, err)
	}
	return u.ID
}

// setRole gives the account userID the role roleID (a built-in word, or a
// custom role whose base becomes users.role), as the users service will.
func (g *guardEnv) setRole(userID, roleID string) {
	g.t.Helper()
	ctx := context.Background()
	var err error
	if core.IsCustomRoleID(roleID) {
		_, err = g.d.DB.Exec(ctx, `UPDATE users SET role = (SELECT base FROM roles WHERE id = ?), role_id = ? WHERE id = ?`,
			roleID, roleID, userID)
	} else {
		_, err = g.d.DB.Exec(ctx, `UPDATE users SET role = ?, role_id = NULL WHERE id = ?`, roleID, userID)
	}
	if err != nil {
		g.t.Fatal(err)
	}
}

func (c cred) apply(r *http.Request) {
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: c.cookie})
		r.Header.Set(mw.HeaderCSRF, c.csrf)
	}
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
}

// principal is what the auth service makes of c right now.
func (g *guardEnv) principal(c cred) *core.Principal {
	g.t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	c.apply(r)
	p, err := g.d.Auth.Authenticate(r)
	if err != nil || p == nil {
		g.t.Fatalf("authenticate: %+v %v", p, err)
	}
	return p
}

// guarded is one mounted admin route: its whole middleware chain exactly as
// the router runs it (chi.Walk: the root chain, the /api/v1 mount point's
// body limit, rate limit, Authenticate and CSRF, and the route's groups)
// around a stand-in handler. The route's own handler never runs, so no
// check changes the deployment.
type guarded struct {
	key     string // "METHOD /api/v1/…"
	method  string
	path    string
	handler http.Handler
}

// reachedStatus is the stand-in handler's answer: the guard let the request through.
const reachedStatus = 299

func (g *guardEnv) adminRoutes() []guarded {
	g.t.Helper()
	router, ok := web.NewRouter(g.d).(chi.Routes)
	if !ok {
		g.t.Fatal("the router is not a chi.Routes")
	}
	reached := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(reachedStatus) })
	var out []guarded
	err := chi.Walk(router, func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/api/v1/admin/") {
			return nil
		}
		h := http.Handler(reached)
		for i := len(mws) - 1; i >= 0; i-- {
			h = mws[i](h)
		}
		out = append(out, guarded{key: method + " " + route, method: method, path: route, handler: h})
		return nil
	})
	if err != nil {
		g.t.Fatal(err)
	}
	slices.SortFunc(out, func(a, b guarded) int { return strings.Compare(a.key, b.key) })
	return out
}

// answer is what a guarded route said.
type answer struct {
	status        int
	code, message string
}

func (a answer) reached() bool { return a.status == reachedStatus }

func (a answer) String() string {
	if a.reached() {
		return "reached the handler"
	}
	return fmt.Sprintf("%d %s %q", a.status, a.code, a.message)
}

func (g *guardEnv) call(rt guarded, credName string) answer {
	g.t.Helper()
	r := httptest.NewRequest(rt.method, rt.path, nil)
	// A client address of its own per request: the API rate limit counts
	// per address, and this test sends more requests than one client may.
	g.calls++
	r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:40000", byte(g.calls>>16), byte(g.calls>>8), byte(g.calls))
	if credName != "" {
		c, ok := g.creds[credName]
		if !ok {
			g.t.Fatalf("no credential %q", credName)
		}
		c.apply(r)
	}
	rec := httptest.NewRecorder()
	rt.handler.ServeHTTP(rec, r)
	a := answer{status: rec.Code}
	if !a.reached() {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		a.code, a.message = e.Error.Code, e.Error.Message
	}
	return a
}

// withoutAny is every permission whose closure holds none of caps: a role
// with it holds none of caps even after the implied ones are added.
func withoutAny(caps []core.Capability) core.CapSet {
	want := core.NewCapSet(caps...)
	var out core.CapSet
	for _, c := range core.AllCaps.List() {
		if core.NewCapSet(c).Closure()&want == 0 {
			out = out.With(c)
		}
	}
	return out
}

// Every admin route is mounted with the guard routeCaps declares, proven
// with real sessions and tokens against the route's real middleware chain:
//
//   - nobody without the permission gets in: anonymous 401; built-in members
//     and guests, a custom role without permissions, and a custom role
//     holding every other permission get 403 forbidden;
//   - built-in owners and admins get exactly the v3 answers (every admin
//     route was RequireAdmin, some with RequireElevated): they pass,
//     elevation_required on the elevated routes without step-up, and an
//     admin's API token needs the admin scope;
//   - a custom role holding just one of the listed permissions passes (step-up
//     where the route needs it), over a session and over an admin-scope
//     token; a token without the admin scope gets `token lacks scope "admin"`;
//   - the administrators-only routes refuse a custom role holding all 17
//     permissions.
func TestAdminRouteGuards(t *testing.T) {
	g := newGuardEnv(t)
	routes := g.adminRoutes()
	if want := len(routeCaps); len(routes) < want {
		t.Fatalf("only %d admin routes found, routeCaps has %d", len(routes), want)
	}
	forbidden := func(t *testing.T, who string, a answer) {
		t.Helper()
		if a.status != http.StatusForbidden || a.code != "forbidden" {
			t.Errorf("%s: %s, want 403 forbidden", who, a)
		}
	}
	for _, rt := range routes {
		decl, ok := routeCaps[rt.key]
		if !ok {
			continue // TestEveryAdminRouteDeclared names it
		}
		t.Run(rt.key, func(t *testing.T) {
			// Built-in roles: the v3 answers.
			if a := g.call(rt, ""); a.status != http.StatusUnauthorized {
				t.Errorf("anonymous: %s", a)
			}
			for _, who := range []string{"olive", "adam", "adam admin token"} {
				if a := g.call(rt, who); !a.reached() {
					t.Errorf("%s: %s", who, a)
				}
			}
			for _, who := range []string{"olive (not elevated)", "adam (not elevated)"} {
				a := g.call(rt, who)
				if decl.elevated && (a.status != http.StatusForbidden || a.code != "elevation_required") {
					t.Errorf("%s: %s, want elevation_required", who, a)
				} else if !decl.elevated && !a.reached() {
					t.Errorf("%s: %s", who, a)
				}
			}
			forbidden(t, "adam files token", g.call(rt, "adam files token"))
			forbidden(t, "mel", g.call(rt, "mel"))
			forbidden(t, "gus", g.call(rt, "gus"))

			// A custom role without permissions.
			g.setPerms(g.probe, 0)
			forbidden(t, "a role without permissions", g.call(rt, "pat"))

			if decl.caps == nil {
				g.setPerms(g.probe, core.AllCaps)
				forbidden(t, "a role with every permission", g.call(rt, "pat"))
				forbidden(t, "a role with every permission, admin token", g.call(rt, "pat admin token"))
				return
			}
			for _, c := range decl.caps {
				g.setPerms(g.probe, core.NewCapSet(c))
				if a := g.call(rt, "pat"); !a.reached() {
					t.Errorf("role with %s: %s", c, a)
				}
				a := g.call(rt, "pat (not elevated)")
				if decl.elevated && (a.status != http.StatusForbidden || a.code != "elevation_required") {
					t.Errorf("role with %s without step-up: %s, want elevation_required", c, a)
				} else if !decl.elevated && !a.reached() {
					t.Errorf("role with %s without step-up: %s", c, a)
				}
				if a := g.call(rt, "pat admin token"); !a.reached() {
					t.Errorf("role with %s, admin token: %s", c, a)
				}
				if a := g.call(rt, "pat files token"); a.status != http.StatusForbidden || a.message != `token lacks scope "admin"` {
					t.Errorf("role with %s, token without the admin scope: %s", c, a)
				}
			}
			// Every other permission is not enough.
			g.setPerms(g.probe, withoutAny(decl.caps))
			a := g.call(rt, "pat")
			forbidden(t, "a role with every other permission", a)
			if want := fmt.Sprintf("this needs the “%s” permission", decl.caps[0].Label()); a.message != want {
				t.Errorf("a role with every other permission: %q, want %q", a.message, want)
			}
		})
	}
}

// The principals of every channel carry the same role and capabilities for
// the same account: a session, an API token (scopes aside), the admin
// socket acting as the user (X-FP-As) and the principal of public share
// operations (Files.SysPrincipalFor) — for the built-in roles, with and
// without sharing.allow_guests_share, and for custom roles.
func TestPrincipalCapsConsistent(t *testing.T) {
	g := newGuardEnv(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaOffline)
	helpdesk := g.addRole("Helpdesk", core.RoleMember, core.MemberCaps.With(core.CapUsersManage, core.CapUsersCredentials))
	contractors := g.addRole("Contractors", core.RoleGuest, core.NewCapSet(core.CapShareRequests, core.CapTokensCreate))
	accounts := map[string]string{"olive": "", "adam": "", "mel": "", "gus": ""}
	for name, roleID := range map[string]string{"hana": helpdesk, "con": contractors} {
		base := core.RoleMember
		if roleID == contractors {
			base = core.RoleGuest
		}
		id := g.addUser(name, base)
		g.setRole(id, roleID)
		accounts[name] = roleID
	}
	// A token each; the built-in Guest role does not allow new tokens, so
	// gus's token is made while gus is a member (existing tokens keep
	// working after a role change).
	tokens := map[string]string{}
	for name := range accounts {
		u, err := g.d.Users.GetByUsername(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if name == "gus" {
			g.setRole(u.ID, "member")
		}
		_, secret, err := g.d.Auth.CreateToken(ctx, sys, core.TokenInput{Name: "consistency",
			Scopes: []string{core.ScopeAdmin}, UserID: u.ID})
		if err != nil && core.AsError(err) != nil && core.AsError(err).Field == "scopes" {
			_, secret, err = g.d.Auth.CreateToken(ctx, sys, core.TokenInput{Name: "consistency",
				Scopes: []string{core.ScopeFilesRead}, UserID: u.ID})
		}
		if err != nil {
			t.Fatalf("token of %s: %v", name, err)
		}
		if name == "gus" {
			g.setRole(u.ID, "guest")
		}
		tokens[name] = secret
	}
	// X-FP-As goes through mw.Authenticate with a trusted in-process principal.
	var acted *core.Principal
	actAs := mw.Inject(g.d)(mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acted = mw.Principal(r)
	})))

	for _, guestsShare := range []bool{false, true} {
		if _, err := g.d.Settings.Set(ctx, sys, map[string]json.RawMessage{
			"sharing.allow_guests_share": json.RawMessage(fmt.Sprint(guestsShare))}); err != nil {
			t.Fatal(err)
		}
		for name, roleID := range accounts {
			u, err := g.d.Users.GetByUsername(ctx, name)
			if err != nil {
				t.Fatal(err)
			}
			if roleID == "" {
				roleID = string(u.Role)
			}
			res, err := g.d.Auth.Login(ctx, core.LoginInput{Username: name, Password: guardPassword},
				core.ReqMeta{IP: netip.MustParseAddr("192.0.2.99")})
			if err != nil {
				t.Fatalf("login %s: %v", name, err)
			}
			acted = nil
			r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			r.Header.Set(mw.HeaderActAs, name)
			actAs.ServeHTTP(httptest.NewRecorder(), r.WithContext(core.WithPrincipal(r.Context(), core.SystemPrincipal(core.ViaSocket))))
			share, err := g.d.Files.SysPrincipalFor(ctx, u.ID)
			if err != nil {
				t.Fatalf("share principal of %s: %v", name, err)
			}
			want := u.Permissions
			for channel, p := range map[string]*core.Principal{
				"session": g.principal(cred{cookie: res.Token}),
				"token":   g.principal(cred{bearer: tokens[name]}),
				"X-FP-As": acted,
				"share":   share,
			} {
				if p == nil || p.Role != u.Role || p.RoleID != roleID || p.RoleName != u.RoleName || p.RoleCaps() != want {
					t.Errorf("%s %s (guests share %v): %+v, want role %s %s %q caps %v", name, channel, guestsShare, p,
						u.Role, roleID, u.RoleName, want)
				}
			}
			if name == "gus" && want != core.BuiltinCaps(core.RoleGuest, guestsShare) {
				t.Errorf("guest permissions with guests share %v: %v", guestsShare, want)
			}
			if name == "con" && want.Has(core.CapShareLinks) {
				t.Errorf("sharing.allow_guests_share reached a custom role: %v", want)
			}
		}
	}
}

// Every registered settings section is either delegated to a permission or
// listed as administrators-only (settingsapi): a new section stays
// administrators-only until someone decides otherwise, and this test makes
// that decision explicit.
func TestSettingsSectionsHaveCap(t *testing.T) {
	buildForAudit(t) // every package's settings.Register has run
	seen := map[string]bool{}
	for _, d := range settings.Defs() {
		if seen[d.Section] {
			continue
		}
		seen[d.Section] = true
		if _, listed := settingsapi.SectionPermission(d.Section); !listed {
			t.Errorf("settings section %q (key %s) is neither delegated nor listed as administrators-only in settingsapi/caps.go",
				d.Section, d.Key)
		}
	}
	if len(seen) < 10 {
		t.Errorf("only %d sections registered", len(seen))
	}
}
