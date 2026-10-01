package meapi_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
	"fileparcel/internal/web/authapi"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/meapi"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/pages"
)

// bootServer is server() plus GET /boot, which answers the page boot data
// (pages.NewPageData) of the same request as JSON: the boot and GET /me
// see the very same principal.
func bootServer(t *testing.T) (*authtest.Env, http.Handler) {
	t.Helper()
	e := authtest.New(t)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.Settings.Put("auth.require_2fa", "off")
	e.Limiter.ApplySettings()
	d := &app.Deps{Env: e.Env, Auth: e.Auth, Users: e.Users, Files: fakeFiles{}, Limiter: e.Limiter}
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP)
	api := chi.NewRouter()
	authapi.Mount(api, d)
	meapi.Mount(api, d)
	api.With(mw.RequireFull).Get("/boot", func(w http.ResponseWriter, r *http.Request) {
		httpx.OK(w, pages.NewPageData(r, "app", "", nil).Boot)
	})
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.RateLimit(mw.BucketAPI, mw.PerIP), mw.Authenticate, mw.CSRF).Mount("/api/v1", api)
	return e, r
}

// Me.Staff and the user's role fields (DESIGN §6a): staff is whether the
// caller can use a server permission on this channel — owners, admins and
// roles with a server permission, on a session or an admin-scope token.
func TestMeStaffAndRole(t *testing.T) {
	e, h := bootServer(t)
	helpdesk := e.AddRole(t, "Helpdesk", core.RoleMember, core.MemberCaps.With(core.CapUsersManage), false)
	auditors := e.AddRole(t, "Auditors", core.RoleGuest, core.NewCapSet(core.CapAuditView), false)
	hana := e.AddUser(t, "hana", pw, core.RoleMember)
	e.SetUserRole(t, hana.ID, helpdesk)
	aud := e.AddUser(t, "aud", pw, core.RoleGuest)
	e.SetUserRole(t, aud.ID, auditors)
	e.AddUser(t, "mona", pw, core.RoleMember)
	adam := e.AddUser(t, "adam", pw, core.RoleAdmin)

	for _, c := range []struct {
		user, roleID, roleName string
		staff                  bool
		directory, tokens      bool
		perms                  core.CapSet
	}{
		{"hana", helpdesk, "Helpdesk", true, true, true, core.MemberCaps.With(core.CapUsersView, core.CapUsersManage)},
		{"aud", auditors, "Auditors", true, false, false, core.NewCapSet(core.CapAuditView)},
		{"mona", "member", "Member", false, true, true, core.MemberCaps},
		{"adam", "admin", "Admin", true, true, true, core.AllCaps},
	} {
		cl := newClient(t, h)
		cl.login(c.user, pw)
		me := decode[core.Me](t, cl.do(http.MethodGet, "/me", nil), http.StatusOK)
		if me.Staff != c.staff || me.User.RoleID != c.roleID || me.User.RoleName != c.roleName ||
			me.User.Permissions != c.perms || me.Features["directory"] != c.directory || me.Features["tokens"] != c.tokens {
			t.Errorf("%s: staff %v role %s %q perms %v features %v", c.user, me.Staff, me.User.RoleID, me.User.RoleName,
				me.User.Permissions, me.Features)
		}
	}

	// An admin's token is staff only with the admin scope.
	sys := core.SystemPrincipal(core.ViaSocket)
	for scopes, want := range map[string]bool{core.ScopeFilesRead: false, core.ScopeAdmin: true} {
		_, secret, err := e.Auth.CreateToken(t.Context(), sys, core.TokenInput{Name: scopes, Scopes: []string{scopes}, UserID: adam.ID})
		if err != nil {
			t.Fatal(err)
		}
		cl := newClient(t, h)
		cl.bearer = secret
		if me := decode[core.Me](t, cl.do(http.MethodGet, "/me", nil), http.StatusOK); me.Staff != want || me.User.Permissions != core.AllCaps {
			t.Errorf("admin token %s: staff %v perms %v", scopes, me.Staff, me.User.Permissions)
		}
	}

	// The bare system principal (admin socket): every permission, staff.
	cl := newClient(t, h)
	cl.principal = sys
	me := decode[core.Me](t, cl.do(http.MethodGet, "/me", nil), http.StatusOK)
	if !me.Staff || me.User.RoleID != "system" || me.User.RoleName != "System" || me.User.Permissions != core.AllCaps {
		t.Fatalf("system /me: staff %v user %+v", me.Staff, me.User)
	}
}

// While the second factor is pending, GET /me is not staff and names no
// role or permission, and the boot has neither.
func TestMePendingHasNoRole(t *testing.T) {
	e, h := bootServer(t)
	e.AddUser(t, "vera", pw, core.RoleAdmin)
	c := newClient(t, h)
	c.login("vera", pw)
	c.enrollTOTP(e)
	noContent(t, c.do(http.MethodPost, "/auth/logout", nil))
	if res := c.login("vera", pw); !res.MFARequired {
		t.Fatal("second factor expected")
	}
	var body struct {
		Staff    *bool           `json:"staff"`
		User     map[string]any  `json:"user"`
		Features map[string]bool `json:"features"`
	}
	w := c.do(http.MethodGet, "/me", nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatalf("pending /me: %d %s", w.Code, w.Body)
	}
	if body.Staff == nil || *body.Staff || body.User["role_id"] != "" || body.User["role_name"] != "" {
		t.Fatalf("pending /me: staff %v user %v", body.Staff, body.User)
	}
	if p, _ := body.User["permissions"].([]any); len(p) != 0 {
		t.Fatalf("pending /me permissions %v", body.User["permissions"])
	}
	for _, k := range []string{"links", "requests", "directory", "tokens"} {
		if body.Features[k] {
			t.Errorf("pending /me feature %s on", k)
		}
	}
}

// GET /me and the page boot report the same role, permissions, staff flag
// and feature flags for the same principal — a guest with and without
// sharing.allow_guests_share, a member, and custom roles (DESIGN §6a).
func TestMeAndBootAgree(t *testing.T) {
	e, h := bootServer(t)
	helpdesk := e.AddRole(t, "Helpdesk", core.RoleMember, core.MemberCaps.With(core.CapUsersManage), false)
	contractors := e.AddRole(t, "Contractors", core.RoleGuest, core.NewCapSet(core.CapShareRequests), false)
	e.AddUser(t, "gus", pw, core.RoleGuest)
	e.AddUser(t, "meg", pw, core.RoleMember)
	e.SetUserRole(t, e.AddUser(t, "hana", pw, core.RoleMember).ID, helpdesk)
	e.SetUserRole(t, e.AddUser(t, "cora", pw, core.RoleGuest).ID, contractors)

	type boot struct {
		User struct {
			Role        core.Role    `json:"role"`
			RoleID      string       `json:"role_id"`
			RoleName    string       `json:"role_name"`
			Permissions *core.CapSet `json:"permissions"`
			Staff       bool         `json:"staff"`
			SpaceID     string       `json:"space_id"`
		} `json:"user"`
		Features map[string]bool `json:"features"`
	}
	for _, share := range []bool{false, true} {
		e.Settings.Put("sharing.allow_guests_share", share)
		for _, name := range []string{"gus", "meg", "hana", "cora"} {
			c := newClient(t, h)
			c.login(name, pw)
			me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
			b := decode[boot](t, c.do(http.MethodGet, "/boot", nil), http.StatusOK)
			if b.User.Permissions == nil || *b.User.Permissions != me.User.Permissions || b.User.Role != me.User.Role ||
				b.User.RoleID != me.User.RoleID || b.User.RoleName != me.User.RoleName || b.User.Staff != me.Staff ||
				b.User.SpaceID != me.SpaceID || !maps.Equal(b.Features, me.Features) {
				t.Errorf("%s (allow_guests_share %v):\n boot %+v %v\n  /me %+v staff %v %v", name, share, b.User,
					b.Features, me.User, me.Staff, me.Features)
			}
			guest := name == "gus"
			if guest && (me.Features["links"] != share || me.Features["requests"] != share ||
				(me.User.Permissions != 0) != share) {
				t.Errorf("guest (allow_guests_share %v): %v %v", share, me.User.Permissions, me.Features)
			}
			if name == "cora" && (me.Features["links"] || !me.Features["requests"] || me.SpaceID != "" ||
				!slices.Equal(me.User.Permissions.List(), []core.Capability{core.CapShareRequests})) {
				t.Errorf("contractor ignores the guest setting: %v %v", me.User.Permissions, me.Features)
			}
		}
	}
	// A role edit is visible on the next request of both.
	e.SetRolePermissions(t, helpdesk, core.NewCapSet(core.CapUsersLookup))
	c := newClient(t, h)
	c.login("hana", pw)
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	b := decode[boot](t, c.do(http.MethodGet, "/boot", nil), http.StatusOK)
	if me.Staff || b.User.Staff || me.Features["tokens"] || b.Features["tokens"] || !me.Features["directory"] {
		t.Fatalf("after the edit: /me %v %v, boot %+v %v", me.Staff, me.Features, b.User, b.Features)
	}
}
