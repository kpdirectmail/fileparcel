package pages

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"fileparcel/internal/core"
)

// The v4 boot fields: limits (always an object) and ingress (only for a
// request that came through a Tailscale ingress listener).
func TestBootLimitsAndIngress(t *testing.T) {
	e := newEnv(t)
	b := bootOf(t, e.do(t, "GET", "/login", nil, "").Body.String())
	if l, ok := b["limits"].(map[string]any); !ok || l == nil {
		t.Fatalf("limits %v", b["limits"])
	}
	if _, ok := b["ingress"]; ok {
		t.Fatalf("ingress on a direct request: %v", b["ingress"])
	}
	for _, kind := range []string{core.IngressFunnel, core.IngressServe} {
		req := httptest.NewRequest("GET", "/login", nil)
		req = req.WithContext(core.WithIngress(req.Context(), &core.IngressInfo{Kind: kind,
			ClientIP: netip.MustParseAddr("203.0.113.9"), Host: "box.tail1234.ts.net"}))
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", kind, rec.Code)
		}
		if got := bootOf(t, rec.Body.String())["ingress"]; got != kind {
			t.Errorf("ingress %v, want %s", got, kind)
		}
	}
}

// Features is shared by the boot and GET /me: the same flags for the same
// principal, and the flags of a principal whose second factor is pending do
// not depend on its role. The principals are built as package auth builds
// them (SetCaps with the role's effective set).
func TestFeatures(t *testing.T) {
	e := newEnv(t)
	anon := Features(e.d, nil)
	for _, k := range []string{"passkeys", "links", "requests", "directory", "tokens", "thumbnails", "mtls_self_service",
		"share_password_required"} {
		if _, ok := anon[k]; !ok {
			t.Errorf("flag %s missing", k)
		}
	}
	if anon["links"] || anon["requests"] || anon["directory"] || anon["tokens"] || !anon["passkeys"] {
		t.Errorf("anonymous %v", anon)
	}
	principal := func(role core.Role, level int, guestsShare bool) *core.Principal {
		p := &core.Principal{UserID: "usr_1", Role: role, RoleID: string(role), Via: core.ViaSession, AuthLevel: level}
		p.SetCaps(core.EffectiveRoleCaps(role, p.RoleID, 0, guestsShare))
		return p
	}
	if f := Features(e.d, principal(core.RoleGuest, core.AuthLevelFull, false)); f["links"] || f["requests"] {
		t.Fatalf("guest %v", f)
	}
	if f := Features(e.d, principal(core.RoleMember, core.AuthLevelFull, false)); !f["links"] || !f["requests"] {
		t.Fatalf("member %v", f)
	}
	for _, share := range []bool{false, true} {
		e.s.set("sharing.allow_guests_share", share)
		pg := Features(e.d, principal(core.RoleGuest, core.AuthLevelPassword, share))
		pm := Features(e.d, principal(core.RoleMember, core.AuthLevelPassword, share))
		pa := Features(e.d, principal(core.RoleAdmin, core.AuthLevelPassword, share))
		if !maps.Equal(pg, pm) || !maps.Equal(pm, pa) || !maps.Equal(pa, anon) {
			t.Fatalf("pending principals differ by role (allow_guests_share %v):\nguest  %v\nmember %v\nadmin  %v", share, pg, pm, pa)
		}
	}
	if f := Features(e.d, principal(core.RoleGuest, core.AuthLevelFull, true)); !f["links"] || !f["requests"] {
		t.Fatalf("guest with sharing %v", f)
	}
	b := bootOf(t, e.do(t, "GET", "/files", nil, "full").Body.String())
	f, _ := b["features"].(map[string]any)
	for k, v := range Features(e.d, principal(core.RoleMember, core.AuthLevelFull, true)) {
		if f[k] != v {
			t.Errorf("boot feature %s = %v, Features %v", k, f[k], v)
		}
	}
}

// intSetting (for the feature files): the value of a registered key, else
// the default.
func TestIntSetting(t *testing.T) {
	e := newEnv(t)
	if got := intSetting(e.d, "storage.zip_password_min", 12); got != 12 {
		t.Fatalf("unregistered key: %d", got)
	}
	e.s.set("storage.zip_password_min", 16)
	if got := intSetting(e.d, "storage.zip_password_min", 12); got != 16 {
		t.Fatalf("registered key: %d", got)
	}
	if got := intSetting(nil, "storage.zip_password_min", 12); got != 12 {
		t.Fatalf("no deps: %d", got)
	}
}

// The permission flags follow the principal's role: links and requests the
// sharing permissions (and the server switches), directory users.lookup or
// users.view, tokens tokens.create — for custom roles as for built-in ones.
func TestFeaturesFollowPermissions(t *testing.T) {
	e := newEnv(t)
	with := func(role core.Role, roleID string, caps core.CapSet) map[string]bool {
		p := &core.Principal{UserID: "usr_1", Role: role, RoleID: roleID, Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
		p.SetCaps(core.EffectiveRoleCaps(role, roleID, caps, false))
		return Features(e.d, p)
	}
	type flags struct{ links, requests, directory, tokens bool }
	get := func(f map[string]bool) flags { return flags{f["links"], f["requests"], f["directory"], f["tokens"]} }
	for name, c := range map[string]struct {
		f    map[string]bool
		want flags
	}{
		"member":        {with(core.RoleMember, "member", 0), flags{true, true, true, true}},
		"guest":         {with(core.RoleGuest, "guest", 0), flags{}},
		"admin":         {with(core.RoleAdmin, "admin", 0), flags{true, true, true, true}},
		"no links":      {with(core.RoleMember, "rol_nolinks", core.MemberCaps.Without(core.CapShareLinks)), flags{false, true, true, true}},
		"contractors":   {with(core.RoleGuest, "rol_contractors", core.NewCapSet(core.CapShareRequests)), flags{false, true, false, false}},
		"auditors":      {with(core.RoleGuest, "rol_auditors", core.NewCapSet(core.CapAuditView, core.CapUsersView)), flags{false, false, true, false}},
		"custom, empty": {with(core.RoleMember, "rol_empty", 0), flags{}},
	} {
		if got := get(c.f); got != c.want {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
	// A token keeps the user permissions without the admin scope, not users.view.
	tok := &core.Principal{UserID: "usr_1", Role: core.RoleGuest, RoleID: "rol_auditors", Via: core.ViaToken,
		AuthLevel: core.AuthLevelFull, Scopes: []string{core.ScopeFilesRead}}
	tok.SetCaps(core.NewCapSet(core.CapUsersView, core.CapShareRequests))
	if got := get(Features(e.d, tok)); got != (flags{requests: true}) {
		t.Errorf("token: %+v", got)
	}
	// The server switches still win.
	e.s.set("sharing.links_enabled", false)
	e.s.set("sharing.requests_enabled", false)
	if got := get(with(core.RoleAdmin, "admin", 0)); got != (flags{directory: true, tokens: true}) {
		t.Errorf("switches off: %+v", got)
	}
}

// The boot user names the role, its permissions and the personal space,
// agreeing with the feature flags (DESIGN §6a); a guest's permissions follow
// sharing.allow_guests_share exactly like the flags.
func TestBootUserRole(t *testing.T) {
	e := newEnv(t)
	u := e.users.users["usr_1"]
	u.Role, u.RoleID, u.RoleName = core.RoleMember, "rol_01k5z8r3m9d4q7w2x6c1v0b5na", "Helpdesk"
	u.Permissions = core.MemberCaps.With(core.CapUsersManage).Closure()
	u.SpaceID = "spc_alice"
	b := bootOf(t, e.do(t, "GET", "/files", nil, "full").Body.String())
	bu, _ := b["user"].(map[string]any)
	perms, _ := bu["permissions"].([]any)
	var names []string
	for _, p := range perms {
		names = append(names, p.(string))
	}
	want := []string{"shares.links", "shares.requests", "users.lookup", "tokens.create", "users.view", "users.manage"}
	if bu["role"] != "member" || bu["role_id"] != u.RoleID || bu["role_name"] != "Helpdesk" || bu["staff"] != true ||
		bu["space_id"] != "spc_alice" || !slices.Equal(names, want) {
		t.Fatalf("boot user %v", bu)
	}
	if f, _ := b["features"].(map[string]any); f["directory"] != true || f["tokens"] != true || f["links"] != true {
		t.Fatalf("features %v", f)
	}

	// A plain guest: no personal space, no staff; permissions and flags
	// follow the setting.
	u.Role, u.RoleID, u.RoleName, u.Permissions, u.SpaceID = core.RoleGuest, "guest", "Guest", 0, ""
	for _, share := range []bool{false, true} {
		e.s.set("sharing.allow_guests_share", share)
		b = bootOf(t, e.do(t, "GET", "/files", nil, "full").Body.String())
		bu, _ = b["user"].(map[string]any)
		f, _ := b["features"].(map[string]any)
		perms, ok := bu["permissions"].([]any)
		if !ok || (len(perms) == 2) != share || f["links"] != share || f["requests"] != share ||
			bu["role_id"] != "guest" || bu["role_name"] != "Guest" {
			t.Fatalf("guest (allow_guests_share %v): user %v features %v", share, bu, f)
		}
		for _, k := range []string{"staff", "space_id"} {
			if _, ok := bu[k]; ok {
				t.Fatalf("guest boot user has %q: %v", k, bu)
			}
		}
	}
}
