package mw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"fileparcel/internal/core"
)

// custom builds a principal holding a custom role with the given permissions,
// as package auth builds it (SetCaps).
func custom(via core.AuthVia, base core.Role, caps core.CapSet, scopes ...string) *core.Principal {
	p := &core.Principal{UserID: "usr_c", Role: base, RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na", RoleName: "Custom",
		Via: via, AuthLevel: 2, Scopes: scopes}
	p.SetCaps(core.EffectiveRoleCaps(base, p.RoleID, caps, false))
	return p
}

// The RequireCap cases of rbac-final §17.1.
func TestRequireCap(t *testing.T) {
	e := newEnv(t)
	d := e.d
	member := &core.Principal{UserID: "m", Role: core.RoleMember, RoleID: "member", Via: core.ViaSession, AuthLevel: 2}
	guest := &core.Principal{UserID: "g", Role: core.RoleGuest, Via: core.ViaSession, AuthLevel: 2}
	pending := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 1}
	enroll := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2, EnrollRequired: true}
	admin := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2}
	owner := &core.Principal{UserID: "o", Role: core.RoleOwner, Via: core.ViaSession, AuthLevel: 2}
	adminTok := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeFilesRead}}
	adminTokFull := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeAdmin}}
	auditor := custom(core.ViaSession, core.RoleGuest, core.NewCapSet(core.CapAuditView))
	auditorTok := custom(core.ViaToken, core.RoleGuest, core.NewCapSet(core.CapAuditView), core.ScopeFilesRead)
	auditorTokFull := custom(core.ViaToken, core.RoleGuest, core.NewCapSet(core.CapAuditView), core.ScopeAdmin)
	helpdesk := custom(core.ViaSession, core.RoleMember, core.MemberCaps.With(core.CapUsersManage))
	unresolved := &core.Principal{UserID: "c", Role: core.RoleMember, RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na", Via: core.ViaSession, AuthLevel: 2}
	sys := core.SystemPrincipal(core.ViaSocket)
	off := core.SystemPrincipal(core.ViaOffline)

	audit := RequireCap(core.CapAuditView)
	anyOf := RequireCap(core.CapSettingsManage, core.CapNetworkManage, core.CapAuditView)
	links := RequireCap(core.CapShareLinks)
	cases := []struct {
		name string
		mw   Middleware
		p    *core.Principal
		want int
		code string
		msg  string
	}{
		{"anonymous", audit, nil, 401, "unauthorized", ""},
		{"mfa pending", audit, pending, 401, "mfa_required", ""},
		{"enroll required", audit, enroll, 403, "mfa_enroll_required", ""},
		{"member", audit, member, 403, "forbidden", "this needs the “Audit and server logs” permission"},
		{"guest", audit, guest, 403, "forbidden", "this needs the “Audit and server logs” permission"},
		{"holder", audit, auditor, 200, "", ""},
		{"holder token without admin scope", audit, auditorTok, 403, "forbidden", `token lacks scope "admin"`},
		{"holder token with admin scope", audit, auditorTokFull, 200, "", ""},
		{"admin", audit, admin, 200, "", ""},
		{"owner", audit, owner, 200, "", ""},
		{"admin token without admin scope", audit, adminTok, 403, "forbidden", `token lacks scope "admin"`},
		{"admin token with admin scope", audit, adminTokFull, 200, "", ""},
		{"system", audit, sys, 200, "", ""},
		{"offline", audit, off, 200, "", ""},
		{"other permission", audit, helpdesk, 403, "forbidden", "this needs the “Audit and server logs” permission"},
		{"custom role without SetCaps: nothing", links, unresolved, 403, "forbidden", "this needs the “Create share links” permission"},
		// Any of: the message names the first permission.
		{"any-of holder", anyOf, auditor, 200, "", ""},
		{"any-of none", anyOf, helpdesk, 403, "forbidden", "this needs the “General settings” permission"},
		{"any-of token", anyOf, auditorTok, 403, "forbidden", `token lacks scope "admin"`},
		// A user permission needs no admin scope.
		{"user permission, member", links, member, 200, "", ""},
		{"user permission, member token", links, &core.Principal{UserID: "m", Role: core.RoleMember, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeFilesRead}}, 200, "", ""},
		{"user permission, guest", links, guest, 403, "forbidden", "this needs the “Create share links” permission"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/api/v1/admin/x", nil)
		if c.p != nil {
			r = withP(r, c.p)
		}
		rec := serve(d, c.mw(http.HandlerFunc(ok)), r)
		if rec.Code != c.want || (c.code != "" && code(t, rec) != c.code) {
			t.Errorf("%s: got %d %s want %d %s", c.name, rec.Code, code(t, rec), c.want, c.code)
			continue
		}
		if c.msg != "" {
			var er struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &er)
			if er.Error.Message != c.msg {
				t.Errorf("%s: message %q, want %q", c.name, er.Error.Message, c.msg)
			}
		}
	}
}

// Before package A builds principals with SetCaps, RequireCap(<server
// permission>) admits exactly the principals RequireAdmin admits.
func TestRequireCapMatchesRequireAdmin(t *testing.T) {
	e := newEnv(t)
	var ps []*core.Principal
	for _, r := range []core.Role{core.RoleOwner, core.RoleAdmin, core.RoleMember, core.RoleGuest} {
		for _, via := range []core.AuthVia{core.ViaSession, core.ViaToken} {
			for _, scopes := range [][]string{nil, {core.ScopeFilesRead}, {core.ScopeAdmin}} {
				for _, level := range []int{core.AuthLevelPassword, core.AuthLevelFull} {
					for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}} {
						ps = append(ps, &core.Principal{UserID: "u", Role: r, RoleID: string(r), Via: via, Scopes: scopes,
							AuthLevel: level, EnrollRequired: flags[0], MustChangePassword: flags[1]})
					}
				}
			}
		}
	}
	ps = append(ps, nil, core.SystemPrincipal(core.ViaSocket), core.SystemPrincipal(core.ViaOffline))
	for _, c := range core.Capabilities {
		if !c.Server {
			continue
		}
		for _, p := range ps {
			serveOne := func(m Middleware) (int, string) {
				r := httptest.NewRequest("GET", "/api/v1/admin/x", nil)
				if p != nil {
					r = withP(r, p)
				}
				rec := serve(e.d, m(http.HandlerFunc(ok)), r)
				return rec.Code, code(t, rec)
			}
			gotS, gotC := serveOne(RequireCap(c.Name))
			wantS, wantC := serveOne(RequireAdmin)
			if gotS != wantS || gotC != wantC {
				t.Errorf("%s for %+v: RequireCap %d %s, RequireAdmin %d %s", c.Name, p, gotS, gotC, wantS, wantC)
			}
		}
	}
}

func TestRequireCapPanicsOnBadInput(t *testing.T) {
	for name, f := range map[string]func(){
		"none":    func() { RequireCap() },
		"unknown": func() { RequireCap(core.CapAuditView, "audit.everything") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}
