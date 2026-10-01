package mw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"fileparcel/internal/auth"
	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
)

// The principals package auth actually builds (session cookies and API
// tokens of owners, admins, members and guests, under both 2FA policies) get
// the same answer from RequireCap as from the guard their route has today:
// RequireAdmin for every server permission, and "any built-in role but
// guest" for the user permissions (sharing.allow_guests_share is off). This
// holds before package A resolves capabilities (principals fall back to
// their built-in role) and after it (EffectiveRoleCaps of a built-in role is
// the same set).
func TestRequireCapMatchesTodayForAuthPrincipals(t *testing.T) {
	defer authtest.FastHashing()()
	const pw = "correct horse battery staple"
	ctx := context.Background()
	meta := core.ReqMeta{IP: netip.MustParseAddr("192.0.2.1"), UserAgent: "mw-test"}
	d := newEnv(t).d
	member := RequireRole(core.RoleOwner, core.RoleAdmin, core.RoleMember)
	status := func(m Middleware, p *core.Principal) (int, string) {
		r := withP(httptest.NewRequest(http.MethodGet, "/api/v1/admin/x", nil), p)
		rec := serve(d, m(http.HandlerFunc(ok)), r)
		return rec.Code, code(t, rec)
	}
	for _, policy := range []string{"off", "admins"} {
		e := authtest.New(t)
		e.Settings.Put("auth.require_2fa", policy)
		sys := core.SystemPrincipal(core.ViaOffline)
		type named struct {
			name string
			p    *core.Principal
		}
		var ps []named
		for _, role := range []core.Role{core.RoleOwner, core.RoleAdmin, core.RoleMember, core.RoleGuest} {
			u := e.AddUser(t, string(role)+"_"+policy, pw, role)
			res, err := e.Auth.Login(ctx, core.LoginInput{Username: u.Username, Password: pw}, meta)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: res.Token})
			p, err := e.Auth.Authenticate(r)
			if err != nil || p == nil {
				t.Fatalf("%s session: %v", role, err)
			}
			ps = append(ps, named{string(role) + " session", p})
			scopeSets := [][]string{{core.ScopeFilesRead}, {core.ScopeFilesRead, core.ScopeShares}}
			if role.IsAdmin() {
				scopeSets = append(scopeSets, []string{core.ScopeAdmin}, []string{core.ScopeFilesRead, core.ScopeAdmin})
			}
			for _, scopes := range scopeSets {
				_, secret, err := e.Auth.CreateToken(ctx, sys, core.TokenInput{Name: fmt.Sprint(scopes), Scopes: scopes, UserID: u.ID})
				if err != nil && role == core.RoleGuest && core.AsError(err) != nil && core.AsError(err).Status == http.StatusForbidden {
					continue // from package A on, a guest's role does not allow API tokens (tokens.create)
				}
				if err != nil {
					t.Fatalf("%s token %v: %v", role, scopes, err)
				}
				r := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
				r.Header.Set("Authorization", "Bearer "+secret)
				p, err := e.Auth.Authenticate(r)
				if err != nil || p == nil || p.Via != core.ViaToken {
					t.Fatalf("%s token %v: %+v %v", role, scopes, p, err)
				}
				ps = append(ps, named{fmt.Sprintf("%s token %v", role, scopes), p})
			}
		}
		ps = append(ps, named{"socket", core.SystemPrincipal(core.ViaSocket)}, named{"offline", sys})
		// The comparison is not vacuous: under "off" an admin session passes a
		// server permission, a member session and an admin's files:read
		// token do not; under "admins" the admin must enrol first.
		byName := map[string]*core.Principal{}
		for _, n := range ps {
			byName[n.name] = n.p
		}
		admin, memberS, adminTok := byName["admin session"], byName["member session"], byName["admin token [files:read]"]
		wantAdmin := http.StatusOK
		if policy == "admins" {
			wantAdmin = http.StatusForbidden
		}
		if s, _ := status(RequireCap(core.CapAuditView), admin); s != wantAdmin || admin.Role != core.RoleAdmin || admin.Via != core.ViaSession {
			t.Fatalf("policy %s: admin session %d (%+v)", policy, s, admin)
		}
		if s, _ := status(RequireCap(core.CapAuditView), memberS); s != http.StatusForbidden || memberS.Role != core.RoleMember || memberS.Via != core.ViaSession {
			t.Fatalf("policy %s: member session %d (%+v)", policy, s, memberS)
		}
		if s, _ := status(RequireCap(core.CapAuditView), adminTok); s != http.StatusForbidden || adminTok.Via != core.ViaToken {
			t.Fatalf("policy %s: admin files:read token %d (%+v)", policy, s, adminTok)
		}
		for _, c := range core.Capabilities {
			today := RequireAdmin
			if !c.Server {
				today = member
			}
			for _, n := range ps {
				gotS, gotC := status(RequireCap(c.Name), n.p)
				wantS, wantC := status(today, n.p)
				if gotS != wantS || gotC != wantC {
					t.Errorf("policy %s, %s, %s: RequireCap %d %s, today %d %s", policy, n.name, c.Name, gotS, gotC, wantS, wantC)
				}
				// Can agrees with the guard's rule on its own.
				var want bool
				switch {
				case n.p.IsSystem():
					want = true
				case c.Server:
					want = n.p.IsAdmin() && n.p.HasScope(core.ScopeAdmin)
				default:
					want = n.p.Role != core.RoleGuest
				}
				if n.p.Can(c.Name) != want {
					t.Errorf("policy %s, %s: Can(%s) = %v", policy, n.name, c.Name, !want)
				}
			}
		}
	}
}
