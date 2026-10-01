package mw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"fileparcel/internal/core"
)

// roleUsers is a Users fake whose accounts carry their role like the real
// users service fills them (RoleID, RoleName, Permissions).
type roleUsers struct{ core.Users }

const helpdeskRoleID = "rol_01k5z8r3m9d4q7w2x6c1v0b5na"

func (roleUsers) GetByUsername(_ context.Context, name string) (*core.User, error) {
	switch name {
	case "hana":
		return &core.User{ID: "usr_hana", Username: "hana", Role: core.RoleMember, RoleID: helpdeskRoleID,
			RoleName: "Helpdesk", Permissions: core.MemberCaps.With(core.CapUsersManage, core.CapUsersView),
			Status: core.UserActive}, nil
	case "gus":
		return &core.User{ID: "usr_gus", Username: "gus", Role: core.RoleGuest, RoleID: "guest", RoleName: "Guest",
			Permissions: core.NewCapSet(core.CapShareLinks, core.CapShareRequests), Status: core.UserActive}, nil
	}
	return nil, core.ErrNotFound
}

// X-FP-As acts with the role and capabilities of the account.
func TestActAsCarriesRoleCaps(t *testing.T) {
	e := newEnv(t)
	e.d.Users = roleUsers{}
	var got *core.Principal
	h := Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = Principal(r) }))
	for _, c := range []struct {
		as, roleID, name string
		caps             core.CapSet
	}{
		{"hana", helpdeskRoleID, "Helpdesk", core.MemberCaps.With(core.CapUsersManage, core.CapUsersView)},
		// The guest setting is part of the account's permissions.
		{"gus", "guest", "Guest", core.NewCapSet(core.CapShareLinks, core.CapShareRequests)},
	} {
		got = nil
		r := withP(httptest.NewRequest(http.MethodGet, "/api/v1/x", nil), core.SystemPrincipal(core.ViaSocket))
		r.Header.Set(HeaderActAs, c.as)
		serve(e.d, h, r)
		if got == nil || got.RoleID != c.roleID || got.RoleName != c.name || got.RoleCaps() != c.caps || got.IsSystem() {
			t.Fatalf("as %s: %+v", c.as, got)
		}
	}
	// The acted-as principal can use exactly the account's permissions (no
	// token scopes apply on the socket), not the system principal's.
	if !got.Can(core.CapShareLinks) || got.Can(core.CapUsersView) {
		t.Errorf("guest caps: %v", got.RoleCaps())
	}
}

// capAuth authenticates the session cookie "role" as a member-based custom
// role holding the permissions named by its value.
type capAuth struct{ core.Auth }

func (capAuth) Authenticate(r *http.Request) (*core.Principal, error) {
	c, err := r.Cookie("role")
	if err != nil {
		return nil, nil
	}
	p := &core.Principal{UserID: "usr_op", Username: "op", Role: core.RoleMember, RoleID: helpdeskRoleID,
		RoleName: "Operators", Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
	p.SetCaps(core.NewCapSet(core.Capability(c.Value)))
	if r.Header.Get("X-Test-Pending") != "" {
		p.AuthLevel = core.AuthLevelPassword
	}
	return p, nil
}

// "Operate the server" (system.manage) keeps working during maintenance, like
// administrators; other permissions do not.
func TestMaintenanceGateSystemManage(t *testing.T) {
	e := newEnv(t)
	e.d.Auth = capAuth{}
	e.s.set(KeyMaintenanceEnabled, true)
	h := Maintenance(http.HandlerFunc(notice))(http.HandlerFunc(ok))
	for _, c := range []struct {
		perm    core.Capability
		pending bool
		want    int
	}{
		{core.CapSystemManage, false, http.StatusOK},
		{core.CapSystemManage, true, http.StatusServiceUnavailable}, // second factor still pending
		{core.CapSystemView, false, http.StatusServiceUnavailable},
		{core.CapSettingsManage, false, http.StatusServiceUnavailable},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/spaces", nil)
		r.AddCookie(&http.Cookie{Name: "role", Value: string(c.perm)})
		if c.pending {
			r.Header.Set("X-Test-Pending", "1")
		}
		if rec := serve(e.d, h, r); rec.Code != c.want {
			t.Errorf("%s (pending %v): %d", c.perm, c.pending, rec.Code)
		}
	}
	// A principal already in the context (put there by in-process code) is
	// judged the same way; socket and offline callers pass anyway.
	op := &core.Principal{UserID: "usr_op", Role: core.RoleMember, RoleID: helpdeskRoleID, Via: core.ViaSession,
		AuthLevel: core.AuthLevelFull}
	op.SetCaps(core.NewCapSet(core.CapSystemManage))
	if rec := serve(e.d, h, withP(httptest.NewRequest(http.MethodGet, "/api/v1/spaces", nil), op)); rec.Code != http.StatusOK {
		t.Errorf("context principal with system.manage: %d", rec.Code)
	}
	op.SetCaps(core.NewCapSet(core.CapAuditView))
	if rec := serve(e.d, h, withP(httptest.NewRequest(http.MethodGet, "/api/v1/spaces", nil), op)); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("context principal with audit.view: %d", rec.Code)
	}
}
