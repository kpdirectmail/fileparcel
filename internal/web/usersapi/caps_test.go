package usersapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/web/httpx"
)

// rawDo sends a request as the stored principal (te.who) and returns the
// status and the decoded error body.
func rawDo(t *testing.T, te *testEnv, method, path string, body any) (int, httpx.ErrorResponse) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, te.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var er httpx.ErrorResponse
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &er)
	return resp.StatusCode, er
}

// addRole stores a member-based custom role straight into the roles table
// and returns its id.
func (te *testEnv) addRole(t *testing.T, name string, perms core.CapSet, delegable bool) string {
	t.Helper()
	id := ids.New(ids.PrefixRole)
	now := te.now.UnixMilli()
	if _, err := te.d.DB.Exec(context.Background(), `INSERT INTO roles (id, name, base, permissions, delegable,
		created_at, updated_at) VALUES (?, ?, 'member', ?, ?, ?, ?)`, id, name, core.EncodeCaps(perms), delegable,
		now, now); err != nil {
		t.Fatal(err)
	}
	return id
}

// holder creates a member account with the custom role roleID and returns
// it as the users service reads it.
func (te *testEnv) holder(t *testing.T, name, roleID string) *core.User {
	t.Helper()
	ctx := context.Background()
	phc, _ := te.auth.HashPassword("correct horse battery")
	u, err := te.d.Users.Create(ctx, core.SystemPrincipal(core.ViaSocket),
		core.NewUser{Username: name, Role: core.RoleMember, PasswordHash: phc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.d.DB.Exec(ctx, `UPDATE users SET role_id = ? WHERE id = ?`, roleID, u.ID); err != nil {
		t.Fatal(err)
	}
	if u, err = te.d.Users.Get(ctx, u.ID); err != nil || u.RoleID != roleID {
		t.Fatalf("holder %s: %+v %v", name, u, err)
	}
	return u
}

// delegate is the elevated session principal auth builds for u.
func (te *testEnv) delegate(u *core.User) *core.Principal {
	p := te.principal(u, true)
	p.RoleID, p.RoleName = u.RoleID, u.RoleName
	p.SetCaps(u.Permissions)
	return p
}

// The credential routes check core.CheckManage with users.credentials: a
// delegate resets the sign-in of the accounts its role may manage only, and
// every refused attempt to change something is audited as denied.
func TestDelegateCredentialRoutes(t *testing.T) {
	te := newTestEnv(t)
	helpdesk := te.addRole(t, "Helpdesk", core.MemberCaps.With(core.CapUsersManage, core.CapUsersCredentials), false)
	finance := te.addRole(t, "Finance", core.MemberCaps, false)
	auditors := te.addRole(t, "Auditors", core.MemberCaps.With(core.CapAuditView), true)
	hana := te.holder(t, "hana", helpdesk)
	fin := te.holder(t, "fin", finance)
	aud := te.holder(t, "aud", auditors)
	p := te.delegate(hana)

	routes := []struct {
		method, suffix string
		body           any
		action         string // audited when refused; "" for the read
		call           string // the fakeAuth call the route makes
	}{
		{"GET", "/sessions", nil, "", "ListSessions"},
		{"DELETE", "/sessions", nil, core.ActSessionRevoke, "RevokeAllSessions"},
		{"POST", "/password", core.PasswordResetInput{Password: "a long enough new password"}, core.ActUserPasswordReset,
			"AdminSetPassword"},
		{"POST", "/reset-mfa", nil, core.ActUserMFAReset, "ResetMFA"},
	}
	for _, u := range []*core.User{te.member, te.guest} {
		for _, rt := range routes {
			path := "/api/v1/admin/users/" + u.ID + rt.suffix
			if st, code := te.as(p).do(t, rt.method, path, rt.body, nil); st >= 300 {
				t.Errorf("%s %s of %s: %d %s", rt.method, rt.suffix, u.Username, st, code)
			}
			if !te.auth.called(rt.call + ":" + u.ID) {
				t.Errorf("%s %s of %s: %s not called", rt.method, rt.suffix, u.Username, rt.call)
			}
		}
	}
	refused := map[*core.User]string{
		te.owner: "only an owner can manage the credentials of an owner",
		te.admin: "only administrators can manage administrator accounts",
		fin:      "accounts with the role “Finance” can only be managed by an administrator",
		aud:      "this account has server permissions you do not have (audit.view)",
		hana:     "ask an administrator to change this on your own account",
	}
	for u, msg := range refused {
		for _, rt := range routes {
			before := len(te.audit.recorded())
			path := "/api/v1/admin/users/" + u.ID + rt.suffix
			te.who.Store(p)
			st, body := rawDo(t, te, rt.method, path, rt.body)
			if st != http.StatusForbidden || body.Error.Code != "forbidden" || body.Error.Message != msg {
				t.Errorf("%s %s of %s: %d %+v", rt.method, rt.suffix, u.Username, st, body)
			}
			if te.auth.called(rt.call + ":" + u.ID) {
				t.Errorf("%s %s of %s: %s was called", rt.method, rt.suffix, u.Username, rt.call)
			}
			added := te.audit.recorded()[before:]
			if rt.action == "" {
				if len(added) != 0 {
					t.Errorf("GET sessions of %s audited: %+v", u.Username, added)
				}
				continue
			}
			if len(added) != 1 || added[0].Action != rt.action || added[0].Outcome != core.OutcomeDenied ||
				added[0].TargetID != u.ID || added[0].TargetName != u.Username {
				t.Errorf("%s %s of %s: audit %+v", rt.method, rt.suffix, u.Username, added)
				continue
			}
			d, _ := added[0].Details.(map[string]any)
			missing, _ := d["missing"].([]core.Capability)
			if d["reason"] != msg || (u == aud) != slices.Equal(missing, []core.Capability{core.CapAuditView}) {
				t.Errorf("%s %s of %s: details %+v", rt.method, rt.suffix, u.Username, d)
			}
		}
	}

	// Without users.credentials the route guard refuses before anything is
	// looked at, and nothing is audited.
	managers := te.addRole(t, "Account managers", core.MemberCaps.With(core.CapUsersManage), true)
	mgr := te.delegate(te.holder(t, "mgr", managers))
	before := len(te.audit.recorded())
	for _, rt := range routes {
		te.who.Store(mgr)
		st, body := rawDo(t, te, rt.method, "/api/v1/admin/users/"+te.member.ID+rt.suffix, rt.body)
		if st != http.StatusForbidden || body.Error.Message != "this needs the “Reset sign-in” permission" {
			t.Errorf("%s %s without users.credentials: %d %+v", rt.method, rt.suffix, st, body)
		}
	}
	if got := te.audit.recorded(); len(got) != before {
		t.Errorf("guard refusals audited: %+v", got[before:])
	}
}

// users.view opens the account and group lists (reads only).
func TestDelegateReadsWithUsersView(t *testing.T) {
	te := newTestEnv(t)
	viewers := te.addRole(t, "Viewers", core.MemberCaps.With(core.CapUsersView), false)
	p := te.delegate(te.holder(t, "vera", viewers))
	for _, path := range []string{"/api/v1/admin/users", "/api/v1/admin/users/" + te.admin.ID, "/api/v1/admin/groups"} {
		if st, code := te.as(p).do(t, "GET", path, nil, nil); st != http.StatusOK {
			t.Errorf("GET %s: %d %s", path, st, code)
		}
	}
	for _, c := range []struct{ method, path, msg string }{
		{"POST", "/api/v1/admin/users", "this needs the “Manage accounts” permission"},
		{"GET", "/api/v1/admin/users/" + te.member.ID + "/sessions", "this needs the “Reset sign-in” permission"},
		{"GET", "/api/v1/admin/invites", "this needs the “Invite people” permission"},
		{"POST", "/api/v1/admin/groups", "this needs the “Manage groups” permission"},
	} {
		te.who.Store(p)
		if st, body := rawDo(t, te, c.method, c.path, map[string]string{}); st != http.StatusForbidden || body.Error.Message != c.msg {
			t.Errorf("%s %s: %d %+v", c.method, c.path, st, body)
		}
	}
}

// Step-up covers every staff role — owner, admin and custom roles with a
// server permission — when an account or invitation gets one, any role
// change of an existing account, and the links of staff invitations.
func TestStaffRolesNeedStepUp(t *testing.T) {
	te := newTestEnv(t)
	sys := core.SystemPrincipal(core.ViaSocket)
	ctx := context.Background()
	helpdesk, err := te.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Helpdesk", Permissions: &[]core.Capability{core.CapUsersManage}})
	if err != nil {
		t.Fatal(err)
	}
	finance, err := te.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Finance"})
	if err != nil {
		t.Fatal(err)
	}
	adm, el := te.principal(te.admin, false), te.principal(te.admin, true)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/admin/users", core.NewUser{Username: "hd", RoleID: helpdesk.ID, GeneratePassword: true}},
		{"POST", "/api/v1/admin/users", core.NewUser{Username: "ad", RoleID: "admin", GeneratePassword: true}},
		{"POST", "/api/v1/admin/invites", core.InviteInput{RoleID: helpdesk.ID}},
		{"POST", "/api/v1/admin/invites", core.InviteInput{RoleID: "admin"}},
		// Any role change, staff or not, and whichever field names it.
		{"PATCH", "/api/v1/admin/users/" + te.member.ID, core.UserUpdate{RoleID: &finance.ID}},
		{"PATCH", "/api/v1/admin/users/" + te.member.ID, core.UserUpdate{RoleID: ptr("guest")}},
		{"PATCH", "/api/v1/admin/users/" + te.member.ID, core.UserUpdate{Role: ptr(core.RoleGuest)}},
	} {
		if st, code := te.as(adm).do(t, c.method, c.path, c.body, nil); st != http.StatusForbidden || code != "elevation_required" {
			t.Errorf("%s %s %+v: %d %s", c.method, c.path, c.body, st, code)
		}
		if st, code := te.as(el).do(t, c.method, c.path, c.body, nil); st >= 300 {
			t.Errorf("elevated %s %s %+v: %d %s", c.method, c.path, c.body, st, code)
		}
		// Undo the role change for the next case.
		if _, err := te.d.Users.Update(ctx, sys, te.member.ID, core.UserUpdate{RoleID: ptr("member")}); err != nil {
			t.Fatal(err)
		}
	}
	// No step-up: non-staff roles for new accounts and invitations, and the
	// current role sent again.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/admin/users", core.NewUser{Username: "fin", RoleID: finance.ID, GeneratePassword: true}},
		{"POST", "/api/v1/admin/invites", core.InviteInput{RoleID: finance.ID, MaxUses: 5}},
		{"PATCH", "/api/v1/admin/users/" + te.member.ID, core.UserUpdate{RoleID: ptr("member"), DisplayName: ptr("M")}},
		{"PATCH", "/api/v1/admin/users/" + te.member.ID, core.UserUpdate{Role: ptr(core.RoleMember)}},
	} {
		if st, code := te.as(adm).do(t, c.method, c.path, c.body, nil); st >= 300 {
			t.Errorf("%s %s %+v: %d %s", c.method, c.path, c.body, st, code)
		}
	}
	// An unknown role is the service's 422, not a step-up prompt.
	if st, code := te.as(adm).do(t, "POST", "/api/v1/admin/users",
		core.NewUser{Username: "x", RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na", GeneratePassword: true}, nil); st != 422 {
		t.Errorf("unknown role: %d %s", st, code)
	}

	// Invitation links: staff ones only with step-up.
	var list core.Page[core.Invite]
	if st, _ := te.as(adm).do(t, "GET", "/api/v1/admin/invites", nil, &list); st != 200 || len(list.Items) != 3 {
		t.Fatalf("list: %d %+v", st, list)
	}
	for _, inv := range list.Items {
		if staff := inv.RoleID != finance.ID; (inv.URL == "") != staff {
			t.Errorf("unelevated: %s link shown %v", inv.RoleName, inv.URL != "")
		}
	}
	if st, _ := te.as(el).do(t, "GET", "/api/v1/admin/invites", nil, &list); st != 200 {
		t.Fatalf("list elevated: %d", st)
	}
	for _, inv := range list.Items {
		if inv.URL == "" {
			t.Errorf("elevated: %s link hidden", inv.RoleName)
		}
	}

	// GET /admin/users?role_id=
	var page core.Page[core.User]
	if st, _ := te.as(adm).do(t, "GET", "/api/v1/admin/users?role_id="+helpdesk.ID, nil, &page); st != 200 ||
		len(page.Items) != 1 || page.Items[0].Username != "hd" || page.Items[0].RoleName != "Helpdesk" {
		t.Fatalf("role_id filter: %d %+v", st, page)
	}
	if st, code := te.as(adm).do(t, "GET", "/api/v1/admin/users?role_id=Helpdesk", nil, nil); st != 422 {
		t.Fatalf("bad role_id filter: %d %s", st, code)
	}
}

// A delegate works through the API with the rules of the users service.
func TestDelegateAccountRoutes(t *testing.T) {
	te := newTestEnv(t)
	helpdesk := te.addRole(t, "Helpdesk", core.MemberCaps.With(core.CapUsersManage, core.CapUsersCredentials), false)
	finance := te.addRole(t, "Finance", core.MemberCaps, false)
	p := te.delegate(te.holder(t, "hana", helpdesk))
	var created core.UserCreated
	if st, code := te.as(p).do(t, "POST", "/api/v1/admin/users", core.NewUser{Username: "newbie", GeneratePassword: true}, &created); st != 201 ||
		created.User == nil || created.User.RoleID != "member" {
		t.Fatalf("create member: %d %s %+v", st, code, created)
	}
	for _, c := range []struct {
		method, path string
		body         any
		msg          string
	}{
		{"POST", "/api/v1/admin/users", core.NewUser{Username: "boss", Role: core.RoleAdmin, GeneratePassword: true},
			"only administrators can grant the admin role"},
		{"POST", "/api/v1/admin/users", core.NewUser{Username: "fin2", RoleID: finance, GeneratePassword: true},
			"administrators have not allowed account managers to give the role “Finance”"},
		{"PATCH", "/api/v1/admin/users/" + te.admin.ID, core.UserUpdate{DisplayName: ptr("x")},
			"only administrators can manage administrator accounts"},
		{"POST", "/api/v1/admin/users/" + te.owner.ID + "/disable", nil, "administrators cannot modify owner accounts"},
		{"DELETE", "/api/v1/admin/users/" + te.member.ID + "?transfer_to=" + te.admin.ID, nil,
			"only administrators can manage administrator accounts"},
	} {
		te.who.Store(p)
		if st, body := rawDo(t, te, c.method, c.path, c.body); st != http.StatusForbidden || body.Error.Message != c.msg {
			t.Errorf("%s %s: %d %+v", c.method, c.path, st, body)
		}
	}
	if st, code := te.as(p).do(t, "PATCH", "/api/v1/admin/users/"+created.User.ID, core.UserUpdate{Role: ptr(core.RoleGuest)}, nil); st != 200 {
		t.Fatalf("member → guest: %d %s", st, code)
	}
}
