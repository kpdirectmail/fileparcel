package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/web"
)

// TestDelegateAccountFlows runs the account routes end to end — router,
// handlers, the users and auth services — for a delegate: a custom role
// with users.manage, users.credentials and invites.manage manages an
// ordinary member from creation to deletion, and every attempt on an
// administrator is refused with the escalation text and audited as denied.
func TestDelegateAccountFlows(t *testing.T) {
	g := newGuardEnv(t)
	ctx := context.Background()
	g.setPerms(g.probe, core.MemberCaps.With(core.CapUsersManage, core.CapUsersCredentials, core.CapInvitesManage))
	router := web.NewRouter(g.d)
	do := func(method, path string, body any, out any) (int, string) {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		r := httptest.NewRequest(method, path, rd)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		g.calls++
		r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:40000", byte(g.calls>>16), byte(g.calls>>8), byte(g.calls))
		g.creds["pat"].apply(r)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		if rec.Code >= 300 {
			_ = json.Unmarshal(rec.Body.Bytes(), &e)
		} else if out != nil {
			if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
				t.Fatalf("%s %s: %s: %v", method, path, rec.Body, err)
			}
		}
		return rec.Code, e.Error.Message
	}

	var created core.UserCreated
	if st, msg := do("POST", "/api/v1/admin/users", core.NewUser{Username: "newbie", GeneratePassword: true}, &created); st != 201 ||
		created.User == nil || created.User.RoleID != "member" || created.Password == "" {
		t.Fatalf("create: %d %s %+v", st, msg, created)
	}
	base := "/api/v1/admin/users/" + created.User.ID
	for _, c := range []struct {
		method, path string
		body         any
		want         int
	}{
		{"PATCH", base, core.UserUpdate{DisplayName: ptr("New Bie")}, 200},
		{"POST", base + "/disable", nil, 204},
		{"POST", base + "/enable", nil, 204},
		{"POST", base + "/unlock", nil, 204},
		{"POST", base + "/password", core.PasswordResetInput{Generate: true}, 200},
		{"POST", base + "/reset-mfa", nil, 204},
		{"GET", base + "/sessions", nil, 200},
		{"DELETE", base + "/sessions", nil, 204},
		{"PATCH", base, core.UserUpdate{Role: ptr(core.RoleGuest)}, 200},
	} {
		if st, msg := do(c.method, c.path, c.body, nil); st != c.want {
			t.Errorf("%s %s: %d %s", c.method, c.path, st, msg)
		}
	}
	var inv core.InviteCreated
	if st, msg := do("POST", "/api/v1/admin/invites", core.InviteInput{Role: core.RoleGuest}, &inv); st != 201 || inv.Invite == nil {
		t.Fatalf("invite: %d %s", st, msg)
	}
	var list core.Page[core.Invite]
	if st, _ := do("GET", "/api/v1/admin/invites", nil, &list); st != 200 || len(list.Items) != 1 || list.Items[0].URL == "" {
		t.Fatalf("invites: %d %+v", st, list)
	}
	if st, msg := do("DELETE", "/api/v1/admin/invites/"+inv.Invite.ID, nil, nil); st != 204 {
		t.Fatalf("revoke: %d %s", st, msg)
	}

	// An administrator is out of reach, and every attempt is on record.
	adam, err := g.d.Users.GetByUsername(ctx, "adam")
	if err != nil {
		t.Fatal(err)
	}
	const refusal = "only administrators can manage administrator accounts"
	attempts := []struct {
		method, suffix, action string
		body                   any
	}{
		{"PATCH", "", core.ActUserUpdate, core.UserUpdate{DisplayName: ptr("x")}},
		{"POST", "/disable", core.ActUserDisable, nil},
		{"POST", "/password", core.ActUserPasswordReset, core.PasswordResetInput{Generate: true}},
		{"POST", "/reset-mfa", core.ActUserMFAReset, nil},
		{"DELETE", "", core.ActUserDelete, nil},
	}
	for _, a := range attempts {
		if st, msg := do(a.method, "/api/v1/admin/users/"+adam.ID+a.suffix, a.body, nil); st != 403 || msg != refusal {
			t.Errorf("%s %s of adam: %d %s", a.method, a.suffix, st, msg)
		}
	}
	if st, msg := do("POST", "/api/v1/admin/invites", core.InviteInput{Role: core.RoleAdmin}, nil); st != 403 ||
		msg != "only administrators can grant the admin role" {
		t.Errorf("admin invite: %d %s", st, msg)
	}
	pat, _ := g.d.Users.GetByUsername(ctx, "pat")
	page, err := g.d.Audit.Query(ctx, core.AuditQuery{ActorID: pat.ID, Outcome: core.OutcomeDenied})
	if err != nil {
		t.Fatal(err)
	}
	denied := map[string]int{}
	for _, r := range page.Items {
		if r.TargetID == adam.ID || r.Action == core.ActInviteCreate {
			denied[r.Action]++
		}
	}
	for _, a := range attempts {
		if denied[a.action] != 1 {
			t.Errorf("%s: %d denied entries (%v)", a.action, denied[a.action], denied)
		}
	}
	if denied[core.ActInviteCreate] != 1 {
		t.Errorf("invite.create: %d denied entries", denied[core.ActInviteCreate])
	}

	if st, msg := do("DELETE", base, nil, nil); st != 204 {
		t.Fatalf("delete: %d %s", st, msg)
	}
}

func ptr[T any](v T) *T { return &v }
