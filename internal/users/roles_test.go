package users

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
)

// ---------- helpers ----------

// get re-reads u (its role fields change with role edits).
func (te *testEnv) get(t *testing.T, u *core.User) *core.User {
	t.Helper()
	x, err := te.svc.Get(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("get %s: %v", u.Username, err)
	}
	return x
}

// principalOf is the principal auth builds for u as it is stored now.
func (te *testEnv) principalOf(t *testing.T, u *core.User) *core.Principal {
	t.Helper()
	return asRole(te.get(t, u))
}

// authzEvents subscribes to authz.changed; the returned func drains what was
// published so far (Publish delivers synchronously into the buffer).
func (te *testEnv) authzEvents(t *testing.T) func() []core.AuthzChangedEvent {
	t.Helper()
	ch, cancel := te.env.Bus.Subscribe(events.TopicAuthzChanged)
	t.Cleanup(cancel)
	return func() []core.AuthzChangedEvent {
		var out []core.AuthzChangedEvent
		for {
			select {
			case e := <-ch:
				out = append(out, e.Data.(core.AuthzChangedEvent))
			default:
				return out
			}
		}
	}
}

// createRole creates a role through the service as the system principal.
func (te *testEnv) createRole(t *testing.T, in core.RoleDefInput) *core.RoleDef {
	t.Helper()
	r, err := te.svc.CreateRole(context.Background(), system(), in)
	if err != nil {
		t.Fatalf("create role %s: %v", in.Name, err)
	}
	return r
}

func capList(cs ...core.Capability) *[]core.Capability { return &cs }

// wantErr fails unless err is base with message msg ("" = any message) and
// field field ("" = any field).
func wantErr(t *testing.T, what string, err error, base *core.Error, field, msg string) {
	t.Helper()
	e := core.AsError(err)
	if e == nil || !errors.Is(err, base) || (field != "" && e.Field != field) || (msg != "" && e.Message != msg) {
		t.Errorf("%s: got %v (field %q), want %s field %q %q", what, err, fieldOf(err), base.Code, field, msg)
	}
}

// ---------- CRUD ----------

func TestRoleCreate(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	helpdeskPerms := core.MemberCaps.With(core.CapUsersManage, core.CapUsersCredentials)

	r, err := te.svc.CreateRole(ctx, as(admin), core.RoleDefInput{
		Name: " Helpdesk ", Description: "Front-line support\nsecond line", Base: core.RoleMember, CopyFrom: "member",
		Permissions: capList(core.CapShareLinks, core.CapShareRequests, core.CapUsersLookup, core.CapTokensCreate,
			core.CapUsersManage, core.CapUsersCredentials, core.CapUsersManage),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ids.Valid(ids.PrefixRole, r.ID) || r.Name != "Helpdesk" || r.Description != "Front-line support\nsecond line" ||
		r.Builtin || r.Base != core.RoleMember || r.Delegable || !r.Staff || r.CreatedBy != admin.ID ||
		r.UpdatedBy != admin.ID || r.CreatedAt == nil || !r.CreatedAt.Equal(te.clock.Now()) {
		t.Fatalf("role %+v", r)
	}
	// Implied permissions are stored with the role (users.view).
	if r.Permissions != helpdeskPerms.With(core.CapUsersView) {
		t.Fatalf("permissions %v", r.Permissions)
	}
	if !r.Editable || !r.Assignable || r.UserCount != 0 || r.GroupCount != 0 || r.GrantCount != 0 {
		t.Fatalf("caller fields %+v", r)
	}
	var stored string
	if err := te.env.DB.QueryRow(ctx, `SELECT permissions FROM roles WHERE id = ?`, r.ID).Scan(&stored); err != nil ||
		stored != core.EncodeCaps(r.Permissions) {
		t.Fatalf("stored %s %v", stored, err)
	}
	e, ok := te.audit.last(core.ActRoleCreate)
	d, _ := e.Details.(map[string]any)
	if !ok || e.ActorID != admin.ID || e.TargetType != "role" || e.TargetID != r.ID || e.TargetName != "Helpdesk" ||
		d["base"] != core.RoleMember || d["permissions"] != r.Permissions || d["delegable"] != false || d["copy_from"] != "member" {
		t.Fatalf("audit %+v", e)
	}

	// Defaults: the base's permissions; copy_from gives the base and the
	// permissions of the copied role (owner/admin: everything, base member).
	te.settings.set(settingGuestsShare, true)
	for _, c := range []struct {
		in    core.RoleDefInput
		base  core.Role
		perms core.CapSet
	}{
		{core.RoleDefInput{Name: "Plain"}, core.RoleMember, core.MemberCaps},
		{core.RoleDefInput{Name: "Visitors", Base: core.RoleGuest}, core.RoleGuest, 0},
		{core.RoleDefInput{Name: "From member", CopyFrom: "member"}, core.RoleMember, core.MemberCaps},
		{core.RoleDefInput{Name: "From guest", CopyFrom: "guest"}, core.RoleGuest,
			core.NewCapSet(core.CapShareLinks, core.CapShareRequests)},
		{core.RoleDefInput{Name: "From admin", CopyFrom: "admin"}, core.RoleMember, core.AllCaps},
		{core.RoleDefInput{Name: "From owner", CopyFrom: "owner", Base: core.RoleGuest}, core.RoleGuest, core.AllCaps},
		{core.RoleDefInput{Name: "From helpdesk", CopyFrom: r.ID}, core.RoleMember, r.Permissions},
		{core.RoleDefInput{Name: "Override", CopyFrom: "admin", Permissions: capList(core.CapAuditView)}, core.RoleMember,
			core.NewCapSet(core.CapAuditView)},
		{core.RoleDefInput{Name: "Nothing", Permissions: capList()}, core.RoleMember, 0},
		{core.RoleDefInput{Name: "Operators", Permissions: capList(core.CapSystemManage), Delegable: true}, core.RoleMember,
			core.NewCapSet(core.CapSystemManage, core.CapSystemView)},
	} {
		got, err := te.svc.CreateRole(ctx, as(admin), c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in.Name, err)
			continue
		}
		if got.Base != c.base || got.Permissions != c.perms || got.Delegable != c.in.Delegable || got.Staff != (c.perms.Server() != 0) {
			t.Errorf("%s: base %s perms %v delegable %v staff %v", c.in.Name, got.Base, got.Permissions, got.Delegable, got.Staff)
		}
	}
	te.settings.set(settingGuestsShare, false)

	for _, c := range []struct {
		in         core.RoleDefInput
		base       *core.Error
		field, msg string
	}{
		{core.RoleDefInput{Name: "X", Base: core.RoleAdmin}, core.ErrInvalid, "base", "custom roles are based on member or guest"},
		{core.RoleDefInput{Name: "X", Base: "boss"}, core.ErrInvalid, "base", ""},
		{core.RoleDefInput{Name: "X", Permissions: capList("files.teleport")}, core.ErrInvalid, "permissions",
			`unknown permission "files.teleport"`},
		{core.RoleDefInput{Name: "X", CopyFrom: "rol_01k5z8r3m9d4q7w2x6c1v0b5na"}, core.ErrInvalid, "copy_from", "unknown role"},
		{core.RoleDefInput{Name: "X", CopyFrom: "system"}, core.ErrInvalid, "copy_from", "unknown role"},
		{core.RoleDefInput{Name: "helpdesk"}, core.ErrConflict, "name", "a role with this name already exists"},
	} {
		_, err := te.svc.CreateRole(ctx, as(admin), c.in)
		wantErr(t, fmt.Sprintf("create %+v", c.in), err, c.base, c.field, c.msg)
	}
	if n := te.count(t, `SELECT count(*) FROM roles`); n != 11 {
		t.Fatalf("%d roles", n)
	}
}

func TestRoleNameRules(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.createRole(t, core.RoleDefInput{Name: "Équipe"})
	for _, c := range []struct{ name, msg string }{
		{"", "role name must not be empty"},
		{"   ", "role name must not be empty"},
		{"ADMIN", "“ADMIN” is a reserved role name"},
		{" Administrator ", "“Administrator” is a reserved role name"},
		{"owner", "“owner” is a reserved role name"},
		{"Member", "“Member” is a reserved role name"},
		{"GUEST", "“GUEST” is a reserved role name"},
		{"System", "“System” is a reserved role name"},
		{"everyone", "“everyone” is a reserved role name"},
		{"All", "“All” is a reserved role name"},
		{"none", "“none” is a reserved role name"},
		{"rol_01k5z8r3m9d4q7w2x6c1v0b5na", "role names cannot start with “rol_”"},
		{"ROL_x", "role names cannot start with “rol_”"},
		{strings.Repeat("x", 65), "role name is longer than 64 characters"},
		{"a\x07b", "role name must not contain control or text-direction characters"},
		{"a\u202eb", "role name must not contain control or text-direction characters"},
		{"\xff", "role name is not valid UTF-8"},
	} {
		_, err := te.svc.CreateRole(ctx, system(), core.RoleDefInput{Name: c.name})
		wantErr(t, fmt.Sprintf("name %q", c.name), err, core.ErrInvalid, "name", c.msg)
	}
	// Unique like node names: case-insensitively, beyond ASCII.
	for _, dup := range []string{"équipe", "ÉQUIPE", "Équipe"} {
		_, err := te.svc.CreateRole(ctx, system(), core.RoleDefInput{Name: dup})
		wantErr(t, "duplicate "+dup, err, core.ErrConflict, "name", "a role with this name already exists")
	}
	ok := te.createRole(t, core.RoleDefInput{Name: strings.Repeat("技", 64)})
	if utf8Len := len([]rune(ok.Name)); utf8Len != 64 {
		t.Fatalf("64 characters: %d", utf8Len)
	}
	// Descriptions: newlines yes, other control characters no, 500 characters.
	for _, c := range []struct {
		desc string
		ok   bool
	}{
		{"line one\nline two", true}, {strings.Repeat("d", 500), true},
		{"tab\there", false}, {strings.Repeat("d", 501), false}, {"bell\x07", false},
	} {
		_, err := te.svc.UpdateRole(ctx, system(), ok.ID, core.RoleDefUpdate{Description: &c.desc})
		if (err == nil) != c.ok || (!c.ok && fieldOf(err) != "description") {
			t.Errorf("description %q: %v", c.desc, err)
		}
	}
}

func TestRoleLimit(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	now := db.Ms(te.clock.Now())
	for i := range maxCustomRoles {
		te.exec(t, `INSERT INTO roles (id, name, base, created_at, updated_at) VALUES (?, ?, 'member', ?, ?)`,
			ids.New(ids.PrefixRole), fmt.Sprintf("Role %03d", i), now, now)
	}
	_, err := te.svc.CreateRole(ctx, system(), core.RoleDefInput{Name: "One too many"})
	wantErr(t, "201st role", err, core.ErrInvalid, "name", "at most 200 roles")
}

func TestRoleAdminOnly(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	r := te.createRole(t, core.RoleDefInput{Name: "Helpdesk", Permissions: capList(core.CapUsersManage), Delegable: true})
	hana := te.mkUser(t, "hana", core.RoleMember)
	te.giveRole(t, hana, r.ID)
	token := as(admin)
	token.Via, token.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	for who, p := range map[string]*core.Principal{
		"member": as(te.mkUser(t, "mia", core.RoleMember)), "delegate": te.principalOf(t, hana), "admin token": token,
	} {
		_, err := te.svc.CreateRole(ctx, p, core.RoleDefInput{Name: "Sneaky"})
		wantErr(t, who+" creates", err, core.ErrForbidden, "", "only administrators can manage roles")
		_, err = te.svc.UpdateRole(ctx, p, r.ID, core.RoleDefUpdate{AddPermissions: []core.Capability{core.CapAuditView}})
		wantErr(t, who+" updates", err, core.ErrForbidden, "", "only administrators can manage roles")
		err = te.svc.DeleteRole(ctx, p, r.ID, "member")
		wantErr(t, who+" deletes", err, core.ErrForbidden, "", "only administrators can manage roles")
	}
	if _, err := te.svc.CreateRole(ctx, nil, core.RoleDefInput{Name: "X"}); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("anonymous: %v", err)
	}
	if got := te.get(t, hana); got.RoleID != r.ID || got.Permissions != core.NewCapSet(core.CapUsersManage, core.CapUsersView) {
		t.Fatalf("role changed: %+v", got)
	}
}

func TestRoleUpdate(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	r := te.createRole(t, core.RoleDefInput{Name: "Helpdesk",
		Permissions: capList(core.CapUsersLookup, core.CapUsersManage, core.CapUsersCredentials)})
	te.createRole(t, core.RoleDefInput{Name: "Finance"})
	hana := te.mkUser(t, "hana", core.RoleMember)
	te.giveRole(t, hana, r.ID)
	te.exec(t, `INSERT INTO sessions (id, token_hash, user_id, auth_level, csrf_secret, created_at, last_seen_at,
		idle_expires_at, expires_at, elevated_until) VALUES ('ses_h', x'01', ?, 2, x'02', 1, 1, 9999999999999, 9999999999999, 9999999999999)`, hana.ID)
	evs := te.authzEvents(t)
	te.audit.reset()
	te.clock.Advance(time.Minute)

	update := func(in core.RoleDefUpdate) *core.RoleDef {
		t.Helper()
		got, err := te.svc.UpdateRole(ctx, as(admin), r.ID, in)
		if err != nil {
			t.Fatalf("update %+v: %v", in, err)
		}
		return got
	}
	// Add and remove (users.view stays: users.credentials still implies it).
	got := update(core.RoleDefUpdate{AddPermissions: []core.Capability{core.CapAuditView},
		RemovePermissions: []core.Capability{core.CapUsersManage, core.CapUsersView}})
	want := core.NewCapSet(core.CapUsersLookup, core.CapUsersCredentials, core.CapUsersView, core.CapAuditView)
	if got.Permissions != want || !got.UpdatedAt.Equal(te.clock.Now()) || got.UpdatedBy != admin.ID || got.UserCount != 1 {
		t.Fatalf("add/remove: %+v", got)
	}
	e, _ := te.audit.last(core.ActRoleUpdate)
	d, _ := e.Details.(map[string]any)
	p, _ := d["permissions"].(map[string]any)
	if e.TargetID != r.ID || p["added"] != core.NewCapSet(core.CapAuditView) || p["removed"] != core.NewCapSet(core.CapUsersManage) ||
		d["users"] != 1 || d["name"] != nil || d["delegable"] != nil {
		t.Fatalf("audit %+v", e)
	}
	// A server permission was added: the holder's step-up window is closed.
	if n := te.count(t, `SELECT count(*) FROM sessions WHERE elevated_until IS NOT NULL`); n != 0 {
		t.Fatal("step-up window kept after new server permissions")
	}
	if ev := evs(); len(ev) != 1 || ev[0].RoleID != r.ID || ev[0].Reason != core.AuthzRoleUpdated || ev[0].UserIDs != nil {
		t.Fatalf("events %+v", ev)
	}
	// The holder's permissions follow at once.
	if u := te.get(t, hana); u.Permissions != want {
		t.Fatalf("holder permissions %v", u.Permissions)
	}

	// Replace (closure applied), rename, describe, delegable.
	got = update(core.RoleDefUpdate{Name: ptr("Support"), Description: ptr("desk"), Delegable: ptr(true),
		Permissions: capList(core.CapUsersManage)})
	if got.Name != "Support" || got.Description != "desk" || !got.Delegable ||
		got.Permissions != core.NewCapSet(core.CapUsersManage, core.CapUsersView) {
		t.Fatalf("replace: %+v", got)
	}
	e, _ = te.audit.last(core.ActRoleUpdate)
	d, _ = e.Details.(map[string]any)
	if e.TargetName != "Support" || d["description"] != true ||
		fmt.Sprint(d["name"]) != fmt.Sprint(map[string]string{"from": "Helpdesk", "to": "Support"}) ||
		fmt.Sprint(d["delegable"]) != fmt.Sprint(map[string]bool{"from": false, "to": true}) {
		t.Fatalf("audit %+v", e)
	}
	// Removing an implied permission while its source stays changes nothing,
	// and neither does an unchanged value: no audit entry, no event.
	evs()
	te.audit.reset()
	got = update(core.RoleDefUpdate{Name: ptr("Support"), RemovePermissions: []core.Capability{core.CapUsersView}})
	if got.Permissions != core.NewCapSet(core.CapUsersManage, core.CapUsersView) || len(te.audit.actions()) != 0 || len(evs()) != 0 {
		t.Fatalf("no-op: %v %v", got.Permissions, te.audit.actions())
	}
	// Re-case the own name.
	if got = update(core.RoleDefUpdate{Name: ptr("SUPPORT")}); got.Name != "SUPPORT" {
		t.Fatalf("recase %q", got.Name)
	}

	for _, c := range []struct {
		id         string
		in         core.RoleDefUpdate
		base       *core.Error
		field, msg string
	}{
		{"member", core.RoleDefUpdate{Name: ptr("x")}, core.ErrInvalid, "id", "built-in roles cannot be changed; duplicate one instead"},
		{"admin", core.RoleDefUpdate{}, core.ErrInvalid, "id", ""},
		{r.ID, core.RoleDefUpdate{Permissions: capList(), AddPermissions: []core.Capability{core.CapAuditView}},
			core.ErrInvalid, "permissions", "send either permissions or add_permissions/remove_permissions, not both"},
		{r.ID, core.RoleDefUpdate{AddPermissions: []core.Capability{"bogus"}}, core.ErrInvalid, "permissions", `unknown permission "bogus"`},
		{r.ID, core.RoleDefUpdate{Name: ptr("finance")}, core.ErrConflict, "name", "a role with this name already exists"},
		{r.ID, core.RoleDefUpdate{Name: ptr("guest")}, core.ErrInvalid, "name", ""},
		{"rol_01k5z8r3m9d4q7w2x6c1v0b5na", core.RoleDefUpdate{Name: ptr("x")}, core.ErrNotFound, "", "role not found"},
		{"system", core.RoleDefUpdate{Name: ptr("x")}, core.ErrNotFound, "", ""},
	} {
		_, err := te.svc.UpdateRole(ctx, as(admin), c.id, c.in)
		wantErr(t, fmt.Sprintf("update %s %+v", c.id, c.in), err, c.base, c.field, c.msg)
	}
	// Taking server permissions away leaves step-up windows alone.
	te.exec(t, `UPDATE sessions SET elevated_until = 9999999999999`)
	update(core.RoleDefUpdate{Permissions: capList()})
	if n := te.count(t, `SELECT count(*) FROM sessions WHERE elevated_until IS NOT NULL`); n != 1 {
		t.Fatal("step-up window closed without new permissions")
	}
}

// ---------- delete ----------

func TestRoleDelete(t *testing.T) {
	ctx := context.Background()
	type env struct {
		te        *testEnv
		admin     *core.User
		role      *core.RoleDef
		ann, bob  *core.User
		inv, used string
		grp       *core.Group
		grantNode string
	}
	setup := func(t *testing.T, base core.Role) env {
		te := newTestEnv(t)
		e := env{te: te, admin: te.mkUser(t, "admin", core.RoleAdmin)}
		e.role = te.createRole(t, core.RoleDefInput{Name: "Finance", Base: base,
			Permissions: capList(core.CapShareLinks, core.CapInvitesManage)})
		e.ann = te.mkUser(t, "ann", base)
		e.bob = te.mkUser(t, "bob", base)
		for _, u := range []*core.User{e.ann, e.bob} {
			if _, err := te.svc.Update(ctx, system(), u.ID, core.UserUpdate{RoleID: &e.role.ID}); err != nil {
				t.Fatal(err)
			}
		}
		inv, _, err := te.svc.CreateInvite(ctx, as(e.admin), core.InviteInput{RoleID: e.role.ID})
		if err != nil {
			t.Fatal(err)
		}
		e.inv = inv.ID
		used, tok, err := te.svc.CreateInvite(ctx, as(e.admin), core.InviteInput{RoleID: e.role.ID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "early"}, testPHC, core.ReqMeta{}); err != nil {
			t.Fatal(err)
		}
		e.used = used.ID
		// ann (as a Finance holder with invites.manage) invited someone.
		if _, _, err := te.svc.CreateInvite(ctx, te.principalOf(t, e.ann), core.InviteInput{}); err != nil {
			t.Fatal(err)
		}
		if e.grp, err = te.svc.CreateGroup(ctx, as(e.admin), core.GroupInput{Name: "Accounts"}); err != nil {
			t.Fatal(err)
		}
		if _, err := te.svc.SetRoleGroup(ctx, as(e.admin), e.role.ID, e.grp.ID, core.GroupRoleManager); err != nil {
			t.Fatal(err)
		}
		e.grantNode = te.rootOf(t, e.grp.SpaceID)
		te.exec(t, `INSERT INTO node_grants (id, node_id, subject_type, subject_id, role, created_at) VALUES
			('gnt_r1', ?, 'role', ?, 'editor', 1)`, e.grantNode, e.role.ID)
		te.exec(t, `INSERT INTO sessions (id, token_hash, user_id, auth_level, csrf_secret, created_at, last_seen_at,
			idle_expires_at, expires_at, elevated_until) VALUES ('ses_a', x'01', ?, 2, x'02', 1, 1, 9999999999999, 9999999999999, 9999999999999)`, e.ann.ID)
		return e
	}

	t.Run("refusals", func(t *testing.T) {
		e := setup(t, core.RoleMember)
		te := e.te
		err := te.svc.DeleteRole(ctx, as(e.admin), e.role.ID, "")
		wantErr(t, "no reassign_to", err, core.ErrConflict, "reassign_to", "3 accounts have this role: choose a role to move them to")
		for _, bad := range []string{"owner", "admin", e.role.ID, "bogus", "system"} {
			err := te.svc.DeleteRole(ctx, as(e.admin), e.role.ID, bad)
			wantErr(t, "reassign_to "+bad, err, core.ErrInvalid, "reassign_to", "choose member, guest or another custom role")
		}
		err = te.svc.DeleteRole(ctx, as(e.admin), e.role.ID, "rol_01k5z8r3m9d4q7w2x6c1v0b5na")
		wantErr(t, "unknown reassign_to", err, core.ErrInvalid, "reassign_to", "unknown role")
		for _, b := range []string{"member", "guest", "owner"} {
			err := te.svc.DeleteRole(ctx, as(e.admin), b, "")
			wantErr(t, "built-in "+b, err, core.ErrInvalid, "id", "built-in roles cannot be deleted")
		}
		err = te.svc.DeleteRole(ctx, as(e.admin), "rol_01k5z8r3m9d4q7w2x6c1v0b5na", "member")
		wantErr(t, "unknown role", err, core.ErrNotFound, "", "role not found")
		// Moving to a guest-based role while holders have personal files.
		visitors := te.createRole(t, core.RoleDefInput{Name: "Visitors", Base: core.RoleGuest})
		for _, u := range []*core.User{e.ann, e.bob} {
			te.mkNode(t, u.SpaceID, te.rootOf(t, u.SpaceID), core.KindFile, "x.txt", 3)
		}
		for _, to := range []string{"guest", visitors.ID} {
			err := te.svc.DeleteRole(ctx, as(e.admin), e.role.ID, to)
			wantErr(t, "to "+to+" with files", err, core.ErrConflict, "reassign_to",
				"2 accounts still have personal files (ann, bob): move or delete them first, or reassign to a member-based role")
		}
		// Nothing changed.
		if n := te.count(t, `SELECT count(*) FROM users WHERE role_id = ?`, e.role.ID); n != 3 {
			t.Fatalf("holders %d", n)
		}
		if n := te.count(t, `SELECT count(*) FROM node_grants WHERE subject_id = ?`, e.role.ID); n != 1 {
			t.Fatalf("grants %d", n)
		}
		if te.count(t, `SELECT count(*) FROM spaces WHERE owner_user_id = ?`, e.ann.ID) != 1 {
			t.Fatal("space removed")
		}
		if n := te.count(t, `SELECT count(*) FROM invites WHERE revoked_at IS NOT NULL`); n != 0 {
			t.Fatalf("%d invites revoked", n)
		}
		// One holder: singular text.
		te.exec(t, `UPDATE users SET role = 'member', role_id = NULL WHERE id IN (?, ?)`, e.ann.ID, e.bob.ID)
		err = te.svc.DeleteRole(ctx, as(e.admin), e.role.ID, "")
		wantErr(t, "one holder", err, core.ErrConflict, "reassign_to", "1 account has this role: choose a role to move it to")
	})

	t.Run("reassign to member", func(t *testing.T) {
		e := setup(t, core.RoleMember)
		te := e.te
		evs := te.authzEvents(t)
		te.audit.reset()
		if err := te.svc.DeleteRole(ctx, as(e.admin), e.role.ID, "member"); err != nil {
			t.Fatal(err)
		}
		if _, err := te.svc.GetRole(ctx, nil, e.role.ID); !errors.Is(err, core.ErrNotFound) {
			t.Fatalf("role still exists: %v", err)
		}
		for _, u := range []*core.User{e.ann, e.bob} {
			got := te.get(t, u)
			if got.RoleID != "member" || got.Role != core.RoleMember || got.SpaceID != u.SpaceID {
				t.Fatalf("%s: %+v", u.Username, got)
			}
		}
		for q, want := range map[string]int{
			`SELECT count(*) FROM node_grants WHERE subject_type = 'role'`:                       0,
			`SELECT count(*) FROM role_groups`:                                                   0,
			`SELECT count(*) FROM sessions WHERE elevated_until IS NOT NULL`:                     0,
			`SELECT count(*) FROM invites WHERE id = '` + e.inv + `' AND revoked_at IS NOT NULL`: 1,
			// A used invitation keeps its status.
			`SELECT count(*) FROM invites WHERE id = '` + e.used + `' AND revoked_at IS NULL`: 1,
			// Member cannot invite: ann's own invitation went with the role.
			`SELECT count(*) FROM invites WHERE created_by = '` + e.ann.ID + `' AND revoked_at IS NOT NULL`: 1,
		} {
			if n := te.count(t, q); n != want {
				t.Errorf("%s = %d, want %d", q, n, want)
			}
		}
		page, _ := te.svc.ListInvites(ctx, as(e.admin), core.PageReq{})
		for _, inv := range page.Items {
			if (inv.ID == e.inv || inv.ID == e.used) && (inv.RoleName != "Deleted role" || inv.RoleID != e.role.ID) {
				t.Errorf("invite %s: %s %q", inv.ID, inv.RoleID, inv.RoleName)
			}
		}
		ent, ok := te.audit.last(core.ActRoleDelete)
		d, _ := ent.Details.(map[string]any)
		early, _ := te.svc.GetByUsername(ctx, "early")
		userIDs, _ := d["user_ids"].([]string)
		if !ok || ent.TargetID != e.role.ID || ent.TargetName != "Finance" || d["reassigned_to"] != "member" ||
			d["reassigned_to_name"] != "Member" || d["users_moved"] != 3 || len(userIDs) != 3 ||
			!slices.Contains(userIDs, early.ID) || d["invites_revoked"] != int64(1) || d["grants_removed"] != int64(1) ||
			d["groups_removed"] != 1 || d["truncated"] != nil {
			t.Fatalf("audit %+v", ent)
		}
		ev := evs()
		if len(ev) != 1 || ev[0].RoleID != e.role.ID || ev[0].Reason != core.AuthzRoleDeleted || len(ev[0].UserIDs) != 3 {
			t.Fatalf("events %+v", ev)
		}
	})

	t.Run("base change", func(t *testing.T) {
		e := setup(t, core.RoleGuest)
		te := e.te
		if e.ann.SpaceID != "" {
			t.Fatal("guest-based holder has a space")
		}
		staff := te.createRole(t, core.RoleDefInput{Name: "Staff", Permissions: capList(core.CapShareLinks, core.CapInvitesManage)})
		if err := te.svc.DeleteRole(ctx, as(e.admin), e.role.ID, staff.ID); err != nil {
			t.Fatal(err)
		}
		got := te.get(t, e.ann)
		if got.RoleID != staff.ID || got.Role != core.RoleMember || got.SpaceID == "" {
			t.Fatalf("moved holder %+v", got)
		}
		te.rootOf(t, got.SpaceID)
		// Staff can still invite: ann's invitation stays.
		if n := te.count(t, `SELECT count(*) FROM invites WHERE created_by = ? AND revoked_at IS NULL`, e.ann.ID); n != 1 {
			t.Fatalf("ann's invitation: %d", n)
		}
		// And back to guest when the personal spaces are empty.
		if err := te.svc.DeleteRole(ctx, as(e.admin), staff.ID, "guest"); err != nil {
			t.Fatal(err)
		}
		if got := te.get(t, e.ann); got.RoleID != "guest" || got.SpaceID != "" {
			t.Fatalf("back to guest %+v", got)
		}
	})

	t.Run("unassigned", func(t *testing.T) {
		te := newTestEnv(t)
		r := te.createRole(t, core.RoleDefInput{Name: "Unused"})
		evs := te.authzEvents(t)
		if err := te.svc.DeleteRole(ctx, system(), r.ID, ""); err != nil {
			t.Fatal(err)
		}
		if ev := evs(); len(ev) != 1 || ev[0].UserIDs != nil {
			t.Fatalf("events %+v", ev)
		}
		if e, _ := te.audit.last(core.ActRoleDelete); e.Details.(map[string]any)["users_moved"] != 0 {
			t.Fatalf("audit %+v", e)
		}
	})
}

// ---------- listing ----------

func TestListAndGetRoles(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	owner := te.mkUser(t, "owner", core.RoleOwner)
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	te.mkUser(t, "m1", core.RoleMember)
	te.mkUser(t, "m2", core.RoleMember)
	te.mkUser(t, "g1", core.RoleGuest)
	helpdesk := te.createRole(t, core.RoleDefInput{Name: "helpdesk", Permissions: capList(core.CapUsersManage, core.CapUsersCredentials)})
	finance := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	auditors := te.createRole(t, core.RoleDefInput{Name: "Auditors", Base: core.RoleGuest,
		Permissions: capList(core.CapAuditView), Delegable: true})
	contractors := te.createRole(t, core.RoleDefInput{Name: "contractors", Base: core.RoleGuest, Delegable: true})
	hana := te.mkUser(t, "hana", core.RoleMember)
	te.giveRole(t, hana, helpdesk.ID)
	fin := te.mkUser(t, "fin", core.RoleMember)
	te.giveRole(t, fin, finance.ID)
	g, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "Money"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.SetRoleGroup(ctx, as(admin), finance.ID, g.ID, ""); err != nil {
		t.Fatal(err)
	}
	root := te.rootOf(t, g.SpaceID)
	past, future := db.Ms(te.clock.Now().Add(-time.Hour)), db.Ms(te.clock.Now().Add(time.Hour))
	te.exec(t, `INSERT INTO node_grants (id, node_id, subject_type, subject_id, role, created_at, expires_at) VALUES
		('gnt_1', ?1, 'role', ?2, 'viewer', 1, NULL), ('gnt_2', ?3, 'role', ?2, 'editor', 1, ?4),
		('gnt_3', ?5, 'role', ?2, 'viewer', 1, ?6)`,
		root, finance.ID, te.rootOf(t, owner.SpaceID), future, te.rootOf(t, admin.SpaceID), past)

	list, err := te.svc.ListRoles(ctx, as(admin))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	byID := map[string]core.RoleDef{}
	for _, r := range list {
		order = append(order, r.Name)
		byID[r.ID] = r
	}
	if !slices.Equal(order, []string{"Owner", "Admin", "Member", "Guest", "Auditors", "contractors", "Finance", "helpdesk"}) {
		t.Fatalf("order %v", order)
	}
	// Built-ins count plain holders only; custom roles their holders, groups
	// and live grants.
	for id, want := range map[string][3]int{
		"owner": {1, 0, 0}, "admin": {1, 0, 0}, "member": {2, 0, 0}, "guest": {1, 0, 0},
		finance.ID: {1, 1, 2}, helpdesk.ID: {1, 0, 0}, auditors.ID: {0, 0, 0},
	} {
		r := byID[id]
		if got := [3]int{r.UserCount, r.GroupCount, r.GrantCount}; got != want {
			t.Errorf("%s counts %v, want %v", id, got, want)
		}
	}
	if r := byID["guest"]; !r.Builtin || r.Permissions != 0 || !r.Delegable || r.Staff || r.Description == "" {
		t.Errorf("guest %+v", r)
	}
	if r := byID["admin"]; !r.Staff || r.Delegable || r.Permissions != core.AllCaps {
		t.Errorf("admin %+v", r)
	}

	// Editable and Assignable follow the caller.
	delegate := te.principalOf(t, hana)
	viewer := te.createRole(t, core.RoleDefInput{Name: "Viewers", Permissions: capList(core.CapUsersView)})
	vic := te.mkUser(t, "vic", core.RoleMember)
	te.giveRole(t, vic, viewer.ID)
	for who, c := range map[string]struct {
		p          *core.Principal
		editable   bool
		assignable []string
	}{
		"owner":  {as(owner), true, []string{"owner", "admin", "member", "guest", auditors.ID, contractors.ID, finance.ID, helpdesk.ID}},
		"admin":  {as(admin), true, []string{"admin", "member", "guest", auditors.ID, contractors.ID, finance.ID, helpdesk.ID}},
		"system": {system(), true, []string{"owner", "admin", "member", "guest", auditors.ID, contractors.ID, finance.ID, helpdesk.ID}},
		// Member, Guest and delegable roles within the delegate's own server
		// permissions: not Auditors (audit.view), not Finance (not delegable).
		"delegate": {delegate, false, []string{"member", "guest", contractors.ID}},
		// users.view alone gives nothing.
		"viewer": {te.principalOf(t, vic), false, nil},
		"nil":    {nil, false, nil},
	} {
		list, err := te.svc.ListRoles(ctx, c.p)
		if err != nil {
			t.Fatal(err)
		}
		var assignable []string
		for _, r := range list {
			if r.Editable != (c.editable && !r.Builtin) {
				t.Errorf("%s: %s editable %v", who, r.ID, r.Editable)
			}
			if r.Assignable {
				assignable = append(assignable, r.ID)
			}
		}
		if r := slices.Index(assignable, viewer.ID); r >= 0 {
			assignable = slices.Delete(assignable, r, r+1)
		}
		if !slices.Equal(assignable, c.assignable) {
			t.Errorf("%s: assignable %v, want %v", who, assignable, c.assignable)
		}
	}

	// GetRole: built-in words and ids; the guest permissions follow the setting.
	te.settings.set(settingGuestsShare, true)
	r, err := te.svc.GetRole(ctx, nil, "guest")
	if err != nil || r.Permissions != core.NewCapSet(core.CapShareLinks, core.CapShareRequests) || r.UserCount != 1 ||
		r.Editable || r.Assignable {
		t.Fatalf("guest %+v %v", r, err)
	}
	if r, err := te.svc.GetRole(ctx, as(admin), finance.ID); err != nil || r.Name != "Finance" || r.GrantCount != 2 || !r.Editable {
		t.Fatalf("finance %+v %v", r, err)
	}
	for _, bad := range []string{"system", "", "rol_01k5z8r3m9d4q7w2x6c1v0b5na", "Finance", "rol_x"} {
		if _, err := te.svc.GetRole(ctx, as(admin), bad); !errors.Is(err, core.ErrNotFound) {
			t.Errorf("GetRole(%q): %v", bad, err)
		}
	}
}

func TestLookupRoles(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.createRole(t, core.RoleDefInput{Name: "zeta", Description: "last"})
	alpha := te.createRole(t, core.RoleDefInput{Name: "Alpha"})
	noLookup := te.createRole(t, core.RoleDefInput{Name: "Quiet", Permissions: capList(core.CapShareLinks)})
	viewers := te.createRole(t, core.RoleDefInput{Name: "Viewers", Base: core.RoleGuest, Permissions: capList(core.CapUsersView)})
	finders := te.createRole(t, core.RoleDefInput{Name: "Finders", Base: core.RoleGuest, Permissions: capList(core.CapUsersLookup)})
	holder := func(name string, base core.Role, roleID string) *core.Principal {
		u := te.mkUser(t, name, base)
		if roleID != "" {
			te.giveRole(t, u, roleID)
		}
		return te.principalOf(t, u)
	}
	for who, c := range map[string]struct {
		p  *core.Principal
		ok bool
	}{
		"member": {holder("mia", core.RoleMember, ""), true},
		"guest":  {holder("gus", core.RoleGuest, ""), false},
		"quiet":  {holder("qui", core.RoleMember, noLookup.ID), false},
		"viewer": {holder("vic", core.RoleGuest, viewers.ID), true},
		"finder": {holder("fay", core.RoleGuest, finders.ID), true},
	} {
		refs, err := te.svc.LookupRoles(ctx, c.p)
		if !c.ok {
			wantErr(t, who, err, core.ErrForbidden, "", "your role cannot search the user directory")
			_, err := te.svc.Lookup(ctx, c.p, "mia")
			wantErr(t, who+" users", err, core.ErrForbidden, "", "your role cannot search the user directory")
			continue
		}
		if err != nil || len(refs) != 5 || refs[0].ID != alpha.ID || refs[0].Name != "Alpha" || refs[4].Description != "last" {
			t.Errorf("%s: %+v %v", who, refs, err)
		}
		if users, err := te.svc.Lookup(ctx, c.p, "mia"); err != nil || len(users) != 1 {
			t.Errorf("%s users: %+v %v", who, users, err)
		}
	}
	if _, err := te.svc.LookupRoles(ctx, nil); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("anonymous: %v", err)
	}
}
