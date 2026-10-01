package users

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

func TestCreateMakesSpaceAndRoot(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	for _, role := range []core.Role{core.RoleOwner, core.RoleAdmin, core.RoleMember} {
		u := te.mkUser(t, "u-"+string(role), role)
		if u.SpaceID == "" {
			t.Fatalf("%s: no personal space", role)
		}
		var kind, owner, name string
		if err := te.env.DB.QueryRow(ctx, `SELECT kind, owner_user_id, name FROM spaces WHERE id = ?`, u.SpaceID).Scan(&kind, &owner, &name); err != nil {
			t.Fatal(err)
		}
		if kind != core.SpaceUser || owner != u.ID || name != PersonalSpaceName {
			t.Fatalf("%s: space %s %s %s", role, kind, owner, name)
		}
		var rootName, rootKey, rootKind string
		if err := te.env.DB.QueryRow(ctx, `SELECT name, name_key, kind FROM nodes WHERE space_id = ? AND parent_id IS NULL`, u.SpaceID).
			Scan(&rootName, &rootKey, &rootKind); err != nil {
			t.Fatal(err)
		}
		if rootName != "My files" || rootKey != "my files" || rootKind != core.KindFolder {
			t.Fatalf("%s: root %q %q %q", role, rootName, rootKey, rootKind)
		}
		if len(u.WebAuthnHandle) != webAuthnHandleLen || u.PasswordHash != testPHC || u.PasswordChangedAt == nil || u.Status != core.UserActive {
			t.Fatalf("%s: user fields %+v", role, u)
		}
	}
	g := te.mkUser(t, "guest1", core.RoleGuest)
	if g.SpaceID != "" || te.count(t, `SELECT count(*) FROM spaces WHERE owner_user_id = ?`, g.ID) != 0 {
		t.Fatal("guest got a personal space")
	}
	if e, ok := te.audit.last(core.ActUserCreate); !ok || e.TargetID != g.ID || e.TargetName != "guest1" {
		t.Fatalf("audit %+v", e)
	}
	// FTS index stays consistent.
	te.exec(t, `INSERT INTO nodes_fts(nodes_fts) VALUES ('integrity-check')`)
}

func TestCreateValidation(t *testing.T) {
	te := newTestEnv(t)
	te.mkUser(t, "Alice", core.RoleMember, withEmail("alice@example.com"))
	cases := []struct {
		name  string
		in    core.NewUser
		want  *core.Error
		field string
	}{
		{"empty username", core.NewUser{}, core.ErrInvalid, "username"},
		{"space in username", core.NewUser{Username: "bad name"}, core.ErrInvalid, "username"},
		{"leading dot", core.NewUser{Username: ".bob"}, core.ErrInvalid, "username"},
		{"trailing dash", core.NewUser{Username: "bob-"}, core.ErrInvalid, "username"},
		{"too long", core.NewUser{Username: strings.Repeat("a", 65)}, core.ErrInvalid, "username"},
		{"unicode", core.NewUser{Username: "bøb"}, core.ErrInvalid, "username"},
		{"reserved system", core.NewUser{Username: "System"}, core.ErrInvalid, "username"},
		{"id-like", core.NewUser{Username: "usr_01j9zq3x4k6m8p0r2t4v6x8z0b"}, core.ErrInvalid, "username"},
		{"duplicate case-insensitive", core.NewUser{Username: "alice"}, core.ErrConflict, "username"},
		{"duplicate email", core.NewUser{Username: "bob", Email: "ALICE@example.com"}, core.ErrConflict, "email"},
		{"bad email", core.NewUser{Username: "bob", Email: "not-an-email"}, core.ErrInvalid, "email"},
		{"email with name", core.NewUser{Username: "bob", Email: "Bob <bob@example.com>"}, core.ErrInvalid, "email"},
		{"bad role", core.NewUser{Username: "bob", Role: "root"}, core.ErrInvalid, "role"},
		{"system role", core.NewUser{Username: "bob", Role: core.RoleSystem}, core.ErrInvalid, "role"},
		{"negative quota", core.NewUser{Username: "bob", QuotaBytes: ptr[int64](-1)}, core.ErrInvalid, "quota_bytes"},
		{"bad group id", core.NewUser{Username: "bob", GroupIDs: []string{"nope"}}, core.ErrInvalid, "group_ids"},
		{"unknown group", core.NewUser{Username: "bob", GroupIDs: []string{"grp_01j9zq3x4k6m8p0r2t4v6x8z0b"}}, core.ErrInvalid, "group_ids"},
		{"bad hash", core.NewUser{Username: "bob", PasswordHash: "plaintext"}, core.ErrInvalid, "password"},
		{"control in display name", core.NewUser{Username: "bob", DisplayName: "a\x01b"}, core.ErrInvalid, "display_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := te.svc.Create(context.Background(), system(), tc.in)
			ce := core.AsError(err)
			if !errors.Is(err, tc.want) || ce == nil || ce.Field != tc.field {
				t.Fatalf("got %v (field %q), want %s on %q", err, fieldOf(err), tc.want.Code, tc.field)
			}
		})
	}
	// Normalization.
	u, err := te.svc.Create(context.Background(), system(), core.NewUser{Username: "  carol ", DisplayName: "  Carol   Q.\tPublic ", PasswordHash: testPHC})
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "carol" || u.DisplayName != "Carol Q. Public" || u.Role != core.RoleMember {
		t.Fatalf("normalized %+v", u)
	}
	d := te.mkUser(t, "dave", core.RoleMember)
	if d.DisplayName != "dave" {
		t.Fatalf("default display name %q", d.DisplayName)
	}
	// Failed creates leave nothing behind (one transaction).
	if n := te.count(t, `SELECT count(*) FROM users`); n != 3 {
		t.Fatalf("users %d", n)
	}
	if n := te.count(t, `SELECT count(*) FROM spaces`); n != 3 {
		t.Fatalf("spaces %d", n)
	}
}

func fieldOf(err error) string {
	if ce := core.AsError(err); ce != nil {
		return ce.Field
	}
	return ""
}

func TestCreateAuthorization(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	owner := te.mkUser(t, "owner", core.RoleOwner)
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	member := te.mkUser(t, "member", core.RoleMember)
	cases := []struct {
		name string
		by   *core.Principal
		role core.Role
		want error
	}{
		{"anonymous", nil, core.RoleMember, core.ErrUnauthorized},
		{"member", as(member), core.RoleMember, core.ErrForbidden},
		{"admin creates member", as(admin), core.RoleMember, nil},
		{"admin creates admin", as(admin), core.RoleAdmin, nil},
		{"admin creates owner", as(admin), core.RoleOwner, core.ErrForbidden},
		{"owner creates owner", as(owner), core.RoleOwner, nil},
		{"system creates owner", system(), core.RoleOwner, nil},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := te.svc.Create(ctx, tc.by, core.NewUser{Username: "n" + string(rune('a'+i)), Role: tc.role, PasswordHash: testPHC})
			if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestBootstrap(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	u, err := te.svc.Bootstrap(ctx, core.NewUser{Username: "admin", Role: core.RoleGuest, PasswordHash: testPHC, MustChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != core.RoleOwner || u.SpaceID == "" || !u.MustChangePassword {
		t.Fatalf("bootstrap user %+v", u)
	}
	if e, ok := te.audit.last(core.ActUserCreate); !ok || e.ActorID != u.ID {
		t.Fatalf("audit %+v", e)
	}
	if _, err := te.svc.Bootstrap(ctx, core.NewUser{Username: "second", PasswordHash: testPHC}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("second bootstrap: %v", err)
	}
	if n, err := te.svc.Count(ctx); err != nil || n != 1 {
		t.Fatalf("count %d %v", n, err)
	}
}

func TestGetAndDerivedFields(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	u := te.mkUser(t, "Alice", core.RoleMember, withEmail("alice@example.com"))
	for _, name := range []string{"alice", "ALICE", " Alice "} {
		got, err := te.svc.GetByUsername(ctx, name)
		if err != nil || got.ID != u.ID {
			t.Fatalf("GetByUsername(%q) = %v %v", name, got, err)
		}
	}
	if _, err := te.svc.Get(ctx, "usr_missing"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := te.svc.GetByUsername(ctx, ""); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
	if u.MFAEnabled {
		t.Fatal("mfa without factors")
	}
	te.exec(t, `INSERT INTO totp_secrets (user_id, secret_enc, confirmed_at, created_at) VALUES (?, 'x', 1, 1)`, u.ID)
	got, _ := te.svc.Get(ctx, u.ID)
	if !got.MFAEnabled {
		t.Fatal("mfa not derived")
	}
	b, _ := json.Marshal(got)
	for _, secret := range []string{"password_hash", "argon2id", "webauthn_handle"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("JSON leaks %s: %s", secret, b)
		}
	}
}

func TestListUsers(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	names := []string{"delta", "Alpha", "charlie", "bravo", "echo"}
	for i, n := range names {
		role := core.RoleMember
		if i == 0 {
			role = core.RoleAdmin
		}
		te.mkUser(t, n, role, withEmail(n+"@example.com"))
		te.clock.Advance(1000)
	}
	e, _ := te.svc.GetByUsername(ctx, "echo")
	if err := te.svc.SetStatus(ctx, system(), e.ID, core.UserDisabled); err != nil {
		t.Fatal(err)
	}
	usernames := func(q core.UserQuery) []string {
		t.Helper()
		var out []string
		for i := 0; i < 10; i++ {
			p, err := te.svc.List(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range p.Items {
				out = append(out, u.Username)
			}
			if p.NextCursor == "" {
				return out
			}
			q.Cursor = p.NextCursor
		}
		t.Fatal("pagination did not end")
		return nil
	}
	cases := []struct {
		name string
		q    core.UserQuery
		want []string
	}{
		{"default by username", core.UserQuery{}, []string{"Alpha", "bravo", "charlie", "delta", "echo"}},
		{"paged", core.UserQuery{PageReq: core.PageReq{Limit: 2}}, []string{"Alpha", "bravo", "charlie", "delta", "echo"}},
		{"desc paged", core.UserQuery{PageReq: core.PageReq{Limit: 2, Desc: true}}, []string{"echo", "delta", "charlie", "bravo", "Alpha"}},
		{"created", core.UserQuery{PageReq: core.PageReq{Limit: 3, Sort: SortCreated}}, names},
		{"role", core.UserQuery{Role: core.RoleAdmin}, []string{"delta"}},
		{"status", core.UserQuery{Status: core.UserDisabled}, []string{"echo"}},
		{"q username", core.UserQuery{Q: "ARL"}, []string{"charlie"}},
		{"q email", core.UserQuery{Q: "bravo@"}, []string{"bravo"}},
		{"q wildcard escaped", core.UserQuery{Q: "%"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := usernames(tc.q); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	for _, bad := range []core.UserQuery{{Role: "x"}, {Status: "x"}, {PageReq: core.PageReq{Sort: "x"}}, {PageReq: core.PageReq{Cursor: "!!"}}} {
		if _, err := te.svc.List(ctx, bad); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestRoleRules(t *testing.T) {
	ctx := context.Background()
	type env struct {
		te                           *testEnv
		owner, owner2, admin, member *core.User
	}
	setup := func(t *testing.T, twoOwners bool) env {
		te := newTestEnv(t)
		e := env{te: te, owner: te.mkUser(t, "owner", core.RoleOwner), admin: te.mkUser(t, "admin", core.RoleAdmin),
			member: te.mkUser(t, "member", core.RoleMember)}
		if twoOwners {
			e.owner2 = te.mkUser(t, "owner2", core.RoleOwner)
		}
		return e
	}
	role := func(r core.Role) core.UserUpdate { return core.UserUpdate{Role: &r} }
	cases := []struct {
		name      string
		twoOwners bool
		run       func(e env) error
		want      error
	}{
		{"admin promotes member to admin", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.admin), e.member.ID, role(core.RoleAdmin))
			return err
		}, nil},
		{"admin cannot grant owner", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.admin), e.member.ID, role(core.RoleOwner))
			return err
		}, core.ErrForbidden},
		{"owner grants owner", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.owner), e.member.ID, role(core.RoleOwner))
			return err
		}, nil},
		{"admin cannot demote owner", true, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.admin), e.owner.ID, role(core.RoleMember))
			return err
		}, core.ErrForbidden},
		{"admin cannot rename owner", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.admin), e.owner.ID, core.UserUpdate{DisplayName: ptr("x")})
			return err
		}, core.ErrForbidden},
		{"admin cannot disable owner", true, func(e env) error {
			return e.te.svc.SetStatus(ctx, as(e.admin), e.owner.ID, core.UserDisabled)
		}, core.ErrForbidden},
		{"admin cannot delete owner", true, func(e env) error {
			return e.te.svc.Delete(ctx, as(e.admin), e.owner.ID, "")
		}, core.ErrForbidden},
		{"admin cannot set owner password", false, func(e env) error {
			return e.te.svc.SetPasswordHash(ctx, as(e.admin), e.owner.ID, testPHC, false)
		}, core.ErrForbidden},
		{"admin cannot unlock owner", false, func(e env) error {
			return e.te.svc.Unlock(ctx, as(e.admin), e.owner.ID)
		}, core.ErrForbidden},
		{"owner changes own role", true, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.owner), e.owner.ID, role(core.RoleAdmin))
			return err
		}, core.ErrForbidden},
		{"admin changes own role", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.admin), e.admin.ID, role(core.RoleMember))
			return err
		}, core.ErrForbidden},
		{"last owner cannot be demoted", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, system(), e.owner.ID, role(core.RoleAdmin))
			return err
		}, core.ErrConflict},
		{"last owner cannot be disabled", false, func(e env) error {
			return e.te.svc.SetStatus(ctx, system(), e.owner.ID, core.UserDisabled)
		}, core.ErrConflict},
		{"last owner cannot be deleted", false, func(e env) error {
			return e.te.svc.Delete(ctx, system(), e.owner.ID, "")
		}, core.ErrConflict},
		{"disabled second owner does not count", true, func(e env) error {
			if err := e.te.svc.SetStatus(ctx, as(e.owner), e.owner2.ID, core.UserDisabled); err != nil {
				return err
			}
			return e.te.svc.Delete(ctx, system(), e.owner.ID, "")
		}, core.ErrConflict},
		{"owner demotes other owner", true, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.owner), e.owner2.ID, role(core.RoleMember))
			return err
		}, nil},
		{"owner deletes other owner", true, func(e env) error {
			return e.te.svc.Delete(ctx, as(e.owner), e.owner2.ID, "")
		}, nil},
		{"nobody disables self", false, func(e env) error {
			return e.te.svc.SetStatus(ctx, as(e.admin), e.admin.ID, core.UserDisabled)
		}, core.ErrForbidden},
		{"nobody deletes self", false, func(e env) error {
			return e.te.svc.Delete(ctx, as(e.admin), e.admin.ID, "")
		}, core.ErrForbidden},
		{"member cannot update others", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.member), e.admin.ID, core.UserUpdate{DisplayName: ptr("x")})
			return err
		}, core.ErrForbidden},
		{"member cannot change own quota", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.member), e.member.ID, core.UserUpdate{QuotaBytes: core.Some[int64](0)})
			return err
		}, core.ErrForbidden},
		{"member cannot clear must-change", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.member), e.member.ID, core.UserUpdate{MustChangePassword: ptr(false)})
			return err
		}, core.ErrForbidden},
		{"member updates own profile", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, as(e.member), e.member.ID, core.UserUpdate{DisplayName: ptr("M"), Email: ptr("m@example.com"),
				Prefs: json.RawMessage(`{"theme":"dark"}`)})
			return err
		}, nil},
		{"member sets own password", false, func(e env) error {
			return e.te.svc.SetPasswordHash(ctx, as(e.member), e.member.ID, testPHC, false)
		}, nil},
		{"member cannot set others' password", false, func(e env) error {
			return e.te.svc.SetPasswordHash(ctx, as(e.member), e.admin.ID, testPHC, false)
		}, core.ErrForbidden},
		{"member cannot disable", false, func(e env) error {
			return e.te.svc.SetStatus(ctx, as(e.member), e.admin.ID, core.UserDisabled)
		}, core.ErrForbidden},
		{"member cannot delete", false, func(e env) error {
			return e.te.svc.Delete(ctx, as(e.member), e.admin.ID, "")
		}, core.ErrForbidden},
		{"anonymous update", false, func(e env) error {
			_, err := e.te.svc.Update(ctx, nil, e.member.ID, core.UserUpdate{DisplayName: ptr("x")})
			return err
		}, core.ErrUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t, tc.twoOwners)
			err := tc.run(e)
			if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			// At least one active owner always remains.
			if n := e.te.count(t, `SELECT count(*) FROM users WHERE role = 'owner' AND status = 'active'`); n < 1 {
				t.Fatal("no active owner left")
			}
		})
	}
}

func TestUpdateFieldsAndAudit(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	u := te.mkUser(t, "bob", core.RoleMember, withEmail("bob@example.com"))
	te.mkUser(t, "carol", core.RoleMember, withEmail("carol@example.com"))

	got, err := te.svc.Update(ctx, as(admin), u.ID, core.UserUpdate{
		DisplayName: ptr("Robert"), Email: ptr("robert@example.com"), QuotaBytes: core.Some[int64](5 << 30),
		MustChangePassword: ptr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Robert" || got.Email != "robert@example.com" || got.QuotaBytes == nil || *got.QuotaBytes != 5<<30 || !got.MustChangePassword {
		t.Fatalf("updated %+v", got)
	}
	var spaceQuota int64
	if err := te.env.DB.QueryRow(ctx, `SELECT quota_bytes FROM spaces WHERE id = ?`, u.SpaceID).Scan(&spaceQuota); err != nil || spaceQuota != 5<<30 {
		t.Fatalf("space quota %d %v", spaceQuota, err)
	}
	if e, ok := te.audit.last(core.ActUserUpdate); !ok || e.ActorID != admin.ID || e.TargetID != u.ID {
		t.Fatalf("audit %+v", e)
	}
	// Quota back to the default (null) and unlimited (0).
	got, err = te.svc.Update(ctx, as(admin), u.ID, core.UserUpdate{QuotaBytes: core.Null[int64]()})
	if err != nil || got.QuotaBytes != nil {
		t.Fatalf("null quota %+v %v", got, err)
	}
	got, err = te.svc.Update(ctx, as(admin), u.ID, core.UserUpdate{QuotaBytes: core.Some[int64](0)})
	if err != nil || got.QuotaBytes == nil || *got.QuotaBytes != 0 {
		t.Fatalf("unlimited %+v %v", got, err)
	}
	// E-mail conflicts, clearing, validation.
	if _, err := te.svc.Update(ctx, as(admin), u.ID, core.UserUpdate{Email: ptr("CAROL@example.com")}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("email conflict: %v", err)
	}
	if got, err = te.svc.Update(ctx, as(admin), u.ID, core.UserUpdate{Email: ptr("")}); err != nil || got.Email != "" {
		t.Fatalf("clear email %+v %v", got, err)
	}
	for _, bad := range []core.UserUpdate{
		{DisplayName: ptr("   ")}, {Email: ptr("x")}, {Prefs: json.RawMessage(`[1]`)}, {Prefs: json.RawMessage(`"s"`)},
		{QuotaBytes: core.Some[int64](-5)}, {Role: ptr(core.Role("boss"))},
	} {
		if _, err := te.svc.Update(ctx, as(admin), u.ID, bad); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	// Preferences-only changes are stored but not audited.
	te.audit.reset()
	got, err = te.svc.Update(ctx, as(u), u.ID, core.UserUpdate{Prefs: json.RawMessage(`{"theme":"dark"}`)})
	if err != nil || string(got.Prefs) != `{"theme":"dark"}` {
		t.Fatalf("prefs %s %v", got.Prefs, err)
	}
	if len(te.audit.actions()) != 0 {
		t.Fatalf("prefs audited: %v", te.audit.actions())
	}
	// A failing audit aborts the change.
	te.audit.failTx.Store(true)
	if _, err := te.svc.Update(ctx, as(admin), u.ID, core.UserUpdate{DisplayName: ptr("Nope")}); err == nil {
		t.Fatal("update committed without audit")
	}
	te.audit.failTx.Store(false)
	if cur, _ := te.svc.Get(ctx, u.ID); cur.DisplayName != "Robert" {
		t.Fatalf("display name changed to %q", cur.DisplayName)
	}
}

func TestRoleChangeKeepsSpacesConsistent(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	owner := te.mkUser(t, "owner", core.RoleOwner)
	m := te.mkUser(t, "mike", core.RoleMember)
	guest := core.RoleGuest
	member := core.RoleMember

	// Empty personal space → removed when demoted to guest.
	got, err := te.svc.Update(ctx, as(owner), m.ID, core.UserUpdate{Role: &guest})
	if err != nil || got.Role != core.RoleGuest || got.SpaceID != "" {
		t.Fatalf("to guest %+v %v", got, err)
	}
	if n := te.count(t, `SELECT count(*) FROM nodes WHERE space_id = ?`, m.SpaceID); n != 0 {
		t.Fatalf("root left behind: %d", n)
	}
	// Guest → member creates a fresh space with root.
	got, err = te.svc.Update(ctx, as(owner), m.ID, core.UserUpdate{Role: &member})
	if err != nil || got.SpaceID == "" || got.SpaceID == m.SpaceID {
		t.Fatalf("to member %+v %v", got, err)
	}
	te.rootOf(t, got.SpaceID)
	// A space with files (even trashed ones) blocks the demotion.
	root := te.rootOf(t, got.SpaceID)
	f := te.mkNode(t, got.SpaceID, root, core.KindFile, "a.txt", 10)
	te.exec(t, `UPDATE nodes SET trashed_at = 1, trash_root = 1 WHERE id = ?`, f)
	if _, err := te.svc.Update(ctx, as(owner), m.ID, core.UserUpdate{Role: &guest}); !errors.Is(err, core.ErrConflict) || fieldOf(err) != "role" {
		t.Fatalf("demote with files: %v", err)
	}
	if cur, _ := te.svc.Get(ctx, m.ID); cur.Role != core.RoleMember || cur.SpaceID != got.SpaceID {
		t.Fatalf("state changed: %+v", cur)
	}
}

func TestSetStatusRevokesSessions(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	u := te.mkUser(t, "bob", core.RoleMember)
	te.exec(t, `INSERT INTO sessions (id, token_hash, user_id, auth_level, csrf_secret, created_at, last_seen_at,
		idle_expires_at, expires_at) VALUES ('ses_1', x'01', ?, 2, x'02', 1, 1, 9999999999999, 9999999999999)`, u.ID)
	if err := te.svc.SetStatus(ctx, as(admin), u.ID, core.UserDisabled); err != nil {
		t.Fatal(err)
	}
	if n := te.count(t, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL`); n != 0 {
		t.Fatal("session not revoked")
	}
	if cur, _ := te.svc.Get(ctx, u.ID); cur.Status != core.UserDisabled {
		t.Fatalf("status %s", cur.Status)
	}
	// Idempotent: no second audit entry.
	te.audit.reset()
	if err := te.svc.SetStatus(ctx, as(admin), u.ID, core.UserDisabled); err != nil || len(te.audit.actions()) != 0 {
		t.Fatalf("repeat: %v %v", err, te.audit.actions())
	}
	if err := te.svc.SetStatus(ctx, as(admin), u.ID, core.UserActive); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(te.audit.actions(), []string{core.ActUserEnable}) {
		t.Fatalf("audit %v", te.audit.actions())
	}
	if err := te.svc.SetStatus(ctx, as(admin), u.ID, "gone"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("bad status: %v", err)
	}
}

func TestDeleteWithTransfer(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	alice := te.mkUser(t, "alice", core.RoleMember)
	bob := te.mkUser(t, "bob", core.RoleMember)
	guest := te.mkUser(t, "guest", core.RoleGuest)

	aRoot := te.rootOf(t, alice.SpaceID)
	bRoot := te.rootOf(t, bob.SpaceID)
	// alice: /Docs/Deep/x.bin (100), /y.txt (20), trashed /old.txt (5)
	docs := te.mkNode(t, alice.SpaceID, aRoot, core.KindFolder, "Docs", 0)
	deep := te.mkNode(t, alice.SpaceID, docs, core.KindFolder, "Deep", 0)
	x := te.mkNode(t, alice.SpaceID, deep, core.KindFile, "x.bin", 100)
	te.mkVersion(t, x, 50) // an older version counts too
	te.mkNode(t, alice.SpaceID, aRoot, core.KindFile, "y.txt", 20)
	old := te.mkNode(t, alice.SpaceID, aRoot, core.KindFile, "old.txt", 5)
	te.exec(t, `UPDATE nodes SET trashed_at = 1, trash_root = 1 WHERE id = ?`, old)
	// bob already has a folder called "From alice" and a file of 7 bytes.
	te.mkNode(t, bob.SpaceID, bRoot, core.KindFolder, "From alice", 0)
	te.mkNode(t, bob.SpaceID, bRoot, core.KindFile, "b.txt", 7)
	// a grant naming alice on bob's file tree, and one naming bob.
	te.exec(t, `INSERT INTO node_grants (id, node_id, subject_type, subject_id, role, created_at) VALUES
		('gnt_1', ?, 'user', ?, 'viewer', 1), ('gnt_2', ?, 'user', ?, 'viewer', 1)`, bRoot, alice.ID, x, bob.ID)

	for _, bad := range []struct {
		to   string
		want error
	}{{alice.ID, core.ErrInvalid}, {guest.ID, core.ErrInvalid}, {"usr_unknown", core.ErrInvalid}} {
		if err := te.svc.Delete(ctx, as(admin), alice.ID, bad.to); !errors.Is(err, bad.want) || fieldOf(err) != "transfer_to" {
			t.Fatalf("transfer to %s: %v", bad.to, err)
		}
	}
	if err := te.svc.Delete(ctx, as(admin), alice.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.Get(ctx, alice.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("alice still exists")
	}
	if n := te.count(t, `SELECT count(*) FROM spaces WHERE id = ?`, alice.SpaceID); n != 0 {
		t.Fatal("alice's space still exists")
	}
	var folder, folderName string
	if err := te.env.DB.QueryRow(ctx, `SELECT id, name FROM nodes WHERE parent_id = ? AND name LIKE 'From alice%' ORDER BY name DESC LIMIT 1`, bRoot).
		Scan(&folder, &folderName); err != nil {
		t.Fatal(err)
	}
	if folderName != "From alice (1)" {
		t.Fatalf("folder name %q", folderName)
	}
	// Every moved node (recursively, including trash) now lives in bob's space.
	for _, id := range []string{docs, deep, x, old} {
		var space string
		if err := te.env.DB.QueryRow(ctx, `SELECT space_id FROM nodes WHERE id = ?`, id).Scan(&space); err != nil {
			t.Fatalf("node %s: %v", id, err)
		}
		if space != bob.SpaceID {
			t.Fatalf("node %s in space %s", id, space)
		}
	}
	var parent string
	_ = te.env.DB.QueryRow(ctx, `SELECT parent_id FROM nodes WHERE id = ?`, docs).Scan(&parent)
	if parent != folder {
		t.Fatalf("docs parent %s want %s", parent, folder)
	}
	var used int64
	_ = te.env.DB.QueryRow(ctx, `SELECT used_bytes FROM spaces WHERE id = ?`, bob.SpaceID).Scan(&used)
	if used != 100+50+20+5+7 {
		t.Fatalf("used_bytes %d", used)
	}
	if n := te.count(t, `SELECT count(*) FROM node_grants WHERE subject_id = ?`, alice.ID); n != 0 {
		t.Fatal("grant naming alice kept")
	}
	if n := te.count(t, `SELECT count(*) FROM node_grants WHERE subject_id = ?`, bob.ID); n != 1 {
		t.Fatal("unrelated grant removed")
	}
	e, ok := te.audit.last(core.ActUserDelete)
	if !ok || e.TargetID != alice.ID {
		t.Fatalf("audit %+v", e)
	}
	if d := e.Details.(map[string]any); d["transfer_to"] != bob.ID || d["moved_nodes"] != int64(5) {
		t.Fatalf("details %+v", d)
	}
	te.exec(t, `INSERT INTO nodes_fts(nodes_fts) VALUES ('integrity-check')`)

	// Without transfer the files go with the account.
	carol := te.mkUser(t, "carol", core.RoleMember)
	cRoot := te.rootOf(t, carol.SpaceID)
	sub := te.mkNode(t, carol.SpaceID, cRoot, core.KindFolder, "Sub", 0)
	te.mkNode(t, carol.SpaceID, sub, core.KindFile, "z", 1)
	if err := te.svc.Delete(ctx, as(admin), carol.ID, ""); err != nil {
		t.Fatal(err)
	}
	if n := te.count(t, `SELECT count(*) FROM nodes WHERE space_id = ?`, carol.SpaceID); n != 0 {
		t.Fatalf("%d nodes left", n)
	}
	te.exec(t, `INSERT INTO nodes_fts(nodes_fts) VALUES ('integrity-check')`)
	// Deleting a user with an empty space and a transfer target creates no folder.
	dave := te.mkUser(t, "dave", core.RoleMember)
	before := te.count(t, `SELECT count(*) FROM nodes WHERE parent_id = ?`, bRoot)
	if err := te.svc.Delete(ctx, as(admin), dave.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if after := te.count(t, `SELECT count(*) FROM nodes WHERE parent_id = ?`, bRoot); after != before {
		t.Fatal("empty transfer created a folder")
	}
	// A guest (no space) can be deleted with a transfer target.
	if err := te.svc.Delete(ctx, as(admin), guest.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.Delete(ctx, as(admin), "usr_missing", ""); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestLookup(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	m := te.mkUser(t, "martin", core.RoleMember, withEmail("martin@example.com"))
	te.mkUser(t, "marta", core.RoleMember, func(in *core.NewUser) { in.DisplayName = "Marta Smith" })
	te.mkUser(t, "amar", core.RoleMember)
	te.mkUser(t, "under_score", core.RoleMember)
	off := te.mkUser(t, "mario", core.RoleMember)
	if err := te.svc.SetStatus(ctx, system(), off.ID, core.UserDisabled); err != nil {
		t.Fatal(err)
	}
	g := te.mkUser(t, "guest", core.RoleGuest)
	names := func(q string) []string {
		t.Helper()
		refs, err := te.svc.Lookup(ctx, as(m), q)
		if err != nil {
			t.Fatalf("lookup %q: %v", q, err)
		}
		var out []string
		for _, r := range refs {
			out = append(out, r.Username)
		}
		return out
	}
	if got := names("mar"); !slices.Equal(got, []string{"marta", "martin", "amar"}) {
		t.Fatalf("mar: %v", got)
	}
	if got := names("SMITH"); !slices.Equal(got, []string{"marta"}) {
		t.Fatalf("display name: %v", got)
	}
	if got := names("martin@example.com"); !slices.Equal(got, []string{"martin"}) {
		t.Fatalf("email: %v", got)
	}
	if got := names("@example"); got != nil {
		t.Fatalf("partial email leaked: %v", got)
	}
	if got := names("r_"); !slices.Equal(got, []string{"under_score"}) {
		t.Fatalf("underscore not literal: %v", got)
	}
	if _, err := te.svc.Lookup(ctx, as(m), "m"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("1 char: %v", err)
	}
	if _, err := te.svc.Lookup(ctx, as(g), "mar"); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("guest: %v", err)
	}
	if _, err := te.svc.Lookup(ctx, nil, "mar"); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("anonymous: %v", err)
	}
}

func TestPromoteGuestWithQuota(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	g := te.mkUser(t, "gwen", core.RoleGuest)
	member := core.RoleMember
	got, err := te.svc.Update(ctx, system(), g.ID, core.UserUpdate{Role: &member, QuotaBytes: core.Some[int64](1 << 20)})
	if err != nil || got.SpaceID == "" || got.QuotaBytes == nil || *got.QuotaBytes != 1<<20 {
		t.Fatalf("promote %+v %v", got, err)
	}
	var q int64
	if err := te.env.DB.QueryRow(ctx, `SELECT quota_bytes FROM spaces WHERE id = ?`, got.SpaceID).Scan(&q); err != nil || q != 1<<20 {
		t.Fatalf("space quota %d %v", q, err)
	}
	if e, ok := te.audit.last(core.ActUserUpdate); !ok || e.ActorName != "system" {
		t.Fatalf("audit %+v", e)
	}
}

// ---------- custom roles on accounts ----------

// Accounts get a role through role_id: users.role becomes its base, the
// personal space follows the base, and role alone gives a built-in role
// (removing any custom role, which is what old clients mean).
func TestAssignRoleID(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	owner := te.mkUser(t, "owner", core.RoleOwner)
	finance := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	contractors := te.createRole(t, core.RoleDefInput{Name: "Contractors", Base: core.RoleGuest,
		Permissions: capList(core.CapShareRequests)})

	// Create.
	fin, err := te.svc.Create(ctx, as(owner), core.NewUser{Username: "fin", RoleID: finance.ID, PasswordHash: testPHC})
	if err != nil {
		t.Fatal(err)
	}
	if fin.Role != core.RoleMember || fin.RoleID != finance.ID || fin.RoleName != "Finance" || fin.SpaceID == "" ||
		fin.Permissions != core.MemberCaps {
		t.Fatalf("finance account %+v", fin)
	}
	e, _ := te.audit.last(core.ActUserCreate)
	if d := e.Details.(map[string]any); d["role"] != core.RoleMember || d["role_id"] != finance.ID || d["role_name"] != "Finance" {
		t.Fatalf("create audit %+v", d)
	}
	con, err := te.svc.Create(ctx, as(owner), core.NewUser{Username: "con", Role: core.RoleGuest, RoleID: contractors.ID, PasswordHash: testPHC})
	if err != nil || con.Role != core.RoleGuest || con.RoleID != contractors.ID || con.SpaceID != "" ||
		con.Permissions != core.NewCapSet(core.CapShareRequests) {
		t.Fatalf("contractor %+v %v", con, err)
	}
	if n := te.count(t, `SELECT count(*) FROM spaces WHERE owner_user_id = ?`, con.ID); n != 0 {
		t.Fatal("guest-based account got a personal space")
	}
	plain, err := te.svc.Create(ctx, as(owner), core.NewUser{Username: "plain", Role: core.RoleMember, RoleID: "member", PasswordHash: testPHC})
	if err != nil || plain.RoleID != "member" {
		t.Fatalf("role_id member: %+v %v", plain, err)
	}
	for _, c := range []struct {
		in         core.NewUser
		field, msg string
	}{
		{core.NewUser{Username: "x1", Role: core.RoleGuest, RoleID: finance.ID}, "role", "the role “Finance” is based on member"},
		{core.NewUser{Username: "x2", Role: core.RoleAdmin, RoleID: "member"}, "role", "the role “Member” is based on member"},
		{core.NewUser{Username: "x3", RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na"}, "role_id", "unknown role"},
		{core.NewUser{Username: "x4", RoleID: "Finance"}, "role_id", "unknown role"},
		{core.NewUser{Username: "x5", RoleID: "system"}, "role_id", "unknown role"},
	} {
		c.in.PasswordHash = testPHC
		_, err := te.svc.Create(ctx, as(owner), c.in)
		wantErr(t, "create "+c.in.Username, err, core.ErrInvalid, c.field, c.msg)
	}
	if n := te.count(t, `SELECT count(*) FROM users WHERE username LIKE 'x%'`); n != 0 {
		t.Fatalf("%d refused accounts stored", n)
	}

	// Update.
	evs := te.authzEvents(t)
	te.exec(t, `INSERT INTO sessions (id, token_hash, user_id, auth_level, csrf_secret, created_at, last_seen_at,
		idle_expires_at, expires_at, elevated_until) VALUES ('ses_p', x'01', ?, 2, x'02', 1, 1, 9999999999999, 9999999999999, 9999999999999)`, plain.ID)
	got, err := te.svc.Update(ctx, as(owner), plain.ID, core.UserUpdate{RoleID: &finance.ID})
	if err != nil || got.RoleID != finance.ID || got.Role != core.RoleMember || got.SpaceID != plain.SpaceID {
		t.Fatalf("to Finance %+v %v", got, err)
	}
	e, _ = te.audit.last(core.ActUserUpdate)
	d := e.Details.(map[string]any)
	if d["role"] != nil || fmt.Sprint(d["role_id"]) != fmt.Sprint(map[string]any{"from": "member", "to": finance.ID, "name": "Finance"}) {
		t.Fatalf("update audit %+v", d)
	}
	if ev := evs(); len(ev) != 1 || !slices.Equal(ev[0].UserIDs, []string{plain.ID}) || ev[0].Reason != core.AuthzRoleAssigned {
		t.Fatalf("events %+v", ev)
	}
	if n := te.count(t, `SELECT count(*) FROM sessions WHERE elevated_until IS NOT NULL`); n != 0 {
		t.Fatal("step-up window survived the role change")
	}
	// The same role again changes nothing (no audit, no event).
	te.audit.reset()
	if _, err := te.svc.Update(ctx, as(owner), plain.ID, core.UserUpdate{RoleID: &finance.ID, Role: ptr(core.RoleMember)}); err != nil ||
		len(te.audit.actions()) != 0 || len(evs()) != 0 {
		t.Fatalf("same role: %v %v", err, te.audit.actions())
	}
	// role alone and role_id "member" both clear the custom role.
	for _, in := range []core.UserUpdate{{Role: ptr(core.RoleMember)}, {RoleID: ptr("member")}} {
		if _, err := te.svc.Update(ctx, as(owner), plain.ID, core.UserUpdate{RoleID: &finance.ID}); err != nil {
			t.Fatal(err)
		}
		got, err := te.svc.Update(ctx, as(owner), plain.ID, in)
		if err != nil || got.RoleID != "member" || got.RoleName != "Member" {
			t.Fatalf("clear with %+v: %+v %v", in, got, err)
		}
	}
	// Guest → member-based creates the space; member-based → guest-based with
	// files is refused; without files the space goes.
	got, err = te.svc.Update(ctx, as(owner), con.ID, core.UserUpdate{RoleID: &finance.ID})
	if err != nil || got.Role != core.RoleMember || got.SpaceID == "" {
		t.Fatalf("guest-based → member-based %+v %v", got, err)
	}
	f := te.mkNode(t, got.SpaceID, te.rootOf(t, got.SpaceID), core.KindFile, "a.txt", 1)
	_, err = te.svc.Update(ctx, as(owner), con.ID, core.UserUpdate{RoleID: &contractors.ID})
	wantErr(t, "to guest-based with files", err, core.ErrConflict, "role", "")
	if cur := te.get(t, con); cur.RoleID != finance.ID || cur.SpaceID != got.SpaceID {
		t.Fatalf("changed anyway: %+v", cur)
	}
	te.exec(t, `DELETE FROM file_versions WHERE node_id = ?`, f)
	te.exec(t, `DELETE FROM nodes WHERE id = ?`, f)
	if got, err = te.svc.Update(ctx, as(owner), con.ID, core.UserUpdate{RoleID: &contractors.ID}); err != nil ||
		got.SpaceID != "" || got.RoleID != contractors.ID {
		t.Fatalf("to guest-based %+v %v", got, err)
	}
	for _, c := range []struct {
		in         core.UserUpdate
		base       *core.Error
		field, msg string
	}{
		{core.UserUpdate{Role: ptr(core.RoleGuest), RoleID: &finance.ID}, core.ErrInvalid, "role", "the role “Finance” is based on member"},
		{core.UserUpdate{RoleID: ptr("rol_01k5z8r3m9d4q7w2x6c1v0b5na")}, core.ErrInvalid, "role_id", "unknown role"},
		{core.UserUpdate{RoleID: ptr("")}, core.ErrInvalid, "role", ""},
	} {
		_, err := te.svc.Update(ctx, as(owner), fin.ID, c.in)
		if c.field == "role" && c.msg == "" {
			// role_id "" with no role is "member" by default: allowed, and a change.
			if err != nil {
				t.Errorf("empty role_id: %v", err)
			}
			continue
		}
		wantErr(t, fmt.Sprintf("update %+v", c.in), err, c.base, c.field, c.msg)
	}
	// Nobody changes their own role.
	_, err = te.svc.Update(ctx, as(owner), owner.ID, core.UserUpdate{RoleID: &finance.ID})
	wantErr(t, "own role", err, core.ErrForbidden, "", "you cannot change your own role")
}

// GET /admin/users?role= filters the base, ?role_id= the role.
func TestListByRoleID(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	finance := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	visitors := te.createRole(t, core.RoleDefInput{Name: "Visitors", Base: core.RoleGuest})
	te.mkUser(t, "adam", core.RoleAdmin)
	te.mkUser(t, "mia", core.RoleMember)
	te.giveRole(t, te.mkUser(t, "fin", core.RoleMember), finance.ID)
	te.giveRole(t, te.mkUser(t, "vis", core.RoleGuest), visitors.ID)
	te.mkUser(t, "gus", core.RoleGuest)
	names := func(q core.UserQuery) []string {
		t.Helper()
		page, err := te.svc.List(ctx, q)
		if err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
		var out []string
		for _, u := range page.Items {
			out = append(out, u.Username)
		}
		return out
	}
	for _, c := range []struct {
		q    core.UserQuery
		want []string
	}{
		{core.UserQuery{Role: core.RoleMember}, []string{"fin", "mia"}},
		{core.UserQuery{Role: core.RoleGuest}, []string{"gus", "vis"}},
		{core.UserQuery{RoleID: "member"}, []string{"mia"}},
		{core.UserQuery{RoleID: "guest"}, []string{"gus"}},
		{core.UserQuery{RoleID: "admin"}, []string{"adam"}},
		{core.UserQuery{RoleID: finance.ID}, []string{"fin"}},
		{core.UserQuery{RoleID: visitors.ID, Role: core.RoleGuest}, []string{"vis"}},
		{core.UserQuery{RoleID: finance.ID, Role: core.RoleGuest}, nil},
		{core.UserQuery{RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na"}, nil},
	} {
		if got := names(c.q); !slices.Equal(got, c.want) {
			t.Errorf("%+v: %v, want %v", c.q, got, c.want)
		}
	}
	for _, bad := range []string{"Finance", "system", "rol_x"} {
		_, err := te.svc.List(ctx, core.UserQuery{RoleID: bad})
		wantErr(t, "role_id "+bad, err, core.ErrInvalid, "role_id", "unknown role")
	}
}

// A delegate — here a Helpdesk holding users.manage and users.credentials —
// manages accounts whose role it could give: Member, Guest and delegable
// roles within its own server permissions; never admins, owners, holders of
// non-delegable roles or its own account's admin fields. Every refusal by
// the escalation rules is audited as denied; plain permission refusals are
// not.
func TestDelegation(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	owner := te.mkUser(t, "owner", core.RoleOwner)
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	member := te.mkUser(t, "member", core.RoleMember)
	helpdesk := te.createRole(t, core.RoleDefInput{Name: "Helpdesk",
		Permissions: capList(core.CapUsersLookup, core.CapUsersManage, core.CapUsersCredentials)})
	finance := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	auditors := te.createRole(t, core.RoleDefInput{Name: "Auditors", Permissions: capList(core.CapAuditView), Delegable: true})
	staff := te.createRole(t, core.RoleDefInput{Name: "Staff", Delegable: true})
	managers := te.createRole(t, core.RoleDefInput{Name: "Managers", Permissions: capList(core.CapUsersManage), Delegable: true})
	holder := func(name string, r *core.RoleDef) *core.User {
		u := te.mkUser(t, name, r.Base)
		te.giveRole(t, u, r.ID)
		return te.get(t, u)
	}
	hana := holder("hana", helpdesk)
	fin := holder("fin", finance)
	aud := holder("aud", auditors)
	sam := holder("sam", staff)
	max := holder("max", managers)
	p := te.principalOf(t, hana)

	denied := func(t *testing.T, what, action string, target *core.User, err error, msg string, missing ...core.Capability) {
		t.Helper()
		wantErr(t, what, err, core.ErrForbidden, "", msg)
		e, ok := te.audit.last(action)
		d, _ := e.Details.(map[string]any)
		got, _ := d["missing"].([]core.Capability)
		if !ok || e.Outcome != core.OutcomeDenied || e.ActorID != hana.ID || e.TargetName != target.Username ||
			d["reason"] != msg || !slices.Equal(got, missing) {
			t.Errorf("%s: audit %+v", what, e)
		}
		te.audit.reset()
	}
	te.audit.reset()

	// Create: Member, Guest, delegable roles without extra server permissions.
	for i, in := range []core.NewUser{{}, {Role: core.RoleGuest}, {RoleID: staff.ID}, {RoleID: "member"}} {
		in.Username, in.PasswordHash = fmt.Sprintf("new%d", i), testPHC
		if _, err := te.svc.Create(ctx, p, in); err != nil {
			t.Errorf("create %+v: %v", in, err)
		}
	}
	for _, c := range []struct {
		in      core.NewUser
		msg     string
		missing []core.Capability
	}{
		{core.NewUser{Role: core.RoleAdmin}, "only administrators can grant the admin role", nil},
		{core.NewUser{RoleID: "owner"}, "only owners can grant the owner role", nil},
		{core.NewUser{RoleID: finance.ID}, "administrators have not allowed account managers to give the role “Finance”", nil},
		{core.NewUser{RoleID: auditors.ID}, "you can only give roles whose server permissions you have yourself (missing: audit.view)",
			[]core.Capability{core.CapAuditView}},
	} {
		c.in.Username, c.in.PasswordHash = "refused", testPHC
		_, err := te.svc.Create(ctx, p, c.in)
		denied(t, fmt.Sprintf("create %+v", c.in), core.ActUserCreate, &core.User{Username: "refused"}, err, c.msg, c.missing...)
	}
	// Initial groups need groups.manage (a plain refusal, not audited).
	g, err := te.svc.CreateGroup(ctx, system(), core.GroupInput{Name: "Team"})
	if err != nil {
		t.Fatal(err)
	}
	te.audit.reset()
	_, err = te.svc.Create(ctx, p, core.NewUser{Username: "grouped", GroupIDs: []string{g.ID}, PasswordHash: testPHC})
	wantErr(t, "group_ids", err, core.ErrForbidden, "group_ids", "adding people to groups needs the “Manage groups” permission")
	if len(te.audit.entries) != 0 {
		t.Fatalf("plain refusal audited: %+v", te.audit.entries)
	}

	// Acting on accounts.
	name := ptr("New name")
	for _, u := range []*core.User{member, sam} {
		if _, err := te.svc.Update(ctx, p, u.ID, core.UserUpdate{DisplayName: name, QuotaBytes: core.Some[int64](1 << 30)}); err != nil {
			t.Errorf("update %s: %v", u.Username, err)
		}
		if err := te.svc.Unlock(ctx, p, u.ID); err != nil {
			t.Errorf("unlock %s: %v", u.Username, err)
		}
		if err := te.svc.SetPasswordHash(ctx, p, u.ID, testPHC, true); err != nil {
			t.Errorf("password of %s: %v", u.Username, err)
		}
	}
	refusals := map[*core.User]struct {
		msg     string
		missing []core.Capability
	}{
		owner: {"administrators cannot modify owner accounts", nil},
		admin: {"only administrators can manage administrator accounts", nil},
		fin:   {"accounts with the role “Finance” can only be managed by an administrator", nil},
		aud:   {"this account has server permissions you do not have (audit.view)", []core.Capability{core.CapAuditView}},
	}
	for u, c := range refusals {
		_, err := te.svc.Update(ctx, p, u.ID, core.UserUpdate{DisplayName: name})
		denied(t, "update "+u.Username, core.ActUserUpdate, u, err, c.msg, c.missing...)
		err = te.svc.SetStatus(ctx, p, u.ID, core.UserDisabled)
		denied(t, "disable "+u.Username, core.ActUserDisable, u, err, c.msg, c.missing...)
		err = te.svc.SetStatus(ctx, p, u.ID, core.UserActive)
		denied(t, "enable "+u.Username, core.ActUserEnable, u, err, c.msg, c.missing...)
		err = te.svc.Unlock(ctx, p, u.ID)
		denied(t, "unlock "+u.Username, core.ActUserUnlock, u, err, c.msg, c.missing...)
		err = te.svc.Delete(ctx, p, u.ID, "")
		denied(t, "delete "+u.Username, core.ActUserDelete, u, err, c.msg, c.missing...)
		// Credentials: the auth service audits these; here they are only refused.
		err = te.svc.SetPasswordHash(ctx, p, u.ID, testPHC, false)
		if e := core.AsError(err); e == nil || e.Status != 403 {
			t.Errorf("password of %s: %v", u.Username, err)
		}
		te.audit.reset()
	}
	// Own account: profile yes, admin fields no.
	if _, err := te.svc.Update(ctx, p, hana.ID, core.UserUpdate{DisplayName: ptr("Hana")}); err != nil {
		t.Errorf("own profile: %v", err)
	}
	for what, in := range map[string]core.UserUpdate{
		"quota":       {QuotaBytes: core.Some[int64](0)},
		"must change": {MustChangePassword: ptr(false)},
		"role":        {RoleID: ptr("member")},
	} {
		_, err := te.svc.Update(ctx, p, hana.ID, in)
		denied(t, "own "+what, core.ActUserUpdate, hana, err, "ask an administrator to change this on your own account")
	}

	// Role changes follow CheckAssign on top of CheckManage.
	for _, to := range []string{staff.ID, "guest", "member"} {
		if _, err := te.svc.Update(ctx, p, member.ID, core.UserUpdate{RoleID: &to}); err != nil {
			t.Errorf("member → %s: %v", to, err)
		}
	}
	_, err = te.svc.Update(ctx, p, member.ID, core.UserUpdate{RoleID: &finance.ID})
	denied(t, "member → Finance", core.ActUserUpdate, member, err,
		"administrators have not allowed account managers to give the role “Finance”")
	_, err = te.svc.Update(ctx, p, member.ID, core.UserUpdate{Role: ptr(core.RoleAdmin)})
	denied(t, "member → admin", core.ActUserUpdate, member, err, "only administrators can grant the admin role")
	if got := te.get(t, member); got.RoleID != "member" {
		t.Fatalf("member's role: %s", got.RoleID)
	}

	// Deleting with transfer_to moves files: users.credentials, and the
	// destination must be manageable too.
	victim := te.mkUser(t, "victim", core.RoleMember)
	err = te.svc.Delete(ctx, te.principalOf(t, max), victim.ID, member.ID)
	wantErr(t, "transfer without users.credentials", err, core.ErrForbidden, "",
		"moving another person's files needs the “Reset sign-in” permission")
	if e, ok := te.audit.last(core.ActUserDelete); !ok || e.Outcome != core.OutcomeDenied || e.ActorID != max.ID ||
		e.TargetID != victim.ID || !slices.Equal(e.Details.(map[string]any)["missing"].([]core.Capability),
		[]core.Capability{core.CapUsersCredentials}) {
		t.Errorf("transfer audit %+v", e)
	}
	te.audit.reset()
	err = te.svc.Delete(ctx, p, victim.ID, admin.ID)
	denied(t, "transfer to admin", core.ActUserDelete, victim, err, "only administrators can manage administrator accounts")
	err = te.svc.Delete(ctx, p, victim.ID, hana.ID)
	// Moving the files to oneself: a message about the destination, not
	// about changing one's own account (still an audited refusal).
	denied(t, "transfer to self", core.ActUserDelete, victim, err,
		"you cannot move another person's files to your own account; ask an administrator")
	if err := te.svc.Delete(ctx, p, victim.ID, member.ID); err != nil {
		t.Fatalf("transfer to member: %v", err)
	}
	// Without transfer, users.manage suffices.
	if err := te.svc.Delete(ctx, te.principalOf(t, max), sam.ID, ""); err != nil {
		t.Fatalf("delete by manager: %v", err)
	}

	// A token needs the admin scope for all of this (plain refusal).
	te.audit.reset()
	tok := te.principalOf(t, hana)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead, core.ScopeShares}
	_, err = te.svc.Update(ctx, tok, member.ID, core.UserUpdate{DisplayName: name})
	wantErr(t, "token without admin scope", err, core.ErrForbidden, "", "this needs the “Manage accounts” permission")
	if len(te.audit.entries) != 0 {
		t.Fatalf("plain refusal audited: %+v", te.audit.entries)
	}
}

// An account that loses invites.manage loses its active invitations with it:
// by a role change, a role edit or the role's deletion.
func TestInvitesRevokedWhenCreatorLosesInvitesManage(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		act  func(te *testEnv, role *core.RoleDef, u *core.User) error
		keep bool
	}{
		{"role change", func(te *testEnv, _ *core.RoleDef, u *core.User) error {
			_, err := te.svc.Update(ctx, system(), u.ID, core.UserUpdate{RoleID: ptr("member")})
			return err
		}, false},
		{"role edit", func(te *testEnv, role *core.RoleDef, _ *core.User) error {
			_, err := te.svc.UpdateRole(ctx, system(), role.ID, core.RoleDefUpdate{RemovePermissions: []core.Capability{core.CapInvitesManage}})
			return err
		}, false},
		{"role deleted", func(te *testEnv, role *core.RoleDef, _ *core.User) error {
			return te.svc.DeleteRole(ctx, system(), role.ID, "guest")
		}, false},
		{"other permission removed", func(te *testEnv, role *core.RoleDef, _ *core.User) error {
			_, err := te.svc.UpdateRole(ctx, system(), role.ID, core.RoleDefUpdate{RemovePermissions: []core.Capability{core.CapShareLinks}})
			return err
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			role := te.createRole(t, core.RoleDefInput{Name: "Inviters",
				Permissions: capList(core.CapShareLinks, core.CapInvitesManage)})
			ivy := te.mkUser(t, "ivy", core.RoleMember)
			te.giveRole(t, ivy, role.ID)
			_, tok, err := te.svc.CreateInvite(ctx, te.principalOf(t, ivy), core.InviteInput{Role: core.RoleGuest, MaxUses: 3})
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.act(te, role, ivy); err != nil {
				t.Fatal(err)
			}
			_, err = te.svc.LookupInvite(ctx, tok)
			if tc.keep != (err == nil) {
				t.Fatalf("invitation kept %v: %v", tc.keep, err)
			}
			if !tc.keep {
				if e, ok := te.audit.last(core.ActInviteRevoke); !ok || e.Details.(map[string]any)["reason"] != revokeCreatorDemoted {
					t.Fatalf("audit %+v", e)
				}
			}
		})
	}
}
