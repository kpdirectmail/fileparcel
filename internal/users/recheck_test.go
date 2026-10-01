package users

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// inviteStatusOf returns the status of invitation id as an administrator
// lists it.
func (te *testEnv) inviteStatusOf(t *testing.T, id string) string {
	t.Helper()
	page, err := te.svc.ListInvites(context.Background(), system(), core.PageReq{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range page.Items {
		if i.ID == id {
			return i.Status
		}
	}
	t.Fatalf("invitation %s not listed", id)
	return ""
}

// revokeReason returns the reason of the invite.revoke entry of id ("" when
// there is none).
func (te *testEnv) revokeReason(id string) string {
	te.audit.mu.Lock()
	defer te.audit.mu.Unlock()
	for _, e := range te.audit.entries {
		if e.Action == core.ActInviteRevoke && e.TargetID == id {
			if d, ok := e.Details.(map[string]any); ok {
				r, _ := d["reason"].(string)
				return r
			}
		}
	}
	return ""
}

func isInvalidInvite(err error) bool {
	return errors.Is(err, core.ErrNotFound) && core.AsError(err).Message == "this invitation is invalid or has expired"
}

// An open invitation must not create an account its creator could not
// invite today, and a staff invitation stays single use and short-lived
// even when its role became staff after it was created: AcceptInvite (and
// LookupInvite) check again, and the role edit revokes what can no longer be
// accepted.
func TestInviteStaleRoleRechecked(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	inviter := te.mkRole(t, "Inviter", core.RoleMember, core.MemberCaps.With(core.CapInvitesManage).Closure(), false)
	support := te.mkRole(t, "Support", core.RoleMember, core.MemberCaps, true)
	dora := te.mkUser(t, "dora", core.RoleMember)
	te.giveRole(t, dora, inviter)
	dp := te.principalOf(t, dora)
	now := te.clock.Now()
	in30d, in3d := now.Add(30*24*time.Hour), now.Add(3*24*time.Hour)

	create := func(by *core.Principal, in core.InviteInput) (*core.Invite, string) {
		t.Helper()
		inv, tok, err := te.svc.CreateInvite(ctx, by, in)
		if err != nil {
			t.Fatalf("create %+v: %v", in, err)
		}
		return inv, tok
	}
	wide, wideTok := create(dp, core.InviteInput{RoleID: support, MaxUses: 50, ExpiresAt: &in30d})
	single, singleTok := create(dp, core.InviteInput{RoleID: support, ExpiresAt: &in3d})
	adminOK, adminOKTok := create(as(admin), core.InviteInput{RoleID: support, ExpiresAt: &in3d})
	adminWide, _ := create(as(admin), core.InviteInput{RoleID: support, MaxUses: 5, ExpiresAt: &in3d})
	member, memberTok := create(dp, core.InviteInput{MaxUses: 10, ExpiresAt: &in30d})

	// Support becomes a staff role.
	te.audit.reset()
	if _, err := te.svc.UpdateRole(ctx, system(), support, core.RoleDefUpdate{
		AddPermissions: []core.Capability{core.CapUsersManage, core.CapAuditView}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		inv    *core.Invite
		status string
		reason string
	}{
		{wide, core.InviteRevoked, revokeStaffLimits},
		{single, core.InviteRevoked, revokeCreatorCannotGive},
		{adminWide, core.InviteRevoked, revokeStaffLimits},
		{adminOK, core.InviteActive, ""},
		{member, core.InviteActive, ""},
	} {
		if got := te.inviteStatusOf(t, c.inv.ID); got != c.status || te.revokeReason(c.inv.ID) != c.reason {
			t.Errorf("%s: status %s reason %q, want %s %q", c.inv.ID, got, te.revokeReason(c.inv.ID), c.status, c.reason)
		}
	}
	for _, tok := range []string{wideTok, singleTok} {
		if _, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "puppet"}, testPHC, core.ReqMeta{}); !isInvalidInvite(err) {
			t.Fatalf("accept of a stale invitation: %v", err)
		}
	}
	// dora's link no longer shows (revoked), the administrator's does work.
	page, _ := te.svc.ListInvites(ctx, dp, core.PageReq{})
	for _, i := range page.Items {
		if (i.ID == wide.ID || i.ID == single.ID) && i.URL != "" {
			t.Errorf("revoked invitation %s still shows its link", i.ID)
		}
	}
	u, err := te.svc.AcceptInvite(ctx, adminOKTok, core.AcceptInvite{Username: "staffer"}, testPHC, core.ReqMeta{})
	if err != nil || !u.Permissions.Has(core.CapUsersManage) {
		t.Fatalf("administrator's single-use invitation: %+v %v", u, err)
	}

	// The accept-time check on its own (a change that bypassed UpdateRole):
	// the role is no longer delegable, so dora's member link still works but
	// a new link of hers for Support does not.
	te.exec(t, `UPDATE roles SET permissions = ? WHERE id = ?`, core.EncodeCaps(core.MemberCaps), support)
	_, supportTok := create(dp, core.InviteInput{RoleID: support, MaxUses: 3})
	te.exec(t, `UPDATE roles SET delegable = 0 WHERE id = ?`, support)
	if _, err := te.svc.LookupInvite(ctx, supportTok); !isInvalidInvite(err) {
		t.Fatalf("lookup of a link for a role that is no longer delegable: %v", err)
	}
	if _, err := te.svc.AcceptInvite(ctx, supportTok, core.AcceptInvite{Username: "puppet3"}, testPHC, core.ReqMeta{}); !isInvalidInvite(err) {
		t.Fatalf("accept of a link for a role that is no longer delegable: %v", err)
	}
	if _, err := te.svc.AcceptInvite(ctx, memberTok, core.AcceptInvite{Username: "newbie"}, testPHC, core.ReqMeta{}); err != nil {
		t.Fatalf("member invitation: %v", err)
	}
	// ... and the staff limits alone: the role gains a server permission
	// behind UpdateRole's back.
	te.exec(t, `UPDATE roles SET delegable = 1 WHERE id = ?`, support)
	_, adminWideTok := create(as(admin), core.InviteInput{RoleID: support, MaxUses: 5, ExpiresAt: &in30d})
	te.exec(t, `UPDATE roles SET permissions = ? WHERE id = ?`, core.EncodeCaps(core.MemberCaps.With(core.CapAuditView)), support)
	if _, err := te.svc.AcceptInvite(ctx, adminWideTok, core.AcceptInvite{Username: "puppet4"}, testPHC, core.ReqMeta{}); !isInvalidInvite(err) {
		t.Fatalf("accept of a reusable invitation for a role that became staff: %v", err)
	}
}

// Making a role non-delegable revokes the open invitations account managers
// created for it; an administrator's stay.
func TestInviteRevokedWhenRoleNoLongerDelegable(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	inviter := te.mkRole(t, "Inviter", core.RoleMember, core.MemberCaps.With(core.CapInvitesManage).Closure(), false)
	vendors := te.mkRole(t, "Vendors", core.RoleGuest, 0, true)
	dora := te.mkUser(t, "dora", core.RoleMember)
	te.giveRole(t, dora, inviter)
	byDora, tok, err := te.svc.CreateInvite(ctx, te.principalOf(t, dora), core.InviteInput{RoleID: vendors, MaxUses: 20})
	if err != nil {
		t.Fatal(err)
	}
	byAdmin, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{RoleID: vendors, MaxUses: 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.UpdateRole(ctx, system(), vendors, core.RoleDefUpdate{Delegable: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if st := te.inviteStatusOf(t, byDora.ID); st != core.InviteRevoked || te.revokeReason(byDora.ID) != revokeCreatorCannotGive {
		t.Errorf("delegate's invitation: %s %q", st, te.revokeReason(byDora.ID))
	}
	if st := te.inviteStatusOf(t, byAdmin.ID); st != core.InviteActive {
		t.Errorf("administrator's invitation: %s", st)
	}
	if _, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "v1"}, testPHC, core.ReqMeta{}); !isInvalidInvite(err) {
		t.Fatalf("accept: %v", err)
	}
}

// A delegate whose role changes loses the invitations for roles the new one
// does not cover (it keeps invites.manage, so the old rule — revoke all
// when invites.manage goes — does not apply), and one whose role loses a
// server permission loses those as well.
func TestInviteRevokedWhenCreatorNoLongerCovers(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	helpdesk := te.mkRole(t, "Helpdesk", core.RoleMember,
		core.MemberCaps.With(core.CapInvitesManage, core.CapUsersManage).Closure(), false)
	inviter := te.mkRole(t, "Inviter", core.RoleMember, core.MemberCaps.With(core.CapInvitesManage).Closure(), false)
	desk := te.mkRole(t, "Desk", core.RoleMember, core.MemberCaps.With(core.CapUsersManage).Closure(), true)
	hana := te.mkUser(t, "hana", core.RoleMember)
	te.giveRole(t, hana, helpdesk)
	hp := te.principalOf(t, hana)
	deskInv, _, err := te.svc.CreateInvite(ctx, hp, core.InviteInput{RoleID: desk})
	if err != nil {
		t.Fatal(err)
	}
	quota := int64(5 << 30)
	quotaInv, _, err := te.svc.CreateInvite(ctx, hp, core.InviteInput{QuotaBytes: &quota})
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := te.svc.CreateInvite(ctx, hp, core.InviteInput{MaxUses: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.Update(ctx, system(), hana.ID, core.UserUpdate{RoleID: &inviter}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{deskInv.ID: core.InviteRevoked, quotaInv.ID: core.InviteRevoked, plain.ID: core.InviteActive} {
		if st := te.inviteStatusOf(t, id); st != want {
			t.Errorf("%s: %s, want %s", id, st, want)
		}
	}
	if r := te.revokeReason(deskInv.ID); r != revokeCreatorCannotGive {
		t.Errorf("reason %q", r)
	}

	// A role edit that takes a server permission from the creator's role.
	ivy := te.mkUser(t, "ivy", core.RoleMember)
	te.giveRole(t, ivy, helpdesk)
	ivyInv, _, err := te.svc.CreateInvite(ctx, te.principalOf(t, ivy), core.InviteInput{RoleID: desk})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.UpdateRole(ctx, system(), helpdesk, core.RoleDefUpdate{
		RemovePermissions: []core.Capability{core.CapUsersManage}}); err != nil {
		t.Fatal(err)
	}
	if st := te.inviteStatusOf(t, ivyInv.ID); st != core.InviteRevoked {
		t.Errorf("after the creator's role lost users.manage: %s", st)
	}
}

// Setting a storage quota on an invitation needs "Manage accounts", like
// setting it on an account; without a quota the default applies.
func TestInviteQuotaNeedsUsersManage(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	inviter := te.mkRole(t, "Inviter", core.RoleMember, core.MemberCaps.With(core.CapInvitesManage).Closure(), false)
	dora := te.mkUser(t, "dora", core.RoleMember)
	te.giveRole(t, dora, inviter)
	dp := te.principalOf(t, dora)
	for _, q := range []int64{0, 1 << 50} {
		_, _, err := te.svc.CreateInvite(ctx, dp, core.InviteInput{QuotaBytes: &q})
		wantErr(t, "quota by an invites-only delegate", err, core.ErrForbidden, "quota_bytes",
			"setting a storage quota needs the “Manage accounts” permission")
	}
	_, tok, err := te.svc.CreateInvite(ctx, dp, core.InviteInput{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "newbie"}, testPHC, core.ReqMeta{})
	if err != nil || u.QuotaBytes != nil {
		t.Fatalf("default quota: %+v %v", u, err)
	}
	q := int64(0)
	if _, _, err := te.svc.CreateInvite(ctx, system(), core.InviteInput{QuotaBytes: &q}); err != nil {
		t.Fatalf("administrator sets a quota: %v", err)
	}
}

// --elevated API tokens stop counting as elevated when their owner's role
// gains a server permission or the owner gets another role, like the step-up
// window of a session.
func TestTokenElevationDroppedOnNewPower(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	ops := te.mkRole(t, "Ops", core.RoleMember, core.MemberCaps.With(core.CapSystemView).Closure(), false)
	olly := te.mkUser(t, "olly", core.RoleMember)
	te.giveRole(t, olly, ops)
	other := te.mkUser(t, "other", core.RoleMember)
	te.giveRole(t, other, ops)
	token := func(id, user, scopes string) {
		te.exec(t, `INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, 1, 9999999999999)`, id, user, id, []byte(id), scopes)
	}
	token("tok_olly", olly.ID, `["admin","elevated"]`)
	token("tok_plain", olly.ID, `["files:read","admin"]`)
	token("tok_other", other.ID, `admin elevated`) // the whitespace form package auth also reads
	scopes := func(id string) string {
		t.Helper()
		var s string
		if err := te.env.DB.QueryRow(ctx, `SELECT scopes FROM api_tokens WHERE id = ?`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// A rename changes nothing.
	if _, err := te.svc.UpdateRole(ctx, system(), ops, core.RoleDefUpdate{Name: ptr("Operators")}); err != nil {
		t.Fatal(err)
	}
	if s := scopes("tok_olly"); !strings.Contains(s, "elevated") {
		t.Fatalf("rename dropped the elevation: %s", s)
	}
	// New server power: every holder's elevated token loses the flag.
	if _, err := te.svc.UpdateRole(ctx, system(), ops, core.RoleDefUpdate{
		AddPermissions: []core.Capability{core.CapUsersCredentials}}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"tok_olly": `["admin"]`, "tok_other": `["admin"]`, "tok_plain": `["files:read","admin"]`} {
		if s := scopes(id); s != want {
			t.Errorf("%s: scopes %s, want %s", id, s, want)
		}
	}
	// A role change (here: to admin) does the same.
	token("tok_olly2", olly.ID, `["admin","elevated"]`)
	if _, err := te.svc.Update(ctx, system(), olly.ID, core.UserUpdate{Role: ptr(core.RoleAdmin)}); err != nil {
		t.Fatal(err)
	}
	if s := scopes("tok_olly2"); s != `["admin"]` {
		t.Errorf("after the promotion: %s", s)
	}
}

// Renaming a role (or changing its description or delegable flag) tells
// the holders nothing about their access: authz.changed with reason
// role_details; a permission change stays role_updated.
func TestRoleDetailsEvent(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	r := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	evs := te.authzEvents(t)
	for _, in := range []core.RoleDefUpdate{{Name: ptr("Accounting")}, {Description: ptr("typo fixed")}, {Delegable: ptr(true)}} {
		if _, err := te.svc.UpdateRole(ctx, system(), r.ID, in); err != nil {
			t.Fatal(err)
		}
		if ev := evs(); len(ev) != 1 || ev[0].Reason != core.AuthzRoleDetails || ev[0].RoleID != r.ID {
			t.Errorf("%+v: events %+v", in, ev)
		}
	}
	if _, err := te.svc.UpdateRole(ctx, system(), r.ID, core.RoleDefUpdate{Name: ptr("Finance"),
		AddPermissions: []core.Capability{core.CapAuditView}}); err != nil {
		t.Fatal(err)
	}
	if ev := evs(); len(ev) != 1 || ev[0].Reason != core.AuthzRoleUpdated {
		t.Errorf("permission change: events %+v", ev)
	}
}

// Role, group and display names refuse invisible format characters, and
// names that differ only by a joiner or direction mark are the same name.
func TestLabelsRefuseInvisibleCharacters(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.createRole(t, core.RoleDefInput{Name: "finance"})
	for _, name := range []string{"finance\u200b", "\u2060", "fin\u00adance", "finance\ufeff", "a\u2061b"} {
		_, err := te.svc.CreateRole(ctx, system(), core.RoleDefInput{Name: name})
		wantErr(t, "role "+name, err, core.ErrInvalid, "name", "role name must not contain invisible characters such as a zero-width space")
	}
	_, err := te.svc.CreateRole(ctx, system(), core.RoleDefInput{Name: "\u200d"})
	wantErr(t, "role of a joiner", err, core.ErrInvalid, "name", "role name must not be empty")
	_, err = te.svc.CreateRole(ctx, system(), core.RoleDefInput{Name: "finance\u200d"})
	wantErr(t, "look-alike role", err, core.ErrConflict, "name", "a role with this name already exists")
	_, err = te.svc.CreateRole(ctx, system(), core.RoleDefInput{Name: "admin\u200e"})
	wantErr(t, "reserved look-alike", err, core.ErrInvalid, "name", "")
	// Joiners in real names stay possible (Persian, emoji sequences).
	te.createRole(t, core.RoleDefInput{Name: "می\u200cخواهم"})
	te.createRole(t, core.RoleDefInput{Name: "👩\u200d💻 Devs"})

	if _, err := te.svc.CreateGroup(ctx, system(), core.GroupInput{Name: "Design"}); err != nil {
		t.Fatal(err)
	}
	_, err = te.svc.CreateGroup(ctx, system(), core.GroupInput{Name: "Design\u200b"})
	wantErr(t, "group with a zero-width space", err, core.ErrInvalid, "name", "")
	_, err = te.svc.CreateGroup(ctx, system(), core.GroupInput{Name: "Design\u200d"})
	wantErr(t, "look-alike group", err, core.ErrConflict, "name", "a group with this name already exists")

	u := te.mkUser(t, "mel", core.RoleMember)
	for _, dn := range []string{"abc\u202edef", "mel\u200b"} {
		_, err := te.svc.Update(ctx, as(u), u.ID, core.UserUpdate{DisplayName: ptr(dn)})
		wantErr(t, "display name "+dn, err, core.ErrInvalid, "display_name", "")
	}
	if got, err := te.svc.Update(ctx, as(u), u.ID, core.UserUpdate{DisplayName: ptr("Mél")}); err != nil || got.DisplayName != "Mél" {
		t.Fatalf("plain display name: %+v %v", got, err)
	}
}
