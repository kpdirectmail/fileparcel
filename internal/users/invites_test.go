package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

func TestInviteLifecycle(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	member := te.mkUser(t, "member", core.RoleMember)
	g, _ := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "Team"})

	if _, _, err := te.svc.CreateInvite(ctx, as(member), core.InviteInput{}); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("member invites: %v", err)
	}
	inv, token, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{
		Email: "new@example.com", Role: core.RoleGuest, GroupIDs: []string{g.ID}, QuotaBytes: ptr[int64](1 << 30), Note: "welcome",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < ids.TokenLen(16) || !ids.ValidToken(token) {
		t.Fatalf("weak token %q", token)
	}
	if inv.Status != core.InviteActive || inv.MaxUses != 1 || inv.URL != "/invite/"+token ||
		!inv.ExpiresAt.Equal(te.clock.Now().Add(7*24*time.Hour)) {
		t.Fatalf("invite %+v", inv)
	}
	// Stored hashed + sealed with the row-bound AAD; never in clear text.
	var hash []byte
	var enc string
	if err := te.env.DB.QueryRow(ctx, `SELECT token_hash, token_enc FROM invites WHERE id = ?`, inv.ID).Scan(&hash, &enc); err != nil {
		t.Fatal(err)
	}
	if !ids.EqualBytes(hash, ids.HashToken(token)) || strings.Contains(enc, token) {
		t.Fatal("token stored in clear")
	}
	if pt, err := te.keys.OpenField(inviteAAD(inv.ID), enc); err != nil || string(pt) != token {
		t.Fatalf("sealed token: %v", err)
	}
	if _, err := te.keys.OpenField(inviteAAD("inv_other"), enc); err == nil {
		t.Fatal("AAD not bound to the row")
	}
	if e, ok := te.audit.last(core.ActInviteCreate); !ok || strings.Contains(stringify(e.Details), token) {
		t.Fatalf("audit %+v", e)
	}

	// Lookup.
	got, err := te.svc.LookupInvite(ctx, token)
	if err != nil || got.ID != inv.ID || got.Role != core.RoleGuest || got.CreatedBy != "" || got.URL != "" {
		t.Fatalf("lookup %+v %v", got, err)
	}
	for _, bad := range []string{"", "short", token + "x", strings.Repeat("A", 200), "../../etc", token[:len(token)-1] + "!"} {
		if _, err := te.svc.LookupInvite(ctx, bad); !errors.Is(err, core.ErrNotFound) {
			t.Errorf("lookup %q: %v", bad, err)
		}
	}

	// Accept: e-mail must match the invite; the account gets role, quota, groups.
	if _, err := te.svc.AcceptInvite(ctx, token, core.AcceptInvite{Username: "newbie", Email: "other@example.com"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("mismatched email: %v", err)
	}
	if _, err := te.svc.AcceptInvite(ctx, token, core.AcceptInvite{Username: "newbie"}, "", core.ReqMeta{}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("no hash: %v", err)
	}
	if _, err := te.svc.AcceptInvite(ctx, token, core.AcceptInvite{Username: "member"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("taken username: %v", err)
	}
	u, err := te.svc.AcceptInvite(ctx, token, core.AcceptInvite{Username: "newbie", DisplayName: "New Bie"}, testPHC, core.ReqMeta{UserAgent: "ua"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != core.RoleGuest || u.Email != "new@example.com" || u.DisplayName != "New Bie" || u.SpaceID != "" ||
		u.QuotaBytes == nil || *u.QuotaBytes != 1<<30 || u.CreatedBy != admin.ID || u.PasswordHash != testPHC {
		t.Fatalf("accepted user %+v", u)
	}
	if gids, _ := te.svc.GroupIDsOf(ctx, u.ID); len(gids) != 1 || gids[0] != g.ID {
		t.Fatalf("groups %v", gids)
	}
	if e, ok := te.audit.last(core.ActInviteAccept); !ok || e.ActorID != u.ID || e.TargetID != inv.ID || e.UserAgent != "ua" {
		t.Fatalf("accept audit %+v", e)
	}
	// Single use.
	if _, err := te.svc.AcceptInvite(ctx, token, core.AcceptInvite{Username: "second"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := te.svc.LookupInvite(ctx, token); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("lookup used: %v", err)
	}
}

func stringify(v any) string {
	var b strings.Builder
	if m, ok := v.(map[string]any); ok {
		for k, x := range m {
			b.WriteString(k)
			b.WriteString("=")
			if s, ok := x.(string); ok {
				b.WriteString(s)
			}
			b.WriteString(";")
		}
	}
	return b.String()
}

func TestInviteExpiryUsesRevoke(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)

	// Expiry.
	exp := te.clock.Now().Add(time.Hour)
	inv, tok, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{ExpiresAt: &exp})
	if err != nil || inv.Role != core.RoleMember {
		t.Fatalf("create %+v %v", inv, err)
	}
	te.clock.Advance(time.Hour)
	if _, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "late"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expired accept: %v", err)
	}

	// Multi-use.
	multi, mtok, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		u, err := te.svc.AcceptInvite(ctx, mtok, core.AcceptInvite{Username: name}, testPHC, core.ReqMeta{})
		if err != nil || u.SpaceID == "" {
			t.Fatalf("accept %s: %+v %v", name, u, err)
		}
	}
	if _, err := te.svc.AcceptInvite(ctx, mtok, core.AcceptInvite{Username: "three"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("third use: %v", err)
	}

	// Revoke (idempotent).
	rev, rtok, _ := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Role: core.RoleAdmin})
	if err := te.svc.RevokeInvite(ctx, as(admin), rev.ID); err != nil {
		t.Fatal(err)
	}
	te.audit.reset()
	if err := te.svc.RevokeInvite(ctx, as(admin), rev.ID); err != nil || len(te.audit.actions()) != 0 {
		t.Fatalf("revoke twice: %v %v", err, te.audit.actions())
	}
	if _, err := te.svc.AcceptInvite(ctx, rtok, core.AcceptInvite{Username: "rev"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("revoked accept: %v", err)
	}
	if err := te.svc.RevokeInvite(ctx, as(admin), "inv_missing"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}

	// Listing: statuses; only active invites carry a link.
	active, atok, _ := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{})
	page, err := te.svc.ListInvites(ctx, as(admin), core.PageReq{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	all := page.Items
	for page.NextCursor != "" {
		if page, err = te.svc.ListInvites(ctx, as(admin), core.PageReq{Limit: 2, Cursor: page.NextCursor}); err != nil {
			t.Fatal(err)
		}
		all = append(all, page.Items...)
	}
	want := map[string]string{inv.ID: core.InviteExpired, multi.ID: core.InviteUsed, rev.ID: core.InviteRevoked, active.ID: core.InviteActive}
	if len(all) != 4 {
		t.Fatalf("listed %d", len(all))
	}
	for i, x := range all {
		if want[x.ID] != x.Status {
			t.Errorf("%s status %s want %s", x.ID, x.Status, want[x.ID])
		}
		if (x.URL != "") != (x.Status == core.InviteActive) {
			t.Errorf("%s url %q", x.ID, x.URL)
		}
		if i > 0 && x.CreatedAt.After(all[i-1].CreatedAt) {
			t.Error("not newest first")
		}
	}
	if all[0].ID != active.ID || all[0].URL != "/invite/"+atok {
		t.Fatalf("first %+v", all[0])
	}
	// Locked keys: the listing still works, without links.
	te.keys.locked.Store(true)
	page, err = te.svc.ListInvites(ctx, as(admin), core.PageReq{})
	if err != nil || page.Items[0].URL != "" {
		t.Fatalf("locked listing %+v %v", page.Items[0], err)
	}
	if _, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{}); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("create while locked: %v", err)
	}
}

func TestInviteValidation(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	now := te.clock.Now()
	cases := []struct {
		name  string
		in    core.InviteInput
		field string
	}{
		{"owner role", core.InviteInput{Role: core.RoleOwner}, "role"},
		{"bogus role", core.InviteInput{Role: "king"}, "role"},
		{"bad email", core.InviteInput{Email: "nope"}, "email"},
		{"past expiry", core.InviteInput{ExpiresAt: ptr(now.Add(-time.Minute))}, "expires_at"},
		{"far expiry", core.InviteInput{ExpiresAt: ptr(now.Add(400 * 24 * time.Hour))}, "expires_at"},
		{"uses", core.InviteInput{MaxUses: -1}, "max_uses"},
		{"too many uses", core.InviteInput{MaxUses: 5000}, "max_uses"},
		// The account gets the invited address and addresses are unique, so
		// only the first acceptance could ever succeed.
		{"email with many uses", core.InviteInput{Email: "team@example.com", MaxUses: 2}, "max_uses"},
		{"quota", core.InviteInput{QuotaBytes: ptr[int64](-2)}, "quota_bytes"},
		{"group id", core.InviteInput{GroupIDs: []string{"x"}}, "group_ids"},
		{"unknown group", core.InviteInput{GroupIDs: []string{"grp_01j9zq3x4k6m8p0r2t4v6x8z0b"}}, "group_ids"},
		{"send without email", core.InviteInput{Send: true}, "email"},
		{"send without smtp", core.InviteInput{Send: true, Email: "a@example.com"}, "send"},
		{"note control chars", core.InviteInput{Note: "a\x07"}, "note"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := te.svc.CreateInvite(ctx, as(admin), tc.in)
			if !errors.Is(err, core.ErrInvalid) || fieldOf(err) != tc.field {
				t.Fatalf("got %v (field %q) want field %q", err, fieldOf(err), tc.field)
			}
		})
	}
	if n := te.count(t, `SELECT count(*) FROM invites`); n != 0 {
		t.Fatalf("%d invites stored", n)
	}
}

func TestInviteSend(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin, func(in *core.NewUser) { in.DisplayName = "Ada Admin" })
	te.notify.enabled.Store(true)
	first, tok, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Send: true, Email: "x@example.com", Note: "hi"})
	if err != nil || first.EmailError != "" {
		t.Fatalf("%+v %v", first, err)
	}
	mails := te.notify.mails()
	if len(mails) != 1 || mails[0].tmpl != "invite" || mails[0].to[0] != "x@example.com" {
		t.Fatalf("mails %+v", mails)
	}
	d := mails[0].data
	if d["url"] != "https://fileparcel.local:8443/invite/"+tok || d["inviter"] != "Ada Admin" || d["note"] != "hi" {
		t.Fatalf("data %+v", d)
	}
	// The public invite page names the inviter as the e-mail does; the creator's ID stays hidden.
	if got, err := te.svc.LookupInvite(ctx, tok); err != nil || got.InvitedBy != "Ada Admin" || got.CreatedBy != "" {
		t.Fatalf("lookup %+v %v", got, err)
	}
	// server.public_url wins for links (API and e-mail).
	te.env.Config.Server.PublicURL = "https://files.example.com/"
	inv, tok2, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Send: true, Email: "y@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.URL != "https://files.example.com/invite/"+tok2 || te.notify.mails()[1].data["url"] != inv.URL || inv.EmailError != "" {
		t.Fatalf("public url: %q / %v", inv.URL, te.notify.mails()[1].data["url"])
	}
}

// A send that queues nothing (mail queue full, no absolute URL for the link)
// still creates the invitation, but says so instead of claiming "sent".
func TestInviteSendFailure(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	te.notify.enabled.Store(true)
	te.notify.fail = core.Errorf(core.ErrUnavailable, "the mail queue is full; try again later")
	inv, tok, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Send: true, Email: "x@example.com"})
	if err != nil || inv.EmailError != "the mail queue is full; try again later" || inv.URL != "/invite/"+tok {
		t.Fatalf("queue full: %+v %v", inv, err)
	}
	if got, err := te.svc.LookupInvite(ctx, tok); err != nil || got.ID != inv.ID {
		t.Fatalf("invitation not stored: %+v %v", got, err)
	}
	e, ok := te.audit.last(core.ActInviteCreate)
	if d, _ := e.Details.(map[string]any); !ok || d["send"] != true || d["sent"] != nil {
		t.Fatalf("audit %+v", e)
	}

	// No public_url and no access URL: nothing to put in the e-mail.
	te.notify.fail = nil
	if err := te.svc.Bind(&core.Services{Notify: te.notify, Network: &fakeNetwork{}}); err != nil {
		t.Fatal(err)
	}
	inv, _, err = te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Send: true, Email: "y@example.com"})
	if err != nil || !strings.Contains(inv.EmailError, "server.public_url") || len(te.notify.mails()) != 0 {
		t.Fatalf("no base URL: %+v %v %d mails", inv, err, len(te.notify.mails()))
	}
	if n := te.count(t, `SELECT count(*) FROM invites`); n != 2 {
		t.Fatalf("%d invites stored", n)
	}
}

// An invitation names the address the account will get; while an account
// (active or disabled) already has it, the link could only ever fail for the
// invitee, so creating it is refused.
func TestInviteEmailTaken(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	te.mkUser(t, "alice", core.RoleMember, withEmail("alice@example.com"))
	carol := te.mkUser(t, "carol", core.RoleMember, withEmail("carol@example.com"))
	if err := te.svc.SetStatus(ctx, system(), carol.ID, core.UserDisabled); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"alice@example.com", "Alice@Example.com", "carol@example.com"} {
		if _, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Email: addr}); !errors.Is(err, core.ErrConflict) || fieldOf(err) != "email" {
			t.Errorf("invite %s: %v (field %q)", addr, err, fieldOf(err))
		}
	}
	if n := te.count(t, `SELECT count(*) FROM invites`); n != 0 {
		t.Fatalf("%d invites stored", n)
	}
	_, tok, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Email: "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if u, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "bob"}, testPHC, core.ReqMeta{}); err != nil || u.Email != "bob@example.com" {
		t.Fatalf("accept %+v %v", u, err)
	}
}

// Only administrators create invitations, so an account that loses its
// administrator rights loses its active invitations with them: otherwise a
// kept link would recreate an administrator (or a member of any group).
func TestInvitesRevokedWhenCreatorLosesAdmin(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		act    func(te *testEnv, owner *core.User, id string) error
		reason string
	}{
		{"delete", func(te *testEnv, owner *core.User, id string) error {
			return te.svc.Delete(ctx, as(owner), id, "")
		}, "creator_deleted"},
		{"demote to member", func(te *testEnv, owner *core.User, id string) error {
			_, err := te.svc.Update(ctx, as(owner), id, core.UserUpdate{Role: ptr(core.RoleMember)})
			return err
		}, "creator_demoted"},
		{"demote to guest", func(te *testEnv, owner *core.User, id string) error {
			_, err := te.svc.Update(ctx, as(owner), id, core.UserUpdate{Role: ptr(core.RoleGuest)})
			return err
		}, "creator_demoted"},
		{"disable", func(te *testEnv, owner *core.User, id string) error {
			return te.svc.SetStatus(ctx, as(owner), id, core.UserDisabled)
		}, "creator_disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			owner := te.mkUser(t, "owner", core.RoleOwner)
			mallory := te.mkUser(t, "mallory", core.RoleAdmin)
			bob := te.mkUser(t, "bob", core.RoleAdmin)
			g, err := te.svc.CreateGroup(ctx, as(owner), core.GroupInput{Name: "Team"})
			if err != nil {
				t.Fatal(err)
			}
			mk := func(by *core.Principal, in core.InviteInput) (string, string) {
				t.Helper()
				inv, tok, err := te.svc.CreateInvite(ctx, by, in)
				if err != nil {
					t.Fatal(err)
				}
				return inv.ID, tok
			}
			// Staff invitations are single use; a member link may serve many.
			admID, admTok := mk(as(mallory), core.InviteInput{Role: core.RoleAdmin})
			memID, memTok := mk(as(mallory), core.InviteInput{GroupIDs: []string{g.ID}, MaxUses: 1000})
			usedID, usedTok := mk(as(mallory), core.InviteInput{})
			if _, err := te.svc.AcceptInvite(ctx, usedTok, core.AcceptInvite{Username: "early"}, testPHC, core.ReqMeta{}); err != nil {
				t.Fatal(err)
			}
			expID, _ := mk(as(mallory), core.InviteInput{ExpiresAt: ptr(te.clock.Now().Add(time.Hour))})
			te.clock.Advance(time.Hour)
			bobID, bobTok := mk(as(bob), core.InviteInput{Role: core.RoleAdmin})
			sysID, sysTok := mk(system(), core.InviteInput{Role: core.RoleAdmin})
			te.audit.reset()

			if err := tc.act(te, owner, mallory.ID); err != nil {
				t.Fatal(err)
			}
			for _, tok := range []string{admTok, memTok} {
				if _, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "mallory2"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrNotFound) {
					t.Fatalf("accept after %s: %v", tc.name, err)
				}
			}
			page, err := te.svc.ListInvites(ctx, as(owner), core.PageReq{})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{admID: core.InviteRevoked, memID: core.InviteRevoked, usedID: core.InviteUsed,
				expID: core.InviteExpired, bobID: core.InviteActive, sysID: core.InviteActive}
			for _, x := range page.Items {
				if want[x.ID] != x.Status {
					t.Errorf("%s: status %s, want %s", x.ID, x.Status, want[x.ID])
				}
			}
			revoked := map[string]bool{}
			for _, e := range te.audit.entries {
				if e.Action != core.ActInviteRevoke {
					continue
				}
				if d, _ := e.Details.(map[string]any); d["reason"] != tc.reason || d["created_by"] != mallory.ID {
					t.Errorf("revoke audit %+v", e)
				}
				revoked[e.TargetID] = true
			}
			if len(revoked) != 2 || !revoked[admID] || !revoked[memID] {
				t.Fatalf("revoke audit for %v", revoked)
			}
			// Other administrators' and the system's invitations are untouched.
			for i, tok := range []string{bobTok, sysTok} {
				if _, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "later" + string(rune('a'+i))}, testPHC, core.ReqMeta{}); err != nil {
					t.Fatalf("other invite: %v", err)
				}
			}
		})
	}

	// Owner → admin keeps administrator rights, and with them the invitations;
	// re-enabling an account does not bring revoked ones back.
	te := newTestEnv(t)
	owner := te.mkUser(t, "owner", core.RoleOwner)
	olga := te.mkUser(t, "olga", core.RoleOwner)
	_, tok, err := te.svc.CreateInvite(ctx, as(olga), core.InviteInput{Role: core.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.Update(ctx, as(owner), olga.ID, core.UserUpdate{Role: ptr(core.RoleAdmin)}); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.LookupInvite(ctx, tok); err != nil {
		t.Fatalf("owner → admin revoked the invitation: %v", err)
	}
	if err := te.svc.SetStatus(ctx, as(owner), olga.ID, core.UserDisabled); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.SetStatus(ctx, as(owner), olga.ID, core.UserActive); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.LookupInvite(ctx, tok); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("re-enabled account's invitation: %v", err)
	}
}

func TestInviteConcurrentAccept(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	_, tok, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, notFound := 0, 0
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			_, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "racer" + string(rune('a'+i))}, testPHC, core.ReqMeta{})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, core.ErrNotFound):
				notFound++
			default:
				t.Errorf("accept: %v", err)
			}
		})
	}
	wg.Wait()
	if ok != 1 || notFound != 7 {
		t.Fatalf("ok %d notFound %d", ok, notFound)
	}
}

// Invitations carry a role: role_id names a custom role (invites.role holds
// its base), and accepting re-resolves it — an invitation whose role is gone
// is as invalid as a revoked one.
func TestInviteCustomRole(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	contractors := te.createRole(t, core.RoleDefInput{Name: "Contractors", Base: core.RoleGuest,
		Permissions: capList(core.CapShareRequests)})
	helpdesk := te.createRole(t, core.RoleDefInput{Name: "Helpdesk", Permissions: capList(core.CapUsersManage)})

	inv, tok, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{RoleID: contractors.ID, MaxUses: 10})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Role != core.RoleGuest || inv.RoleID != contractors.ID || inv.RoleName != "Contractors" {
		t.Fatalf("invite %+v", inv)
	}
	var role, roleID string
	if err := te.env.DB.QueryRow(ctx, `SELECT role, role_id FROM invites WHERE id = ?`, inv.ID).Scan(&role, &roleID); err != nil ||
		role != "guest" || roleID != contractors.ID {
		t.Fatalf("stored %s %s %v", role, roleID, err)
	}
	e, _ := te.audit.last(core.ActInviteCreate)
	if d := e.Details.(map[string]any); d["role"] != core.RoleGuest || d["role_id"] != contractors.ID || d["role_name"] != "Contractors" {
		t.Fatalf("audit %+v", d)
	}
	if got, err := te.svc.LookupInvite(ctx, tok); err != nil || got.RoleID != contractors.ID || got.RoleName != "Contractors" {
		t.Fatalf("lookup %+v %v", got, err)
	}
	u, err := te.svc.AcceptInvite(ctx, tok, core.AcceptInvite{Username: "con"}, testPHC, core.ReqMeta{})
	if err != nil || u.Role != core.RoleGuest || u.RoleID != contractors.ID || u.SpaceID != "" {
		t.Fatalf("accepted %+v %v", u, err)
	}
	e, _ = te.audit.last(core.ActInviteAccept)
	if d := e.Details.(map[string]any); d["role_id"] != contractors.ID || d["role_name"] != "Contractors" {
		t.Fatalf("accept audit %+v", d)
	}
	e, _ = te.audit.last(core.ActUserCreate)
	if d := e.Details.(map[string]any); d["role_id"] != contractors.ID || d["invite_id"] != inv.ID {
		t.Fatalf("accept create audit %+v", d)
	}
	// The e-mail names the role.
	te.notify.enabled.Store(true)
	if _, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{RoleID: contractors.ID, Email: "c@example.com", Send: true}); err != nil {
		t.Fatal(err)
	}
	if m := te.notify.mails(); len(m) != 1 || m[0].data["role"] != "Contractors" {
		t.Fatalf("mail %+v", m)
	}

	// The role goes away: the link stops working (uniform 404).
	_, tok2, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{RoleID: contractors.ID, MaxUses: 10})
	if err != nil {
		t.Fatal(err)
	}
	te.exec(t, `UPDATE users SET role_id = NULL WHERE role_id = ?`, contractors.ID)
	te.exec(t, `DELETE FROM roles WHERE id = ?`, contractors.ID)
	if _, err := te.svc.AcceptInvite(ctx, tok2, core.AcceptInvite{Username: "late"}, testPHC, core.ReqMeta{}); !errors.Is(err, core.ErrNotFound) ||
		core.AsError(err).Message != "this invitation is invalid or has expired" {
		t.Fatalf("accept after the role was deleted: %v", err)
	}
	page, _ := te.svc.ListInvites(ctx, as(admin), core.PageReq{})
	for _, x := range page.Items {
		if x.RoleID == contractors.ID && x.RoleName != "Deleted role" {
			t.Errorf("deleted role name %q", x.RoleName)
		}
	}

	// Staff invitations: single use, at most 7 days.
	now := te.clock.Now()
	for _, c := range []struct {
		in    core.InviteInput
		field string
	}{
		{core.InviteInput{Role: core.RoleAdmin, MaxUses: 2}, "max_uses"},
		{core.InviteInput{RoleID: "admin", ExpiresAt: ptr(now.Add(8 * 24 * time.Hour))}, "expires_at"},
		{core.InviteInput{RoleID: helpdesk.ID, MaxUses: 2}, "max_uses"},
		{core.InviteInput{RoleID: helpdesk.ID, ExpiresAt: ptr(now.Add(7*24*time.Hour + time.Minute))}, "expires_at"},
		{core.InviteInput{RoleID: "owner"}, "role_id"},
		{core.InviteInput{Role: core.RoleGuest, RoleID: helpdesk.ID}, "role"},
		{core.InviteInput{RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na"}, "role_id"},
	} {
		_, _, err := te.svc.CreateInvite(ctx, as(admin), c.in)
		wantErr(t, fmt.Sprintf("invite %+v", c.in), err, core.ErrInvalid, c.field, "")
	}
	for _, in := range []core.InviteInput{
		{RoleID: helpdesk.ID, ExpiresAt: ptr(now.Add(7 * 24 * time.Hour))},
		{Role: core.RoleAdmin},
		{Role: core.RoleMember, MaxUses: 50, ExpiresAt: ptr(now.Add(30 * 24 * time.Hour))},
	} {
		if _, _, err := te.svc.CreateInvite(ctx, as(admin), in); err != nil {
			t.Errorf("invite %+v: %v", in, err)
		}
	}
}

// A delegate with invites.manage invites for the roles it may give, adds
// groups only with groups.manage, and may revoke any invitation.
func TestInviteDelegation(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	inviters := te.createRole(t, core.RoleDefInput{Name: "Inviters", Permissions: capList(core.CapInvitesManage)})
	finance := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	staff := te.createRole(t, core.RoleDefInput{Name: "Staff", Delegable: true})
	ivy := te.mkUser(t, "ivy", core.RoleMember)
	te.giveRole(t, ivy, inviters.ID)
	p := te.principalOf(t, ivy)
	g, _ := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "Team"})
	adminInv, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Role: core.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	te.audit.reset()

	for _, in := range []core.InviteInput{{}, {Role: core.RoleGuest}, {RoleID: staff.ID, MaxUses: 20}} {
		if _, _, err := te.svc.CreateInvite(ctx, p, in); err != nil {
			t.Errorf("invite %+v: %v", in, err)
		}
	}
	for _, c := range []struct {
		in  core.InviteInput
		msg string
	}{
		{core.InviteInput{Role: core.RoleAdmin, Email: "boss@example.com"}, "only administrators can grant the admin role"},
		{core.InviteInput{RoleID: finance.ID}, "administrators have not allowed account managers to give the role “Finance”"},
	} {
		_, _, err := te.svc.CreateInvite(ctx, p, c.in)
		wantErr(t, fmt.Sprintf("invite %+v", c.in), err, core.ErrForbidden, "", c.msg)
		e, ok := te.audit.last(core.ActInviteCreate)
		if !ok || e.Outcome != core.OutcomeDenied || e.ActorID != ivy.ID || e.TargetType != "invite" ||
			e.TargetName != c.in.Email || e.Details.(map[string]any)["reason"] != c.msg {
			t.Errorf("denied audit %+v", e)
		}
	}
	_, _, err = te.svc.CreateInvite(ctx, p, core.InviteInput{GroupIDs: []string{g.ID}})
	wantErr(t, "group_ids", err, core.ErrForbidden, "group_ids", "adding people to groups needs the “Manage groups” permission")
	if n := te.count(t, `SELECT count(*) FROM invites WHERE created_by = ?`, ivy.ID); n != 3 {
		t.Fatalf("%d invitations stored", n)
	}
	// Revoking only reduces access: any invitation.
	if err := te.svc.RevokeInvite(ctx, p, adminInv.ID); err != nil {
		t.Fatalf("revoke admin invite: %v", err)
	}
	err = te.svc.RevokeInvite(ctx, as(te.mkUser(t, "mia", core.RoleMember)), adminInv.ID)
	wantErr(t, "member revokes", err, core.ErrForbidden, "", "this needs the “Invite people” permission")
}
