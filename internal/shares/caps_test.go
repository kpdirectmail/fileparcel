package shares

import (
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// shares.manage ("Manage everyone's links") opens the cross-user view of a
// custom role exactly as it does for administrators — list, view, disable or
// enable, revoke and the access log — but never the links themselves: even
// with auth.admin_can_access_files on, only built-in owners and admins see
// other people's links. Over an API token the permission needs the admin
// scope.
func TestSharesManagePermission(t *testing.T) {
	f := setup(t)
	file := f.PutFile(f.aliceRoot, "report.pdf", []byte("r"))
	s, _ := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID})
	f.Settings.Put(settingAdminFiles, true)
	defer f.Settings.Put(settingAdminFiles, false)

	linkManager := func(via core.AuthVia, scopes ...string) *core.Principal {
		p := &core.Principal{UserID: f.bob, Username: "bob", Role: core.RoleMember,
			RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na", RoleName: "Link managers", Via: via, Scopes: scopes,
			AuthLevel: core.AuthLevelFull}
		p.SetCaps(core.MemberCaps.With(core.CapSharesManage))
		return p
	}
	session := linkManager(core.ViaSession)
	all, err := f.svc.ListAll(core.WithPrincipal(f.ctx, session), core.ShareQuery{})
	if err != nil || len(all.Items) != 1 || all.Items[0].ID != s.ID || all.Items[0].URL != "" {
		t.Fatalf("list all: %+v %v", all.Items, err)
	}
	g, err := f.svc.Get(f.ctx, session, s.ID)
	if err != nil || g.URL != "" {
		t.Fatalf("get: %+v %v", g, err)
	}
	if _, err := f.svc.AccessLog(f.ctx, session, s.ID, core.PageReq{}); err != nil {
		t.Fatalf("access log: %v", err)
	}
	// Like administrators: others' shares may only be disabled or enabled.
	_, err = f.svc.Update(f.ctx, session, s.ID, core.ShareUpdate{Title: ptr("hijack")})
	wantCode(t, err, core.ErrForbidden)
	if u, err := f.svc.Update(f.ctx, session, s.ID, core.ShareUpdate{Disabled: ptr(true)}); err != nil ||
		u.Status != core.ShareDisabled || u.URL != "" {
		t.Fatalf("disable: %+v %v", u, err)
	}

	// A token without the admin scope is back to its own shares.
	noAdmin := linkManager(core.ViaToken, core.ScopeShares, core.ScopeFilesRead)
	_, err = f.svc.Get(f.ctx, noAdmin, s.ID)
	wantCode(t, err, core.ErrNotFound)
	wantCode(t, f.svc.Revoke(f.ctx, noAdmin, s.ID), core.ErrNotFound)
	if g, err := f.svc.Get(f.ctx, linkManager(core.ViaToken, core.ScopeAdmin), s.ID); err != nil || g.URL != "" {
		t.Fatalf("admin-scope token: %+v %v", g, err)
	}

	// The built-in admin still sees the link with the file-access setting.
	admin := &core.Principal{UserID: "usr_admin", Username: "root", Role: core.RoleAdmin, Via: core.ViaSession,
		AuthLevel: core.AuthLevelFull}
	if g, err := f.svc.Get(f.ctx, admin, s.ID); err != nil || g.URL == "" {
		t.Fatalf("admin: %+v %v", g, err)
	}

	// Without the permission a custom role sees only its own shares.
	plain := linkManager(core.ViaSession)
	plain.SetCaps(core.MemberCaps)
	_, err = f.svc.Get(f.ctx, plain, s.ID)
	wantCode(t, err, core.ErrNotFound)

	if err := f.svc.Revoke(f.ctx, session, s.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// asGuest returns p as a built-in guest's principal, the way package auth
// builds it: shares.links and shares.requests only while
// sharing.allow_guests_share is on.
func asGuest(p *core.Principal, guestsShare bool) *core.Principal {
	g := p.Clone()
	g.Role, g.RoleID, g.RoleName = core.RoleGuest, string(core.RoleGuest), "Guest"
	g.SetCaps(core.BuiltinCaps(core.RoleGuest, guestsShare))
	return g
}

// withRole returns p as the holder of a custom role with base and caps.
func withRole(p *core.Principal, base core.Role, caps core.CapSet) *core.Principal {
	r := p.Clone()
	r.Role, r.RoleID, r.RoleName = base, "rol_01k5z8r3m9d4q7w2x6c1v0b5nb", "Custom"
	r.SetCaps(caps.Closure())
	return r
}

// Creating a link needs shares.links and a file request shares.requests,
// whatever the base role: a guest-based role holding shares.links shares
// without sharing.allow_guests_share, a member-based role without it does
// not. Editing an existing share (other than disabling it) needs the
// permission of its kind again.
func TestShareCreationFollowsRolePermissions(t *testing.T) {
	f := setup(t)
	folder := f.Mkdir(f.aliceRoot, "F")
	file := f.PutFile(folder, "x.txt", []byte("x"))
	alice := f.P(f.alice)
	link := core.ShareInput{NodeID: file.ID}
	request := core.ShareInput{Kind: core.ShareRequest, NodeID: folder}
	refusal := func(err error) string {
		t.Helper()
		ce := core.AsError(err)
		if ce == nil || ce.Code != core.ErrForbidden.Code {
			t.Fatalf("error %v, want forbidden", err)
		}
		return ce.Message
	}

	noLinks := withRole(alice, core.RoleMember, core.MemberCaps.Without(core.CapShareLinks))
	_, _, err := f.svc.Create(f.ctx, noLinks, link)
	if msg := refusal(err); msg != "your role does not allow share links" {
		t.Errorf("link without shares.links: %q", msg)
	}
	req, _ := f.create(noLinks, request)

	noRequests := withRole(alice, core.RoleMember, core.MemberCaps.Without(core.CapShareRequests))
	_, _, err = f.svc.Create(f.ctx, noRequests, request)
	if msg := refusal(err); msg != "your role does not allow file requests" {
		t.Errorf("request without shares.requests: %q", msg)
	}
	lnk, _ := f.create(noRequests, link)

	// A guest-based role with shares.links: sharing.allow_guests_share
	// (off) does not matter; the plain guest follows the setting.
	contractor := withRole(alice, core.RoleGuest, core.NewCapSet(core.CapShareLinks))
	f.create(contractor, link)
	_, _, err = f.svc.Create(f.ctx, contractor, request)
	refusal(err)
	_, _, err = f.svc.Create(f.ctx, asGuest(alice, false), link)
	refusal(err)
	f.create(asGuest(alice, true), request)

	// Over an API token the sharing permissions need no admin scope.
	tok := withRole(alice, core.RoleMember, core.MemberCaps)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeShares, core.ScopeFilesRead, core.ScopeFilesWrite}
	f.create(tok, link)
	f.create(tok, request)

	// Edits re-check the permission of the share's own kind.
	if _, err := f.svc.Update(f.ctx, noLinks, req.ID, core.ShareUpdate{Title: ptr("Drop files here")}); err != nil {
		t.Errorf("edit a request without shares.links: %v", err)
	}
	if _, err := f.svc.Update(f.ctx, noRequests, lnk.ID, core.ShareUpdate{Title: ptr("Report")}); err != nil {
		t.Errorf("edit a link without shares.requests: %v", err)
	}
	demoted := withRole(alice, core.RoleMember, core.NewCapSet(core.CapUsersLookup)) // lost both
	for _, id := range []string{req.ID, lnk.ID} {
		_, err := f.svc.Update(f.ctx, demoted, id, core.ShareUpdate{Title: ptr("again")})
		if msg := refusal(err); !strings.HasSuffix(msg, "; the link can only be disabled or deleted") ||
			!strings.HasPrefix(msg, "your role does not allow ") {
			t.Errorf("edit after losing the permission: %q", msg)
		}
		if _, err := f.svc.Update(f.ctx, demoted, id, core.ShareUpdate{Disabled: ptr(true)}); err != nil {
			t.Errorf("disable after losing the permission: %v", err)
		}
		_, err = f.svc.Update(f.ctx, demoted, id, core.ShareUpdate{Disabled: ptr(false)})
		refusal(err)
	}
	if err := f.svc.Revoke(f.ctx, demoted, lnk.ID); err != nil {
		t.Errorf("revoke after losing the permission: %v", err)
	}
}
