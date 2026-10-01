package files

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// TestPermissionMatrix checks DESIGN §6 for every kind of principal against
// view / edit / manage / owner operations, with 404 for invisible nodes and
// 403 for insufficient permissions.
func TestPermissionMatrix(t *testing.T) {
	e := newEnv(t)
	owner := e.user("owner", core.RoleMember)
	manager := e.user("manager", core.RoleMember)
	member := e.user("member", core.RoleMember)
	editor := e.user("editor", core.RoleMember)
	viewer := e.user("viewer", core.RoleMember)
	guest := e.user("guest", core.RoleGuest)
	stranger := e.user("stranger", core.RoleMember)
	admin := e.user("admin", core.RoleAdmin)
	groupViewer := e.user("gviewer", core.RoleMember)
	expired := e.user("expired", core.RoleMember)

	// Personal space of owner with a shared folder.
	shared := e.mkdir(owner, owner.rootID, "Shared")
	inner := e.file(owner, shared.ID, "inner.txt", "secret")
	e.grant(owner, shared.ID, core.SubjectUser, editor.UserID, core.GrantEditor)
	e.grant(owner, shared.ID, core.SubjectUser, viewer.UserID, core.GrantViewer)
	e.grant(owner, shared.ID, core.SubjectUser, guest.UserID, core.GrantViewer)
	gid2, _, _ := e.group("Viewers")
	e.member(gid2, groupViewer, core.GroupRoleMember)
	e.grant(owner, shared.ID, core.SubjectGroup, gid2, core.GrantViewer)
	exp := e.clock.Now().Add(time.Hour)
	if _, err := e.svc.SetGrant(e.ctx, owner.Principal, shared.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: expired.UserID, Role: core.GrantEditor, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(2 * time.Hour) // the grant has expired now

	// Team space.
	gid, _, groot := e.group("Team")
	e.member(gid, manager, core.GroupRoleManager)
	e.member(gid, member, core.GroupRoleMember)
	teamDoc := e.file(manager, groot, "team.txt", "t")

	view := func(p *core.Principal, id string) error { _, err := e.svc.Get(e.ctx, p, id); return err }
	edit := func(p *core.Principal, id string) error {
		n, err := e.svc.Mkdir(e.ctx, p, id, "probe-"+p.Username)
		if err == nil {
			// clean up so the next probe of the same principal works
			if err := e.svc.Trash(e.ctx, owner.Principal, []string{n.ID}); err != nil && code(err) != "not_found" {
				t.Fatal(err)
			}
			_ = e.svc.Trash(e.ctx, manager.Principal, []string{n.ID})
		}
		return err
	}
	manage := func(p *core.Principal, id string) error { _, err := e.svc.Grants(e.ctx, p, id); return err }

	rows := []struct {
		name                    string
		p                       *core.Principal
		node                    string
		view, edit, manage, own string // expected error codes
	}{
		{"owner", owner.Principal, shared.ID, "", "", "", ""},
		{"editor grant", editor.Principal, shared.ID, "", "", "forbidden", "forbidden"},
		{"viewer grant", viewer.Principal, shared.ID, "", "forbidden", "forbidden", "forbidden"},
		{"guest viewer grant", guest.Principal, shared.ID, "", "forbidden", "forbidden", "forbidden"},
		{"group viewer grant", groupViewer.Principal, shared.ID, "", "forbidden", "forbidden", "forbidden"},
		{"expired grant", expired.Principal, shared.ID, "not_found", "not_found", "not_found", "not_found"},
		{"stranger", stranger.Principal, shared.ID, "not_found", "not_found", "not_found", "not_found"},
		{"admin without access", admin.Principal, shared.ID, "not_found", "not_found", "not_found", "not_found"},
		{"group manager", manager.Principal, groot, "", "", "", ""},
		{"group member", member.Principal, groot, "", "", "forbidden", "forbidden"},
		{"non-member", stranger.Principal, groot, "not_found", "not_found", "not_found", "not_found"},
		{"owner in team", owner.Principal, groot, "not_found", "not_found", "not_found", "not_found"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := code(view(r.p, r.node)); got != r.view {
				t.Errorf("view: %q, want %q", got, r.view)
			}
			if got := code(edit(r.p, r.node)); got != r.edit {
				t.Errorf("edit: %q, want %q", got, r.edit)
			}
			if got := code(manage(r.p, r.node)); got != r.manage {
				t.Errorf("manage: %q, want %q", got, r.manage)
			}
			// Owner level: purge of a trashed item below the node.
			n, err := e.svc.CommitFile(e.ctx, owner.Principal, shared.ID, "purge-me.txt", e.blobs.put(t, []byte("x")),
				core.FileMeta{}, core.ConflictRename)
			parent := owner.Principal
			if r.node == groot {
				n, err = e.svc.CommitFile(e.ctx, manager.Principal, groot, "purge-me.txt", e.blobs.put(t, []byte("x")),
					core.FileMeta{}, core.ConflictRename)
				parent = manager.Principal
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := e.svc.Trash(e.ctx, parent, []string{n.ID}); err != nil {
				t.Fatal(err)
			}
			if got := code(e.svc.Purge(e.ctx, r.p, []string{n.ID})); got != r.own {
				t.Errorf("purge: %q, want %q", got, r.own)
			}
		})
	}

	// Inherited grants: the viewer sees the file inside the shared folder,
	// but nothing outside it.
	if _, err := e.svc.Get(e.ctx, viewer.Principal, inner.ID); err != nil {
		t.Fatalf("inherited view: %v", err)
	}
	if _, err := e.svc.Get(e.ctx, viewer.Principal, owner.rootID); code(err) != "not_found" {
		t.Fatalf("viewer sees root: %v", err)
	}
	if _, err := e.svc.Get(e.ctx, member.Principal, teamDoc.ID); err != nil {
		t.Fatalf("member reads team doc: %v", err)
	}

	// Admin override: PermManage everywhere, audited as admin.file_access.
	e.settings.set(settingAdminAccess, true)
	before := e.audit.count(core.ActAdminFileAccess)
	n, err := e.svc.Get(e.ctx, admin.Principal, inner.ID)
	if err != nil || n.Perm != core.PermManage {
		t.Fatalf("admin override: %+v %v", n, err)
	}
	if e.audit.count(core.ActAdminFileAccess) != before+1 {
		t.Fatal("admin.file_access not audited")
	}
	if err := e.svc.Purge(e.ctx, admin.Principal, []string{inner.ID}); code(err) != "forbidden" {
		t.Fatalf("admin purge in personal space: %v", err)
	}
	if spaces, err := e.svc.Spaces(e.ctx, admin.Principal); err != nil || len(spaces) < 3 {
		t.Fatalf("admin spaces: %d %v", len(spaces), err)
	}
	// A member (not admin) never gets the override.
	if _, err := e.svc.Get(e.ctx, stranger.Principal, inner.ID); code(err) != "not_found" {
		t.Fatalf("stranger with override on: %v", err)
	}
	// Nor does an API token of an admin that lacks the admin scope: the
	// override follows mw.RequireAdmin, which pairs the role with the scope.
	adminRO := *admin.Principal
	adminRO.Via, adminRO.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	if _, err := e.svc.Get(e.ctx, &adminRO, inner.ID); code(err) != "not_found" {
		t.Fatalf("admin token without the admin scope: %v", err)
	}
	if spaces, err := e.svc.Spaces(e.ctx, &adminRO); err != nil || len(spaces) != 1 {
		t.Fatalf("admin token without the admin scope sees %d spaces (%v)", len(spaces), err)
	}
	adminRO.Scopes = []string{core.ScopeFilesRead, core.ScopeAdmin}
	if n, err := e.svc.Get(e.ctx, &adminRO, inner.ID); err != nil || n.Perm != core.PermManage {
		t.Fatalf("admin token with the admin scope: %+v %v", n, err)
	}
	e.settings.set(settingAdminAccess, false)

	// The system principal can do everything.
	sys := core.SystemPrincipal(core.ViaSocket)
	if _, err := e.svc.Grants(e.ctx, sys, shared.ID); err != nil {
		t.Fatalf("system: %v", err)
	}
	// Anonymous is 401.
	if _, err := e.svc.Get(e.ctx, nil, shared.ID); code(err) != "unauthorized" {
		t.Fatalf("anonymous: %v", err)
	}

	// Token scopes.
	ro := *owner.Principal
	ro.Via, ro.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	if _, err := e.svc.Get(e.ctx, &ro, shared.ID); err != nil {
		t.Fatalf("read token get: %v", err)
	}
	if _, err := e.svc.Mkdir(e.ctx, &ro, shared.ID, "x"); code(err) != "forbidden" {
		t.Fatalf("read token mkdir: %v", err)
	}
	// Starring writes the stars table, so it needs files:write even though
	// it only needs to see the node.
	if err := e.svc.Star(e.ctx, &ro, shared.ID, true); code(err) != "forbidden" {
		t.Fatalf("read token star: %v", err)
	}
	if err := e.svc.Star(e.ctx, &ro, shared.ID, false); code(err) != "forbidden" {
		t.Fatalf("read token unstar: %v", err)
	}
	rw := *owner.Principal
	rw.Via, rw.Scopes = core.ViaToken, []string{core.ScopeFilesWrite}
	if err := e.svc.Star(e.ctx, &rw, shared.ID, true); err != nil {
		t.Fatalf("write token star: %v", err)
	}
	if err := e.svc.Star(e.ctx, &rw, shared.ID, false); err != nil {
		t.Fatalf("write token unstar: %v", err)
	}
	wo := *owner.Principal
	wo.Via, wo.Scopes = core.ViaToken, []string{core.ScopeShares}
	if _, err := e.svc.Get(e.ctx, &wo, shared.ID); code(err) != "forbidden" {
		t.Fatalf("shares-only token get: %v", err)
	}
	if err := e.svc.Star(e.ctx, &wo, shared.ID, true); code(err) != "forbidden" {
		t.Fatalf("shares-only token star: %v", err)
	}
	// Listing grants is a read (files:read), although it needs PermManage;
	// changing them is a write.
	if _, err := e.svc.Grants(e.ctx, &ro, shared.ID); err != nil {
		t.Fatalf("read token grants: %v", err)
	}
	if _, err := e.svc.Grants(e.ctx, &rw, shared.ID); code(err) != "forbidden" {
		t.Fatalf("write-only token grants: %v", err)
	}
	if _, err := e.svc.SetGrant(e.ctx, &ro, shared.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: stranger.UserID, Role: core.GrantViewer}); code(err) != "forbidden" {
		t.Fatalf("read token set grant: %v", err)
	}
	roViewer := *viewer.Principal
	roViewer.Via, roViewer.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	if _, err := e.svc.Grants(e.ctx, &roViewer, shared.ID); code(err) != "forbidden" {
		t.Fatalf("viewer's read token grants: %v", err)
	}
	// Sharing (Authorize PermManage, the shares service's check) needs
	// files:read: its writes are guarded by the shares scope.
	bot := *owner.Principal
	bot.Via, bot.Scopes = core.ViaToken, []string{core.ScopeShares, core.ScopeFilesRead}
	if _, err := e.svc.Authorize(e.ctx, &bot, shared.ID, core.PermManage); err != nil {
		t.Fatalf("share bot token, manage: %v", err)
	}
	if _, err := e.svc.Authorize(e.ctx, &bot, shared.ID, core.PermEdit); code(err) != "forbidden" {
		t.Fatalf("share bot token, edit: %v", err)
	}
	if _, err := e.svc.Authorize(e.ctx, &wo, shared.ID, core.PermManage); code(err) != "forbidden" {
		t.Fatalf("shares-only token, manage: %v", err)
	}

	// Grant management rules.
	if _, err := e.svc.SetGrant(e.ctx, owner.Principal, shared.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: owner.UserID, Role: core.GrantViewer}); code(err) != "invalid" {
		t.Fatalf("self grant: %v", err)
	}
	if _, err := e.svc.SetGrant(e.ctx, owner.Principal, shared.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: "usr_00000000000000000000000000", Role: core.GrantViewer}); code(err) != "invalid" {
		t.Fatalf("unknown subject: %v", err)
	}
	if _, err := e.svc.SetGrant(e.ctx, owner.Principal, shared.ID, core.GrantInput{SubjectType: "robot",
		SubjectID: viewer.UserID, Role: core.GrantViewer}); code(err) != "invalid" {
		t.Fatalf("bad subject type: %v", err)
	}
	if _, err := e.svc.SetGrant(e.ctx, owner.Principal, shared.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: viewer.UserID, Role: "owner"}); code(err) != "invalid" {
		t.Fatalf("bad role: %v", err)
	}
	past := e.clock.Now().Add(-time.Minute)
	if _, err := e.svc.SetGrant(e.ctx, owner.Principal, shared.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: viewer.UserID, Role: core.GrantViewer, ExpiresAt: &past}); code(err) != "invalid" {
		t.Fatalf("past expiry: %v", err)
	}
	// Upgrade viewer → editor (same subject: update in place).
	g := e.grant(owner, shared.ID, core.SubjectUser, viewer.UserID, core.GrantEditor)
	if g.Role != core.GrantEditor || g.SubjectName != "viewer" {
		t.Fatalf("upgrade: %+v", g)
	}
	sub := e.mkdir(owner, shared.ID, "sub")
	grants, err := e.svc.Grants(e.ctx, owner.Principal, sub.ID)
	// editor, viewer (now editor), guest and the Viewers group; the expired
	// grant is not listed.
	if err != nil || len(grants) != 4 || grants[0].NodeID != shared.ID {
		t.Fatalf("inherited grants: %+v %v", grants, err)
	}
	if err := e.svc.RemoveGrant(e.ctx, owner.Principal, sub.ID, g.ID); code(err) != "not_found" {
		t.Fatalf("remove inherited grant on child: %v", err)
	}
	if err := e.svc.RemoveGrant(e.ctx, owner.Principal, shared.ID, g.ID); err != nil {
		t.Fatalf("remove grant: %v", err)
	}
	if _, err := e.svc.Get(e.ctx, viewer.Principal, shared.ID); code(err) != "not_found" {
		t.Fatalf("revoked grant still works: %v", err)
	}
	if e.audit.count(core.ActGrantSet) < 6 || e.audit.count(core.ActGrantRemove) != 1 {
		t.Fatalf("grant audits %d %d", e.audit.count(core.ActGrantSet), e.audit.count(core.ActGrantRemove))
	}
}

func TestSysPrincipalFor(t *testing.T) {
	e := newEnv(t)
	u := e.user("carol", core.RoleMember)
	p, err := e.svc.SysPrincipalFor(e.ctx, u.UserID)
	if err != nil || p.UserID != u.UserID || p.Via != core.ViaShare || !p.Full() || p.IsAdmin() {
		t.Fatalf("principal: %+v %v", p, err)
	}
	if _, err := e.svc.Get(e.ctx, p, u.rootID); err != nil {
		t.Fatalf("acts as the user: %v", err)
	}
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET status = 'disabled' WHERE id = ?`, u.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SysPrincipalFor(e.ctx, u.UserID); code(err) != "forbidden" {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := e.svc.SysPrincipalFor(e.ctx, "usr_00000000000000000000000000"); code(err) != "not_found" {
		t.Fatalf("unknown: %v", err)
	}
}

// TestAdminOverrideAuditsTransfers pins that a purge and a cross-space move
// that only auth.admin_can_access_files allows are audited as
// admin.file_access (DESIGN §6). Both authorize the node for PermEdit and
// compare the *effective* permission (override included) against
// transferPerm afterwards, so the audit in authorize() never fires for an
// actor whose natural permission already reaches PermEdit — a plain member
// of a group space, for instance.
func TestAdminOverrideAuditsTransfers(t *testing.T) {
	e := newEnv(t)
	admin := e.user("root", core.RoleOwner)
	gid, _, groupRoot := e.group("Team")
	e.member(gid, admin, core.GroupRoleMember) // natural PermEdit, not PermManage
	e.settings.set(settingAdminAccess, true)

	doc := e.file(admin, groupRoot, "team.txt", "team")
	keep := e.file(admin, groupRoot, "moved.txt", "moved")

	// Purge: needs PermManage in a group space; the member holds PermEdit.
	if err := e.svc.Trash(e.ctx, admin.Principal, []string{doc.ID}); err != nil {
		t.Fatal(err)
	}
	before := e.audit.count(core.ActAdminFileAccess)
	if err := e.svc.Purge(e.ctx, admin.Principal, []string{doc.ID}); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := e.audit.count(core.ActAdminFileAccess); got != before+1 {
		t.Fatalf("purge admin.file_access entries %d -> %d, want one more", before, got)
	}

	// Cross-space move out of the group space: same requirement.
	before = e.audit.count(core.ActAdminFileAccess)
	if _, err := e.svc.Move(e.ctx, admin.Principal, []string{keep.ID}, admin.rootID, core.ConflictFail); err != nil {
		t.Fatalf("move: %v", err)
	}
	if got := e.audit.count(core.ActAdminFileAccess); got != before+1 {
		t.Fatalf("move admin.file_access entries %d -> %d, want one more", before, got)
	}

	// A manager of the group needs no override, so nothing is audited.
	mgr := e.user("mgr", core.RoleMember)
	e.member(gid, mgr, core.GroupRoleManager)
	other := e.file(mgr, groupRoot, "mine.txt", "mine")
	if err := e.svc.Trash(e.ctx, mgr.Principal, []string{other.ID}); err != nil {
		t.Fatal(err)
	}
	before = e.audit.count(core.ActAdminFileAccess)
	if err := e.svc.Purge(e.ctx, mgr.Principal, []string{other.ID}); err != nil {
		t.Fatalf("manager purge: %v", err)
	}
	if got := e.audit.count(core.ActAdminFileAccess); got != before {
		t.Fatalf("manager purge audited %d admin.file_access entries", got-before)
	}
}

// TestAdminOverridePurgeAuditedOncePerCall: a purge that takes several
// transactions (maxPurgeNodes) records the override once per call and node
// — the chunks re-check the permission but do not audit again (DESIGN §9.6
// allows a second entry only for a higher requirement).
func TestAdminOverridePurgeAuditedOncePerCall(t *testing.T) {
	defer func(n int) { maxPurgeNodes = n }(maxPurgeNodes)
	maxPurgeNodes = 4
	for _, c := range []struct {
		name string
		role string // group role of the admin ("" = not a member)
		want []string
	}{
		{"not a member", "", []string{"edit", "manage"}},
		{"member", core.GroupRoleMember, []string{"manage"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			admin := e.user("root", core.RoleOwner)
			mgr := e.user("mgr", core.RoleMember)
			gid, _, groot := e.group("Team")
			e.member(gid, mgr, core.GroupRoleManager)
			if c.role != "" {
				e.member(gid, admin, c.role)
			}
			big := e.mkdir(mgr, groot, "big")
			for i := range 10 {
				e.file(mgr, big.ID, fmt.Sprintf("f%d.txt", i), "x")
			}
			if err := e.svc.Trash(e.ctx, mgr.Principal, []string{big.ID}); err != nil {
				t.Fatal(err)
			}
			e.settings.set(settingAdminAccess, true)
			if err := e.svc.Purge(e.ctx, admin.Principal, []string{big.ID}); err != nil {
				t.Fatalf("purge: %v", err)
			}
			if n := e.audit.count(core.ActFilePurge); n != 3 {
				t.Fatalf("%d file.purge entries, want 3 (one per chunk)", n)
			}
			var got []string
			for _, a := range e.audit.all(core.ActAdminFileAccess) {
				got = append(got, a.Details.(map[string]any)["need"].(string))
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("admin.file_access entries %v, want %v", got, c.want)
			}
		})
	}
}
