package files

import (
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// The holder of an expiring manager grant cannot make it permanent by
// granting again to a group or role that includes them (the self-share rule
// covered only their own account): a grant to such a subject may last only
// as long as their own access of that level. People whose access does not
// depend on grants (the owner, a group manager) are not limited, nor are
// subjects that do not include the caller, nor lower levels the caller holds
// for good.
func TestSelfIncludingGrantKeepsExpiry(t *testing.T) {
	e := newEnv(t)
	owner := e.user("olga", core.RoleMember)
	con := e.user("con", core.RoleGuest)
	contractors := e.role("Contractors", core.RoleGuest)
	e.assign(con, contractors)
	gid, _, _ := e.group("Crew")
	e.member(gid, con, core.GroupRoleMember)
	other := e.user("oscar", core.RoleMember)
	briefs := e.mkdir(owner, owner.rootID, "Briefs")
	exp := e.clock.Now().Add(24 * time.Hour)
	set := func(p *user, in core.GrantInput) (*core.Grant, error) {
		return e.svc.SetGrant(e.ctx, p.Principal, briefs.ID, in)
	}
	if _, err := set(owner, core.GrantInput{SubjectType: core.SubjectRole, SubjectID: contractors,
		Role: core.GrantManager, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}

	later := exp.Add(24 * time.Hour)
	for _, c := range []struct {
		name string
		in   core.GrantInput
	}{
		{"own role without expiry", core.GrantInput{SubjectType: core.SubjectRole, SubjectID: contractors, Role: core.GrantManager}},
		{"own role later", core.GrantInput{SubjectType: core.SubjectRole, SubjectID: contractors, Role: core.GrantManager, ExpiresAt: &later}},
		{"own group without expiry", core.GrantInput{SubjectType: core.SubjectGroup, SubjectID: gid, Role: core.GrantViewer}},
	} {
		_, err := set(con, c.in)
		if ce := core.AsError(err); code(err) != "invalid" || ce.Field != "expires_at" ||
			!strings.Contains(ce.Message, "your own access to \"Briefs\" ends") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// Within the holder's own access: allowed (a lower level, the same expiry).
	if g, err := set(con, core.GrantInput{SubjectType: core.SubjectGroup, SubjectID: gid, Role: core.GrantEditor, ExpiresAt: &exp}); err != nil ||
		g.ExpiresAt == nil || !g.ExpiresAt.Equal(exp) {
		t.Fatalf("group until the holder's own expiry: %+v %v", g, err)
	}
	// Someone else: the manager level lets the holder share on (permanently).
	if _, err := set(con, core.GrantInput{SubjectType: core.SubjectUser, SubjectID: other.UserID, Role: core.GrantViewer}); err != nil {
		t.Fatalf("share with someone else: %v", err)
	}
	// The owner is not limited.
	if g, err := set(owner, core.GrantInput{SubjectType: core.SubjectRole, SubjectID: contractors, Role: core.GrantManager}); err != nil || g.ExpiresAt != nil {
		t.Fatalf("owner removes the expiry: %+v %v", g, err)
	}
	// Once it is permanent, the holder may re-grant their role or group freely.
	if _, err := set(con, core.GrantInput{SubjectType: core.SubjectGroup, SubjectID: gid, Role: core.GrantViewer}); err != nil {
		t.Fatalf("holder with a permanent grant: %v", err)
	}

	// The QA scenario: the expiry the owner set stays; two days later the
	// holder has nothing.
	e2 := newEnv(t)
	o2 := e2.user("olga", core.RoleMember)
	c2 := e2.user("con", core.RoleGuest)
	r2 := e2.role("Contractors", core.RoleGuest)
	e2.assign(c2, r2)
	b2 := e2.mkdir(o2, o2.rootID, "Briefs")
	exp2 := e2.clock.Now().Add(24 * time.Hour)
	if _, err := e2.svc.SetGrant(e2.ctx, o2.Principal, b2.ID, core.GrantInput{SubjectType: core.SubjectRole, SubjectID: r2,
		Role: core.GrantManager, ExpiresAt: &exp2}); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.svc.SetGrant(e2.ctx, c2.Principal, b2.ID, core.GrantInput{SubjectType: core.SubjectRole, SubjectID: r2,
		Role: core.GrantManager}); err == nil {
		t.Fatal("the holder removed the expiry of the grant that gives them access")
	}
	e2.clock.Advance(48 * time.Hour)
	if got := e2.perm(c2.Principal, b2.ID); got != "" {
		t.Errorf("two days later the holder still has %q", got)
	}
}

// A group manager's access comes from the space: re-granting their own
// group inside the team folder is not limited.
func TestSelfIncludingGrantGroupManager(t *testing.T) {
	e := newEnv(t)
	boss := e.user("boss", core.RoleMember)
	gid, _, root := e.group("Team")
	e.member(gid, boss, core.GroupRoleManager)
	docs := e.mkdir(boss, root, "Docs")
	if _, err := e.svc.SetGrant(e.ctx, boss.Principal, docs.ID, core.GrantInput{SubjectType: core.SubjectGroup,
		SubjectID: gid, Role: core.GrantManager}); err != nil {
		t.Fatalf("group manager grants their own group: %v", err)
	}
}
