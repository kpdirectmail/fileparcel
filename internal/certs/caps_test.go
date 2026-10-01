package certs

import (
	"context"
	"errors"
	"testing"

	"fileparcel/internal/core"
)

// A holder of certs.manage ("Certificates") revokes other people's client
// certificates like an administrator, owners' excepted; an API token needs
// the admin scope for it. Without the permission only one's own
// certificates are found.
func TestRevokeClientByPermission(t *testing.T) {
	const ownerID = "usr_000000000000000000000owner"
	te := newTestEnv(t)
	te.addUser(t, ownerID, "olivia", "active")
	te.addUser(t, aliceID, "alice", "active")
	te.addUser(t, bobID, "bob", "active")
	ctx := context.Background()
	if _, err := te.env.DB.Exec(ctx, `UPDATE users SET role = 'owner' WHERE id = ?`, ownerID); err != nil {
		t.Fatal(err)
	}
	svc := te.initService(t)
	delegate := func(caps core.CapSet, via core.AuthVia, scopes ...string) *core.Principal {
		p := &core.Principal{UserID: bobID, Username: "bob", Role: core.RoleMember, RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na",
			RoleName: "Certificate managers", Via: via, Scopes: scopes, AuthLevel: core.AuthLevelFull}
		p.SetCaps(caps)
		return p
	}
	certsManage := core.MemberCaps.With(core.CapCertsManage)
	in := core.ClientCertInput{UserID: aliceID, Password: "password"}

	for what, by := range map[string]*core.Principal{
		"without the permission":        delegate(core.MemberCaps, core.ViaSession),
		"token without the admin scope": delegate(certsManage, core.ViaToken, core.ScopeFilesRead),
	} {
		cc, _, _ := issue(t, svc, in)
		if err := svc.RevokeClient(ctx, by, cc.ID, ""); !errors.Is(err, core.ErrNotFound) {
			t.Errorf("%s: %v", what, err)
		}
	}
	for what, by := range map[string]*core.Principal{
		"session":           delegate(certsManage, core.ViaSession),
		"admin-scope token": delegate(certsManage, core.ViaToken, core.ScopeAdmin),
	} {
		cc, _, _ := issue(t, svc, in)
		if err := svc.RevokeClient(ctx, by, cc.ID, "lost"); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	cc, _, _ := issue(t, svc, core.ClientCertInput{UserID: ownerID, Password: "password"})
	if err := svc.RevokeClient(ctx, delegate(certsManage, core.ViaSession), cc.ID, ""); !errors.Is(err, core.ErrForbidden) {
		t.Errorf("an owner's certificate: %v", err)
	}
}
