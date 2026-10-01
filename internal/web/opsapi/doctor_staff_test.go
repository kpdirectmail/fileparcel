package opsapi

import (
	"context"
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
)

// ListRoles implements core.Users for the doctor: the built-in roles, then
// one custom role per distinct custom RoleID of the fake's users (staff when
// the user's permissions include a server permission). rolesErr fails it.
func (u *fakeUsers) ListRoles(context.Context, *core.Principal) ([]core.RoleDef, error) {
	if err := rolesErr; err != nil {
		return nil, err
	}
	out := core.BuiltinRoles(false)
	for _, x := range u.users {
		if core.IsCustomRoleID(x.RoleID) && !slices.ContainsFunc(out, func(r core.RoleDef) bool { return r.ID == x.RoleID }) {
			out = append(out, core.RoleDef{ID: x.RoleID, Name: x.RoleName, Base: x.Role, Permissions: x.Permissions,
				Staff: x.Permissions.Server() != 0})
		}
	}
	return out, nil
}

// rolesErr makes fakeUsers.ListRoles fail.
var rolesErr error

// The admin_2fa check covers staff accounts: owners, admins and holders of
// custom roles with a server permission — not member-based roles with user
// permissions only. A role list that cannot be read makes the check
// inconclusive rather than vouching for the accounts it did not see.
func TestDoctorAdmin2FAStaffRoles(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	helpdesk := core.MemberCaps.With(core.CapUsersManage).Closure()
	te.users.users = []core.User{
		{ID: "usr_o", Username: "olga", Role: core.RoleOwner, RoleID: "owner", Status: "active"},
		{ID: "usr_h", Username: "hank", Role: core.RoleMember, RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5h1",
			RoleName: "Helpdesk", Permissions: helpdesk, Status: "active"},
		{ID: "usr_i", Username: "ida", Role: core.RoleMember, RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5h1",
			RoleName: "Helpdesk", Permissions: helpdesk, Status: "disabled"},
		{ID: "usr_a", Username: "aud", Role: core.RoleGuest, RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5a1",
			RoleName: "Auditors", Permissions: core.NewCapSet(core.CapAuditView), Status: "active"},
		{ID: "usr_c", Username: "cora", Role: core.RoleGuest, RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5c1",
			RoleName: "Contractors", Permissions: core.NewCapSet(core.CapShareRequests), Status: "active"},
		{ID: "usr_m", Username: "mel", Role: core.RoleMember, RoleID: "member", Status: "active"},
	}
	te.auth.mfa["usr_o"] = &core.MFAStatus{TOTPEnabled: true}
	c := te.doctor("").find("admin_2fa")
	if c.Name != "Two-factor authentication for staff accounts" || c.Status != CheckWarn ||
		c.Message != "Without two-factor authentication: aud, hank" {
		t.Fatalf("staff roles: %+v", c)
	}
	te.auth.mfa["usr_h"] = &core.MFAStatus{PasskeyCount: 1}
	te.auth.mfa["usr_a"] = &core.MFAStatus{TOTPEnabled: true}
	if c := te.doctor("").find("admin_2fa"); c.Status != CheckOK || c.Message != "All 3 staff accounts use two-factor authentication" {
		t.Fatalf("all staff with 2FA: %+v", c)
	}
	rolesErr = core.ErrUnavailable
	defer func() { rolesErr = nil }()
	if c := te.doctor("").find("admin_2fa"); c.Status != CheckInfo || !strings.Contains(c.Message, "could not be listed") {
		t.Fatalf("roles unreadable: %+v", c)
	}
}
