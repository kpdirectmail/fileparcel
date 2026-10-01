package auth_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
)

// Custom roles of the tests below (DESIGN §6a examples).
var (
	helpdeskCaps  = func() core.CapSet { return core.MemberCaps.With(core.CapUsersManage, core.CapUsersCredentials) }
	auditorCaps   = func() core.CapSet { return core.NewCapSet(core.CapAuditView, core.CapSystemView) }
	operatorsCaps = func() core.CapSet { return core.MemberCaps.With(core.CapAuditView) }
)

// Session and token principals carry the role id, name and capabilities of
// their account, resolved from the authenticating row on every request.
func TestPrincipalRoleCaps(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	helpdesk := e.AddRole(t, "Helpdesk", core.RoleMember, helpdeskCaps(), false)
	auditors := e.AddRole(t, "Auditors", core.RoleGuest, auditorCaps(), false)

	type want struct {
		role   core.Role
		roleID string
		name   string
		caps   core.CapSet
	}
	cases := map[string]want{
		"olive": {core.RoleOwner, "owner", "Owner", core.AllCaps},
		"adam":  {core.RoleAdmin, "admin", "Admin", core.AllCaps},
		"mel":   {core.RoleMember, "member", "Member", core.MemberCaps},
		"gus":   {core.RoleGuest, "guest", "Guest", 0},
		// Implied permissions are added when the role is read (closure).
		"hana": {core.RoleMember, helpdesk, "Helpdesk", helpdeskCaps().With(core.CapUsersView)},
		"aud":  {core.RoleGuest, auditors, "Auditors", auditorCaps()},
	}
	ids := map[string]string{}
	for name, w := range cases {
		base := w.role
		u := e.AddUser(t, name, pw, base)
		ids[name] = u.ID
		if core.IsCustomRoleID(w.roleID) {
			e.SetUserRole(t, u.ID, w.roleID)
		}
	}
	for name, w := range cases {
		p := authenticate(t, e, login(t, e, name, pw).Token)
		if p.Role != w.role || p.RoleID != w.roleID || p.RoleName != w.name || p.RoleCaps() != w.caps {
			t.Errorf("%s session: %s %s %q %v", name, p.Role, p.RoleID, p.RoleName, p.RoleCaps())
		}
		if !w.caps.Has(core.CapTokensCreate) {
			continue // the role does not allow API tokens (built-in Guest, Auditors)
		}
		scopes := []string{core.ScopeFilesRead}
		_, secret, err := e.Auth.CreateToken(ctx, sys, core.TokenInput{Name: "t", Scopes: scopes, UserID: ids[name]})
		if err != nil {
			t.Fatalf("%s token: %v", name, err)
		}
		bp, err := bearer(t, e, secret)
		if err != nil || bp.RoleID != w.roleID || bp.RoleName != w.name || bp.RoleCaps() != w.caps {
			t.Errorf("%s token: %+v %v", name, bp, err)
		}
		// Server permissions need the admin scope on a token.
		if bp.Can(core.CapAuditView) || (w.caps.Has(core.CapShareLinks) && !bp.Can(core.CapShareLinks)) {
			t.Errorf("%s token: scopes not applied", name)
		}
	}

	// A permission edit applies to the next request of an existing session.
	hana := login(t, e, "hana", pw).Token
	e.SetRolePermissions(t, helpdesk, core.MemberCaps.With(core.CapAuditView))
	if p := authenticate(t, e, hana); p.Can(core.CapUsersManage) || !p.Can(core.CapAuditView) {
		t.Errorf("after the role edit: %v", p.RoleCaps())
	}
	// So does a role change: back to plain Member, then to Admin.
	e.SetUserRole(t, ids["hana"], "member")
	if p := authenticate(t, e, hana); p.RoleID != "member" || p.RoleName != "Member" || p.RoleCaps() != core.MemberCaps {
		t.Errorf("after the demotion: %+v", p)
	}
	e.SetUserRole(t, ids["hana"], "admin")
	if p := authenticate(t, e, hana); !p.IsAdmin() || p.RoleID != "admin" || p.RoleCaps() != core.AllCaps {
		t.Errorf("after the promotion: %+v", p)
	}

	// sharing.allow_guests_share gives built-in guests links and requests;
	// custom guest-based roles keep their own permissions.
	e.Settings.Put("sharing.allow_guests_share", true)
	links := core.NewCapSet(core.CapShareLinks, core.CapShareRequests)
	if p := authenticate(t, e, login(t, e, "gus", pw).Token); p.RoleCaps() != links {
		t.Errorf("guest with guests_share: %v", p.RoleCaps())
	}
	if p := authenticate(t, e, login(t, e, "aud", pw).Token); p.RoleCaps() != auditorCaps() {
		t.Errorf("guest-based role with guests_share: %v", p.RoleCaps())
	}
	if u, err := e.Users.Get(ctx, ids["gus"]); err != nil || u.Permissions != links {
		t.Errorf("guest account permissions: %+v %v", u, err)
	}
}

// auth.require_2fa = admins covers every staff account: owners, admins and
// custom roles with a server permission.
func TestRequire2FAForStaffRoles(t *testing.T) {
	e := authtest.New(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	staff := e.AddRole(t, "Operators", core.RoleMember, operatorsCaps(), false)
	plain := e.AddRole(t, "Contractors", core.RoleGuest, core.NewCapSet(core.CapShareRequests), false)
	op := e.AddUser(t, "op", pw, core.RoleMember)
	e.SetUserRole(t, op.ID, staff)
	con := e.AddUser(t, "con", pw, core.RoleGuest)
	e.SetUserRole(t, con.ID, plain)
	e.AddUser(t, "mem", pw, core.RoleMember)

	for name, want := range map[string]bool{"op": true, "con": false, "mem": false} {
		res := login(t, e, name, pw)
		if res.EnrollRequired != want {
			t.Errorf("%s login: enroll required %v", name, res.EnrollRequired)
		}
		if p := authenticate(t, e, res.Token); p.EnrollRequired != want {
			t.Errorf("%s session: enroll required %v", name, p.EnrollRequired)
		}
	}
	st, err := e.Auth.MFAStatus(ctx, op.ID)
	if err != nil || !st.Required || !st.EnrollRequired {
		t.Errorf("staff MFA status: %+v %v", st, err)
	}
	_, secret, err := e.Auth.CreateToken(ctx, sys, core.TokenInput{Name: "t", Scopes: []string{core.ScopeFilesRead}, UserID: op.ID})
	if err != nil {
		t.Fatal(err)
	}
	if bp, err := bearer(t, e, secret); err != nil || !bp.EnrollRequired {
		t.Errorf("staff token: %+v %v", bp, err)
	}
	// Losing the server permission lifts the requirement on the next request.
	e.SetRolePermissions(t, staff, core.MemberCaps)
	if bp, err := bearer(t, e, secret); err != nil || bp.EnrollRequired {
		t.Errorf("after the role edit: %+v %v", bp, err)
	}
}

// The token owner's role must allow API tokens; the admin scope needs a
// staff owner; --elevated tokens count as elevated only while the owner is
// staff.
func TestCreateTokenByRole(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	noTokens := e.AddRole(t, "Kiosk", core.RoleMember, core.MemberCaps.Without(core.CapTokensCreate), false)
	helpdesk := e.AddRole(t, "Helpdesk", core.RoleMember, helpdeskCaps(), false)
	auditors := e.AddRole(t, "Auditors", core.RoleGuest, auditorCaps(), false)
	guest := e.AddUser(t, "gus", pw, core.RoleGuest)
	kiosk := e.AddUser(t, "kiosk", pw, core.RoleMember)
	e.SetUserRole(t, kiosk.ID, noTokens)
	hana := e.AddUser(t, "hana", pw, core.RoleMember)
	e.SetUserRole(t, hana.ID, helpdesk)
	aud := e.AddUser(t, "aud", pw, core.RoleGuest)
	e.SetUserRole(t, aud.ID, auditors)
	e.AddUser(t, "mel", pw, core.RoleMember)
	read := []string{core.ScopeFilesRead}

	// No tokens.create: refused for the owner themselves and over the socket.
	for _, u := range []*core.User{guest, kiosk} {
		p := authenticate(t, e, login(t, e, u.Username, pw).Token)
		_, _, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "t", Scopes: read})
		if ce := core.AsError(err); ce == nil || ce.Code != "forbidden" || ce.Message != "the role of "+u.Username+" does not allow API tokens" {
			t.Errorf("%s: %v", u.Username, err)
		}
		if _, _, err := e.Auth.CreateToken(ctx, sys, core.TokenInput{Name: "t", Scopes: read, UserID: u.ID}); !isCode(err, core.ErrForbidden) {
			t.Errorf("%s over the socket: %v", u.Username, err)
		}
	}
	// A guest-based role that holds tokens.create? Auditors do not: refused.
	if _, _, err := e.Auth.CreateToken(ctx, sys, core.TokenInput{Name: "t", Scopes: read, UserID: aud.ID}); !isCode(err, core.ErrForbidden) {
		t.Errorf("auditor token: %v", err)
	}
	e.SetRolePermissions(t, auditors, auditorCaps().With(core.CapTokensCreate))

	// The admin scope needs server permissions.
	pm := elevated(e, authenticate(t, e, login(t, e, "mel", pw).Token))
	_, _, err := e.Auth.CreateToken(ctx, pm, core.TokenInput{Name: "t", Scopes: []string{core.ScopeAdmin}})
	if ce := core.AsError(err); ce == nil || ce.Field != "scopes" || ce.Message != "the admin scope needs an account with server permissions" {
		t.Errorf("member admin scope: %v", err)
	}
	for _, name := range []string{"hana", "aud"} {
		p := authenticate(t, e, login(t, e, name, pw).Token)
		in := core.TokenInput{Name: "ops", Scopes: []string{core.ScopeAdmin}, Elevated: true, ExpiresAt: ptr(e.Clock.Now().Add(24 * time.Hour))}
		if _, _, err := e.Auth.CreateToken(ctx, p, in); !isCode(err, core.ErrElevationRequired) {
			t.Errorf("%s admin scope without step-up: %v", name, err)
		}
		tok, secret, err := e.Auth.CreateToken(ctx, elevated(e, p), in)
		if err != nil || !tok.Elevated {
			t.Fatalf("%s staff admin token: %+v %v", name, tok, err)
		}
		bp, err := bearer(t, e, secret)
		if err != nil || !bp.Elevated(e.Clock.Now()) {
			t.Errorf("%s elevated staff token: %+v %v", name, bp, err)
		}
		if name == "hana" && !bp.Can(core.CapUsersManage) || name == "aud" && !bp.Can(core.CapAuditView) {
			t.Errorf("%s admin-scope token lacks its server permissions: %v", name, bp.RoleCaps())
		}
	}
	// Demoted to a role without server permissions, the elevated token no
	// longer counts as elevated (and holds no server permission).
	_, secret, err := e.Auth.CreateToken(ctx, sys, core.TokenInput{Name: "ops2", Scopes: []string{core.ScopeAdmin},
		Elevated: true, ExpiresAt: ptr(e.Clock.Now().Add(time.Hour)), UserID: hana.ID})
	if err != nil {
		t.Fatal(err)
	}
	e.SetUserRole(t, hana.ID, "member")
	if bp, err := bearer(t, e, secret); err != nil || bp.Elevated(e.Clock.Now()) || bp.Can(core.CapUsersView) {
		t.Errorf("demoted owner's elevated token: %+v %v", bp, err)
	}
}

// A delegate with users.credentials manages the credentials of the accounts
// its role may manage (core.CheckManage) and nothing else; refusals by the
// escalation rules are audited as denied.
func TestAuthorizeForDelegation(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	ctx := context.Background()
	helpdesk := e.AddRole(t, "Helpdesk", core.RoleMember, helpdeskCaps(), false)
	operators := e.AddRole(t, "Operators", core.RoleMember, operatorsCaps(), true)
	finance := e.AddRole(t, "Finance", core.RoleMember, core.MemberCaps, false)
	team := e.AddRole(t, "Team", core.RoleMember, core.MemberCaps, true)
	auditors := e.AddRole(t, "Auditors", core.RoleGuest, auditorCaps(), true)
	users := map[string]*core.User{}
	for name, roleID := range map[string]string{"hana": helpdesk, "op": operators, "fin": finance, "tea": team,
		"aud": auditors, "mel": "member", "gus": "guest", "adam": "admin", "olive": "owner"} {
		base := core.Role(roleID)
		if core.IsCustomRoleID(roleID) {
			base = core.RoleMember
			if roleID == auditors {
				base = core.RoleGuest
			}
		}
		users[name] = e.AddUser(t, name, pw, base)
		if core.IsCustomRoleID(roleID) {
			e.SetUserRole(t, users[name].ID, roleID)
		}
	}
	ph := elevated(e, authenticate(t, e, login(t, e, "hana", pw).Token))
	ph.IP = clientMeta.IP
	pm := elevated(e, authenticate(t, e, login(t, e, "mel", pw).Token)) // before the helpdesk resets mel's password

	allowed := []string{"mel", "gus", "tea", "hana"} // hana: self-service
	for _, name := range allowed {
		if err := e.Auth.RevokeAllSessions(ctx, ph, users[name].ID, ph.SessionID); err != nil {
			t.Errorf("revoke sessions of %s: %v", name, err)
		}
	}
	for _, name := range []string{"mel", "tea"} {
		if err := e.Auth.AdminSetPassword(ctx, ph, users[name].ID, "a new helpdesk-chosen password", true); err != nil {
			t.Errorf("reset password of %s: %v", name, err)
		}
		if err := e.Auth.ResetMFA(ctx, ph, users[name].ID); err != nil {
			t.Errorf("reset 2FA of %s: %v", name, err)
		}
	}
	refused := map[string]struct {
		msg     string
		missing []core.Capability
	}{
		"olive": {"only an owner can manage the credentials of an owner", nil},
		"adam":  {"only administrators can manage administrator accounts", nil},
		"fin":   {"accounts with the role “Finance” can only be managed by an administrator", nil},
		"op":    {"this account has server permissions you do not have (audit.view)", []core.Capability{core.CapAuditView}},
		"aud":   {"this account has server permissions you do not have (system.view, audit.view)", []core.Capability{core.CapSystemView, core.CapAuditView}},
	}
	for name, w := range refused {
		before := e.Audit.Count(core.ActUserPasswordReset, core.OutcomeDenied)
		err := e.Auth.AdminSetPassword(ctx, ph, users[name].ID, "the helpdesk's chosen password", false)
		if ce := core.AsError(err); ce == nil || ce.Code != "forbidden" || ce.Message != w.msg {
			t.Errorf("reset password of %s: %v", name, err)
			continue
		}
		denied := e.Audit.Entries(core.ActUserPasswordReset, core.OutcomeDenied)
		if len(denied) != before+1 {
			t.Errorf("%s: %d denied entries", name, len(denied))
			continue
		}
		d := denied[len(denied)-1]
		details, _ := d.Details.(map[string]any)
		missing, _ := details["missing"].([]core.Capability)
		if d.ActorID != users["hana"].ID || d.TargetID != users[name].ID || d.TargetName != name || d.IP != clientMeta.IP.String() ||
			details["reason"] != w.msg || !slices.Equal(missing, w.missing) {
			t.Errorf("%s: denied entry %+v", name, d)
		}
		for what, err := range map[string]error{
			"reset mfa":    e.Auth.ResetMFA(ctx, ph, users[name].ID),
			"totp disable": e.Auth.TOTPDisable(ctx, ph, users[name].ID),
			"revoke all":   e.Auth.RevokeAllSessions(ctx, ph, users[name].ID, ""),
		} {
			if !isCode(err, core.ErrForbidden) {
				t.Errorf("%s of %s: %v", what, name, err)
			}
		}
		if _, _, err := e.Auth.CreateToken(ctx, ph, core.TokenInput{Name: "x", Scopes: []string{core.ScopeFilesRead}, UserID: users[name].ID}); !isCode(err, core.ErrForbidden) {
			t.Errorf("token for %s: %v", name, err)
		}
	}
	for action, n := range map[string]int{core.ActUserMFAReset: 5, core.ActMFATOTPDisable: 5, core.ActSessionRevoke: 5, core.ActTokenCreate: 5} {
		if got := e.Audit.Count(action, core.OutcomeDenied); got != n {
			t.Errorf("%s denied entries: %d, want %d", action, got, n)
		}
	}

	// Without users.credentials (a plain member, or the Helpdesk through a
	// token without the admin scope) the refusal is a plain 403, not audited.
	_, secret, err := e.Auth.CreateToken(ctx, core.SystemPrincipal(core.ViaSocket), core.TokenInput{Name: "r",
		Scopes: []string{core.ScopeFilesRead}, UserID: users["hana"].ID})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bearer(t, e, secret)
	if err != nil {
		t.Fatal(err)
	}
	before := len(e.Audit.Entries("", core.OutcomeDenied))
	for who, p := range map[string]*core.Principal{"member": pm, "helpdesk files:read token": pt} {
		if err := e.Auth.RevokeAllSessions(ctx, p, users["gus"].ID, ""); !isCode(err, core.ErrForbidden) {
			t.Errorf("%s: %v", who, err)
		}
	}
	if err := e.Auth.ResetMFA(ctx, pm, users["mel"].ID); !isCode(err, core.ErrForbidden) {
		t.Errorf("member resets their own 2FA through ResetMFA: %v", err)
	}
	if got := len(e.Audit.Entries("", core.OutcomeDenied)); got != before {
		t.Errorf("plain refusals audited: %d entries", got-before)
	}

	// Credentials addressed by id (tokens, passkeys) are the caller's own over
	// the network, for delegates as for administrators.
	tok, _, err := e.Auth.CreateToken(ctx, pm, core.TokenInput{Name: "m", Scopes: []string{core.ScopeFilesRead}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.RevokeToken(ctx, ph, tok.ID); !isCode(err, core.ErrNotFound) {
		t.Errorf("helpdesk revokes a member's token by id: %v", err)
	}
	if err := e.Auth.RevokeToken(ctx, core.SystemPrincipal(core.ViaSocket), tok.ID); err != nil {
		t.Errorf("socket revokes a member's token: %v", err)
	}
}
