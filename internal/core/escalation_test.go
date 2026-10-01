package core

import (
	"errors"
	"slices"
	"testing"
)

// Principals and accounts of the escalation tables (DESIGN §6a.4). Custom
// role ids only need the rol_ prefix here; the rules never look them up.
const (
	idHelpdesk  = "rol_helpdesk00000000000000000"
	idAuditors  = "rol_auditors00000000000000000"
	idFinance   = "rol_finance000000000000000000"
	idTeam      = "rol_team000000000000000000000"
	idOperators = "rol_operators0000000000000000"
	idViewers   = "rol_viewers00000000000000000"
)

func escActor(name string, base Role, roleID string, stored CapSet) *Principal {
	p := &Principal{UserID: "usr_" + name, Username: name, Role: base, RoleID: roleID, Via: ViaSession, AuthLevel: AuthLevelFull}
	if roleID == "" {
		p.RoleID = string(base)
	}
	p.SetCaps(EffectiveRoleCaps(base, p.RoleID, stored, false))
	return p
}

func escTarget(name string, base Role, roleID, roleName string, stored CapSet, delegable bool) *User {
	if roleID == "" {
		roleID, roleName = string(base), BuiltinRoleName(base)
	}
	return &User{ID: "usr_" + name, Username: name, Role: base, RoleID: roleID, RoleName: roleName,
		Permissions: EffectiveRoleCaps(base, roleID, stored, false), RoleDelegable: RoleDelegable(roleID, delegable)}
}

// The actors and the accounts they act on. They are built by a function:
// package-level variables are initialised before roles.go's init builds the
// capability index, so CapSet values computed there would all be empty.
var (
	escOwner, escAdmin, escMember, escSystem, escHelpdesk, escAuditor, escInviter *Principal

	tOwner, tAdmin, tMember, tGuest, tTeam, tFinance, tOperator, tViewer, tSelf *User
)

func escFixtures() {
	escOwner = escActor("owner", RoleOwner, "", 0)
	escAdmin = escActor("admin", RoleAdmin, "", 0)
	escMember = escActor("member", RoleMember, "", 0)
	escSystem = SystemPrincipal(ViaSocket)
	escHelpdesk = escActor("helpdesk", RoleMember, idHelpdesk, MemberCaps.With(CapUsersManage, CapUsersCredentials))
	escAuditor = escActor("auditor", RoleGuest, idAuditors, NewCapSet(CapAuditView))
	escInviter = escActor("inviter", RoleMember, idTeam, NewCapSet(CapInvitesManage))

	tOwner = escTarget("owner2", RoleOwner, "", "", 0, false)
	tAdmin = escTarget("admin2", RoleAdmin, "", "", 0, false)
	tMember = escTarget("member2", RoleMember, "", "", 0, false)
	tGuest = escTarget("guest2", RoleGuest, "", "", 0, false)
	tTeam = escTarget("team", RoleMember, idTeam, "Team", MemberCaps, true)                                // delegable, no server permission
	tFinance = escTarget("finance", RoleMember, idFinance, "Finance", MemberCaps, false)                   // not delegable
	tOperator = escTarget("operator", RoleMember, idOperators, "Operators", NewCapSet(CapAuditView), true) // delegable staff
	tViewer = escTarget("viewer", RoleGuest, idViewers, "Viewers", NewCapSet(CapUsersView), true)          // covered by Helpdesk
	tSelf = escTarget("helpdesk", RoleMember, idHelpdesk, "Helpdesk", MemberCaps.With(CapUsersManage, CapUsersCredentials), true)
}

// checkRefusal compares err with the expectation: want "" = allowed;
// otherwise the client message, and escalation says whether the cause is an
// *EscalationError (audited as denied) with missing permissions.
func checkRefusal(t *testing.T, name string, err error, want string, escalation bool, missing ...Capability) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		return
	}
	ce := AsError(err)
	if ce == nil {
		t.Errorf("%s: allowed, want %q", name, want)
		return
	}
	if ce.Message != want {
		t.Errorf("%s: message %q, want %q", name, ce.Message, want)
	}
	esc := AsEscalation(err)
	if (esc != nil) != escalation {
		t.Errorf("%s: escalation cause %v, want %v", name, esc, escalation)
		return
	}
	if esc != nil {
		if !errors.Is(err, ErrForbidden) || ce.Status != 403 || esc.Reason != want {
			t.Errorf("%s: %+v / %+v", name, ce, esc)
		}
		if !slices.Equal(esc.Missing, missing) {
			t.Errorf("%s: missing %v, want %v", name, esc.Missing, missing)
		}
	}
}

func TestCheckManage(t *testing.T) {
	escFixtures()
	const (
		ownerMsg   = "administrators cannot modify owner accounts"
		ownerCreds = "only an owner can manage the credentials of an owner"
		adminMsg   = "only administrators can manage administrator accounts"
		selfMsg    = "ask an administrator to change this on your own account"
		financeMsg = "accounts with the role “Finance” can only be managed by an administrator"
		staffMsg   = "this account has server permissions you do not have (audit.view)"
		needManage = "this needs the “Manage accounts” permission"
		needCreds  = "this needs the “Reset sign-in” permission"
	)
	type row struct {
		by      *Principal
		target  *User
		need    Capability
		want    string
		esc     bool
		missing []Capability
	}
	M, C := CapUsersManage, CapUsersCredentials
	rows := map[string]row{
		"owner→owner":           {escOwner, tOwner, C, "", false, nil},
		"owner→admin":           {escOwner, tAdmin, M, "", false, nil},
		"admin→owner manage":    {escAdmin, tOwner, M, ownerMsg, true, nil},
		"admin→owner creds":     {escAdmin, tOwner, C, ownerCreds, true, nil},
		"admin→admin":           {escAdmin, tAdmin, M, "", false, nil},
		"admin→finance":         {escAdmin, tFinance, C, "", false, nil},
		"admin→operator":        {escAdmin, tOperator, M, "", false, nil},
		"system→owner":          {escSystem, tOwner, C, "", false, nil},
		"helpdesk→owner":        {escHelpdesk, tOwner, M, ownerMsg, true, nil},
		"helpdesk→admin":        {escHelpdesk, tAdmin, C, adminMsg, true, nil},
		"helpdesk→member":       {escHelpdesk, tMember, M, "", false, nil},
		"helpdesk→guest":        {escHelpdesk, tGuest, C, "", false, nil},
		"helpdesk→delegable":    {escHelpdesk, tTeam, M, "", false, nil},
		"helpdesk→nondelegable": {escHelpdesk, tFinance, C, financeMsg, true, nil},
		"helpdesk→staff":        {escHelpdesk, tOperator, M, staffMsg, true, []Capability{CapAuditView}},
		"helpdesk→covered":      {escHelpdesk, tViewer, M, "", false, nil},
		"helpdesk→self":         {escHelpdesk, tSelf, M, selfMsg, true, nil},
		"auditor→member":        {escAuditor, tMember, M, needManage, false, nil},
		"inviter→guest creds":   {escInviter, tGuest, C, needCreds, false, nil},
		"member→guest":          {escMember, tGuest, M, needManage, false, nil},
	}
	for name, r := range rows {
		checkRefusal(t, name, CheckManage(r.by, r.target, r.need), r.want, r.esc, r.missing...)
	}
	if err := CheckManage(nil, tMember, M); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("nil actor: %v", err)
	}
	if err := CheckManage(escHelpdesk, nil, M); !errors.Is(err, ErrNotFound) {
		t.Errorf("nil target: %v", err)
	}
	// Server permissions on an API token need the admin scope: the same
	// Helpdesk account through a files:read token lacks users.manage.
	tok := escHelpdesk.Clone()
	tok.Via, tok.Scopes = ViaToken, []string{ScopeFilesRead}
	checkRefusal(t, "helpdesk token", CheckManage(tok, tMember, M), needManage, false)
	tok.Scopes = []string{ScopeAdmin}
	checkRefusal(t, "helpdesk admin token", CheckManage(tok, tMember, M), "", false)
	// The token scopes of an admin do not matter for the owner rule's order:
	// without the admin scope the permission check refuses first.
	at := escAdmin.Clone()
	at.Via, at.Scopes = ViaToken, []string{ScopeFilesRead}
	checkRefusal(t, "admin files:read token", CheckManage(at, tMember, C), needCreds, false)
}

func TestCheckAssign(t *testing.T) {
	escFixtures()
	const (
		ownerRole   = "only owners can grant the owner role"
		ownerTarget = "administrators cannot modify owner accounts"
		adminRole   = "only administrators can grant the admin role"
		financeRole = "administrators have not allowed account managers to give the role “Finance”"
		missingAud  = "you can only give roles whose server permissions you have yourself (missing: audit.view)"
		adminTarget = "only administrators can manage administrator accounts"
		nondeleg    = "accounts with the role “Finance” can only be managed by an administrator"
	)
	builtin := map[Role]*RoleDef{}
	for _, r := range BuiltinRoles(false) {
		builtin[r.Base] = &r
	}
	custom := func(id, name string, base Role, caps CapSet, delegable bool) *RoleDef {
		return &RoleDef{ID: id, Name: name, Base: base, Permissions: caps.Closure(), Delegable: delegable}
	}
	finance := custom(idFinance, "Finance", RoleMember, MemberCaps, false)
	operators := custom(idOperators, "Operators", RoleMember, NewCapSet(CapAuditView), true)
	viewers := custom(idViewers, "Viewers", RoleGuest, NewCapSet(CapUsersView), true)
	team := custom(idTeam, "Team", RoleMember, MemberCaps, true)
	type row struct {
		by      *Principal
		c       AssignCheck
		want    string
		missing []Capability
	}
	rows := map[string]row{
		"owner gives owner":            {escOwner, AssignCheck{To: builtin[RoleOwner]}, "", nil},
		"owner changes an owner":       {escOwner, AssignCheck{To: builtin[RoleMember], Target: tOwner}, "", nil},
		"admin gives owner":            {escAdmin, AssignCheck{To: builtin[RoleOwner]}, ownerRole, nil},
		"admin changes an owner":       {escAdmin, AssignCheck{To: builtin[RoleMember], Target: tOwner}, ownerTarget, nil},
		"admin gives admin":            {escAdmin, AssignCheck{To: builtin[RoleAdmin], Target: tMember}, "", nil},
		"admin gives non-delegable":    {escAdmin, AssignCheck{To: finance, Target: tGuest}, "", nil},
		"admin gives staff role":       {escAdmin, AssignCheck{To: operators}, "", nil},
		"system gives owner":           {escSystem, AssignCheck{To: builtin[RoleOwner], Target: tOwner}, "", nil},
		"helpdesk gives owner":         {escHelpdesk, AssignCheck{To: builtin[RoleOwner]}, ownerRole, nil},
		"helpdesk gives admin":         {escHelpdesk, AssignCheck{To: builtin[RoleAdmin]}, adminRole, nil},
		"helpdesk gives member":        {escHelpdesk, AssignCheck{To: builtin[RoleMember]}, "", nil},
		"helpdesk gives guest":         {escHelpdesk, AssignCheck{To: builtin[RoleGuest], Target: tMember}, "", nil},
		"helpdesk gives non-delegable": {escHelpdesk, AssignCheck{To: finance}, financeRole, nil},
		"helpdesk gives staff role":    {escHelpdesk, AssignCheck{To: operators}, missingAud, []Capability{CapAuditView}},
		"helpdesk gives covered role":  {escHelpdesk, AssignCheck{To: viewers, Target: tGuest}, "", nil},
		"helpdesk gives delegable":     {escHelpdesk, AssignCheck{To: team, Target: tMember}, "", nil},
		"helpdesk changes an admin":    {escHelpdesk, AssignCheck{To: builtin[RoleMember], Target: tAdmin}, adminTarget, nil},
		"helpdesk changes non-deleg":   {escHelpdesk, AssignCheck{To: builtin[RoleMember], Target: tFinance}, nondeleg, nil},
		"helpdesk changes an owner":    {escHelpdesk, AssignCheck{To: builtin[RoleGuest], Target: tOwner}, ownerTarget, nil},
		"inviter invites member":       {escInviter, AssignCheck{To: builtin[RoleMember]}, "", nil},
		// invites.manage implies users.view, so a Viewers invitation is covered.
		"inviter invites covered role": {escInviter, AssignCheck{To: viewers}, "", nil},
		"inviter invites staff role":   {escInviter, AssignCheck{To: operators}, missingAud, []Capability{CapAuditView}},
	}
	for name, r := range rows {
		checkRefusal(t, name, CheckAssign(r.by, r.c), r.want, r.want != "", r.missing...)
	}
	if err := CheckAssign(nil, AssignCheck{To: builtin[RoleMember]}); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("nil actor: %v", err)
	}
	if err := CheckAssign(escAdmin, AssignCheck{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no role: %v", err)
	}
}

func TestCovers(t *testing.T) {
	escFixtures()
	cases := []struct {
		name string
		by   *Principal
		caps CapSet
		want bool
	}{
		{"admin everything", escAdmin, AllCaps, true},
		{"system everything", escSystem, AllCaps, true},
		{"helpdesk own set", escHelpdesk, NewCapSet(CapUsersView, CapUsersManage, CapUsersCredentials), true},
		{"helpdesk user caps only", escHelpdesk, UserCaps, true},
		{"helpdesk audit", escHelpdesk, NewCapSet(CapUsersView, CapAuditView), false},
		{"member nothing server", escMember, MemberCaps, true},
		{"member a server cap", escMember, NewCapSet(CapUsersView), false},
		{"nil", nil, 0, false},
	}
	for _, c := range cases {
		if got := Covers(c.by, c.caps); got != c.want {
			t.Errorf("%s: Covers = %v", c.name, got)
		}
	}
	// Token scopes do not narrow Covers (the action itself is gated by Can).
	tok := escHelpdesk.Clone()
	tok.Via, tok.Scopes = ViaToken, []string{ScopeFilesRead}
	if !Covers(tok, NewCapSet(CapUsersManage)) {
		t.Error("Covers applied token scopes")
	}
}

func TestRoleDelegable(t *testing.T) {
	for id, want := range map[string]bool{"owner": false, "admin": false, "system": false, "member": true, "guest": true, "": false} {
		if RoleDelegable(id, true) != want {
			t.Errorf("%q: %v", id, !want)
		}
	}
	if !RoleDelegable(idTeam, true) || RoleDelegable(idTeam, false) {
		t.Error("custom roles follow their flag")
	}
}

func TestEscalationErrorText(t *testing.T) {
	err := escalation(NewCapSet(CapAuditView, CapSystemView), "no (%s)", NewCapSet(CapAuditView, CapSystemView))
	ce := AsError(err)
	if ce == nil || ce.Message != "no (system.view, audit.view)" || ce.Code != "forbidden" {
		t.Fatalf("%+v", ce)
	}
	esc := AsEscalation(err)
	if esc == nil || !slices.Equal(esc.Missing, []Capability{CapSystemView, CapAuditView}) {
		t.Fatalf("%+v", esc)
	}
	if got := esc.Error(); got != "escalation refused: no (system.view, audit.view) (missing [system.view audit.view])" {
		t.Errorf("Error() = %q", got)
	}
	if AsEscalation(ErrForbidden) != nil || AsEscalation(nil) != nil {
		t.Error("AsEscalation on a plain error")
	}
	if got := NeedPermission(CapAuditView).Error(); got != "this needs the “Audit and server logs” permission" {
		t.Errorf("NeedPermission = %q", got)
	}
}
