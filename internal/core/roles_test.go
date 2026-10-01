package core

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The catalog is append-only: bit i is Capabilities[i] and CapSet values
// never leave the process, but the order is also the UI order and the CLI's
// and the docs' table order. Append new entries at the end of this list.
var goldenCapabilityOrder = []Capability{
	"shares.links", "shares.requests", "users.lookup", "tokens.create",
	"users.view", "users.manage", "users.credentials", "invites.manage", "groups.manage",
	"shares.manage", "settings.manage", "network.manage", "certs.manage", "backups.run",
	"system.view", "system.manage", "audit.view",
}

func TestCapabilityCatalogInvariants(t *testing.T) {
	if len(Capabilities) > 64 {
		t.Fatalf("%d capabilities do not fit a CapSet", len(Capabilities))
	}
	var names []Capability
	for _, c := range Capabilities {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, goldenCapabilityOrder) {
		t.Fatalf("catalog order changed (append only):\n got %q\nwant %q", names, goldenCapabilityOrder)
	}
	groups := map[string]bool{}
	for _, g := range CapabilityGroups {
		if g.ID == "" || g.Label == "" || groups[g.ID] {
			t.Errorf("bad group %+v", g)
		}
		groups[g.ID] = true
	}
	if want := []string{"sharing", "people", "content", "server", "monitoring"}; len(CapabilityGroups) != len(want) {
		t.Errorf("groups %v", CapabilityGroups)
	} else {
		for i, g := range CapabilityGroups {
			if g.ID != want[i] {
				t.Errorf("group %d = %q, want %q", i, g.ID, want[i])
			}
		}
	}
	userCaps := []Capability{CapShareLinks, CapShareRequests, CapUsersLookup, CapTokensCreate}
	highImpact := []Capability{CapUsersManage, CapUsersCredentials, CapGroupsManage, CapSettingsManage,
		CapNetworkManage, CapCertsManage, CapSystemManage}
	seen := map[Capability]bool{}
	for _, c := range Capabilities {
		if seen[c.Name] {
			t.Errorf("duplicate %s", c.Name)
		}
		seen[c.Name] = true
		if c.Label == "" || c.Description == "" || !groups[c.Group] {
			t.Errorf("%s: label %q description %q group %q", c.Name, c.Label, c.Description, c.Group)
		}
		if c.Server == slices.Contains(userCaps, c.Name) {
			t.Errorf("%s: server = %v", c.Name, c.Server)
		}
		if c.HighImpact != slices.Contains(highImpact, c.Name) || c.HighImpact != (c.Warning != "") {
			t.Errorf("%s: high impact %v, warning %q", c.Name, c.HighImpact, c.Warning)
		}
		for _, im := range c.Implies {
			if !im.Valid() || im == c.Name {
				t.Errorf("%s implies %q", c.Name, im)
			}
		}
		if !c.Name.Valid() || c.Name.Label() != c.Label || c.Name.Server() != c.Server {
			t.Errorf("%s: accessors", c.Name)
		}
	}
	// Implies is acyclic: no capability reaches itself.
	for _, c := range Capabilities {
		reach := NewCapSet(c.Implies...).Closure()
		if reach.Has(c.Name) {
			t.Errorf("%s implies itself (cycle)", c.Name)
		}
	}
	// Verbatim spot checks (the UI, CLI and docs show these texts).
	if i, _ := CapNetworkManage.Info(); i.Label != "Network & VPN" ||
		i.Warning != "Can make the server reachable from the internet, or lock everyone out." {
		t.Errorf("network.manage %+v", i)
	}
	if i, _ := CapUsersManage.Info(); !slices.Equal(i.Implies, []Capability{CapUsersView}) ||
		!strings.HasPrefix(i.Description, "Create, edit, disable, enable, unlock and delete accounts") {
		t.Errorf("users.manage %+v", i)
	}
	if Capability("nope").Valid() || Capability("nope").Server() || Capability("nope").Label() != "nope" {
		t.Error("unknown capability")
	}
	if _, ok := Capability("nope").Info(); ok {
		t.Error("Info of an unknown capability")
	}
}

func TestCatalogIsACopy(t *testing.T) {
	c := Catalog()
	if len(c.Items) != len(Capabilities) || len(c.Groups) != len(CapabilityGroups) {
		t.Fatalf("catalog %d/%d", len(c.Items), len(c.Groups))
	}
	c.Items[5].Implies[0] = "x"
	c.Items[0].Label = "x"
	c.Groups[0].Label = "x"
	if Capabilities[5].Implies[0] != CapUsersView || Capabilities[0].Label == "x" || CapabilityGroups[0].Label == "x" {
		t.Fatal("Catalog shares memory with the package variables")
	}
	i, _ := CapUsersManage.Info()
	i.Implies[0] = "x"
	if Capabilities[5].Implies[0] != CapUsersView {
		t.Fatal("Info shares Implies")
	}
}

func TestBuiltinCapSets(t *testing.T) {
	if got := AllCaps.List(); !slices.Equal(got, goldenCapabilityOrder) {
		t.Fatalf("AllCaps %v", got)
	}
	if UserCaps|ServerCaps != AllCaps || UserCaps&ServerCaps != 0 || len(ServerCaps.List()) != 13 {
		t.Fatalf("user %v server %v", UserCaps.List(), ServerCaps.List())
	}
	want := []Capability{CapShareLinks, CapShareRequests, CapUsersLookup, CapTokensCreate}
	if !slices.Equal(MemberCaps.List(), want) || MemberCaps != UserCaps {
		t.Fatalf("MemberCaps %v", MemberCaps.List())
	}
}

func TestCapSetOps(t *testing.T) {
	s := NewCapSet(CapAuditView, "bogus", CapShareLinks, CapShareLinks)
	if !slices.Equal(s.List(), []Capability{CapShareLinks, CapAuditView}) {
		t.Fatalf("List %v", s.List())
	}
	if !s.Has(CapAuditView) || s.Has(CapUsersView) || s.Has("bogus") {
		t.Fatal("Has")
	}
	if w := s.With(CapUsersView, "bogus"); !w.Has(CapUsersView) || !w.Has(CapAuditView) || s.Has(CapUsersView) {
		t.Fatal("With")
	}
	if w := s.Without(CapAuditView, "bogus"); w.Has(CapAuditView) || !w.Has(CapShareLinks) {
		t.Fatal("Without")
	}
	if !s.SubsetOf(AllCaps) || AllCaps.SubsetOf(s) || !CapSet(0).SubsetOf(s) || !s.SubsetOf(s) {
		t.Fatal("SubsetOf")
	}
	if m := AllCaps.Minus(s); m.Has(CapAuditView) || !m.Has(CapUsersView) || m|s != AllCaps {
		t.Fatal("Minus")
	}
	if srv := s.Server(); !slices.Equal(srv.List(), []Capability{CapAuditView}) {
		t.Fatalf("Server %v", srv.List())
	}
	if CapSet(0).List() == nil || len(CapSet(0).List()) != 0 {
		t.Fatal("List of the empty set must be [] (never nil)")
	}
	if s.String() != "shares.links, audit.view" || !slices.Equal(s.Names(), []string{"shares.links", "audit.view"}) {
		t.Fatalf("String %q Names %q", s.String(), s.Names())
	}
}

func TestCapSetClosure(t *testing.T) {
	cases := []struct {
		in, want CapSet
	}{
		{0, 0},
		{NewCapSet(CapUsersManage), NewCapSet(CapUsersManage, CapUsersView)},
		{NewCapSet(CapUsersCredentials, CapInvitesManage), NewCapSet(CapUsersCredentials, CapInvitesManage, CapUsersView)},
		{NewCapSet(CapGroupsManage), NewCapSet(CapGroupsManage, CapUsersView)},
		{NewCapSet(CapSystemManage), NewCapSet(CapSystemManage, CapSystemView)},
		{NewCapSet(CapAuditView, CapShareLinks), NewCapSet(CapAuditView, CapShareLinks)},
		{AllCaps, AllCaps},
		{CapSet(1) << 63, 0}, // a bit beyond the catalog is dropped
	}
	for _, c := range cases {
		if got := c.in.Closure(); got != c.want {
			t.Errorf("Closure(%v) = %v, want %v", c.in.List(), got.List(), c.want.List())
		}
	}
}

func TestCapSetJSON(t *testing.T) {
	b, err := json.Marshal(CapSet(0))
	if err != nil || string(b) != `[]` {
		t.Fatalf("empty: %s %v", b, err)
	}
	b, _ = json.Marshal(NewCapSet(CapAuditView, CapShareLinks, CapUsersView))
	if string(b) != `["shares.links","users.view","audit.view"]` {
		t.Fatalf("order: %s", b)
	}
	for in, want := range map[string]CapSet{
		`["audit.view","shares.links"]`:                 NewCapSet(CapAuditView, CapShareLinks),
		`["audit.view","from.the.future","audit.view"]`: NewCapSet(CapAuditView),
		`[]`:   0,
		`null`: 0,
	} {
		s := NewCapSet(CapUsersView) // must be overwritten
		if err := json.Unmarshal([]byte(in), &s); err != nil || s != want {
			t.Errorf("unmarshal %s = %v %v, want %v", in, s.List(), err, want.List())
		}
	}
	var s CapSet
	if err := json.Unmarshal([]byte(`"audit.view"`), &s); err == nil {
		t.Error("a string is not a permission list")
	}
	// Inside a struct (value and pointer receivers).
	r := RoleDef{ID: "rol_x", Permissions: NewCapSet(CapShareRequests)}
	b, _ = json.Marshal(r)
	if !strings.Contains(string(b), `"permissions":["shares.requests"]`) {
		t.Fatalf("struct: %s", b)
	}
	b, _ = json.Marshal(&r)
	var back RoleDef
	if err := json.Unmarshal(b, &back); err != nil || back.Permissions != r.Permissions {
		t.Fatalf("round trip %v %v", back.Permissions.List(), err)
	}
}

func TestParseCaps(t *testing.T) {
	s, err := ParseCaps([]Capability{CapUsersManage, CapShareLinks, CapUsersManage})
	if err != nil || s != NewCapSet(CapUsersManage, CapShareLinks) {
		t.Fatalf("%v %v", s.List(), err)
	}
	if s.Has(CapUsersView) {
		t.Fatal("ParseCaps must not add implied permissions")
	}
	if s, err := ParseCaps(nil); err != nil || s != 0 {
		t.Fatalf("nil: %v %v", s, err)
	}
	_, err = ParseCaps([]Capability{CapShareLinks, "users.godmode"})
	e := AsError(err)
	if !errors.Is(err, ErrInvalid) || e.Field != "permissions" || e.Message != `unknown permission "users.godmode"` {
		t.Fatalf("unknown: %v", err)
	}
}

func TestStoredCaps(t *testing.T) {
	if s := DecodeStoredCaps(`["audit.view","gone.away","users.manage"]`); s != NewCapSet(CapAuditView, CapUsersManage) {
		t.Fatalf("decode %v", s.List())
	}
	for _, bad := range []string{"", "{", `"x"`, `{"a":1}`, `[1,2]`} {
		if s := DecodeStoredCaps(bad); s != 0 {
			t.Errorf("decode %q = %v", bad, s.List())
		}
	}
	if EncodeCaps(0) != "[]" || EncodeCaps(NewCapSet(CapAuditView, CapShareLinks)) != `["shares.links","audit.view"]` {
		t.Fatalf("encode %s", EncodeCaps(NewCapSet(CapAuditView, CapShareLinks)))
	}
	if s := DecodeStoredCaps(EncodeCaps(AllCaps)); s != AllCaps {
		t.Fatal("round trip")
	}
}

func TestIsCustomRoleID(t *testing.T) {
	for id, want := range map[string]bool{
		"rol_01k5abcdefghjkmnpqrstvwxyz": true, "rol_x": true,
		"": false, "member": false, "admin": false, "system": false, "usr_01k5abcdefghjkmnpqrstvwxyz": false, "ROL_x": false,
	} {
		if IsCustomRoleID(id) != want {
			t.Errorf("IsCustomRoleID(%q) != %v", id, want)
		}
	}
}

func TestEffectiveRoleCaps(t *testing.T) {
	custom := "rol_01k5abcdefghjkmnpqrstvwxyz"
	stored := NewCapSet(CapAuditView, CapUsersManage)
	both := NewCapSet(CapShareLinks, CapShareRequests)
	cases := []struct {
		name        string
		base        Role
		roleID      string
		stored      CapSet
		guestsShare bool
		want        CapSet
	}{
		{"owner", RoleOwner, "owner", 0, false, AllCaps},
		{"admin", RoleAdmin, "", stored, false, AllCaps},
		{"system", RoleSystem, "system", 0, false, AllCaps},
		{"member", RoleMember, "member", 0, false, MemberCaps},
		{"member ignores stored", RoleMember, "", stored, true, MemberCaps},
		{"guest", RoleGuest, "guest", 0, false, 0},
		{"guest sharing", RoleGuest, "guest", 0, true, both},
		{"custom member-based: closure", RoleMember, custom, stored, false, stored.With(CapUsersView)},
		{"custom guest-based: setting ignored", RoleGuest, custom, 0, true, 0},
		{"custom guest-based with links", RoleGuest, custom, NewCapSet(CapShareLinks), true, NewCapSet(CapShareLinks)},
		{"unknown base", Role("robot"), "", 0, true, 0},
	}
	for _, c := range cases {
		if got := EffectiveRoleCaps(c.base, c.roleID, c.stored, c.guestsShare); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got.List(), c.want.List())
		}
	}
	if BuiltinCaps(RoleMember, true) != MemberCaps || BuiltinCaps(RoleGuest, true) != both || BuiltinCaps(Role("x"), true) != 0 {
		t.Fatal("BuiltinCaps")
	}
}

func TestBuiltinRoles(t *testing.T) {
	names := map[Role]string{RoleOwner: "Owner", RoleAdmin: "Admin", RoleMember: "Member", RoleGuest: "Guest", RoleSystem: "System"}
	for r, n := range names {
		if BuiltinRoleName(r) != n {
			t.Errorf("BuiltinRoleName(%s) = %q", r, BuiltinRoleName(r))
		}
	}
	if BuiltinRoleName("robot") != "robot" {
		t.Error("unknown role name")
	}
	for _, share := range []bool{false, true} {
		rs := BuiltinRoles(share)
		if len(rs) != 4 {
			t.Fatalf("%d built-ins", len(rs))
		}
		for i, r := range []Role{RoleOwner, RoleAdmin, RoleMember, RoleGuest} {
			d := rs[i]
			if d.ID != string(r) || d.Base != r || !d.Builtin || d.Name != names[r] || d.Description == "" ||
				d.Permissions != BuiltinCaps(r, share) || d.Delegable != (r == RoleMember || r == RoleGuest) ||
				d.Staff != r.IsAdmin() || d.Editable || d.Assignable || d.CreatedAt != nil {
				t.Errorf("built-in %s (share %v): %+v", r, share, d)
			}
		}
	}
	if !strings.Contains(BuiltinRoles(false)[1].Description, "“Administrators can access all files”") {
		t.Error("admin description")
	}
}

// TestPrincipalCan is the Principal.Can matrix of rbac-final §17.1.
func TestPrincipalCan(t *testing.T) {
	custom := "rol_01k5abcdefghjkmnpqrstvwxyz"
	auditor := func(via AuthVia, scopes ...string) *Principal {
		p := &Principal{UserID: "usr_a", Role: RoleGuest, RoleID: custom, RoleName: "Auditors", Via: via, AuthLevel: 2, Scopes: scopes}
		p.SetCaps(EffectiveRoleCaps(RoleGuest, custom, NewCapSet(CapAuditView), false))
		return p
	}
	type want struct{ user, server, audit, staff, access bool }
	cases := []struct {
		name string
		p    *Principal
		w    want
	}{
		{"nil", nil, want{}},
		{"system", SystemPrincipal(ViaSocket), want{true, true, true, true, true}},
		{"owner session", &Principal{Role: RoleOwner, Via: ViaSession, AuthLevel: 2}, want{true, true, true, true, true}},
		{"admin session", &Principal{Role: RoleAdmin, Via: ViaSession, AuthLevel: 2}, want{true, true, true, true, true}},
		{"admin token without admin scope", &Principal{Role: RoleAdmin, Via: ViaToken, AuthLevel: 2, Scopes: []string{ScopeFilesRead}}, want{true, false, false, true, false}},
		{"admin token with admin scope", &Principal{Role: RoleAdmin, Via: ViaToken, AuthLevel: 2, Scopes: []string{ScopeAdmin}}, want{true, true, true, true, true}},
		{"member", &Principal{Role: RoleMember, Via: ViaSession, AuthLevel: 2}, want{true, false, false, false, false}},
		{"guest", &Principal{Role: RoleGuest, Via: ViaSession, AuthLevel: 2}, want{false, false, false, false, false}},
		{"auditor session", auditor(ViaSession), want{false, false, true, true, true}},
		{"auditor token without admin scope", auditor(ViaToken, ScopeFilesRead), want{false, false, false, true, false}},
		{"auditor token with admin scope", auditor(ViaToken, ScopeAdmin), want{false, false, true, true, true}},
		// Literals without SetCaps: the built-in role's set; a custom role id: nothing (fail closed).
		{"member literal", &Principal{Role: RoleMember, RoleID: "member"}, want{true, false, false, false, false}},
		{"custom literal", &Principal{Role: RoleMember, RoleID: custom}, want{false, false, false, false, false}},
		{"admin literal with custom id", &Principal{Role: RoleAdmin, RoleID: custom}, want{true, true, true, true, true}},
	}
	for _, c := range cases {
		got := want{
			user:   c.p.Can(CapShareLinks),
			server: c.p.Can(CapSettingsManage),
			audit:  c.p.Can(CapAuditView),
			staff:  c.p.Staff(),
			access: c.p.ServerAccess(),
		}
		if got != c.w {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.w)
		}
		if c.p.Can("bogus") {
			t.Errorf("%s: unknown capability allowed", c.name)
		}
	}
	a := auditor(ViaSession)
	if !a.CanAny(CapUsersView, CapAuditView) || a.CanAny(CapUsersView, CapShareLinks) || a.CanAny() {
		t.Fatal("CanAny")
	}
	if (&Principal{Role: RoleGuest}).RoleCaps() != 0 || (*Principal)(nil).RoleCaps() != 0 {
		t.Fatal("RoleCaps")
	}
	// SetCaps wins for built-in member/guest bases, never for owner/admin/system.
	m := &Principal{Role: RoleMember, RoleID: "member"}
	m.SetCaps(0)
	if m.Can(CapShareLinks) || m.RoleCaps() != 0 {
		t.Fatal("SetCaps(0) on a member")
	}
	ad := &Principal{Role: RoleAdmin}
	ad.SetCaps(0)
	if ad.RoleCaps() != AllCaps {
		t.Fatal("admin keeps every capability")
	}
	sys := SystemPrincipal(ViaOffline)
	if sys.RoleID != "system" || sys.RoleName != "System" || sys.Caps != AllCaps || !sys.capsSet {
		t.Fatalf("system principal %+v", sys)
	}
	if c := a.Clone(); c.RoleID != custom || c.RoleName != "Auditors" || c.RoleCaps() != a.RoleCaps() || !c.capsSet {
		t.Fatalf("Clone %+v", c)
	}
}

// Before package A builds principals with SetCaps, every principal falls back
// to its built-in role: holding any server permission is exactly what
// mw.RequireAdmin checks (IsAdmin && HasScope(admin)), so a route guarded by
// RequireCap(<server permission>) admits the same principals as before.
func TestCanMatchesRequireAdminWithoutSetCaps(t *testing.T) {
	for _, r := range []Role{RoleOwner, RoleAdmin, RoleMember, RoleGuest, RoleSystem, ""} {
		for _, via := range []AuthVia{ViaSession, ViaToken, ViaSocket, ViaOffline, ViaShare} {
			if r == RoleSystem && via == ViaToken {
				continue // the system principal never comes from a token (and passes Can regardless)
			}
			for _, scopes := range [][]string{nil, {ScopeFilesRead}, {ScopeAdmin}, {ScopeAdmin, ScopeFilesWrite}} {
				p := &Principal{Role: r, RoleID: string(r), Via: via, AuthLevel: 2, Scopes: scopes}
				admin := p.IsAdmin() && p.HasScope(ScopeAdmin)
				for _, c := range Capabilities {
					if c.Server && p.Can(c.Name) != admin {
						t.Errorf("%s via %s scopes %v: Can(%s) = %v, RequireAdmin %v", r, via, scopes, c.Name, p.Can(c.Name), admin)
					}
				}
				if p.ServerAccess() != admin {
					t.Errorf("%s via %s scopes %v: ServerAccess %v", r, via, scopes, p.ServerAccess())
				}
			}
		}
	}
}
