package core

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The v4 JSON contract: one representative value of every type the v4
// packages exchange over the API, marshaled and compared with the golden
// files in testdata/contract (field names, order, omitempty). The web UI and
// the CLI code against these files; changing one is a contract change
// (implementation plan §11.5). Regenerate after an agreed change with
//
//	go test ./internal/core -run TestContractJSON -update-contract
var updateContract = flag.Bool("update-contract", false, "rewrite internal/core/testdata/contract/*.json")

// contractCase is one golden file: testdata/contract/<name>.json holds v.
type contractCase struct {
	name string
	v    any
}

// contractCases are the representative values of the JSON contract.
func contractCases() []contractCase {
	at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	later := at.Add(90 * time.Minute)
	expires := at.Add(7 * 24 * time.Hour)
	quota := int64(10 << 30)
	const (
		roleID  = "rol_01k5z8r3m9d4q7w2x6c1v0b5na" // Helpdesk
		finID   = "rol_01k5z8r3m9d4q7w2x6c1v0b5np" // Finance
		userID  = "usr_01k5z8r3m9d4q7w2x6c1v0b5nb"
		adminID = "usr_01k5z8r3m9d4q7w2x6c1v0b5nc"
		groupID = "grp_01k5z8r3m9d4q7w2x6c1v0b5nd"
		spaceID = "spc_01k5z8r3m9d4q7w2x6c1v0b5ne"
		gSpace  = "spc_01k5z8r3m9d4q7w2x6c1v0b5nf"
		nodeID  = "nod_01k5z8r3m9d4q7w2x6c1v0b5ng"
		folder  = "nod_01k5z8r3m9d4q7w2x6c1v0b5nh"
		verID   = "ver_01k5z8r3m9d4q7w2x6c1v0b5nj"
		grantID = "gnt_01k5z8r3m9d4q7w2x6c1v0b5nk"
		batchID = "upb_01k5z8r3m9d4q7w2x6c1v0b5nm"
		invID   = "inv_01k5z8r3m9d4q7w2x6c1v0b5nn"
	)
	helpdesk := NewCapSet(CapShareLinks, CapUsersLookup, CapTokensCreate, CapUsersManage, CapUsersCredentials).Closure()
	role := RoleDef{
		ID: roleID, Name: "Helpdesk", Description: "Front-line support", Base: RoleMember,
		Permissions: helpdesk, Delegable: false, CreatedAt: &at, UpdatedAt: &at, CreatedBy: adminID,
		Staff: true, UserCount: 3, GroupCount: 1, GrantCount: 2, Editable: true, Assignable: true,
	}
	ref := RoleRef{ID: finID, Name: "Finance", MemberRole: GroupRoleManager}
	user := User{
		ID: userID, Username: "alice", DisplayName: "Alice", Email: "alice@example.test",
		Role: RoleMember, RoleID: roleID, RoleName: "Helpdesk", Permissions: helpdesk, RoleDelegable: true,
		Status: UserActive, PasswordChangedAt: &at, QuotaBytes: &quota, LastLoginAt: &later, LastLoginIP: "192.0.2.10",
		Prefs: json.RawMessage(`{"theme":"dark"}`), CreatedAt: at, UpdatedAt: later, CreatedBy: adminID,
		SpaceID: spaceID, MFAEnabled: true,
	}
	roleGroup := RoleGroup{RoleID: finID, RoleName: "Finance", GroupID: groupID, GroupName: "Finance", SpaceID: gSpace,
		MemberRole: GroupRoleMember, AddedAt: at, AddedBy: adminID}
	grant := Grant{ID: grantID, NodeID: folder, SubjectType: SubjectRole, SubjectID: finID, SubjectName: "Finance",
		Role: GrantManager, CreatedBy: adminID, CreatedAt: at, ExpiresAt: &expires,
		NodeName: "Reports", NodePath: "/Company/Reports", NodeKind: KindFolder, SpaceKind: SpaceGroup,
		SpaceName: "Company", CallerPerm: PermManage}
	accessGroup := AccessGroup{GroupID: groupID, Name: "Finance", SpaceID: gSpace, Role: GroupRoleManager, Direct: true,
		DirectRole: GroupRoleMember, ViaRoles: []RoleRef{ref}}
	checks := []IngressCheck{
		{ID: "tailscale.https", Label: "HTTPS certificates", Status: "ok"},
		{ID: "tailscale.funnel_attr", Label: "Funnel permission", Status: "warn", Message: "the tailnet policy does not grant funnel",
			Hint: "add the funnel node attribute", FixURL: "https://login.tailscale.com/admin/acls"},
	}
	keyExpiry := at.Add(180 * 24 * time.Hour)
	ts := &TailscaleInfo{Running: true, Kind: IfTailscale, BackendState: "Running", DNSName: "box.tail1234.ts.net",
		Tailnet: "tail1234.ts.net", ControlURL: "https://controlplane.tailscale.com",
		IPs:         []netip.Addr{netip.MustParseAddr("100.64.0.10"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		CertCapable: true, Installed: true, Version: "1.102.4", NodeID: "nXXXXXXCNTRL", CanConfigure: true,
		FunnelCapable: true, FunnelPorts: []int{443, 8443, 10000}, KeyExpiry: &keyExpiry}
	funnel := IngressEntry{Kind: IngressFunnel, Mode: FunnelShares, Port: 443, HostPort: "box.tail1234.ts.net:443",
		URL: "https://box.tail1234.ts.net/", Backend: "unix:/srv/fileparcel/run/ts-funnel.sock", State: IngressStateActive,
		AppliedAt: &at, LastRequestAt: &later, LastPublicRequestAt: &later, ProbedAt: &at, Checks: checks}
	serve := IngressEntry{Kind: IngressServe, Mode: FunnelOff, Port: 443, State: IngressStateOff, Checks: []IngressCheck{}}
	status := IngressStatus{Available: true, Transport: "localapi", Funnel: funnel, Serve: serve,
		FunnelPorts: []int{443, 10000}, AllowAdmin: false, Require2FA: true,
		Foreign: []ForeignServe{{HostPort: "box.tail1234.ts.net:8443", Mount: "/", Target: "https+insecure://localhost:8443",
			Funnel: false, Foreground: false, Bypass: true}},
		Tailscale: ts}
	vpn := VPNInfo{ID: "tailscale", Kind: IfTailscale, Label: "Tailscale", Role: VPNRoleMesh, RoleSource: VPNRoleSourceAuto,
		Interfaces: []string{"tailscale0"}, Ranges: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}, Allowed: "partly",
		CanAllow: true, Recommended: true,
		Warning: "shared with NetBird, NordVPN Meshnet, Cloudflare WARP and ISP carrier-grade NAT"}
	egress := VPNInfo{ID: "wg0-mullvad", Kind: IfExitVPN, Label: "Mullvad VPN", Provider: "mullvad", Role: VPNRoleEgress,
		RoleSource: VPNRoleSourceOverride, Interfaces: []string{"wg0-mullvad"}, Ranges: []string{}, Allowed: "no",
		Note: "an outgoing VPN; it does not let other devices in"}
	exposure := Exposure{ID: "tailscale.userspace", Severity: "warn",
		Message: "Tailscale runs without a TUN device: tailnet connections reach FileParcel from 127.0.0.1 and bypass the access policy.",
		Hint:    "run tailscaled with a TUN device, or use Serve (fileparcel network tailscale-serve enable)"}
	iface := NetInterface{Name: "wg0-mullvad", Kind: IfExitVPN, Label: "Mullvad VPN", Up: true,
		Addrs: []netip.Prefix{netip.MustParsePrefix("10.64.1.2/32")}, MTU: 1380, IsVPN: true,
		Role: VPNRoleEgress, RoleSource: VPNRoleSourceAuto, Provider: "mullvad", Detail: "carries the default route", DefaultRoute: true}
	lan := NetInterface{Name: "eth0", Kind: IfLAN, Label: "LAN", Up: true,
		Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")}, MTU: 1500, Role: VPNRoleLocal, RoleSource: VPNRoleSourceAuto}
	yes, no := true, false

	return []contractCase{
		{"user", user},
		{"invite", Invite{ID: invID, Email: "bob@example.test", Role: RoleMember, RoleID: roleID, RoleName: "Helpdesk",
			GroupIDs: []string{groupID}, MaxUses: 1, ExpiresAt: expires, CreatedBy: adminID, CreatedAt: at,
			Status: InviteActive, URL: "/invite/abc"}},
		{"group", Group{ID: groupID, Name: "Finance", Description: "Money", CreatedAt: at, CreatedBy: adminID,
			MemberCount: 4, SpaceID: gSpace, MyRole: GroupRoleManager, RoleCount: 1, Roles: []RoleGroup{roleGroup}, Via: "role"}},
		{"group_member", GroupMember{GroupID: groupID, UserID: userID, Username: "alice", DisplayName: "Alice",
			Role: GroupRoleManager, AddedAt: at, Direct: true, DirectRole: GroupRoleMember, ViaRoles: []RoleRef{ref}}},
		{"grant", grant},
		{"role_def", role},
		{"role_def_builtin", BuiltinRoles(false)[2]},
		{"role_def_input", RoleDefInput{Name: "Helpdesk", Description: "Front-line support", Base: RoleMember, CopyFrom: "member",
			Permissions: &[]Capability{CapUsersManage, CapUsersCredentials}, Delegable: true}},
		{"role_def_update", RoleDefUpdate{AddPermissions: []Capability{CapAuditView}, RemovePermissions: []Capability{CapShareLinks},
			Delegable: &no}},
		{"role_ref", RoleRef{ID: finID, Name: "Finance", Description: "Accounting"}},
		{"role_group", roleGroup},
		{"role_group_input", RoleGroupInput{MemberRole: GroupRoleManager}},
		{"capability_catalog", CapabilityCatalog{Items: []CapabilityInfo{Catalog().Items[0], Catalog().Items[5]}, Groups: Catalog().Groups}},
		{"user_access", UserAccess{User: user.Ref(), Role: role, Permissions: helpdesk, Staff: true, FilesOverride: false,
			PersonalSpace: true, Groups: []AccessGroup{accessGroup}, Grants: []Grant{grant}, HiddenGrants: 2, AdminTokens: 1,
			Manageable: true}},
		{"subject_grants", SubjectGrants{Items: []Grant{grant}, Hidden: 3}},
		{"me", Me{User: &user, CSRF: "csrf-token", Prefs: json.RawMessage(`{"theme":"dark"}`), MFAPending: false,
			Features: map[string]bool{"passkeys": true, "links": true, "requests": true, "thumbnails": true,
				"mtls_self_service": false, "share_password_required": false, "directory": true, "tokens": true,
				"zip_legacy_encryption": true, "internet_links": true, "funnel_2fa": true},
			SpaceID: spaceID, GroupSpaceIDs: map[string]string{groupID: gSpace},
			Groups: []Group{{ID: groupID, Name: "Finance", CreatedAt: at, MemberCount: 4, SpaceID: gSpace,
				MyRole: GroupRoleManager, RoleCount: 1, Via: "direct"}},
			Via: ViaSession, Staff: true}},
		{"authz_changed_event", AuthzChangedEvent{UserIDs: []string{userID}, RoleID: roleID, Reason: AuthzRoleDeleted}},
		{"batch_input", BatchInput{FolderID: folder, Mode: UploadModeZip, ZipName: "Trip", Conflict: ConflictRename,
			Files:         []UploadFileInput{{ClientRef: "c1", RelPath: "Trip/a.jpg", Size: 1024, MTime: 1790000000000}},
			ZipEncryption: ZipEncAES256, ZipPassword: "correct horse battery"}},
		{"upload_batch", UploadBatch{ID: batchID, UserID: userID, FolderID: folder, Mode: UploadModeZip, ZipName: "Trip",
			ZipEncryption: ZipEncAES256, Conflict: ConflictRename, DeclaredFiles: 1, DeclaredBytes: 1024, ReservedBytes: 1024,
			State: BatchOpen, CreatedAt: at, UpdatedAt: at, ExpiresAt: expires, PartSize: PartSize, Parallel: 4, SmallMax: 1 << 20}},
		{"node_protected", Node{ID: nodeID, SpaceID: spaceID, ParentID: folder, Kind: KindFile, Name: "Trip.zip", Size: 2048,
			MIME: "application/zip", VersionID: verID, ContentHash: "b3:0123", CreatedAt: at, UpdatedAt: at, CreatedBy: userID,
			UpdatedBy: userID, Perm: PermOwner, ZipEncryption: ZipEncZipCrypto}},
		{"file_version", FileVersion{ID: verID, NodeID: nodeID, Size: 2048, ContentHash: "b3:0123", CreatedAt: at,
			CreatedBy: userID, ZipEncryption: ZipEncAES256, CreatedByName: "Alice", Current: true}},
		{"ingress_status", status},
		{"ingress_entry", funnel},
		{"funnel_input", FunnelInput{Mode: FunnelApp, Port: 8443, AllowAdmin: &no, Require2FA: &yes, Confirm: "public"}},
		{"serve_input", ServeInput{Enabled: true, Port: 443}},
		{"vpn_info", vpn},
		{"exposure", exposure},
		{"net_interface", iface},
		{"network_overview", NetworkOverview{Interfaces: []NetInterface{lan, iface},
			URLs: []AccessURL{{URL: "https://box.tail1234.ts.net/", Kind: URLKindTailscaleServe,
				Label: "Tailscale Serve (tailnet, no port)", Trusted: true, Recommended: true}},
			Policy:    AccessPolicy{Mode: AccessAllowlist, Allow: []string{"192.168.1.0/24"}, Deny: []string{}},
			Tailscale: ts, ClientIP: "192.168.1.30", Ingress: &status, VPNs: []VPNInfo{vpn, egress},
			Exposures: []Exposure{exposure}}},
		{"setting_view_managed", SettingView{Key: "funnel.mode", Section: "funnel", Order: 10, Type: "enum",
			Label: "Tailscale Funnel", Value: json.RawMessage(`"off"`), Default: json.RawMessage(`"off"`),
			Enum: []string{"off", "shares", "app"}, Managed: "PUT /api/v1/admin/network/funnel"}},
	}
}

// encodeContract renders v as the golden files do: indented, "&" and "<" as is.
func encodeContract(t *testing.T, name string, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // readable goldens ("&", "<" as is); the same JSON either way
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return buf.Bytes()
}

func TestContractJSON(t *testing.T) {
	dir := filepath.Join("testdata", "contract")
	if *updateContract {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cases := contractCases()
	names := map[string]bool{}
	for _, c := range cases {
		if names[c.name] {
			t.Fatalf("duplicate contract case %s", c.name)
		}
		names[c.name] = true
	}
	if !*updateContract {
		// Every golden file belongs to a case (none left behind by a rename).
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if n := strings.TrimSuffix(filepath.Base(f), ".json"); !names[n] {
				t.Errorf("golden %s has no contract case", f)
			}
		}
	}
	for _, c := range cases {
		got := encodeContract(t, c.name, c.v)
		file := filepath.Join(dir, c.name+".json")
		if *updateContract {
			if err := os.WriteFile(file, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v (run with -update-contract to create it)", c.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the JSON contract changed (plan §11.5).\n got: %s\nwant: %s", c.name, got, want)
		}
	}
}

// The goldens decode back into their types without loss (the CLI and tests
// decode what the server sends): unmarshal each file into a fresh value of
// the type, marshal it again and get the same bytes. This covers the
// decoders of CapSet (names) and Secret (a plain string).
func TestContractJSONDecodes(t *testing.T) {
	for _, c := range contractCases() {
		want, err := os.ReadFile(filepath.Join("testdata", "contract", c.name+".json"))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		dec := json.NewDecoder(bytes.NewReader(want))
		dec.DisallowUnknownFields() // every golden field exists in the type
		ptr := reflect.New(reflect.TypeOf(c.v))
		if err := dec.Decode(ptr.Interface()); err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
			continue
		}
		if got := encodeContract(t, c.name, ptr.Elem().Interface()); !bytes.Equal(got, want) {
			t.Errorf("%s: decode + encode changed the JSON\n got: %s\nwant: %s", c.name, got, want)
		}
	}
}
