package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Roles and permissions (DESIGN §6a). Every account has exactly one role: a
// built-in role (owner, admin, member, guest; core.Role) or a custom role
// ("rol_…", RoleDef) that is based on member or guest. A role grants a set of
// capabilities (permissions): user capabilities shape an ordinary account,
// server capabilities open parts of the Admin area. Owners, admins and the
// system principal hold every capability plus the admin-only surfaces; the
// escalation rules that decide who may give or manage which role live in
// escalation.go.

// Capability is one permission a role grants (DESIGN §6a). The string is the stable API/DB name.
type Capability string

// Capabilities, in catalog (= bit) order.
const (
	CapShareLinks       Capability = "shares.links"
	CapShareRequests    Capability = "shares.requests"
	CapUsersLookup      Capability = "users.lookup"
	CapTokensCreate     Capability = "tokens.create"
	CapUsersView        Capability = "users.view"
	CapUsersManage      Capability = "users.manage"
	CapUsersCredentials Capability = "users.credentials"
	CapInvitesManage    Capability = "invites.manage"
	CapGroupsManage     Capability = "groups.manage"
	CapSharesManage     Capability = "shares.manage"
	CapSettingsManage   Capability = "settings.manage"
	CapNetworkManage    Capability = "network.manage"
	CapCertsManage      Capability = "certs.manage"
	CapBackupsRun       Capability = "backups.run"
	CapSystemView       Capability = "system.view"
	CapSystemManage     Capability = "system.manage"
	CapAuditView        Capability = "audit.view"
)

// CapabilityInfo is one catalog entry (GET /admin/capabilities, role editor, CLI, docs).
type CapabilityInfo struct {
	Name        Capability   `json:"name"`
	Group       string       `json:"group"` // sharing | people | content | server | monitoring
	Label       string       `json:"label"`
	Description string       `json:"description"`
	Server      bool         `json:"server"` // opens an Admin-area surface; needs the admin token scope
	HighImpact  bool         `json:"high_impact"`
	Warning     string       `json:"warning,omitempty"`
	Implies     []Capability `json:"implies,omitempty"`
}

// CapabilityGroup is a UI section of the catalog.
type CapabilityGroup struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// CapabilityCatalog is GET /admin/capabilities.
type CapabilityCatalog struct {
	Items  []CapabilityInfo  `json:"items"`
	Groups []CapabilityGroup `json:"groups"`
}

// Capabilities is the permission catalog. Catalog order = bit order = UI
// order, and it is append-only: never renumber, reorder or reuse an entry
// (roles.permissions stores names, but CapSet bits follow this order).
// Labels, descriptions and warnings are UI/CLI texts. Implies is applied on
// save and on load (CapSet.Closure). Read it through Catalog or
// Capability.Info; never modify it.
var Capabilities = []CapabilityInfo{
	{
		Name:        CapShareLinks,
		Group:       "sharing",
		Label:       "Create share links",
		Description: "Create public links to files and folders they manage (only while share links are enabled in Settings → Sharing).",
		Server:      false,
	},
	{
		Name:        CapShareRequests,
		Group:       "sharing",
		Label:       "Create file requests",
		Description: "Create upload links that let anyone add files to a folder they manage (only while file requests are enabled).",
		Server:      false,
	},
	{
		Name:        CapUsersLookup,
		Group:       "sharing",
		Label:       "Find people and roles",
		Description: "Search the user directory and the list of roles when sharing.",
		Server:      false,
	},
	{
		Name:        CapTokensCreate,
		Group:       "sharing",
		Label:       "Create API tokens",
		Description: "Create personal access tokens for the command line and scripts. Removing this stops new tokens; existing tokens keep working until they are revoked.",
		Server:      false,
	},
	{
		Name:        CapUsersView,
		Group:       "people",
		Label:       "View people",
		Description: "See accounts (including e-mail addresses and last sign-in), groups, roles and who has access to what.",
		Server:      true,
	},
	{
		Name:        CapUsersManage,
		Group:       "people",
		Label:       "Manage accounts",
		Description: "Create, edit, disable, enable, unlock and delete accounts and give them roles: Member, Guest and the roles an administrator allows — never accounts or roles with server permissions this role does not have.",
		Server:      true,
		HighImpact:  true,
		Warning:     "Can delete accounts together with their personal files, and create accounts with a password they choose.",
		Implies:     []Capability{CapUsersView},
	},
	{
		Name:        CapUsersCredentials,
		Group:       "people",
		Label:       "Reset sign-in",
		Description: "Reset passwords and two-factor authentication, see and end sessions, and manage other people's passkeys and API tokens, for the accounts they may manage.",
		Server:      true,
		HighImpact:  true,
		Warning:     "Can reset passwords, and so sign in as the accounts they manage and open their files.",
		Implies:     []Capability{CapUsersView},
	},
	{
		Name:        CapInvitesManage,
		Group:       "people",
		Label:       "Invite people",
		Description: "Create, list and revoke invitation links for the roles they may give.",
		Server:      true,
		Implies:     []Capability{CapUsersView},
	},
	{
		Name:        CapGroupsManage,
		Group:       "people",
		Label:       "Manage groups",
		Description: "Create, rename and delete groups and their team folders, change members and managers, and make roles members of groups.",
		Server:      true,
		HighImpact:  true,
		Warning:     "Can add themselves to any group and open its team folder; deleting a group deletes its team folder.",
		Implies:     []Capability{CapUsersView},
	},
	{
		Name:        CapSharesManage,
		Group:       "content",
		Label:       "Manage everyone's links",
		Description: "List every share link and file request, see their access logs, disable, enable and revoke them. The links themselves stay hidden.",
		Server:      true,
	},
	{
		Name:        CapSettingsManage,
		Group:       "server",
		Label:       "General settings",
		Description: "Change Settings → General (except maintenance mode), Storage and Sharing.",
		Server:      true,
		HighImpact:  true,
		Warning:     "Can change quotas and upload limits, how long deleted files and old versions are kept, and the rules for public links.",
	},
	{
		Name:        CapNetworkManage,
		Group:       "server",
		Label:       "Network & VPN",
		Description: "Change the network access policy, mDNS, VPN and Tailscale Serve/Funnel settings.",
		Server:      true,
		HighImpact:  true,
		Warning:     "Can make the server reachable from the internet, or lock everyone out.",
	},
	{
		Name:        CapCertsManage,
		Group:       "server",
		Label:       "Certificates",
		Description: "Renew and configure TLS certificates (ACME, Tailscale, the local certificate authority) and mTLS, and issue and revoke client certificates. Uploading a custom certificate stays with administrators.",
		Server:      true,
		HighImpact:  true,
		Warning:     "Can replace the local certificate authority (every device must trust it again) and require client certificates.",
	},
	{
		Name:        CapBackupsRun,
		Group:       "server",
		Label:       "Run backups",
		Description: "List, start and verify backups (not download, restore, delete or configure them).",
		Server:      true,
	},
	{
		Name:        CapSystemView,
		Group:       "monitoring",
		Label:       "Server status",
		Description: "See the dashboard, system information, health checks and background jobs.",
		Server:      true,
	},
	{
		Name:        CapSystemManage,
		Group:       "monitoring",
		Label:       "Operate the server",
		Description: "Restart the server, turn maintenance mode on or off (and keep working during it), change the log level, and run or cancel maintenance jobs.",
		Server:      true,
		HighImpact:  true,
		Warning:     "Can restart the server and put it into maintenance mode.",
		Implies:     []Capability{CapSystemView},
	},
	{
		Name:        CapAuditView,
		Group:       "monitoring",
		Label:       "Audit and server logs",
		Description: "Search, verify and export the audit log and read the server log. Both show names and addresses from everyone's activity.",
		Server:      true,
	},
}

// CapabilityGroups are the UI sections of the catalog, in UI order.
var CapabilityGroups = []CapabilityGroup{
	{ID: "sharing", Label: "Sharing & account"},
	{ID: "people", Label: "People"},
	{ID: "content", Label: "Content"},
	{ID: "server", Label: "Server"},
	{ID: "monitoring", Label: "Monitoring"},
}

// capIndex maps a capability name to its bit (index in Capabilities).
var capIndex map[Capability]int

// Built-in capability sets (§2.2), built in init from Capabilities:
// UserCaps = the non-server entries, ServerCaps = the server entries,
// AllCaps = every entry (owner, admin, system), MemberCaps = the built-in
// Member role (shares.links, shares.requests, users.lookup, tokens.create).
var UserCaps, ServerCaps, AllCaps, MemberCaps CapSet

func init() {
	if len(Capabilities) > 64 {
		panic(fmt.Sprintf("core: %d capabilities do not fit a CapSet (at most 64)", len(Capabilities)))
	}
	capIndex = make(map[Capability]int, len(Capabilities))
	for i, c := range Capabilities {
		if _, dup := capIndex[c.Name]; dup {
			panic(fmt.Sprintf("core: duplicate capability %q", c.Name))
		}
		capIndex[c.Name] = i
		bit := CapSet(1) << i
		AllCaps |= bit
		if c.Server {
			ServerCaps |= bit
		} else {
			UserCaps |= bit
		}
	}
	MemberCaps = NewCapSet(CapShareLinks, CapShareRequests, CapUsersLookup, CapTokensCreate)
}

// Catalog returns the capability catalog (GET /admin/capabilities) as fresh
// copies: callers may modify the result.
func Catalog() CapabilityCatalog {
	items := make([]CapabilityInfo, len(Capabilities))
	for i, c := range Capabilities {
		items[i] = c.clone()
	}
	groups := make([]CapabilityGroup, len(CapabilityGroups))
	copy(groups, CapabilityGroups)
	return CapabilityCatalog{Items: items, Groups: groups}
}

func (c CapabilityInfo) clone() CapabilityInfo {
	if c.Implies != nil {
		c.Implies = append([]Capability(nil), c.Implies...)
	}
	return c
}

// Valid reports whether c is a catalog entry.
func (c Capability) Valid() bool {
	_, ok := capIndex[c]
	return ok
}

// Info returns a copy of c's catalog entry.
func (c Capability) Info() (CapabilityInfo, bool) {
	i, ok := capIndex[c]
	if !ok {
		return CapabilityInfo{}, false
	}
	return Capabilities[i].clone(), true
}

// Server reports whether c is a server capability (an Admin-area surface;
// API tokens need the admin scope to use it). Unknown names are not.
func (c Capability) Server() bool {
	i, ok := capIndex[c]
	return ok && Capabilities[i].Server
}

// Label returns the catalog label, or the name when c is unknown.
func (c Capability) Label() string {
	if i, ok := capIndex[c]; ok {
		return Capabilities[i].Label
	}
	return string(c)
}

// CapSet is a set of capabilities; bit i is Capabilities[i]. Bits exist only in
// memory: the database and JSON always use names, in catalog order.
type CapSet uint64

// NewCapSet returns the set of cs; unknown names are ignored.
func NewCapSet(cs ...Capability) CapSet {
	var s CapSet
	for _, c := range cs {
		if i, ok := capIndex[c]; ok {
			s |= 1 << i
		}
	}
	return s
}

// Has reports whether c is in s (false for unknown names).
func (s CapSet) Has(c Capability) bool {
	i, ok := capIndex[c]
	return ok && s&(1<<i) != 0
}

// With returns s plus cs (unknown names ignored).
func (s CapSet) With(cs ...Capability) CapSet { return s | NewCapSet(cs...) }

// Without returns s minus cs.
func (s CapSet) Without(cs ...Capability) CapSet { return s &^ NewCapSet(cs...) }

// SubsetOf reports whether every capability of s is in o (s &^ o == 0).
func (s CapSet) SubsetOf(o CapSet) bool { return s&^o == 0 }

// Minus returns the capabilities of s that are not in o.
func (s CapSet) Minus(o CapSet) CapSet { return s &^ o }

// Server returns the server capabilities of s (s & ServerCaps).
func (s CapSet) Server() CapSet { return s & ServerCaps }

// Closure returns s plus everything its capabilities imply, transitively.
// Bits beyond the catalog are dropped.
func (s CapSet) Closure() CapSet {
	s &= AllCaps
	for {
		next := s
		for i, c := range Capabilities {
			if s&(1<<i) != 0 {
				next |= NewCapSet(c.Implies...)
			}
		}
		if next == s {
			return s
		}
		s = next
	}
}

// List returns the names of s in catalog order (never nil).
func (s CapSet) List() []Capability {
	out := []Capability{}
	for i, c := range Capabilities {
		if s&(1<<i) != 0 {
			out = append(out, c.Name)
		}
	}
	return out
}

// Names returns List as strings (audit details, error messages).
func (s CapSet) Names() []string {
	l := s.List()
	out := make([]string, len(l))
	for i, c := range l {
		out[i] = string(c)
	}
	return out
}

// String renders the names joined by ", " ("" for the empty set).
func (s CapSet) String() string { return strings.Join(s.Names(), ", ") }

// MarshalJSON renders the names in catalog order: ["shares.links", …]; 0 → [].
func (s CapSet) MarshalJSON() ([]byte, error) { return json.Marshal(s.List()) }

// UnmarshalJSON reads an array of names; unknown names are ignored (a newer
// server may know more), null and [] give the empty set.
func (s *CapSet) UnmarshalJSON(b []byte) error {
	var names []Capability
	if err := json.Unmarshal(b, &names); err != nil {
		return err
	}
	*s = NewCapSet(names...)
	return nil
}

// ParseCaps validates API/CLI input: every name must be a catalog entry
// (else Invalid("permissions", `unknown permission "x"`)); duplicates are
// allowed and collapse. Implied capabilities are not added (use Closure).
func ParseCaps(names []Capability) (CapSet, error) {
	var s CapSet
	for _, c := range names {
		i, ok := capIndex[c]
		if !ok {
			return 0, Invalid("permissions", fmt.Sprintf("unknown permission %q", string(c)))
		}
		s |= 1 << i
	}
	return s, nil
}

// DecodeStoredCaps reads roles.permissions (a JSON array of names). Unknown
// names are ignored (fail closed, forward compatible); bad JSON gives the
// empty set. Implied capabilities are not added (EffectiveRoleCaps does).
func DecodeStoredCaps(jsonText string) CapSet {
	var names []Capability
	if json.Unmarshal([]byte(jsonText), &names) != nil {
		return 0
	}
	return NewCapSet(names...)
}

// EncodeCaps renders a set for roles.permissions (catalog order; "[]" when empty).
func EncodeCaps(s CapSet) string {
	b, _ := s.MarshalJSON()
	return string(b)
}

// customRolePrefix starts every custom role id (ids.PrefixRole + "_").
const customRolePrefix = "rol_"

// IsCustomRoleID reports whether id is a custom role id ("rol_…"). It does
// not check that the role exists.
func IsCustomRoleID(id string) bool { return strings.HasPrefix(id, customRolePrefix) }

// BuiltinCaps is the set of a built-in role (§2.2): owner, admin and system →
// AllCaps; member → MemberCaps; guest → none, or shares.links and
// shares.requests while sharing.allow_guests_share is on (guestsShare);
// anything else → none.
func BuiltinCaps(r Role, guestsShare bool) CapSet {
	switch r {
	case RoleOwner, RoleAdmin, RoleSystem:
		return AllCaps
	case RoleMember:
		return MemberCaps
	case RoleGuest:
		if guestsShare {
			return NewCapSet(CapShareLinks, CapShareRequests)
		}
	}
	return 0
}

// EffectiveRoleCaps is the only formula for the capabilities of an account
// (§2.2): base owner/admin/system → AllCaps; IsCustomRoleID(roleID) →
// stored.Closure() (sharing.allow_guests_share never applies); else
// BuiltinCaps(base, guestsShare).
func EffectiveRoleCaps(base Role, roleID string, stored CapSet, guestsShare bool) CapSet {
	switch {
	case base.IsAdmin():
		return AllCaps
	case IsCustomRoleID(roleID):
		return stored.Closure()
	}
	return BuiltinCaps(base, guestsShare)
}

// BuiltinRoleName is "Owner", "Admin", "Member", "Guest" or "System" (the
// role string for anything else).
func BuiltinRoleName(r Role) string {
	switch r {
	case RoleOwner:
		return "Owner"
	case RoleAdmin:
		return "Admin"
	case RoleMember:
		return "Member"
	case RoleGuest:
		return "Guest"
	case RoleSystem:
		return "System"
	}
	return string(r)
}

// builtinRoleDescriptions are the UI/CLI descriptions of the built-in roles.
var builtinRoleDescriptions = map[Role]string{
	RoleOwner:  "Full control, including other owners. At least one active owner must remain.",
	RoleAdmin:  "Runs the server: people, roles, settings, network, certificates, encryption and backups. Cannot change owners, and cannot open other people's files unless “Administrators can access all files” is on.",
	RoleMember: "Has “My files”, uses the team folders of their groups, shares, creates links and file requests, finds people and creates API tokens.",
	RoleGuest:  "No personal space; works only in folders shared with them or their role. Creates links and file requests only when Settings → Sharing allows guests to share.",
}

// BuiltinRoles returns the four built-in RoleDefs in the order owner, admin,
// member, guest: ID = Base = the role, Builtin, Permissions = BuiltinCaps,
// Delegable for member and guest, Staff for owner and admin. The counts and
// the caller-dependent Editable/Assignable are left zero.
func BuiltinRoles(guestsShare bool) []RoleDef {
	out := make([]RoleDef, 0, 4)
	for _, r := range []Role{RoleOwner, RoleAdmin, RoleMember, RoleGuest} {
		out = append(out, RoleDef{
			ID:          string(r),
			Name:        BuiltinRoleName(r),
			Description: builtinRoleDescriptions[r],
			Builtin:     true,
			Base:        r,
			Permissions: BuiltinCaps(r, guestsShare),
			Delegable:   r == RoleMember || r == RoleGuest,
			Staff:       r.IsAdmin(),
		})
	}
	return out
}

// ---------- role types (API) ----------

// RoleDef is a role as the API shows it: the four built-ins (ID = Base = the role) and custom roles.
type RoleDef struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Builtin     bool       `json:"builtin"`
	Base        Role       `json:"base"`
	Permissions CapSet     `json:"permissions"`
	Delegable   bool       `json:"delegable"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	UpdatedBy   string     `json:"updated_by,omitempty"`
	// Derived:
	Staff      bool `json:"staff"`       // owner/admin, or holds a server permission
	UserCount  int  `json:"user_count"`  // built-ins: plain holders only (role_id NULL)
	GroupCount int  `json:"group_count"` // custom: role_groups rows
	GrantCount int  `json:"grant_count"` // custom: live node grants to the role
	Editable   bool `json:"editable"`    // the caller may edit/delete it (built-in admin && custom)
	Assignable bool `json:"assignable"`  // the caller holds users.manage or invites.manage and CheckAssign(caller, {To: this}) passes
}

// RoleDefInput is POST /admin/roles.
type RoleDefInput struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Base        Role          `json:"base,omitempty"`        // member | guest; "" = base of CopyFrom (owner/admin → member), else member
	CopyFrom    string        `json:"copy_from,omitempty"`   // role id: start from its permissions (owner/admin → AllCaps)
	Permissions *[]Capability `json:"permissions,omitempty"` // replaces the start set when non-nil
	Delegable   bool          `json:"delegable,omitempty"`
}

// RoleDefUpdate is PATCH /admin/roles/{id}. Permissions (full replacement) and
// AddPermissions/RemovePermissions are mutually exclusive (422 field "permissions").
type RoleDefUpdate struct {
	Name              *string       `json:"name,omitempty"`
	Description       *string       `json:"description,omitempty"`
	Permissions       *[]Capability `json:"permissions,omitempty"`
	AddPermissions    []Capability  `json:"add_permissions,omitempty"`
	RemovePermissions []Capability  `json:"remove_permissions,omitempty"`
	Delegable         *bool         `json:"delegable,omitempty"`
}

// RoleRef is the public view of a role (GET /roles, via_roles).
type RoleRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MemberRole  string `json:"member_role,omitempty"` // in GroupMember.ViaRoles / AccessGroup.ViaRoles
}

// RoleGroup is one role → group membership (table role_groups).
type RoleGroup struct {
	RoleID     string    `json:"role_id"`
	RoleName   string    `json:"role_name"`
	GroupID    string    `json:"group_id"`
	GroupName  string    `json:"group_name"`
	SpaceID    string    `json:"space_id,omitempty"`
	MemberRole string    `json:"member_role"` // GroupRoleMember | GroupRoleManager
	AddedAt    time.Time `json:"added_at"`
	AddedBy    string    `json:"added_by,omitempty"`
}

// RoleGroupInput is PUT /admin/roles/{id}/groups/{groupId} (member_role default member).
type RoleGroupInput struct {
	MemberRole string `json:"member_role,omitempty"`
}

// AccessGroup is one effective group membership of a user.
type AccessGroup struct {
	GroupID    string    `json:"group_id"`
	Name       string    `json:"name"`
	SpaceID    string    `json:"space_id,omitempty"`
	Role       string    `json:"role"` // effective: member | manager
	Direct     bool      `json:"direct"`
	DirectRole string    `json:"direct_role,omitempty"`
	ViaRoles   []RoleRef `json:"via_roles,omitempty"`
}

// SubjectGrantQuery selects GET /admin/grants.
type SubjectGrantQuery struct {
	SubjectType string // user | group | role
	SubjectID   string
	Expand      bool // user only: also grants to their effective groups and to their custom role
}

// SubjectGrants is the answer of GET /admin/grants.
type SubjectGrants struct {
	Items  []Grant `json:"items"`
	Hidden int     `json:"hidden"` // grants on items whose names the caller may not see
}

// UserAccess is GET /admin/users/{id}/access: the effective-access preview.
type UserAccess struct {
	User          UserRef       `json:"user"`
	Role          RoleDef       `json:"role"`
	Permissions   CapSet        `json:"permissions"`
	Staff         bool          `json:"staff"`
	FilesOverride bool          `json:"files_override"` // built-in owner/admin and auth.admin_can_access_files
	PersonalSpace bool          `json:"personal_space"`
	Groups        []AccessGroup `json:"groups"`
	Grants        []Grant       `json:"grants"` // user, group and role grants (Expand)
	HiddenGrants  int           `json:"hidden_grants"`
	AdminTokens   int           `json:"admin_tokens"` // live admin-scope tokens; 0 unless the caller has users.credentials
	Manageable    bool          `json:"manageable"`   // CheckManage(caller, user, users.manage) passes
}
