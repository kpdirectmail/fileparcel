package core

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// This file defines every model and Input/Query/Update/Result type used by
// the service interfaces. json tags are the API schema (snake_case).
// Fields tagged json:"-" are internal (hashes, secrets, raw keys) and are
// never sent to clients.

// ======================= users & groups =======================

// User statuses (users.status).
const (
	UserActive   = "active"
	UserDisabled = "disabled"
)

// User is an account (table users).
type User struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
	Role        Role   `json:"role"` // the built-in base role (users.role)
	// RoleID is the role the account has: "owner"|"admin"|"member"|"guest"|"rol_…" (never empty).
	// Role stays the base (users.role).
	RoleID string `json:"role_id"`
	// Derived:
	RoleName      string `json:"role_name"`   // custom name, else "Owner"/"Admin"/"Member"/"Guest"
	Permissions   CapSet `json:"permissions"` // EffectiveRoleCaps (with sharing.allow_guests_share)
	RoleDelegable bool   `json:"-"`           // delegable role (built-in member/guest, or a custom role marked delegable), for CheckManage
	Status        string `json:"status"`      // UserActive | UserDisabled
	// PasswordHash is the argon2id PHC string ("" = no password set).
	PasswordHash       string     `json:"-"`
	PasswordChangedAt  *time.Time `json:"password_changed_at,omitempty"`
	MustChangePassword bool       `json:"must_change_password"`
	// WebAuthnHandle is the random WebAuthn user handle (users.webauthn_handle).
	WebAuthnHandle []byte `json:"-"`
	// QuotaBytes: nil = use storage.default_quota_gb; 0 = unlimited; >0 = limit.
	QuotaBytes   *int64     `json:"quota_bytes"`
	FailedLogins int        `json:"failed_logins"`
	LockLevel    int        `json:"lock_level"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP  string     `json:"last_login_ip,omitempty"`
	// Prefs is the user's UI preferences object (users.prefs JSON, default {}).
	Prefs     json.RawMessage `json:"prefs,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	CreatedBy string          `json:"created_by,omitempty"`

	// Derived (not columns):
	// SpaceID is the personal space ("" for guests).
	SpaceID string `json:"space_id,omitempty"`
	// MFAEnabled reports TOTP or at least one passkey (filled where cheap).
	MFAEnabled bool `json:"mfa_enabled"`
}

// Locked reports whether the account is locked out at now.
func (u *User) Locked(now time.Time) bool { return u.LockedUntil != nil && now.Before(*u.LockedUntil) }

// Ref returns the public reference of u.
func (u *User) Ref() UserRef {
	return UserRef{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}
}

// UserRef is the minimal public view of a user (lookup pickers, owners).
type UserRef struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// NewUser is the input of Users.Create/Bootstrap and Auth.Setup.
// Users.Create/Bootstrap store PasswordHash (set by the caller after
// Auth.CheckPasswordPolicy + Auth.HashPassword); they never look at Password.
// Auth.Setup hashes Password itself.
type NewUser struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	Role        Role   `json:"role,omitempty"` // default member
	// RoleID gives a role: a built-in word or "rol_…". Role must then be "" or its base (422 field role).
	RoleID string `json:"role_id,omitempty"`
	// Password is plaintext input (API/CLI); input only, never stored or echoed.
	Password string `json:"password,omitempty"`
	// GeneratePassword asks the handler to generate a password (returned once).
	GeneratePassword   bool     `json:"generate_password,omitempty"`
	PasswordHash       string   `json:"-"`
	MustChangePassword bool     `json:"must_change_password,omitempty"`
	QuotaBytes         *int64   `json:"quota_bytes,omitempty"` // see User.QuotaBytes
	GroupIDs           []string `json:"group_ids,omitempty"`   // initial memberships (role member)
	// SetupToken is used by POST /auth/setup (input only).
	SetupToken string `json:"setup_token,omitempty"`
}

// UserUpdate is a partial update (PATCH /admin/users/{id}; Users.Update).
// nil / unset fields are left unchanged. Role, RoleID, QuotaBytes and
// MustChangePassword are admin fields (see the Users doc comment). PATCH
// /me/profile decodes ProfileUpdate instead.
type UserUpdate struct {
	DisplayName *string `json:"display_name,omitempty"`
	Email       *string `json:"email,omitempty"` // "" clears
	Role        *Role   `json:"role,omitempty"`
	// RoleID gives a role (built-in word or "rol_…"); Role must then be absent or its base.
	// Sending Role without RoleID gives that built-in role (and removes any custom role).
	RoleID             *string `json:"role_id,omitempty"`
	MustChangePassword *bool   `json:"must_change_password,omitempty"`
	// QuotaBytes: null = back to the default, 0 = unlimited, >0 = limit.
	QuotaBytes Opt[int64] `json:"quota_bytes,omitzero"`
	// Prefs replaces the preferences object.
	Prefs json.RawMessage `json:"prefs,omitempty"`
}

// ProfileUpdate is PATCH /me/profile: the fields a user may change on their
// own account. Decoding it (httpx.Decode, unknown fields rejected) makes it
// impossible to smuggle role/quota changes through the profile endpoint.
type ProfileUpdate struct {
	DisplayName *string `json:"display_name,omitempty"`
	Email       *string `json:"email,omitempty"` // "" clears
	// Prefs replaces the preferences object (theme, density, view, …).
	Prefs json.RawMessage `json:"prefs,omitempty"`
}

// UserUpdate converts the profile change into a UserUpdate for Users.Update.
func (p ProfileUpdate) UserUpdate() UserUpdate {
	return UserUpdate{DisplayName: p.DisplayName, Email: p.Email, Prefs: p.Prefs}
}

// UserQuery filters Users.List.
type UserQuery struct {
	PageReq
	Q      string `json:"q,omitempty"`      // matches username, display name, email
	Role   Role   `json:"role,omitempty"`   // filter by the base role
	Status string `json:"status,omitempty"` // active | disabled
	// RoleID filters by role: a built-in word (plain holders only: role_id IS NULL) or "rol_…".
	RoleID string `json:"role_id,omitempty"`
}

// Session is a browser login session (table sessions).
type Session struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	TokenHash     []byte     `json:"-"`
	AuthLevel     int        `json:"auth_level"`
	MFAMethod     string     `json:"mfa_method,omitempty"` // totp | recovery | passkey
	CSRFSecret    []byte     `json:"-"`
	Remember      bool       `json:"remember"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	IdleExpiresAt time.Time  `json:"idle_expires_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	ElevatedUntil *time.Time `json:"elevated_until,omitempty"`
	IP            string     `json:"ip,omitempty"`
	UserAgent     string     `json:"user_agent,omitempty"`
	// ClientCertSerial is the mTLS client certificate the session was created with.
	ClientCertSerial string     `json:"client_cert_serial,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	// Current is true for the session making the request (derived).
	Current bool `json:"current"`
}

// Group membership roles (group_members.role).
const (
	GroupRoleMember  = "member"
	GroupRoleManager = "manager"
)

// Group is a user group; each group owns a "Team folder" space.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	// Derived:
	MemberCount int         `json:"member_count"` // distinct users, direct or through a role
	SpaceID     string      `json:"space_id,omitempty"`
	MyRole      string      `json:"my_role,omitempty"` // for MyGroups: the effective GroupRoleMember | GroupRoleManager (manager wins)
	RoleCount   int         `json:"role_count"`        // role_groups rows
	Roles       []RoleGroup `json:"roles,omitempty"`   // GetGroup only
	Via         string      `json:"via,omitempty"`     // MyGroups: "direct" | "role" ("direct" when both)
}

// GroupInput creates or updates a group. On update, Name "" and Description
// nil mean "unchanged".
type GroupInput struct {
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// GroupMember is one membership.
type GroupMember struct {
	GroupID     string    `json:"group_id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"` // effective (direct or through a role; manager wins): GroupRoleMember | GroupRoleManager
	AddedAt     time.Time `json:"added_at"`
	Direct      bool      `json:"direct"`                // a direct membership (group_members) exists
	DirectRole  string    `json:"direct_role,omitempty"` // its role
	ViaRoles    []RoleRef `json:"via_roles,omitempty"`   // the custom roles that make the user a member (MemberRole set)
}

// Invite statuses (derived).
const (
	InviteActive  = "active"
	InviteUsed    = "used"
	InviteExpired = "expired"
	InviteRevoked = "revoked"
)

// Invite is an invitation link (table invites). URL is /invite/<token>.
type Invite struct {
	ID         string     `json:"id"`
	Email      string     `json:"email,omitempty"`
	Role       Role       `json:"role"`    // the base: admin | member | guest
	RoleID     string     `json:"role_id"` // the role, as for User
	GroupIDs   []string   `json:"group_ids"`
	QuotaBytes *int64     `json:"quota_bytes"`
	MaxUses    int        `json:"max_uses"`
	Uses       int        `json:"uses"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Note       string     `json:"note,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	TokenHash  []byte     `json:"-"`
	// Derived:
	RoleName string `json:"role_name"` // "Deleted role" when the custom role is gone
	Status   string `json:"status"`    // InviteActive | InviteUsed | InviteExpired | InviteRevoked
	// URL is the absolute or root-relative invite URL (admin views only; from token_enc).
	URL string `json:"url,omitempty"`
	// InvitedBy is the creator's display name, set only by LookupInvite for
	// the public invite page (as the invite e-mail names the inviter; the
	// creator's ID stays hidden). "" for invites made from the CLI.
	InvitedBy string `json:"invited_by,omitempty"`
	// EmailError is set only on the result of CreateInvite with Send when no
	// e-mail was queued (why; the invitation itself was created). Not stored.
	EmailError string `json:"email_error,omitempty"`
}

// InviteInput creates an invite.
type InviteInput struct {
	Email string `json:"email,omitempty"`
	Role  Role   `json:"role"` // admin | member | guest
	// RoleID gives a role: a built-in word or "rol_…". Role must then be "" or its base (422 field role).
	RoleID     string     `json:"role_id,omitempty"`
	GroupIDs   []string   `json:"group_ids,omitempty"`
	QuotaBytes *int64     `json:"quota_bytes,omitempty"`
	MaxUses    int        `json:"max_uses,omitempty"`   // default 1
	ExpiresAt  *time.Time `json:"expires_at,omitempty"` // default now + 7 days
	Note       string     `json:"note,omitempty"`
	Send       bool       `json:"send,omitempty"` // e-mail the invite (needs SMTP and Email)
}

// AcceptInvite is the input of POST /auth/invite/{token}/accept.
type AcceptInvite struct {
	Username    string `json:"username"`
	Password    string `json:"password"` // input only
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

// ======================= auth =======================

// MFA methods (LoginResult.Methods, Session.MFAMethod).
const (
	MFATOTP     = "totp"
	MFARecovery = "recovery"
	MFAPasskey  = "passkey"
)

// LoginInput is POST /auth/login.
type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"` // input only
	Remember bool   `json:"remember"`
	// AfterInvite is set by the invitation flow only (never from JSON): the sign-in right after the account was
	// created with an invitation. Over Tailscale Funnel it is not refused for the missing second factor (the
	// invitation proved the person); the session still has to set one up there (auth.applyIngress).
	AfterInvite bool `json:"-"`
}

// LoginResult is returned by every login step. When MFARequired is set the
// session exists at AuthLevel 1 and the client must call /auth/totp,
// /auth/recovery or the passkey flow.
type LoginResult struct {
	User               *User    `json:"user,omitempty"`
	MFARequired        bool     `json:"mfa_required,omitempty"`
	Methods            []string `json:"methods,omitempty"` // MFATOTP, MFARecovery, MFAPasskey
	EnrollRequired     bool     `json:"enroll_required,omitempty"`
	MustChangePassword bool     `json:"must_change_password,omitempty"`
	CSRF               string   `json:"csrf,omitempty"`
	// Token is the raw session token for Auth.SessionCookie (never serialized).
	Token string `json:"-"`
	// CookieExpires is the cookie expiry (zero = browser-session cookie).
	CookieExpires time.Time `json:"-"`
	Session       *Session  `json:"-"`
}

// ElevateInput is POST /auth/elevate: exactly one of Password, TOTP or
// Passkey (+FlowID from a PasskeyLoginBegin for the same user).
type ElevateInput struct {
	Password string          `json:"password,omitempty"` // input only
	TOTP     string          `json:"totp,omitempty"`
	Passkey  json.RawMessage `json:"passkey,omitempty"` // WebAuthn assertion response
	FlowID   string          `json:"flow_id,omitempty"`
}

// TOTPEnrollment is returned by Auth.TOTPBegin.
type TOTPEnrollment struct {
	Secret     string `json:"secret"`      // base32, for manual entry
	OTPAuthURI string `json:"otpauth_uri"` // otpauth://totp/…
	QRDataURI  string `json:"qr_data_uri"` // data:image/svg+xml;base64,…
}

// MFAStatus summarises a user's second factors.
type MFAStatus struct {
	TOTPEnabled       bool `json:"totp_enabled"`
	TOTPPending       bool `json:"totp_pending"` // begun but not confirmed
	RecoveryCodesLeft int  `json:"recovery_codes_left"`
	PasskeyCount      int  `json:"passkey_count"`
	// Required reports whether auth.require_2fa applies to this user.
	Required bool `json:"required"`
	// FunnelRequired reports that the caller reaches this, their own account, over Tailscale Funnel while
	// funnel.require_2fa is on: that address only lets in accounts with a second factor.
	FunnelRequired bool `json:"funnel_required,omitempty"`
	EnrollRequired bool `json:"enroll_required"` // Required or FunnelRequired, and no second factor yet
}

// Passkey is a registered WebAuthn credential (table webauthn_credentials).
type Passkey struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	Name           string     `json:"name"`
	CredentialID   []byte     `json:"-"`
	AAGUID         string     `json:"aaguid,omitempty"` // UUID form
	SignCount      uint32     `json:"sign_count"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"` // synced passkey
	RPID           string     `json:"rp_id"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	// Credential is the decrypted webauthn.Credential JSON (credential_enc).
	Credential json.RawMessage `json:"-"`
}

// APIToken is a personal access token (table api_tokens). The secret
// ("fpt_<id-suffix>_<secret>") is returned only once by CreateToken.
type APIToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`   // Scope* constants
	Elevated   bool       `json:"elevated"` // ScopeElevated present
	TokenHash  []byte     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// TokenInput creates an API token.
type TokenInput struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = never (elevated tokens: max 30 days)
	Elevated  bool       `json:"elevated,omitempty"`   // admin scope acting as elevated; needs step-up
	UserID    string     `json:"user_id,omitempty"`    // admin/CLI: create for another user
}

// ClientCert is an issued mTLS client certificate (table client_certs).
type ClientCert struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	Username          string     `json:"username,omitempty"` // derived
	Name              string     `json:"name"`
	Serial            string     `json:"serial"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	NotBefore         time.Time  `json:"not_before"`
	NotAfter          time.Time  `json:"not_after"`
	IssuedBy          string     `json:"issued_by,omitempty"`
	IssuedAt          time.Time  `json:"issued_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevokeReason      string     `json:"revoke_reason,omitempty"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
}

// ClientCertInput issues a client certificate (returned as PKCS#12).
type ClientCertInput struct {
	UserID   string `json:"user_id"`
	Name     string `json:"name"`
	Days     int    `json:"days,omitempty"`     // default 365
	Password string `json:"password,omitempty"` // p12 password (input only; generated when empty)
	Legacy   bool   `json:"legacy,omitempty"`   // LegacyDES encoder for old Android/macOS
}

// ======================= files =======================

// Permission levels.
const (
	PermNone Perm = iota
	PermView
	PermEdit
	PermManage
	PermOwner
)

var permNames = [...]string{"none", "view", "edit", "manage", "owner"}

// String returns none|view|edit|manage|owner.
func (p Perm) String() string {
	if p >= 0 && int(p) < len(permNames) {
		return permNames[p]
	}
	return fmt.Sprintf("perm(%d)", int(p))
}

// MarshalText renders the permission name (JSON uses the name).
func (p Perm) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText parses a permission name.
func (p *Perm) UnmarshalText(b []byte) error {
	for i, n := range permNames {
		if n == string(b) {
			*p = Perm(i)
			return nil
		}
	}
	return fmt.Errorf("unknown permission %q", b)
}

// Conflict policies.
const (
	ConflictRename  ConflictPolicy = "rename"  // "name (1).ext"
	ConflictReplace ConflictPolicy = "replace" // new version of the existing file
	ConflictSkip    ConflictPolicy = "skip"
	ConflictFail    ConflictPolicy = "fail" // ErrConflict
)

// Valid reports whether c is a known policy.
func (c ConflictPolicy) Valid() bool {
	switch c {
	case ConflictRename, ConflictReplace, ConflictSkip, ConflictFail:
		return true
	}
	return false
}

// Space kinds.
const (
	SpaceUser  = "user"  // personal space ("My files")
	SpaceGroup = "group" // group space ("Team folder")
)

// Space is a storage root (table spaces).
type Space struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // SpaceUser | SpaceGroup
	OwnerUserID string    `json:"owner_user_id,omitempty"`
	GroupID     string    `json:"group_id,omitempty"`
	Name        string    `json:"name"`
	QuotaBytes  *int64    `json:"quota_bytes"`
	UsedBytes   int64     `json:"used_bytes"`
	CreatedAt   time.Time `json:"created_at"`
	// Derived:
	RootID string `json:"root_id"` // root folder node
	Perm   Perm   `json:"perm"`    // the principal's permission on the root
}

// Node kinds.
const (
	KindFolder = "folder"
	KindFile   = "file"
)

// Node is a file or folder (table nodes).
type Node struct {
	RID         int64      `json:"-"` // rowid (FTS)
	ID          string     `json:"id"`
	SpaceID     string     `json:"space_id"`
	ParentID    string     `json:"parent_id,omitempty"` // "" for a space root
	Kind        string     `json:"kind"`                // KindFolder | KindFile
	Name        string     `json:"name"`                // NFC
	NameKey     string     `json:"-"`                   // casefold(NFC(name))
	Size        int64      `json:"size"`                // files: bytes of the current version
	MIME        string     `json:"mime,omitempty"`
	VersionID   string     `json:"version_id,omitempty"`
	ContentHash string     `json:"content_hash,omitempty"`
	ClientMtime *time.Time `json:"client_mtime,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   string     `json:"created_by,omitempty"`
	UpdatedBy   string     `json:"updated_by,omitempty"`
	TrashedAt   *time.Time `json:"trashed_at,omitempty"`
	TrashedBy   string     `json:"trashed_by,omitempty"`
	TrashRoot   bool       `json:"trash_root,omitempty"`
	ThumbBlobID string     `json:"-"`
	// BlobID is the current version's blob (files; internal).
	BlobID string `json:"-"`

	// Derived (filled where cheap / relevant):
	HasThumb   bool   `json:"has_thumb"`
	Starred    bool   `json:"starred"`
	Perm       Perm   `json:"perm"`                  // the principal's permission
	Path       string `json:"path,omitempty"`        // "/Folder/Sub/name" within the space (search, trash)
	ChildCount *int64 `json:"child_count,omitempty"` // folders, when listed
	// ZipEncryption is the protection of the current version (derived):
	// ZipEncAES256 | ZipEncZipCrypto, "" when not a protected zip.
	ZipEncryption string `json:"zip_encryption,omitempty"`
}

// IsDir reports whether n is a folder.
func (n *Node) IsDir() bool { return n.Kind == KindFolder }

// FileMeta is metadata for Files.CommitFile.
type FileMeta struct {
	MIME        string     `json:"mime,omitempty"` // "" = detect from name
	ClientMtime *time.Time `json:"client_mtime,omitempty"`
	// ZipEncryption marks the new version as a protected zip (ZipEncAES256 |
	// ZipEncZipCrypto). Set by the upload.zip job only; never from a request body.
	ZipEncryption string `json:"-"`
}

// ListQuery filters folder listings, trash, starred and shared-with-me.
// Sort: name|size|updated|kind (folders first unless sorting by kind desc).
type ListQuery struct {
	PageReq
	Kind string `json:"kind,omitempty"` // KindFolder | KindFile | "" (both)
}

// SearchQuery is GET /search?q=&space=&kind=. Queries of >= 3 characters use
// the FTS5 trigram index; shorter ones use LIKE on name_key.
type SearchQuery struct {
	PageReq
	Q       string `json:"q"`
	SpaceID string `json:"space,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// WalkEntry is one node visited by Files.Walk (DFS, parents before children).
type WalkEntry struct {
	Node Node `json:"node"`
	// Path is the slash-separated path relative to the walk root's parent,
	// i.e. it starts with the root item's own name ("Photos/2024/a.jpg").
	Path  string `json:"path"`
	Depth int    `json:"depth"` // 0 for a root item
}

// FileVersion is one stored version of a file (table file_versions).
type FileVersion struct {
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	BlobID      string    `json:"-"`
	Size        int64     `json:"size"`
	ContentHash string    `json:"content_hash,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	// ZipEncryption is the protection of this version's bytes (ZipEncAES256 |
	// ZipEncZipCrypto; "" = not a protected zip).
	ZipEncryption string `json:"zip_encryption,omitempty"`
	// Derived:
	CreatedByName string `json:"created_by_name,omitempty"`
	Current       bool   `json:"current"`
}

// Grant subject types and roles.
const (
	SubjectUser  = "user"
	SubjectGroup = "group"
	SubjectRole  = "role"    // a custom role ("rol_…"): everyone holding it
	GrantViewer  = "viewer"  // PermView
	GrantEditor  = "editor"  // PermEdit
	GrantManager = "manager" // PermManage
)

// Grant gives a user, group or custom role access to a node and its
// descendants (table node_grants). A grant whose NodeID differs from the
// queried node is inherited from an ancestor.
type Grant struct {
	ID          string     `json:"id"`
	NodeID      string     `json:"node_id"`
	SubjectType string     `json:"subject_type"` // SubjectUser | SubjectGroup | SubjectRole
	SubjectID   string     `json:"subject_id"`
	SubjectName string     `json:"subject_name,omitempty"` // derived
	Role        string     `json:"role"`                   // GrantViewer | GrantEditor | GrantManager
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// Derived, filled by Files.SubjectGrants only (GET /admin/grants):
	NodeName   string `json:"node_name,omitempty"`
	NodePath   string `json:"node_path,omitempty"`
	NodeKind   string `json:"node_kind,omitempty"`
	SpaceKind  string `json:"space_kind,omitempty"`
	SpaceName  string `json:"space_name,omitempty"`
	CallerPerm Perm   `json:"caller_perm,omitempty"` // the caller's permission on the node (manage → may change/remove)
}

// GrantInput creates or updates (same subject) a grant.
type GrantInput struct {
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	Role        string     `json:"role"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// FolderStats is GET /nodes/{id}/stats (recursive, excluding trash).
type FolderStats struct {
	NodeID  string `json:"node_id"`
	Files   int64  `json:"files"`
	Folders int64  `json:"folders"`
	Bytes   int64  `json:"bytes"`
}

// Usage is a user's storage usage (GET /me/usage).
type Usage struct {
	UserID  string `json:"user_id"`
	SpaceID string `json:"space_id,omitempty"`
	// UsedBytes counts live files and trash of the personal space.
	UsedBytes     int64 `json:"used_bytes"`
	TrashBytes    int64 `json:"trash_bytes"`
	ReservedBytes int64 `json:"reserved_bytes"` // open upload reservations
	// QuotaBytes is the effective quota; 0 = unlimited.
	QuotaBytes int64 `json:"quota_bytes"`
}

// Archive formats.
const (
	ArchiveZip = "zip"
	ArchiveTar = "tar"
)

// ArchiveInput is POST /archives (and the share archive endpoint).
type ArchiveInput struct {
	NodeIDs []string `json:"node_ids"`
	Format  string   `json:"format,omitempty"` // ArchiveZip (default) | ArchiveTar
	Name    string   `json:"name,omitempty"`   // download name without extension
}

// ArchiveTicket is a consumed single-use archive ticket (table archive_tickets).
type ArchiveTicket struct {
	UserID    string    `json:"user_id,omitempty"`  // principal-bound ticket
	ShareID   string    `json:"share_id,omitempty"` // share-bound ticket
	NodeIDs   []string  `json:"node_ids"`
	Format    string    `json:"format"`
	Name      string    `json:"name"` // file name including extension
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ======================= uploads =======================

// Upload batch modes and states.
const (
	UploadModeFiles = "files"
	UploadModeZip   = "zip"

	BatchOpen       = "open"
	BatchFinalizing = "finalizing"
	BatchDone       = "done"
	BatchAborted    = "aborted"
	BatchFailed     = "failed"
	BatchExpired    = "expired"
)

// Upload file kinds and states.
const (
	UploadKindFile = "file"
	UploadKindDir  = "dir"

	UploadPending   = "pending"
	UploadUploading = "uploading"
	UploadUploaded  = "uploaded"
	UploadCommitted = "committed"
	UploadSkipped   = "skipped"
	UploadFailed    = "failed"
	UploadAborted   = "aborted"
)

// UploadBatch is a group of files uploaded together (table upload_batches).
type UploadBatch struct {
	ID            string         `json:"id"`
	UserID        string         `json:"user_id"` // quota owner (share owner for file requests)
	ShareID       string         `json:"share_id,omitempty"`
	Uploader      string         `json:"uploader,omitempty"`
	ActorSession  string         `json:"-"`
	FolderID      string         `json:"folder_id"`
	Mode          string         `json:"mode"` // UploadModeFiles | UploadModeZip
	ZipName       string         `json:"zip_name,omitempty"`
	ZipEncryption string         `json:"zip_encryption,omitempty"` // protected zip: ZipEncAES256 | ZipEncZipCrypto (the password is never returned)
	Conflict      ConflictPolicy `json:"conflict"`
	DeclaredFiles int            `json:"declared_files"`
	DeclaredBytes int64          `json:"declared_bytes"`
	ReservedBytes int64          `json:"reserved_bytes"`
	State         string         `json:"state"` // Batch* constants
	JobID         string         `json:"job_id,omitempty"`
	ResultNodeID  string         `json:"result_node_id,omitempty"`
	Error         string         `json:"error,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	// Protocol parameters (DESIGN §8.1):
	PartSize int64 `json:"part_size"` // PartSize
	Parallel int   `json:"parallel"`  // storage.upload_parallel
	SmallMax int64 `json:"small_max"` // files <= SmallMax use the small path
	// Files is filled by CreateBatch/GetBatch.
	Files []UploadFileState `json:"files,omitempty"`
}

// BatchInput is POST /upload-batches.
type BatchInput struct {
	FolderID string            `json:"folder_id"`
	Mode     string            `json:"mode"` // default files
	ZipName  string            `json:"zip_name,omitempty"`
	Conflict ConflictPolicy    `json:"conflict,omitempty"` // default rename
	Uploader string            `json:"uploader,omitempty"` // file requests with require_uploader_name
	Files    []UploadFileInput `json:"files"`
	// ZipEncryption protects the zip (mode zip only): ZipEncAES256 |
	// ZipEncZipCrypto; "" with a password means aes256.
	ZipEncryption string `json:"zip_encryption,omitempty"`
	// ZipPassword is write-only: never returned, logged or stored in clear
	// (Secret prints "[redacted]"; LogValue omits it).
	ZipPassword Secret `json:"zip_password,omitempty"`
}

// UploadFileInput declares one file or directory of a batch.
type UploadFileInput struct {
	ClientRef string `json:"client_ref"`
	RelPath   string `json:"rel_path"` // "Trip/day1/a.jpg"
	Size      int64  `json:"size"`
	// MTime is the client modification time in Unix milliseconds (DESIGN §8.1).
	MTime int64  `json:"mtime,omitempty"`
	Kind  string `json:"kind,omitempty"` // UploadKindFile (default) | UploadKindDir
	MIME  string `json:"mime,omitempty"`
}

// UploadFileState is the server view of one uploaded file (table upload_files).
type UploadFileState struct {
	ID        string `json:"id"`
	BatchID   string `json:"batch_id"`
	ClientRef string `json:"client_ref"`
	RelPath   string `json:"rel_path"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	PartCount int    `json:"part_count"`
	// PartsDone lists completed part numbers (never null: [] when none).
	PartsDone []int     `json:"parts_done"`
	State     string    `json:"state"` // Upload* state constants
	NodeID    string    `json:"node_id,omitempty"`
	Error     string    `json:"error,omitempty"`
	BlobID    string    `json:"-"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ======================= shares =======================

// Share kinds.
const (
	ShareLink    = "link"
	ShareRequest = "request" // file request (public upload)
)

// Share statuses (derived).
const (
	ShareActive    = "active"
	ShareExpired   = "expired"
	ShareDisabled  = "disabled"
	ShareExhausted = "exhausted" // max_downloads reached
)

// Share access actions (share_access_log.action).
const (
	AccessView         = "view"
	AccessPreview      = "preview"
	AccessDownload     = "download"
	AccessZip          = "zip"
	AccessUpload       = "upload"
	AccessPasswordOK   = "password_ok"
	AccessPasswordFail = "password_fail"
	AccessBlocked      = "blocked"
)

// Share is a public link or file request (table shares).
type Share struct {
	ID                  string     `json:"id"`
	Kind                string     `json:"kind"` // ShareLink | ShareRequest
	NodeID              string     `json:"node_id"`
	CreatedBy           string     `json:"created_by"`
	TokenHash           []byte     `json:"-"`
	Title               string     `json:"title,omitempty"`
	Message             string     `json:"message,omitempty"`
	PasswordHash        string     `json:"-"`
	PasswordVersion     int        `json:"-"`
	AllowDownload       bool       `json:"allow_download"`
	AllowPreview        bool       `json:"allow_preview"`
	AllowUpload         bool       `json:"allow_upload"`
	RequireUploaderName bool       `json:"require_uploader_name"`
	UploadMaxFileBytes  *int64     `json:"upload_max_file_bytes"`
	UploadQuotaBytes    *int64     `json:"upload_quota_bytes"`
	UploadUsedBytes     int64      `json:"upload_used_bytes"`
	MaxDownloads        *int64     `json:"max_downloads"`
	DownloadCount       int64      `json:"download_count"`
	ExpiresAt           *time.Time `json:"expires_at"`
	NotifyOwner         bool       `json:"notify_owner"`
	DisabledAt          *time.Time `json:"disabled_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastAccessAt        *time.Time `json:"last_access_at,omitempty"`

	// Derived:
	HasPassword bool   `json:"has_password"`
	Status      string `json:"status"` // Share* status constants
	// Unavailable: the status is active but the link does not open, because
	// the shared item is in the trash, its creator is disabled, or its
	// creator lost access to it (view for a link, edit for a file request).
	Unavailable   bool   `json:"unavailable,omitempty"`
	URL           string `json:"url,omitempty"` // /s/<token> (owner/admin views; from token_enc)
	NodeName      string `json:"node_name,omitempty"`
	NodeKind      string `json:"node_kind,omitempty"`
	CreatedByName string `json:"created_by_name,omitempty"`
}

// ShareInput creates a share. nil pointers take defaults (allow_download and
// allow_preview default to true; expiry defaults to sharing.default_expiry_days).
type ShareInput struct {
	Kind                string     `json:"kind"` // ShareLink | ShareRequest
	NodeID              string     `json:"node_id"`
	Title               string     `json:"title,omitempty"`
	Message             string     `json:"message,omitempty"`
	Password            string     `json:"password,omitempty"` // input only
	AllowDownload       *bool      `json:"allow_download,omitempty"`
	AllowPreview        *bool      `json:"allow_preview,omitempty"`
	AllowUpload         bool       `json:"allow_upload,omitempty"`
	RequireUploaderName bool       `json:"require_uploader_name,omitempty"`
	UploadMaxFileBytes  *int64     `json:"upload_max_file_bytes,omitempty"`
	UploadQuotaBytes    *int64     `json:"upload_quota_bytes,omitempty"`
	MaxDownloads        *int64     `json:"max_downloads,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	// NoExpiry requests a share without expiry (subject to sharing.max_expiry_days).
	NoExpiry    bool `json:"no_expiry,omitempty"`
	NotifyOwner bool `json:"notify_owner,omitempty"`
}

// ShareUpdate is PATCH /shares/{id}. Unset fields are unchanged; Opt fields
// accept null to clear (no limit / no expiry). Password: "" removes the
// password (and bumps password_version), any other value sets it.
type ShareUpdate struct {
	Title               *string        `json:"title,omitempty"`
	Message             *string        `json:"message,omitempty"`
	Password            *string        `json:"password,omitempty"` // input only
	AllowDownload       *bool          `json:"allow_download,omitempty"`
	AllowPreview        *bool          `json:"allow_preview,omitempty"`
	AllowUpload         *bool          `json:"allow_upload,omitempty"`
	RequireUploaderName *bool          `json:"require_uploader_name,omitempty"`
	UploadMaxFileBytes  Opt[int64]     `json:"upload_max_file_bytes,omitzero"`
	UploadQuotaBytes    Opt[int64]     `json:"upload_quota_bytes,omitzero"`
	MaxDownloads        Opt[int64]     `json:"max_downloads,omitzero"`
	ExpiresAt           Opt[time.Time] `json:"expires_at,omitzero"`
	NotifyOwner         *bool          `json:"notify_owner,omitempty"`
	Disabled            *bool          `json:"disabled,omitempty"` // true sets disabled_at, false clears it
}

// ShareQuery filters share lists.
type ShareQuery struct {
	PageReq
	Kind   string `json:"kind,omitempty"`    // ShareLink | ShareRequest
	NodeID string `json:"node_id,omitempty"` // shares of one node
	UserID string `json:"user_id,omitempty"` // ListAll: creator filter
	Status string `json:"status,omitempty"`  // active | inactive | "" (all)
}

// ShareAccess is one share access log row (table share_access_log).
type ShareAccess struct {
	ID        int64     `json:"id"`
	ShareID   string    `json:"share_id"`
	At        time.Time `json:"at"`
	Action    string    `json:"action"` // Access* constants
	NodeID    string    `json:"node_id,omitempty"`
	Bytes     int64     `json:"bytes,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Uploader  string    `json:"uploader,omitempty"`
	// Files is the number of files stored in this upload. It is NOT
	// persisted (share_access_log has no such column); it only travels to
	// the owner notification.
	Files int `json:"files,omitempty"`
}

// ======================= audit =======================

// Audit outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// AuditEntry is the input of Audit.Record. Actor fields, IP, UserAgent and
// RequestID are filled from the context Principal when empty; set them
// explicitly for anonymous events (e.g. a failed login: ActorName = the
// attempted username). Outcome defaults to OutcomeSuccess. Details is
// marshaled to JSON (never put secrets in it).
type AuditEntry struct {
	Action     string // dotted action, see the Act* constants
	Outcome    string
	TargetType string // "user", "node", "share", "setting", …
	TargetID   string
	TargetName string
	Details    any
	ActorID    string
	ActorName  string
	ActorVia   string
	IP         string
	UserAgent  string
	RequestID  string
}

// AuditRecord is a stored audit row (table audit_log).
type AuditRecord struct {
	Seq        int64           `json:"seq"`
	ID         string          `json:"id"`
	At         time.Time       `json:"at"`
	ActorID    string          `json:"actor_id,omitempty"`
	ActorName  string          `json:"actor_name,omitempty"`
	ActorVia   string          `json:"actor_via,omitempty"`
	IP         string          `json:"ip,omitempty"`
	UserAgent  string          `json:"user_agent,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	Action     string          `json:"action"`
	Outcome    string          `json:"outcome"`
	TargetType string          `json:"target_type,omitempty"`
	TargetID   string          `json:"target_id,omitempty"`
	TargetName string          `json:"target_name,omitempty"`
	Details    json.RawMessage `json:"details"`
	PrevHash   []byte          `json:"-"`
	Hash       []byte          `json:"-"`
}

// AuditQuery filters the audit log. Action matches exactly, or as a prefix
// when it ends with "." or ".*" ("auth." = every auth action).
type AuditQuery struct {
	PageReq
	Since      *time.Time `json:"since,omitempty"`
	Until      *time.Time `json:"until,omitempty"`
	ActorID    string     `json:"actor_id,omitempty"`
	Action     string     `json:"action,omitempty"`
	Outcome    string     `json:"outcome,omitempty"`
	TargetType string     `json:"target_type,omitempty"`
	TargetID   string     `json:"target_id,omitempty"`
	Q          string     `json:"q,omitempty"` // free text on actor/target names
}

// AuditVerify is the result of verifying the audit hash chain.
type AuditVerify struct {
	OK       bool   `json:"ok"`
	Checked  int64  `json:"checked"`
	FirstSeq int64  `json:"first_seq"`
	LastSeq  int64  `json:"last_seq"`
	BrokenAt int64  `json:"broken_at,omitempty"` // first seq whose hash does not verify
	Message  string `json:"message,omitempty"`
}

// ======================= jobs =======================

// Job states.
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
	JobCanceled  = "canceled"
)

// Job is a background job (table jobs).
type Job struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	State         string          `json:"state"` // Job* states
	Params        json.RawMessage `json:"params,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	Error         string          `json:"error,omitempty"`
	ProgressDone  int64           `json:"progress_done"`
	ProgressTotal int64           `json:"progress_total"`
	Note          string          `json:"note,omitempty"`
	CreatedBy     string          `json:"created_by,omitempty"`
	Schedule      string          `json:"schedule,omitempty"` // schedule name when started by the scheduler
	Attempts      int             `json:"attempts"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     *time.Time      `json:"started_at,omitempty"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
}

// JobQuery filters Jobs.List.
type JobQuery struct {
	PageReq
	Kind      string `json:"kind,omitempty"`
	State     string `json:"state,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
}

// JobSchedule is a cron schedule (table schedules).
type JobSchedule struct {
	Name      string          `json:"name"`
	Cron      string          `json:"cron"` // 5-field cron
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params,omitempty"`
	Enabled   bool            `json:"enabled"`
	LastRunAt *time.Time      `json:"last_run_at,omitempty"`
	NextRunAt *time.Time      `json:"next_run_at,omitempty"`
	LastJobID string          `json:"last_job_id,omitempty"`
}

// ======================= backups =======================

// Backup scopes, states, encryption modes and triggers.
const (
	BackupFull     = "full"
	BackupMetadata = "metadata"

	BackupRunning = "running"
	BackupReady   = "ready"
	BackupFailed  = "failed"

	BackupX25519     = "x25519"
	BackupPassphrase = "passphrase"

	TriggerManual     = "manual"
	TriggerSchedule   = "schedule"
	TriggerPreUpgrade = "pre-upgrade"
	TriggerFinal      = "final"
	TriggerImport     = "import"
)

// Backup is one backup archive (table backups).
type Backup struct {
	ID            string     `json:"id"`
	Scope         string     `json:"scope"`
	State         string     `json:"state"`
	FileName      string     `json:"file_name"`
	Size          int64      `json:"size"`
	SHA256        string     `json:"sha256,omitempty"`
	Encryption    string     `json:"encryption"`
	Recipients    []string   `json:"recipients,omitempty"` // age recipients (public)
	BlobCount     int64      `json:"blob_count"`
	BlobBytes     int64      `json:"blob_bytes"`
	DBSize        int64      `json:"db_size"`
	AppVersion    string     `json:"app_version,omitempty"`
	SchemaVersion int        `json:"schema_version"`
	Note          string     `json:"note,omitempty"`
	Trigger       string     `json:"trigger"`
	JobID         string     `json:"job_id,omitempty"`
	CreatedBy     string     `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	VerifyOK      *bool      `json:"verify_ok,omitempty"`
	Error         string     `json:"error,omitempty"`
	CopiedTo      string     `json:"copied_to,omitempty"`
}

// BackupInput starts a backup.
type BackupInput struct {
	Scope string `json:"scope,omitempty"` // BackupFull (default) | BackupMetadata
	Note  string `json:"note,omitempty"`
	// Trigger defaults to TriggerManual; pre-upgrade/final are accepted from the
	// system principal only.
	Trigger string `json:"trigger,omitempty"`
	// CopyTo is an extra destination path outside HOME (system principal only).
	CopyTo string `json:"copy_to,omitempty"`
}

// BackupConfig is the backup.* settings in one object (GET/PUT /admin/backups/config).
type BackupConfig struct {
	Enabled      bool     `json:"enabled"`
	ScheduleMeta string   `json:"schedule_meta"` // cron, "" = off
	ScheduleFull string   `json:"schedule_full"` // cron, "" = off
	KeepLast     int      `json:"keep_last"`
	KeepDaily    int      `json:"keep_daily"`
	KeepWeekly   int      `json:"keep_weekly"`
	KeepMonthly  int      `json:"keep_monthly"`
	Encryption   string   `json:"encryption"` // BackupX25519 | BackupPassphrase
	Recipients   []string `json:"recipients"`
	CopyTo       string   `json:"copy_to"`
	// HasIdentity / HasPassphrase report whether the secrets are set (output only).
	HasIdentity   bool `json:"has_identity"`
	HasPassphrase bool `json:"has_passphrase"`
	// IdentityRecipient is the public key of the stored backup identity,
	// which every x25519 backup is encrypted to besides Recipients (output
	// only; "" while no identity is stored or the keys are locked).
	IdentityRecipient string `json:"identity_recipient,omitempty"`
	// Passphrase sets backup.passphrase (input only; nil = unchanged). It is
	// never serialized: MarshalJSON drops it, so a GET can't leak it even if
	// the service fills it in.
	Passphrase *string `json:"passphrase,omitempty"`
}

// MarshalJSON renders the config without the input-only Passphrase.
func (c BackupConfig) MarshalJSON() ([]byte, error) {
	type plain BackupConfig
	p := plain(c)
	p.Passphrase = nil
	return json.Marshal(p)
}

// RestoreCreds decrypt a backup: an age identity (AGE-SECRET-KEY-…) or the
// passphrase. Input only.
type RestoreCreds struct {
	Identity   string `json:"identity,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// RestoreOpts tunes an offline restore.
type RestoreOpts struct {
	MetadataOnly bool `json:"metadata_only,omitempty"`
	DryRun       bool `json:"dry_run,omitempty"`
}

// ======================= settings =======================

// SettingView is one catalog entry (GET /admin/settings).
type SettingView struct {
	Key         string          `json:"key"`
	Section     string          `json:"section"`
	Order       int             `json:"order"`
	Type        string          `json:"type"` // settings.Type* names: bool, int, string, …
	Label       string          `json:"label"`
	Description string          `json:"description,omitempty"`
	Value       json.RawMessage `json:"value"`   // null for secrets
	Default     json.RawMessage `json:"default"` // null for secrets
	Min         *int64          `json:"min,omitempty"`
	Max         *int64          `json:"max,omitempty"`
	Enum        []string        `json:"enum,omitempty"`
	Restart     bool            `json:"restart"`
	Secret      bool            `json:"secret"`
	IsSet       bool            `json:"is_set"`    // value differs from default / secret present
	Bootstrap   bool            `json:"bootstrap"` // stored in fileparcel.toml
	// OverriddenByEnv names the env var currently overriding the value ("" = none).
	OverriddenByEnv string     `json:"overridden_by_env,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UpdatedBy       string     `json:"updated_by,omitempty"`
	// Managed names the route that owns the key (e.g. "PUT
	// /api/v1/admin/network/funnel"): PATCH/DELETE /admin/settings refuse it
	// with 409 ("" = an ordinary key).
	Managed string `json:"managed,omitempty"`
}

// SettingsResult is the response of PATCH /admin/settings.
type SettingsResult struct {
	Applied         []string `json:"applied"`
	RestartRequired []string `json:"restart_required"`
	// Warnings are about values that were applied but will not take full
	// effect (a tls.extra_sans name the local CA may not sign, …); set by
	// the settings API, not the store.
	Warnings []string `json:"warnings,omitempty"`
}

// ======================= network / tls / keys / mdns =======================

// Interface kinds (DESIGN §10.1).
const (
	IfLoopback  = "loopback"
	IfTailscale = "tailscale"
	IfHeadscale = "headscale"
	IfWireGuard = "wireguard"
	IfZeroTier  = "zerotier"
	IfNetBird   = "netbird"
	IfNebula    = "nebula"
	IfVPN       = "vpn"
	IfContainer = "container"
	IfWiFi      = "wifi"
	IfLAN       = "lan"
)

// NetInterface is a classified network interface.
type NetInterface struct {
	Name  string         `json:"name"`
	Kind  string         `json:"kind"`  // If* constants
	Label string         `json:"label"` // "Tailscale", "Wi-Fi", …
	Up    bool           `json:"up"`
	Addrs []netip.Prefix `json:"addrs"`
	MTU   int            `json:"mtu"`
	IsVPN bool           `json:"is_vpn"`
	// Role says what the interface is good for (VPNRole* constants:
	// mesh|unknown|access|egress|overlay|local|none); it drives URLs, SANs,
	// mDNS, the install allowlist and firewall hints (DESIGN §10.1).
	Role         string `json:"role"`
	RoleSource   string `json:"role_source,omitempty"`   // VPNRoleSourceAuto | VPNRoleSourceOverride (network.iface_roles)
	Provider     string `json:"provider,omitempty"`      // "nordvpn","mullvad","proton","cloudflare","twingate","firezone","cisco","paloalto",…
	Detail       string `json:"detail,omitempty"`        // "carries the default route", "NordVPN Meshnet", "kill-switch interface"
	DefaultRoute bool   `json:"default_route,omitempty"` // carries the effective default route
}

// Access URL kinds.
const (
	URLKindIP       = "ip"
	URLKindMDNS     = "mdns"
	URLKindHostname = "hostname"
	URLKindMagicDNS = "magicdns"
	URLKindPublic   = "public"
	URLKindExtra    = "extra"

	URLKindFunnel         = "funnel"          // Tailscale Funnel (internet), app mode
	URLKindTailscaleServe = "tailscale_serve" // Tailscale Serve (tailnet, no port)
)

// AccessURL is one way to reach the server (DESIGN §10.2).
type AccessURL struct {
	URL         string `json:"url"`
	Kind        string `json:"kind"` // URLKind* constants
	Interface   string `json:"interface,omitempty"`
	Label       string `json:"label"`
	Trusted     bool   `json:"trusted"` // certificate covers it and is publicly trusted
	Recommended bool   `json:"recommended"`
}

// Access modes (network.access_mode).
const (
	AccessPrivate   = "private"
	AccessAllowlist = "allowlist"
	AccessAny       = "any"
)

// AccessPolicy is the connection allowlist (DESIGN §10.3). Allow/Deny hold
// CIDRs or single IPs. Loopback is always allowed; Deny always wins.
type AccessPolicy struct {
	Mode  string   `json:"mode"` // Access* modes
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// TailscaleInfo describes the local Tailscale/Headscale node.
type TailscaleInfo struct {
	Running      bool         `json:"running"`
	Kind         string       `json:"kind,omitempty"` // IfTailscale | IfHeadscale
	BackendState string       `json:"backend_state,omitempty"`
	DNSName      string       `json:"dns_name,omitempty"` // MagicDNS FQDN (no trailing dot)
	Tailnet      string       `json:"tailnet,omitempty"`
	ControlURL   string       `json:"control_url,omitempty"`
	IPs          []netip.Addr `json:"ips,omitempty"`
	// CertCapable reports whether `tailscale cert` is expected to work
	// (HTTPS enabled for the tailnet, operator permission).
	CertCapable bool   `json:"cert_capable"`
	Error       string `json:"error,omitempty"`
	// Installed reports whether a tailscaled socket or tailscale CLI was
	// found. Running=false with Installed=false means Tailscale is simply
	// not used on this machine (Error then says so), not a failure.
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"` // tailscaled version
	NodeID    string `json:"node_id,omitempty"` // StableNodeID of this node
	// Userspace: tailscaled runs without a TUN device (tailnet connections
	// then reach FileParcel from 127.0.0.1).
	Userspace bool `json:"userspace"`
	ShieldsUp bool `json:"shields_up"` // tailnet peers cannot connect
	// CanConfigure: this process may change the Serve/Funnel configuration
	// (Linux: root or the tailscaled operator).
	CanConfigure  bool       `json:"can_configure"`
	FunnelCapable bool       `json:"funnel_capable"`         // https and funnel node capabilities
	FunnelPorts   []int      `json:"funnel_ports,omitempty"` // ports the funnel capability allows
	KeyExpiry     *time.Time `json:"key_expiry,omitempty"`   // node key expiry (nil: disabled or unknown)
	KindGuessed   bool       `json:"kind_guessed,omitempty"` // Kind guessed from the MagicDNS suffix (prefs unreadable)
}

// Certificate sources.
const (
	CertSourceLocal     = "local"
	CertSourceACME      = "acme"
	CertSourceTailscale = "tailscale"
	CertSourceCustom    = "custom"
)

// CertInfo describes one X.509 certificate.
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	IPs         []string  `json:"ips,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"` // SHA-256 of DER, hex with colons
	Source      string    `json:"source,omitempty"`
}

// CertStatus is GET /admin/certs.
type CertStatus struct {
	CA              *CertInfo  `json:"ca,omitempty"`
	CAConstrained   bool       `json:"ca_constrained"`
	PermittedDNS    []string   `json:"permitted_dns,omitempty"`
	PermittedIPs    []string   `json:"permitted_ips,omitempty"`
	Leaf            *CertInfo  `json:"leaf,omitempty"`
	ClientCA        *CertInfo  `json:"client_ca,omitempty"`
	Custom          *CertInfo  `json:"custom,omitempty"`
	Tailscale       *CertInfo  `json:"tailscale,omitempty"`
	ACME            []CertInfo `json:"acme,omitempty"`
	ACMEEnabled     bool       `json:"acme_enabled"`
	ACMEError       string     `json:"acme_error,omitempty"`
	TailscaleError  string     `json:"tailscale_error,omitempty"`
	MTLSMode        string     `json:"mtls_mode"`
	HSTS            bool       `json:"hsts"`
	PubliclyTrusted bool       `json:"publicly_trusted"` // for the default server name
}

// Master key modes.
const (
	KeyModePlain  = "plain"
	KeyModeSealed = "sealed"
)

// KEK purposes and states (table keyring).
const (
	KEKBlob  = "blob"
	KEKField = "field"
	KEKMAC   = "mac"

	KEKActive  = "active"
	KEKRetired = "retired"
)

// KEKInfo describes one keyring entry.
type KEKInfo struct {
	ID        string     `json:"id"`
	Purpose   string     `json:"purpose"`
	State     string     `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
	Refs      int64      `json:"refs"` // rows still referencing it
}

// KeyStatus is GET /admin/keys.
type KeyStatus struct {
	State              KeyState  `json:"state"`
	Mode               string    `json:"mode,omitempty"` // KeyModePlain | KeyModeSealed
	MKID               string    `json:"mk_id,omitempty"`
	Cipher             CipherID  `json:"cipher"`
	CipherName         string    `json:"cipher_name"`
	KEKs               []KEKInfo `json:"keks"`
	RecoveryConfigured bool      `json:"recovery_configured"`
	Mlocked            bool      `json:"mlocked"`
	WebUnlock          string    `json:"web_unlock"` // keys.web_unlock
}

// mDNS states.
const (
	MDNSPublishing = "publishing"
	MDNSPublished  = "published"
	MDNSCollision  = "collision"
	MDNSError      = "error"
	MDNSOff        = "off"
)

// MDNSStatus is GET /admin/mdns.
type MDNSStatus struct {
	Mode    string `json:"mode"`    // auto|avahi|dnssd|builtin|off
	Backend string `json:"backend"` // effective backend
	Name    string `json:"name"`    // effective FQDN
	// Configured is the <name>.local built from mdns.name / server.name. It
	// differs from Name while a collision rename is in effect.
	Configured string   `json:"configured,omitempty"`
	State      string   `json:"state"` // MDNS* states
	Error      string   `json:"error,omitempty"`
	Interfaces []string `json:"interfaces"`
}
