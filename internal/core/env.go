package core

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"fileparcel/internal/buildinfo"
	"fileparcel/internal/config"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
)

// ---------- env / identity ----------

// Clock abstracts time for testability. Services must use Env.Clock.Now()
// instead of time.Now() for anything persisted or compared (expiry, lockout).
type Clock interface{ Now() time.Time }

// SystemClock is the real clock (UTC).
type SystemClock struct{}

// Now returns time.Now().UTC().
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// ClockFunc adapts a function to Clock (tests: core.ClockFunc(func() time.Time { return fixed })).
type ClockFunc func() time.Time

// Now calls f.
func (f ClockFunc) Now() time.Time { return f() }

// Env is the shared environment passed to every service constructor.
// Keys, Settings and Audit are filled progressively by wire.Build (in that
// order), so a constructor may only use the fields filled before it runs
// (see DESIGN §5.2); read them lazily at call time otherwise.
type Env struct {
	Home   *home.Home
	Config *config.Config
	DB     *db.DB
	Log    *slog.Logger
	Clock  Clock
	Bus    *events.Bus
	Build  buildinfo.Info

	Keys     Keys     // set right after keys.Open
	Settings Settings // set right after settings.New
	Audit    Audit    // set right after audit.New
}

// Now is shorthand for e.Clock.Now() (falls back to the system clock).
func (e *Env) Now() time.Time {
	if e == nil || e.Clock == nil {
		return time.Now().UTC()
	}
	return e.Clock.Now()
}

// Role is a user role. "system" is only used by SystemPrincipal (admin socket
// and in-process CLI); it is never stored in the users table.
type Role string

// Roles.
const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleGuest  Role = "guest"
	RoleSystem Role = "system"
)

// Valid reports whether r is a storable user role (owner, admin, member, guest).
func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember, RoleGuest:
		return true
	}
	return false
}

// IsAdmin reports whether the role has administrative rights (owner, admin, system).
func (r Role) IsAdmin() bool { return r == RoleOwner || r == RoleAdmin || r == RoleSystem }

// AuthVia says how a request was authenticated.
type AuthVia string

// Authentication channels.
const (
	ViaSession AuthVia = "session" // browser cookie __Host-fp_session
	ViaToken   AuthVia = "token"   // Authorization: Bearer fpt_…
	ViaSocket  AuthVia = "socket"  // admin Unix socket (peer-cred checked)
	ViaShare   AuthVia = "share"   // public share link / file request
	ViaOffline AuthVia = "offline" // in-process CLI (server not running)
)

// Authentication levels (Principal.AuthLevel).
const (
	AuthLevelPassword = 1 // password verified, second factor pending
	AuthLevelFull     = 2 // fully authenticated
)

// API token scopes (DESIGN §9.3). Non-token principals implicitly have every scope.
const (
	ScopeFilesRead  = "files:read"
	ScopeFilesWrite = "files:write"
	ScopeShares     = "shares"
	ScopeAdmin      = "admin"
	// ScopeElevated is a pseudo-scope stored in api_tokens.scopes for tokens
	// created with --elevated (admin tokens that count as step-up elevated).
	// The schema has no dedicated column for it.
	ScopeElevated = "elevated"
)

// AllScopes lists the grantable token scopes (without the ScopeElevated pseudo-scope).
var AllScopes = []string{ScopeFilesRead, ScopeFilesWrite, ScopeShares, ScopeAdmin}

// Principal is the authenticated actor of a request (or of a system action).
// It is created by Auth.Authenticate (or SystemPrincipal) and stored in the
// request context with WithPrincipal.
type Principal struct {
	UserID, Username string
	Role             Role // built-in base role (unchanged meaning; custom roles keep member or guest here)
	// RoleID is the role id: "owner"|"admin"|"member"|"guest"|"rol_…"|"system"; "" when unknown.
	RoleID string
	// RoleName is the role's display name ("Admin", "Finance").
	RoleName string
	// Caps are the role capabilities (EffectiveRoleCaps) recorded by SetCaps;
	// token scopes are applied by Can. Read them through RoleCaps.
	Caps             CapSet
	capsSet          bool // Caps was resolved by the principal's builder (SetCaps)
	Via              AuthVia
	SessionID        string   // for Via=session
	TokenID          string   // for Via=token
	Scopes           []string // for Via=token
	AuthLevel        int      // 1 = password ok, MFA pending; 2 = full
	EnrollRequired   bool     // 2FA policy requires enrollment first
	ElevatedUntil    time.Time
	ClientCertSerial string
	IP               netip.Addr
	UserAgent        string
	RequestID        string

	// MustChangePassword marks a full session of an account whose password
	// was set by an administrator or the installer (users.
	// must_change_password): until it is changed only the routes needed for
	// that work (mw.RequireFull). Never set for tokens or the admin socket.
	MustChangePassword bool
}

// IsAdmin reports whether the principal is owner, admin or system (a
// built-in full administrator; custom roles never are).
func (p *Principal) IsAdmin() bool { return p != nil && p.Role.IsAdmin() }

// SetCaps records the resolved role capabilities.
func (p *Principal) SetCaps(c CapSet) { p.Caps, p.capsSet = c, true }

// RoleCaps is the account's capability set, ignoring token scopes: nil → 0;
// system/owner/admin → AllCaps; SetCaps was called → Caps;
// IsCustomRoleID(RoleID) without SetCaps → 0 (fail closed); else
// BuiltinCaps(Role, false). Principals built as literals without SetCaps
// (tests, the admin socket's --as before package A) therefore keep the
// permissions of their built-in role.
func (p *Principal) RoleCaps() CapSet {
	switch {
	case p == nil:
		return 0
	case p.Role.IsAdmin():
		return AllCaps
	case p.capsSet:
		return p.Caps
	case IsCustomRoleID(p.RoleID):
		return 0
	}
	return BuiltinCaps(p.Role, false)
}

// Can reports whether p may use c on this channel: nil or unknown c → false;
// the system principal → true; server capabilities need the admin scope on
// API tokens (HasScope); then RoleCaps().Has(c). Can does not look at the
// authentication level (the route guards do).
func (p *Principal) Can(c Capability) bool {
	switch {
	case p == nil || !c.Valid():
		return false
	case p.IsSystem():
		return true
	case c.Server() && !p.HasScope(ScopeAdmin):
		return false
	}
	return p.RoleCaps().Has(c)
}

// CanAny reports whether p may use at least one of cs (Can).
func (p *Principal) CanAny(cs ...Capability) bool {
	for _, c := range cs {
		if p.Can(c) {
			return true
		}
	}
	return false
}

// Staff reports whether the account is owner/admin/system or its role holds
// a server capability, ignoring token scopes (2FA policy, admin scope,
// elevated tokens).
func (p *Principal) Staff() bool {
	return p != nil && (p.Role.IsAdmin() || p.RoleCaps().Server() != 0)
}

// ServerAccess reports whether p can use at least one server capability on
// this channel (Me.Staff, SSE admin subscription): p.IsSystem() ||
// (p.Staff() && p.HasScope(ScopeAdmin)).
func (p *Principal) ServerAccess() bool {
	return p.IsSystem() || (p.Staff() && p.HasScope(ScopeAdmin))
}

// IsSystem reports whether this is the system principal (socket / offline CLI).
func (p *Principal) IsSystem() bool { return p != nil && p.Role == RoleSystem }

// Elevated reports whether the step-up window is open at now. The system
// principal is always elevated.
func (p *Principal) Elevated(now time.Time) bool {
	if p == nil {
		return false
	}
	if p.Role == RoleSystem {
		return true
	}
	return now.Before(p.ElevatedUntil)
}

// Full reports whether authentication is complete: AuthLevel 2 and no pending
// 2FA enrollment.
func (p *Principal) Full() bool {
	return p != nil && p.AuthLevel >= AuthLevelFull && !p.EnrollRequired
}

// HasScope reports whether the principal may use scope s. Only token
// principals are restricted; every other channel has all scopes.
func (p *Principal) HasScope(s string) bool {
	if p == nil {
		return false
	}
	if p.Via != ViaToken {
		return true
	}
	return slices.Contains(p.Scopes, s)
}

// Meta returns the request metadata carried by the principal.
func (p *Principal) Meta() ReqMeta {
	if p == nil {
		return ReqMeta{}
	}
	return ReqMeta{IP: p.IP, UserAgent: p.UserAgent, RequestID: p.RequestID}
}

// Clone returns a copy of p (Scopes copied).
func (p *Principal) Clone() *Principal {
	if p == nil {
		return nil
	}
	c := *p
	c.Scopes = slices.Clone(p.Scopes)
	return &c
}

// SystemPrincipal returns the all-powerful principal used by the admin socket
// (via = ViaSocket) and the in-process CLI (via = ViaOffline): role system
// (RoleID "system", RoleName "System", every capability), full auth level,
// always elevated, no user id, username "system".
func SystemPrincipal(via AuthVia) *Principal {
	p := &Principal{
		Username:  "system",
		Role:      RoleSystem,
		RoleID:    string(RoleSystem),
		RoleName:  BuiltinRoleName(RoleSystem),
		Via:       via,
		AuthLevel: AuthLevelFull,
		IP:        netip.IPv6Loopback(),
	}
	p.SetCaps(AllCaps)
	return p
}

type principalKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal stored in ctx, or nil (anonymous).
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

// ReqMeta is client metadata recorded with logins, audit entries and share access.
type ReqMeta struct {
	IP        netip.Addr
	UserAgent string
	RequestID string
	// Ingress is the Tailscale ingress the request came through: "" (a
	// direct connection), IngressFunnel or IngressServe (httpx.Meta).
	Ingress string
}
