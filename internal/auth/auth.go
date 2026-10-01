// Package auth implements passwords (argon2id via crypt), sessions, lockout,
// TOTP, recovery codes, WebAuthn passkeys, API tokens, CSRF tokens, step-up
// elevation and the first-run setup token (DESIGN §9.3). Owned by unit B.
//
// # Sessions
//
// A browser session is a row of the sessions table; the cookie
// __Host-fp_session carries 32 random bytes (base62) and the table stores only
// SHA-256 of it. A session starts at AuthLevel 1 when the account has a second
// factor (10 minutes to complete it) and at AuthLevel 2 otherwise. The token
// is rotated when the second factor completes, on step-up elevation and on a
// password change (see RotateSession). Idle expiry is auth.session_idle_min;
// the absolute lifetime is auth.session_max_days for "remember me" sessions
// and 24 hours (with a browser-session cookie) otherwise. last_seen_at is
// written at most once a minute.
//
// # CSRF
//
// CSRFToken is base64url(HMAC-SHA256(sessions.csrf_secret, session id)); the
// secret is cached in memory per session.
//
// # API tokens
//
// Personal access tokens look like fpt_<token id suffix>_<secret> and are sent
// as "Authorization: Bearer …". The table stores SHA-256 of the whole token.
//
// # Trusted in-process principals
//
// Requests from the admin socket and the in-process CLI carry a system
// principal in their context before authentication; Authenticate returns it
// unchanged (mw.Authenticate implements X-FP-As on top of it).
//
// # RotateSession and RPID
//
// Both are part of core.Auth (DESIGN §5.1b) and the web packages call them
// straight through the interface. RotateSession exists because Elevate and
// ChangePassword cannot return the rotated session token, so the handler has
// to ask for it separately to re-set the cookie; RPID reports the effective
// WebAuthn relying-party ID for GET /auth/state.
//
// # Service methods outside core.Auth
//
// EnsureRecoveryCodes (the first passkey of an account mints recovery codes,
// so a passkey is never the only way in) and PasskeyOnlyAccounts (how many
// accounts turning auth.passkeys off would strand) are not in core.Auth;
// meapi reaches EnsureRecoveryCodes through a small interface of its own.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/ratelimit"
)

// Cookie, token and lifetime constants (DESIGN §9.3).
const (
	// CookieName is the session cookie. The __Host- prefix makes browsers
	// insist on Secure, Path=/ and no Domain attribute.
	CookieName = "__Host-fp_session"
	// TokenPrefix starts every personal access token: fpt_<id suffix>_<secret>.
	TokenPrefix = "fpt_"
	// MaxPasswordBytes bounds passwords (argon2 input); longer inputs are
	// refused before any hashing.
	MaxPasswordBytes = 1024
	// RecoveryCodeCount is the number of recovery codes generated at once.
	RecoveryCodeCount = 10
	// PendingTTL is how long a password-only (AuthLevel 1) session has to
	// complete the second factor.
	PendingTTL = 10 * time.Minute
	// BrowserSessionTTL is the absolute lifetime of sessions created without
	// "remember me" (their cookie is a browser-session cookie).
	BrowserSessionTTL = 24 * time.Hour
	// FlowTTL is the lifetime of a pending WebAuthn ceremony.
	FlowTTL = 5 * time.Minute
	// MaxElevatedTokenTTL is the longest lifetime of an --elevated API token.
	MaxElevatedTokenTTL = 30 * 24 * time.Hour
	// elevatedExpirySkew is how far past MaxElevatedTokenTTL a requested
	// expiry may lie and still be clamped to it rather than refused: the web
	// UI asks for exactly "30 days from now" by the browser's clock.
	elevatedExpirySkew = 5 * time.Minute

	sessionTokenBytes = 32 // 43 base62 characters
	apiSecretBytes    = 32
	csrfSecretBytes   = 32
	touchInterval     = time.Minute // last_seen_at / last_used_at write throttle
	maxFlows          = 10_000
	maxCSRFCache      = 50_000
	maxNameRunes      = 64
	maxUserAgent      = 512

	// bucketFail is the limiter bucket counting failed authentication
	// attempts per client IP (password, second factor, passkey, elevation,
	// password change, setup token). It allows ratelimit.login_per_min
	// failures per minute; the HTTP layer additionally limits the request
	// rate of the login routes with the "login" bucket.
	bucketFail = "auth_fail"

	metaSetupToken = "setup_token_hash"
)

// Errors shared by several flows. They are uniform on purpose (DESIGN §9.3).
var (
	errInvalidCredentials = core.Errorf(core.ErrUnauthorized, "invalid username or password")
	// errFunnelCredentials replaces errInvalidCredentials over Tailscale Funnel while funnel.require_2fa is on
	// (badCredentials): the same answer for every failed password sign-in there, naming the missing second factor.
	errFunnelCredentials = core.Errorf(core.ErrUnauthorized, "invalid username or password, or the account has no "+
		"two-factor authentication yet: over this internet address only accounts with two-factor authentication can "+
		"sign in (sign in once at your home or VPN address and set it up under Settings → Security)")
	errSignInExpired = core.Errorf(core.ErrUnauthorized, "your sign-in expired; please sign in again")
	errBadToken      = core.Errorf(core.ErrUnauthorized, "invalid or expired API token")
	errPasskeyFailed = core.Errorf(core.ErrUnauthorized, "the passkey could not be verified")
	errNotPending    = core.Errorf(core.ErrConflict, "there is no pending second-factor step for this session")
)

// Service implements core.Auth.
type Service struct {
	env     *core.Env
	users   core.Users
	limiter *ratelimit.Registry
	log     *slog.Logger

	csrfMu sync.Mutex
	csrf   map[string]csrfEntry // session id → secret (cache of sessions.csrf_secret)

	failMu   sync.Mutex
	failRate int64 // failures per minute currently configured for bucketFail

	flowMu    sync.Mutex
	flows     map[string]*flow // pending WebAuthn ceremonies
	flowSweep time.Time        // last sweep of expired flows

	waMu  sync.Mutex
	wa    *webAuthnConfig
	waKey string

	mdns atomic.Pointer[mdnsRef] // late-bound (Bind); effective .local name
}

type csrfEntry struct {
	userID string
	secret []byte
}

// mdnsRef wraps the late-bound mDNS service (Bind).
type mdnsRef struct{ m core.MDNS }

var (
	_ core.Auth   = (*Service)(nil)
	_ core.Binder = (*Service)(nil)
)

// Bind picks up the mDNS service so that the WebAuthn RP ID follows the
// effective (collision-renamed) .local name, exactly like the certificate
// SANs do (netinfo.mdnsName → certs). Without it a rename to
// fileparcel-2.local would leave the RP ID naming a host the leaf no longer
// covers, and every passkey ceremony would fail in the browser.
func (s *Service) Bind(reg *core.Services) error {
	if reg != nil && reg.MDNS != nil {
		s.mdns.Store(&mdnsRef{m: reg.MDNS})
	}
	return nil
}

// New creates the service (constructor signature fixed by DESIGN §5.2).
// env.DB is required; env.Keys, env.Settings and env.Audit are read at call
// time (settings fall back to their registered defaults when nil). limiter
// may be nil (no failure throttling).
func New(env *core.Env, users core.Users, limiter *ratelimit.Registry) (*Service, error) {
	if env == nil || env.DB == nil {
		return nil, errors.New("auth: an environment with a database is required")
	}
	if users == nil {
		return nil, errors.New("auth: the users service is required")
	}
	log := env.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		env:     env,
		users:   users,
		limiter: limiter,
		log:     log.With("svc", "auth"),
		csrf:    map[string]csrfEntry{},
		flows:   map[string]*flow{},
	}
	s.configureFailBucket()
	return s, nil
}

// ---------- passwords ----------

// HashPassword implements core.Auth: an argon2id PHC string with
// crypt.PasswordParams. Passwords longer than MaxPasswordBytes are refused.
func (s *Service) HashPassword(pw string) (string, error) {
	if pw == "" {
		return "", core.Invalid("password", "password required")
	}
	if len(pw) > MaxPasswordBytes {
		return "", core.Invalid("password", "password too long")
	}
	return crypt.HashPassword(pw)
}

// VerifyPassword implements core.Auth. An empty or malformed hash never
// verifies, but still costs one argon2 computation (timing equalization).
func (s *Service) VerifyPassword(phc, pw string) (ok bool, needsRehash bool) {
	if len(pw) > MaxPasswordBytes {
		return false, false
	}
	if phc == "" {
		crypt.VerifyDummy(pw)
		return false, false
	}
	if _, err := crypt.ParsePHC(phc); err != nil {
		crypt.VerifyDummy(pw)
		return false, false
	}
	return crypt.VerifyPassword(phc, pw)
}

// verifyPasswordCtx is VerifyPassword for the sign-in request: it gives up
// when ctx ends and fails fast when too many argon2 checks are queued
// (crypt.VerifyPasswordContext; a 503 then). A non-nil err means the
// password was not checked, so it must never count as a failed attempt.
func (s *Service) verifyPasswordCtx(ctx context.Context, phc, pw string) (ok, needsRehash bool, err error) {
	if len(pw) > MaxPasswordBytes {
		return false, false, nil
	}
	if phc == "" {
		err = crypt.VerifyDummyContext(ctx, pw)
	} else if _, perr := crypt.ParsePHC(phc); perr != nil {
		err = crypt.VerifyDummyContext(ctx, pw)
	} else {
		ok, needsRehash, err = crypt.VerifyPasswordContext(ctx, phc, pw)
	}
	if errors.Is(err, crypt.ErrArgonBusy) {
		err = core.Errorf(core.ErrUnavailable, "the server is busy checking passwords; try again in a moment")
	}
	return ok, needsRehash, err
}

// ---------- settings ----------

func (s *Service) now() time.Time { return s.env.Now() }

// settingInt returns a positive int setting, or def.
func (s *Service) settingInt(key string, def int64) int64 {
	if s.env.Settings == nil {
		return def
	}
	if v := s.env.Settings.Int(key); v > 0 {
		return v
	}
	return def
}

// settingString returns a string setting ("" when unset or unknown).
func (s *Service) settingString(key string) string {
	if s.env.Settings == nil {
		return ""
	}
	return strings.TrimSpace(s.env.Settings.String(key))
}

// settingBool returns a bool setting, or def when it is not registered.
func (s *Service) settingBool(key string, def bool) bool {
	if s.env.Settings == nil {
		return def
	}
	if _, err := s.env.Settings.Raw(key); err != nil {
		return def
	}
	return s.env.Settings.Bool(key)
}

func (s *Service) idleTTL() time.Duration {
	return time.Duration(s.settingInt("auth.session_idle_min", DefaultSessionIdleMin)) * time.Minute
}

func (s *Service) rememberTTL() time.Duration {
	return time.Duration(s.settingInt("auth.session_max_days", DefaultSessionMaxDays)) * 24 * time.Hour
}

func (s *Service) stepUpTTL() time.Duration {
	return time.Duration(s.settingInt("auth.stepup_min", DefaultStepUpMin)) * time.Minute
}

func (s *Service) passkeysEnabled() bool { return s.settingBool("auth.passkeys", true) }

// requires2FA applies auth.require_2fa (off|admins|all) to an account with
// the built-in base role and the role capabilities caps (the account's role
// set, not token-filtered): "admins" covers owners, admins and every role
// with a server permission (staff).
func (s *Service) requires2FA(role core.Role, caps core.CapSet) bool {
	switch s.settingString("auth.require_2fa") {
	case Require2FAOff:
		return false
	case Require2FAAll:
		return true
	default: // admins (the default)
		return role.IsAdmin() || caps.Server() != 0
	}
}

// instanceName is ui.instance_name (the WebAuthn RP name and TOTP issuer).
func (s *Service) instanceName() string {
	if n := s.settingString("ui.instance_name"); n != "" {
		return n
	}
	return "FileParcel"
}

// ---------- failure throttling ----------

// configureFailBucket (re)configures bucketFail from ratelimit.login_per_min
// when the setting changed.
func (s *Service) configureFailBucket() {
	if s.limiter == nil {
		return
	}
	rate := s.settingInt("ratelimit.login_per_min", ratelimit.DefaultLoginPerMin)
	s.failMu.Lock()
	defer s.failMu.Unlock()
	if rate == s.failRate {
		return
	}
	s.failRate = rate
	s.limiter.Configure(bucketFail, float64(rate), int(rate))
}

func ipKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return "unknown"
	}
	return ip.Unmap().String()
}

// failAllowed reports whether ip may make another authentication attempt
// (it has failures left in bucketFail). It consumes nothing.
func (s *Service) failAllowed(ip netip.Addr) error {
	if s.limiter == nil {
		return nil
	}
	s.configureFailBucket()
	if s.limiter.Tokens(bucketFail, ipKey(ip)) < 1 {
		return core.Errorf(core.ErrRateLimited, "too many failed attempts; wait a minute and try again")
	}
	return nil
}

// failed records a failed authentication attempt of ip.
func (s *Service) failed(ip netip.Addr) {
	if s.limiter == nil {
		return
	}
	s.limiter.Allow(bucketFail, ipKey(ip))
}

// ---------- audit ----------

// record writes an audit entry outside any transaction.
func (s *Service) record(ctx context.Context, e core.AuditEntry) {
	if s.env.Audit != nil {
		s.env.Audit.Record(ctx, e)
	}
}

// recordTx writes an audit entry inside tx.
func (s *Service) recordTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	if s.env.Audit == nil {
		return nil
	}
	return s.env.Audit.RecordTx(ctx, tx, e)
}

// withMeta fills the client fields of e from meta (for anonymous flows
// where the context carries no principal).
func withMeta(e core.AuditEntry, meta core.ReqMeta) core.AuditEntry {
	if e.IP == "" && meta.IP.IsValid() {
		e.IP = meta.IP.String()
	}
	if e.UserAgent == "" {
		e.UserAgent = clip(meta.UserAgent, maxUserAgent)
	}
	if e.RequestID == "" {
		e.RequestID = meta.RequestID
	}
	return e
}

// asUser sets the actor of e to u (logins, where ctx has no principal yet).
func asUser(e core.AuditEntry, u *core.User, via core.AuthVia) core.AuditEntry {
	if u != nil {
		e.ActorID, e.ActorName = u.ID, u.Username
		if e.TargetType == "" {
			e.TargetType, e.TargetID, e.TargetName = "user", u.ID, u.Username
		}
	}
	if e.ActorVia == "" {
		e.ActorVia = string(via)
	}
	return e
}

// ---------- users ----------

// activeUser returns an active user by id. Missing or disabled users are
// ErrUnauthorized (their credentials no longer count).
func (s *Service) activeUser(ctx context.Context, id string) (*core.User, error) {
	if id == "" {
		return nil, core.ErrUnauthorized
	}
	u, err := s.users.Get(ctx, id)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, core.ErrUnauthorized
		}
		return nil, err
	}
	if u.Status != core.UserActive {
		return nil, core.ErrUnauthorized
	}
	return u, nil
}

// requireUser returns the active user behind a user principal.
func (s *Service) requireUser(ctx context.Context, p *core.Principal) (*core.User, error) {
	if p == nil {
		return nil, core.ErrUnauthorized
	}
	if p.UserID == "" {
		return nil, core.Errorf(core.ErrInvalid, "this action needs a user account (use --as USER on the admin socket)")
	}
	return s.activeUser(ctx, p.UserID)
}

// authorizeFor checks that by may manage the credentials (sessions, second
// factors, passkeys, API tokens, password) of userID: the user themselves,
// the system principal, or a holder of users.credentials (API tokens need
// the admin scope) who may manage the account under core.CheckManage — only
// an owner touches an owner's credentials, and a delegate only those of the
// accounts their role may manage. A refusal by the escalation rules is
// audited as action with outcome denied. Failures are ErrForbidden
// (ErrNotFound for an unknown user).
func (s *Service) authorizeFor(ctx context.Context, by *core.Principal, userID, action string) error {
	switch {
	case by == nil:
		return core.ErrUnauthorized
	case userID == "":
		return core.ErrForbidden
	case by.UserID == userID || by.IsSystem():
		return nil
	case !by.Can(core.CapUsersCredentials):
		return core.ErrForbidden
	}
	target, err := s.users.Get(ctx, userID)
	if err != nil {
		return err
	}
	if err := core.CheckManage(by, target, core.CapUsersCredentials); err != nil {
		s.auditDenied(ctx, by, action, target, err)
		return err
	}
	return nil
}

// ownCredentialsOnly narrows by for the operations that address one passkey
// or API token by id (RenamePasskey, DeletePasskey, RevokeToken — the /me
// routes): over the network they act on the caller's own credentials only,
// administrators and delegates included, like DELETE /me/client-certs/{id}.
// Cross-user changes go through /admin/users (reset-mfa, password,
// disable), which also revoke the account's sessions and alert its owner.
// The admin socket and the offline CLI keep the rule of authorizeFor.
func ownCredentialsOnly(by *core.Principal) *core.Principal {
	if by == nil || by.Via == core.ViaSocket || by.Via == core.ViaOffline {
		return by
	}
	n := by.Clone()
	n.Role, n.RoleID = core.RoleMember, string(core.RoleMember)
	n.SetCaps(by.RoleCaps().Without(core.CapUsersCredentials))
	return n
}

// ---------- small helpers ----------

// clip truncates s to max bytes at a rune boundary.
func clip(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// cleanName validates a user-chosen label (passkey and token names):
// trimmed, 1..maxNameRunes runes, no control characters.
func cleanName(field, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", core.Invalid(field, "a name is required")
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxNameRunes {
		return "", core.Invalid(field, "names are limited to 64 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", core.Invalid(field, "names must not contain control characters")
		}
	}
	return name, nil
}

// clientIP returns the client address of r: the address a Tailscale
// ingress listener validated (core.IngressFrom), else the direct peer, or —
// when the peer is a trusted proxy (server.trusted_proxies) — the
// right-most X-Forwarded-For hop that is not itself trusted (same rule as
// mw).
func (s *Service) clientIP(r *http.Request) netip.Addr {
	if in := core.IngressFrom(r.Context()); in != nil && in.ClientIP.IsValid() {
		return in.ClientIP.Unmap().WithZone("")
	}
	peer := remoteIP(r.RemoteAddr)
	trusted := s.trustedProxies()
	if len(trusted) == 0 || !inPrefixes(peer, trusted) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	ip := peer
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		a, err := netip.ParseAddr(strings.Trim(h, "[]"))
		if err != nil {
			ap, err2 := netip.ParseAddrPort(h)
			if err2 != nil {
				break
			}
			a = ap.Addr()
		}
		ip = a.Unmap().WithZone("")
		if !inPrefixes(ip, trusted) {
			break
		}
	}
	return ip
}

func (s *Service) trustedProxies() []netip.Prefix {
	var src []string
	if s.env.Settings != nil {
		if _, err := s.env.Settings.Raw("server.trusted_proxies"); err == nil {
			src = s.env.Settings.Strings("server.trusted_proxies")
		}
	}
	if src == nil && s.env.Config != nil {
		src = s.env.Config.Server.TrustedProxies
	}
	out := make([]netip.Prefix, 0, len(src))
	for _, v := range src {
		v = strings.TrimSpace(v)
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(v); err == nil {
			a = a.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func inPrefixes(ip netip.Addr, list []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteIP parses an http.Request.RemoteAddr; unparseable addresses (Unix
// sockets, in-process transports) are the IPv6 loopback.
func remoteIP(addr string) netip.Addr {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if a, err := netip.ParseAddr(strings.Trim(addr, "[]")); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.IPv6Loopback()
}
