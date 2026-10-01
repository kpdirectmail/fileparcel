package auth

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// sessionColumns is the column list scanned by scanSession.
const sessionColumns = `s.id, s.user_id, s.auth_level, COALESCE(s.mfa_method, ''), s.csrf_secret, s.remember,
	s.created_at, s.last_seen_at, s.idle_expires_at, s.expires_at, s.elevated_until,
	COALESCE(s.ip, ''), COALESCE(s.user_agent, ''), COALESCE(s.client_cert_serial, ''), s.revoked_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanSession(sc rowScanner, extra ...any) (*core.Session, error) {
	var (
		ss                           core.Session
		remember                     int64
		created, seen, idle, expires int64
		elevated, revoked            sql.NullInt64
	)
	dest := append([]any{&ss.ID, &ss.UserID, &ss.AuthLevel, &ss.MFAMethod, &ss.CSRFSecret, &remember,
		&created, &seen, &idle, &expires, &elevated, &ss.IP, &ss.UserAgent, &ss.ClientCertSerial, &revoked}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return nil, err
	}
	ss.Remember = remember != 0
	ss.CreatedAt, ss.LastSeenAt = db.FromMs(created), db.FromMs(seen)
	ss.IdleExpiresAt, ss.ExpiresAt = db.FromMs(idle), db.FromMs(expires)
	ss.ElevatedUntil, ss.RevokedAt = db.FromNullMs(elevated), db.FromNullMs(revoked)
	return &ss, nil
}

// live reports whether the session is usable at now.
func live(ss *core.Session, now time.Time) bool {
	return ss.RevokedAt == nil && now.Before(ss.ExpiresAt) && now.Before(ss.IdleExpiresAt)
}

// csrfFor computes the CSRF token of a session (DESIGN §9.3).
func csrfFor(secret []byte, sessionID string) string {
	if len(secret) == 0 || sessionID == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(crypt.HMACRaw(secret, []byte(sessionID)))
}

// validSessionToken checks the shape of a cookie value before any lookup.
func validSessionToken(tok string) bool {
	return len(tok) == ids.TokenLen(sessionTokenBytes) && ids.ValidToken(tok)
}

// setLifetimes computes idle/absolute expiry for a session at now.
func (s *Service) setLifetimes(ss *core.Session, now time.Time) {
	if ss.AuthLevel < core.AuthLevelFull {
		ss.ExpiresAt = now.Add(PendingTTL)
		ss.IdleExpiresAt = ss.ExpiresAt
		return
	}
	abs := BrowserSessionTTL
	if ss.Remember {
		abs = s.rememberTTL()
	}
	ss.ExpiresAt = now.Add(abs)
	ss.IdleExpiresAt = now.Add(s.idleTTL())
	if ss.IdleExpiresAt.After(ss.ExpiresAt) {
		ss.IdleExpiresAt = ss.ExpiresAt
	}
}

// cookieExpiry is the cookie expiry of a session: its absolute expiry for
// fully authenticated "remember me" sessions, else zero (browser session).
func cookieExpiry(ss *core.Session) time.Time {
	if ss.Remember && ss.AuthLevel >= core.AuthLevelFull {
		return ss.ExpiresAt
	}
	return time.Time{}
}

// sessionSpec describes a session to create.
type sessionSpec struct {
	userID   string
	level    int
	method   string
	remember bool
	meta     core.ReqMeta
}

// insertSession creates a session row inside tx and returns it with its
// token.
func (s *Service) insertSession(ctx context.Context, tx *sql.Tx, spec sessionSpec, now time.Time) (*core.Session, string, error) {
	token := ids.Token(sessionTokenBytes)
	ss := &core.Session{
		ID: ids.New(ids.PrefixSession), UserID: spec.userID, AuthLevel: spec.level, MFAMethod: spec.method,
		CSRFSecret: crypt.RandomBytes(csrfSecretBytes), Remember: spec.remember,
		CreatedAt: now, LastSeenAt: now, UserAgent: clip(spec.meta.UserAgent, maxUserAgent),
	}
	if spec.meta.IP.IsValid() {
		ss.IP = spec.meta.IP.Unmap().String()
	}
	s.setLifetimes(ss, now)
	_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id, token_hash, user_id, auth_level, mfa_method, csrf_secret,
		remember, created_at, last_seen_at, idle_expires_at, expires_at, ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ss.ID, ids.HashToken(token), ss.UserID, ss.AuthLevel, db.NullString(ss.MFAMethod), ss.CSRFSecret,
		db.Bool(ss.Remember), db.Ms(now), db.Ms(now), db.Ms(ss.IdleExpiresAt), db.Ms(ss.ExpiresAt),
		db.NullString(ss.IP), db.NullString(ss.UserAgent))
	if err != nil {
		return nil, "", err
	}
	return ss, token, nil
}

// revokePrevious revokes the session the request came with (if any) when a
// new session replaces it (login, setup, passwordless passkey login).
func revokePrevious(ctx context.Context, tx *sql.Tx, prev *core.Principal, now time.Time) (string, error) {
	if prev == nil || prev.Via != core.ViaSession || prev.SessionID == "" {
		return "", nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		db.Ms(now), prev.SessionID)
	return prev.SessionID, err
}

// loginResult builds the result of a completed or pending login.
func loginResult(u *core.User, ss *core.Session, token string) *core.LoginResult {
	res := &core.LoginResult{
		CSRF:          csrfFor(ss.CSRFSecret, ss.ID),
		Token:         token,
		CookieExpires: cookieExpiry(ss),
		Session:       ss,
	}
	if ss.AuthLevel >= core.AuthLevelFull {
		res.User = u
		res.MustChangePassword = u.MustChangePassword
	}
	return res
}

// ---------- CSRF ----------

func (s *Service) cacheCSRF(sessionID, userID string, secret []byte) {
	if sessionID == "" || len(secret) == 0 {
		return
	}
	s.csrfMu.Lock()
	defer s.csrfMu.Unlock()
	if len(s.csrf) >= maxCSRFCache {
		clear(s.csrf)
	}
	s.csrf[sessionID] = csrfEntry{userID: userID, secret: secret}
}

func (s *Service) dropCSRF(sessionIDs ...string) {
	s.csrfMu.Lock()
	defer s.csrfMu.Unlock()
	for _, id := range sessionIDs {
		delete(s.csrf, id)
	}
}

// dropUserCSRF forgets the cached secrets of every session of userID except keep.
func (s *Service) dropUserCSRF(userID, keep string) {
	s.csrfMu.Lock()
	defer s.csrfMu.Unlock()
	for id, e := range s.csrf {
		if e.userID == userID && id != keep {
			delete(s.csrf, id)
		}
	}
}

// csrfSecret returns the CSRF secret of a live session (cache, then DB).
func (s *Service) csrfSecret(ctx context.Context, sessionID string) []byte {
	s.csrfMu.Lock()
	e, ok := s.csrf[sessionID]
	s.csrfMu.Unlock()
	if ok {
		return e.secret
	}
	var secret []byte
	var userID string
	err := s.env.DB.QueryRow(ctx, `SELECT csrf_secret, user_id FROM sessions WHERE id = ? AND revoked_at IS NULL`,
		sessionID).Scan(&secret, &userID)
	if err != nil {
		if !db.IsNoRows(err) {
			s.log.Warn("csrf secret lookup failed", "err", err)
		}
		return nil
	}
	s.cacheCSRF(sessionID, userID, secret)
	return secret
}

// CSRFToken implements core.Auth: base64url(HMAC-SHA256(csrf_secret,
// session id)) for session principals, "" otherwise.
func (s *Service) CSRFToken(p *core.Principal) string {
	if p == nil || p.Via != core.ViaSession || p.SessionID == "" {
		return ""
	}
	return csrfFor(s.csrfSecret(context.Background(), p.SessionID), p.SessionID)
}

// CheckCSRF implements core.Auth (constant-time comparison).
func (s *Service) CheckCSRF(p *core.Principal, token string) bool {
	want := s.CSRFToken(p)
	if want == "" || token == "" {
		return false
	}
	return hmac.Equal([]byte(want), []byte(token))
}

// ---------- cookies ----------

// SessionCookie implements core.Auth: the __Host-fp_session cookie (Secure,
// HttpOnly, SameSite=Lax, Path=/). A zero exp makes a browser-session
// cookie; an empty token makes a cookie that deletes the session cookie.
func (s *Service) SessionCookie(token string, exp time.Time) *http.Cookie {
	c := &http.Cookie{Name: CookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	switch {
	case token == "":
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0).UTC()
	case !exp.IsZero():
		c.Expires = exp.UTC()
		c.MaxAge = max(1, int(exp.Sub(s.now())/time.Second))
	}
	return c
}

// ---------- authentication ----------

// Authenticate implements core.Auth. It returns, in this order:
//   - the trusted in-process principal already in the request context
//     (admin socket / offline CLI) unchanged;
//   - the principal of a valid "Authorization: Bearer fpt_…" token
//     (an invalid, expired or revoked fpt_ token is ErrUnauthorized);
//   - the principal of a valid session cookie; a missing, malformed,
//     expired or revoked cookie means anonymous (nil, nil).
//
// Any other Authorization header — another scheme, or a Bearer value that
// is not an fpt_ token — is not a FileParcel credential and is ignored: a
// reverse proxy with an outer Basic-auth gate (whose credentials browsers
// then attach to every request) or one that forwards its own bearer token
// must not sign every cookie session out.
func (s *Service) Authenticate(r *http.Request) (*core.Principal, error) {
	if p := core.PrincipalFrom(r.Context()); p != nil && (p.Via == core.ViaSocket || p.Via == core.ViaOffline) {
		return p.Clone(), nil
	}
	if h := strings.TrimSpace(r.Header.Get("Authorization")); h != "" {
		if scheme, cred, _ := strings.Cut(h, " "); strings.EqualFold(scheme, "Bearer") &&
			strings.HasPrefix(strings.TrimSpace(cred), TokenPrefix) {
			p, err := s.authenticateToken(r, h)
			if p != nil {
				s.applyIngress(r, p)
			}
			return p, err
		}
	}
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	p, err := s.authenticateSession(r.Context(), c.Value)
	if err != nil || p == nil {
		return nil, err
	}
	p.IP = s.clientIP(r)
	p.UserAgent = r.UserAgent()
	s.applyIngress(r, p)
	return p, nil
}

func (s *Service) authenticateSession(ctx context.Context, token string) (*core.Principal, error) {
	if !validSessionToken(token) {
		return nil, nil
	}
	var username, role, status string
	var hasMFA, mustChange bool
	var roleID, roleName, perms sql.NullString
	row := s.env.DB.QueryRow(ctx, `SELECT `+sessionColumns+`, u.username, u.role, u.status, u.must_change_password,
		(EXISTS (SELECT 1 FROM totp_secrets ts WHERE ts.user_id = u.id AND ts.confirmed_at IS NOT NULL)
		 OR EXISTS (SELECT 1 FROM webauthn_credentials wc WHERE wc.user_id = u.id)), `+principalRoleCols+`
		FROM sessions s JOIN users u ON u.id = s.user_id`+principalRoleJoin+` WHERE s.token_hash = ?`, ids.HashToken(token))
	ss, err := scanSession(row, &username, &role, &status, &mustChange, &hasMFA, &roleID, &roleName, &perms)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	now := s.now()
	if !live(ss, now) || status != core.UserActive {
		return nil, nil
	}
	s.cacheCSRF(ss.ID, ss.UserID, ss.CSRFSecret)
	if ss.AuthLevel >= core.AuthLevelFull && now.Sub(ss.LastSeenAt) >= touchInterval {
		s.touchSession(ctx, ss, now)
	}
	p := &core.Principal{
		UserID: ss.UserID, Username: username, Role: core.Role(role), Via: core.ViaSession,
		SessionID: ss.ID, AuthLevel: ss.AuthLevel, ClientCertSerial: ss.ClientCertSerial,
	}
	s.setRoleCaps(p, roleID, roleName, perms)
	if ss.ElevatedUntil != nil {
		p.ElevatedUntil = *ss.ElevatedUntil
	}
	p.EnrollRequired = p.AuthLevel >= core.AuthLevelFull && !hasMFA && s.requires2FA(p.Role, p.RoleCaps())
	// Read on every request, so the gate lifts with the password change
	// (SetPasswordHash clears the column). Tokens are not gated: an admin
	// reset revokes them, and a session in this state cannot mint new ones.
	p.MustChangePassword = p.AuthLevel >= core.AuthLevelFull && mustChange
	return p, nil
}

// touchSession records activity (throttled by the caller to once a minute)
// and extends the idle expiry. Failures are logged, never fatal.
func (s *Service) touchSession(ctx context.Context, ss *core.Session, now time.Time) {
	idle := now.Add(s.idleTTL())
	if idle.After(ss.ExpiresAt) {
		idle = ss.ExpiresAt
	}
	_, err := s.env.DB.Exec(ctx, `UPDATE sessions SET last_seen_at = ?, idle_expires_at = ?
		WHERE id = ? AND revoked_at IS NULL AND last_seen_at < ?`,
		db.Ms(now), db.Ms(idle), ss.ID, db.Ms(now.Add(-touchInterval/2)))
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Warn("session touch failed", "session", ss.ID, "err", err)
	}
}

// ---------- rotation ----------

// RotateSession gives the session of p a new token (the CSRF token stays
// the same) and returns the result to set as cookie: Token, CookieExpires,
// CSRF and Session. It is called by the web layer after Elevate and
// ChangePassword (DESIGN §9.3 "token rotated on … elevation and password
// change"); core.Auth has no way to return the new token from those
// methods. Non-session principals yield (nil, nil).
func (s *Service) RotateSession(ctx context.Context, p *core.Principal) (*core.LoginResult, error) {
	if p == nil || p.Via != core.ViaSession || p.SessionID == "" {
		return nil, nil
	}
	now := s.now()
	token := ids.Token(sessionTokenBytes)
	var ss *core.Session
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		ss, err = scanSession(tx.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions s WHERE s.id = ?`, p.SessionID))
		if err != nil {
			if db.IsNoRows(err) {
				return errSignInExpired
			}
			return err
		}
		if !live(ss, now) || ss.UserID != p.UserID {
			return errSignInExpired
		}
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET token_hash = ? WHERE id = ?`, ids.HashToken(token), ss.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.cacheCSRF(ss.ID, ss.UserID, ss.CSRFSecret)
	return &core.LoginResult{CSRF: csrfFor(ss.CSRFSecret, ss.ID), Token: token, CookieExpires: cookieExpiry(ss), Session: ss}, nil
}

// ---------- logout & session management ----------

// Logout implements core.Auth: revokes the session of p (no-op for other
// principals).
func (s *Service) Logout(ctx context.Context, p *core.Principal) error {
	if p == nil || p.Via != core.ViaSession || p.SessionID == "" {
		return nil
	}
	now := s.now()
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, db.Ms(now), p.SessionID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActAuthLogout, TargetType: "session", TargetID: p.SessionID})
	})
	s.dropCSRF(p.SessionID)
	return err
}

// ListSessions implements core.Auth: the live sessions of userID, most
// recently active first. Session.Current marks the session of the context
// principal.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]core.Session, error) {
	now := db.Ms(s.now())
	rows, err := s.env.DB.Query(ctx, `SELECT `+sessionColumns+` FROM sessions s
		WHERE s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.idle_expires_at > ?
		ORDER BY s.last_seen_at DESC, s.id DESC LIMIT 1000`, userID, now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cur string
	if p := core.PrincipalFrom(ctx); p != nil && p.Via == core.ViaSession {
		cur = p.SessionID
	}
	out := []core.Session{}
	for rows.Next() {
		ss, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		ss.CSRFSecret = nil
		ss.Current = ss.ID == cur
		out = append(out, *ss)
	}
	return out, rows.Err()
}

// RevokeSession implements core.Auth. by must be the user or may manage
// their credentials (authorizeFor); a session that does not belong to
// userID is ErrNotFound.
func (s *Service) RevokeSession(ctx context.Context, by *core.Principal, userID, sessionID string) error {
	if err := s.authorizeFor(ctx, by, userID, core.ActSessionRevoke); err != nil {
		return err
	}
	now := s.now()
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
			db.Ms(now), sessionID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return core.NotFoundf("session not found")
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActSessionRevoke, TargetType: "session", TargetID: sessionID,
			Details: map[string]any{"user_id": userID}})
	})
	if err != nil {
		return err
	}
	s.dropCSRF(sessionID)
	return nil
}

// RevokeAllSessions implements core.Auth: revokes every session of userID
// except exceptID ("" = all).
func (s *Service) RevokeAllSessions(ctx context.Context, by *core.Principal, userID, exceptID string) error {
	if err := s.authorizeFor(ctx, by, userID, core.ActSessionRevoke); err != nil {
		return err
	}
	now := s.now()
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		n, err := revokeUserSessions(ctx, tx, userID, exceptID, now)
		if err != nil || n == 0 {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActSessionRevoke, TargetType: "user", TargetID: userID,
			Details: map[string]any{"count": n, "all": true, "kept_current": exceptID != ""}})
	})
	if err != nil {
		return err
	}
	s.dropUserCSRF(userID, exceptID)
	return nil
}

// revokeUserSessions revokes the live sessions of userID except exceptID.
func revokeUserSessions(ctx context.Context, tx *sql.Tx, userID, exceptID string, now time.Time) (int64, error) {
	res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ? AND revoked_at IS NULL`,
		db.Ms(now), userID, exceptID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
