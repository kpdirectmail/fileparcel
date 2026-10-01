package auth

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// mfaInfo summarises the second factors of a user.
type mfaInfo struct {
	totp         bool // confirmed TOTP secret
	totpPending  bool // begun, not confirmed
	recoveryLeft int
	passkeys     int
}

func (m mfaInfo) enabled() bool { return m.totp || m.passkeys > 0 }

// loadMFA reads the second factors of userID.
func (s *Service) loadMFA(ctx context.Context, userID string) (mfaInfo, error) {
	var m mfaInfo
	err := s.env.DB.Read(ctx, func(tx *sql.Tx) error {
		var confirmed sql.NullInt64
		switch err := tx.QueryRowContext(ctx, `SELECT confirmed_at FROM totp_secrets WHERE user_id = ?`, userID).Scan(&confirmed); {
		case err == nil:
			m.totp, m.totpPending = confirmed.Valid, !confirmed.Valid
		case !db.IsNoRows(err):
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`,
			userID).Scan(&m.recoveryLeft); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&m.passkeys)
	})
	return m, err
}

// methods lists the second-factor methods usable to complete a login.
func (s *Service) methods(m mfaInfo) []string {
	var out []string
	if m.totp {
		out = append(out, core.MFATOTP)
	}
	if m.recoveryLeft > 0 {
		out = append(out, core.MFARecovery)
	}
	if m.passkeys > 0 && s.passkeysEnabled() {
		out = append(out, core.MFAPasskey)
	}
	return out
}

// Login implements core.Auth: username + password. Unknown users, wrong
// passwords, locked and disabled accounts all get the same 401 "invalid
// username or password" after the same argon2 work. Wrong passwords count
// towards the lockout (Users.RecordLoginFailure) and the per-IP failure
// limit. When the account has a second factor the session starts at
// AuthLevel 1 and the result has MFARequired and Methods. The session the
// request came with (ctx principal) is revoked.
func (s *Service) Login(ctx context.Context, in core.LoginInput, meta core.ReqMeta) (*core.LoginResult, error) {
	username := strings.TrimSpace(in.Username)
	fail := core.AuditEntry{Action: core.ActAuthLogin, Outcome: core.OutcomeFailure, ActorName: clip(username, 64),
		ActorVia: string(core.ViaSession), Details: map[string]any{"method": "password"}}
	if err := s.failAllowed(meta.IP); err != nil {
		return nil, err
	}
	if username == "" || in.Password == "" || len(in.Password) > MaxPasswordBytes || len(username) > 256 {
		s.failed(meta.IP)
		return nil, s.badCredentials(ctx, meta)
	}
	u, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			return nil, err
		}
		// Same cost as a real check, and busy exactly when a real one is.
		if _, _, err := s.verifyPasswordCtx(ctx, "", in.Password); err != nil {
			return nil, err
		}
		s.failed(meta.IP)
		fail.Details = map[string]any{"method": "password", "reason": "unknown_user"}
		s.record(ctx, withMeta(fail, meta))
		return nil, s.badCredentials(ctx, meta)
	}
	ok, rehash, err := s.verifyPasswordCtx(ctx, u.PasswordHash, in.Password)
	if err != nil {
		return nil, err // not checked (busy, or the client left): no failure counted
	}
	if err := s.funnelLogin(ctx, u, ok, in.AfterInvite, meta); err != nil {
		return nil, err
	}
	now := s.now()
	reason := ""
	switch {
	case u.Locked(now):
		reason = "locked"
	case !ok:
		reason = "bad_password"
	case u.Status != core.UserActive:
		reason = "disabled"
	}
	if reason != "" {
		s.failed(meta.IP)
		fail.ActorID, fail.TargetType, fail.TargetID, fail.TargetName = u.ID, "user", u.ID, u.Username
		details := map[string]any{"method": "password", "reason": reason}
		if reason == "bad_password" && u.Status == core.UserActive {
			if until := s.countFailure(ctx, u, meta); until != nil {
				details["locked_until"] = until.UTC()
			}
		}
		fail.Details = details
		s.record(ctx, withMeta(fail, meta))
		return nil, s.badCredentials(ctx, meta)
	}
	if rehash {
		s.rehash(ctx, u, in.Password)
	}
	m, err := s.loadMFA(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	level, methods := core.AuthLevelFull, []string(nil)
	if m.enabled() {
		level, methods = core.AuthLevelPassword, s.methods(m)
		if len(methods) == 0 {
			s.log.Warn("user has a second factor but no usable method (passkeys disabled?)", "user", u.ID)
		}
	}
	details := map[string]any{"method": "password", "mfa_pending": level < core.AuthLevelFull}
	if overFunnel(ctx, meta) {
		details["ingress"] = core.IngressFunnel
		if in.AfterInvite {
			details["after_invite"] = true // the Funnel two-factor rule's one exception (funnelLogin)
		}
	}
	res, err := s.startSession(ctx, u, sessionSpec{userID: u.ID, level: level, remember: in.Remember, meta: meta}, details, nil)
	if err != nil {
		return nil, err
	}
	if level < core.AuthLevelFull {
		res.MFARequired, res.Methods = true, methods
		return res, nil
	}
	// at full level the account has no second factor: over Funnel (only the sign-in after an invitation gets here
	// then) the session can only set one up (applyIngress), so say so
	res.EnrollRequired = s.requires2FA(u.Role, u.Permissions) || (overFunnel(ctx, meta) && s.funnelRequires2FA())
	return res, nil
}

// countFailure records a failed credential check against the account
// (Users.RecordLoginFailure: lockout after auth.lockout_threshold failures,
// base × 2^level). It returns the end of the lock when the account is
// locked now. The users service audits auth.lockout itself when a new lock
// starts, so it is not recorded twice here.
//
// The client address travels in meta: a brute-forced POST /auth/login comes
// from a signed-out browser, so there is no context principal and both the
// auth.lockout audit row and the "account locked" security e-mail would name
// no address — exactly the case they exist for. An existing principal is
// never replaced; on the Elevate and ChangePassword paths it is the real
// actor and carries the same address.
func (s *Service) countFailure(ctx context.Context, u *core.User, meta core.ReqMeta) *time.Time {
	if s.funnelFailure(ctx, u, meta) {
		return nil
	}
	if core.PrincipalFrom(ctx) == nil && (meta.IP.IsValid() || meta.UserAgent != "" || meta.RequestID != "") {
		ctx = core.WithPrincipal(ctx, &core.Principal{IP: meta.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID})
	}
	lockedUntil, err := s.users.RecordLoginFailure(ctx, u.ID)
	if err != nil {
		s.log.Warn("record login failure", "user", u.ID, "err", err)
		return nil
	}
	if lockedUntil != nil && lockedUntil.After(s.now()) {
		return lockedUntil
	}
	return nil
}

// rehash stores a fresh hash when the parameters changed. It only replaces
// the exact hash that was verified (no race with a concurrent change) and
// deliberately bypasses Users.SetPasswordHash, which would record a password
// change.
func (s *Service) rehash(ctx context.Context, u *core.User, pw string) {
	phc, err := s.HashPassword(pw)
	if err != nil {
		return
	}
	if _, err := s.env.DB.Exec(ctx, `UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?`,
		phc, u.ID, u.PasswordHash); err != nil {
		s.log.Warn("password rehash failed", "user", u.ID, "err", err)
	}
}

// startSession creates a session for u (revoking the session of the ctx
// principal), audits auth.login and, for full sessions, records the
// successful login. extra runs inside the same transaction.
func (s *Service) startSession(ctx context.Context, u *core.User, spec sessionSpec, details map[string]any,
	extra func(tx *sql.Tx) error) (*core.LoginResult, error) {
	now := s.now()
	prev := core.PrincipalFrom(ctx)
	var ss *core.Session
	var token, revoked string
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if extra != nil {
			if err := extra(tx); err != nil {
				return err
			}
		}
		var err error
		if revoked, err = revokePrevious(ctx, tx, prev, now); err != nil {
			return err
		}
		if ss, token, err = s.insertSession(ctx, tx, spec, now); err != nil {
			return err
		}
		e := asUser(core.AuditEntry{Action: core.ActAuthLogin, Details: details}, u, core.ViaSession)
		e.TargetType, e.TargetID, e.TargetName = "session", ss.ID, u.Username
		return s.recordTx(ctx, tx, withMeta(e, spec.meta))
	})
	if err != nil {
		return nil, err
	}
	if revoked != "" {
		s.dropCSRF(revoked)
	}
	s.cacheCSRF(ss.ID, ss.UserID, ss.CSRFSecret)
	if ss.AuthLevel >= core.AuthLevelFull {
		if err := s.users.RecordLoginSuccess(ctx, u.ID, spec.meta); err != nil {
			s.log.Warn("record login success", "user", u.ID, "err", err)
		}
	}
	return loginResult(u, ss, token), nil
}

// pendingUser checks that p is a password-only (AuthLevel 1) session and
// returns its active, unlocked user.
func (s *Service) pendingUser(ctx context.Context, p *core.Principal) (*core.User, error) {
	if p == nil || p.Via != core.ViaSession || p.SessionID == "" {
		return nil, errSignInExpired
	}
	if p.AuthLevel >= core.AuthLevelFull {
		return nil, errNotPending
	}
	u, err := s.activeUser(ctx, p.UserID)
	if err != nil {
		if errors.Is(err, core.ErrUnauthorized) {
			return nil, errSignInExpired
		}
		return nil, err
	}
	if u.Locked(s.now()) {
		return nil, errSignInExpired
	}
	return u, nil
}

// errFactorConsumed signals that a one-time factor (TOTP step, recovery
// code) was used concurrently.
var errFactorConsumed = errors.New("auth: factor already used")

// completeMFA upgrades the pending session of p to AuthLevel 2 with a new
// token and CSRF secret (DESIGN §9.3: rotation on login completion).
// consume runs first in the same transaction and marks the factor used.
func (s *Service) completeMFA(ctx context.Context, p *core.Principal, u *core.User, method string, meta core.ReqMeta,
	consume func(tx *sql.Tx) error) (*core.LoginResult, error) {
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
		if !live(ss, now) || ss.UserID != u.ID || ss.AuthLevel >= core.AuthLevelFull {
			return errSignInExpired
		}
		if consume != nil {
			if err := consume(tx); err != nil {
				return err
			}
		}
		ss.AuthLevel, ss.MFAMethod, ss.LastSeenAt = core.AuthLevelFull, method, now
		ss.CSRFSecret = randomSecret()
		s.setLifetimes(ss, now)
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET token_hash = ?, auth_level = ?, mfa_method = ?, csrf_secret = ?,
			last_seen_at = ?, idle_expires_at = ?, expires_at = ? WHERE id = ?`,
			ids.HashToken(token), ss.AuthLevel, method, ss.CSRFSecret, db.Ms(now), db.Ms(ss.IdleExpiresAt),
			db.Ms(ss.ExpiresAt), ss.ID); err != nil {
			return err
		}
		e := asUser(core.AuditEntry{Action: core.ActAuthMFA, Details: map[string]any{"method": method}}, u, core.ViaSession)
		return s.recordTx(ctx, tx, withMeta(e, meta))
	})
	if err != nil {
		return nil, err
	}
	s.cacheCSRF(ss.ID, ss.UserID, ss.CSRFSecret)
	if err := s.users.RecordLoginSuccess(ctx, u.ID, meta); err != nil {
		s.log.Warn("record login success", "user", u.ID, "err", err)
	}
	return loginResult(u, ss, token), nil
}

// mfaFailed handles a wrong second factor: failure limit, lockout counter,
// audit; a lockout also ends the pending session.
func (s *Service) mfaFailed(ctx context.Context, p *core.Principal, u *core.User, method string, meta core.ReqMeta) error {
	s.failed(meta.IP)
	s.record(ctx, withMeta(asUser(core.AuditEntry{Action: core.ActAuthMFA, Outcome: core.OutcomeFailure,
		Details: map[string]any{"method": method}}, u, core.ViaSession), meta))
	if s.countFailure(ctx, u, meta) != nil && p != nil && p.SessionID != "" {
		if _, err := s.env.DB.Exec(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
			db.Ms(s.now()), p.SessionID); err != nil {
			s.log.Warn("revoke pending session", "err", err)
		}
		s.dropCSRF(p.SessionID)
	}
	if method == core.MFARecovery {
		return core.Invalid("code", "that recovery code is not valid or was already used")
	}
	return core.Invalid("code", "that code is not valid; wait for the next code and try again")
}

// VerifyTOTP implements core.Auth: completes a pending login with an
// authenticator code (replayed time steps are rejected).
func (s *Service) VerifyTOTP(ctx context.Context, p *core.Principal, code string) (*core.LoginResult, error) {
	meta := p.Meta()
	u, err := s.pendingUser(ctx, p)
	if err != nil {
		return nil, err
	}
	if err := s.failAllowed(meta.IP); err != nil {
		return nil, err
	}
	step, ok, err := s.checkTOTP(ctx, u.ID, code, true)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, s.mfaFailed(ctx, p, u, core.MFATOTP, meta)
	}
	res, err := s.completeMFA(ctx, p, u, core.MFATOTP, meta, func(tx *sql.Tx) error { return consumeTOTPStep(ctx, tx, u.ID, step) })
	if errors.Is(err, errFactorConsumed) {
		return nil, s.mfaFailed(ctx, p, u, core.MFATOTP, meta)
	}
	return res, err
}

// VerifyRecovery implements core.Auth: completes a pending login with a
// single-use recovery code.
func (s *Service) VerifyRecovery(ctx context.Context, p *core.Principal, code string) (*core.LoginResult, error) {
	meta := p.Meta()
	u, err := s.pendingUser(ctx, p)
	if err != nil {
		return nil, err
	}
	if err := s.failAllowed(meta.IP); err != nil {
		return nil, err
	}
	id, err := s.matchRecovery(ctx, u.ID, code)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, s.mfaFailed(ctx, p, u, core.MFARecovery, meta)
	}
	res, err := s.completeMFA(ctx, p, u, core.MFARecovery, meta, func(tx *sql.Tx) error { return consumeRecovery(ctx, tx, id, s.now()) })
	if errors.Is(err, errFactorConsumed) {
		return nil, s.mfaFailed(ctx, p, u, core.MFARecovery, meta)
	}
	return res, err
}

// ---------- first-run setup ----------

// usersExist reports whether any account exists.
func (s *Service) usersExist(ctx context.Context) (bool, error) {
	var n int
	err := s.env.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&n)
	return n != 0, err
}

// SetupToken implements core.Auth: while no account exists it creates a new
// one-time setup token (replacing any previous one; only SHA-256 of it is
// stored in meta.setup_token_hash) for POST /auth/setup. The caller prints
// it. ErrConflict once an account exists.
func (s *Service) SetupToken(ctx context.Context) (string, error) {
	exist, err := s.usersExist(ctx)
	if err != nil {
		return "", err
	}
	if exist {
		return "", core.Errorf(core.ErrConflict, "setup was already completed")
	}
	tok := ids.Token(32)
	_, err = s.env.DB.Exec(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, metaSetupToken, hex.EncodeToString(ids.HashToken(tok)))
	if err != nil {
		return "", err
	}
	return tok, nil
}

// Setup implements core.Auth: creates the first owner account with the
// one-time setup token and signs it in. Only Username, DisplayName, Email and
// Password of in are used; the role is always owner. 409 once an account
// exists, 403 (field setup_token) for a wrong token.
func (s *Service) Setup(ctx context.Context, setupToken string, in core.NewUser, meta core.ReqMeta) (*core.LoginResult, error) {
	if err := s.failAllowed(meta.IP); err != nil {
		return nil, err
	}
	exist, err := s.usersExist(ctx)
	if err != nil {
		return nil, err
	}
	if exist {
		return nil, core.Errorf(core.ErrConflict, "setup was already completed; sign in instead")
	}
	var stored string
	switch err := s.env.DB.QueryRow(ctx, `SELECT value FROM meta WHERE key = ?`, metaSetupToken).Scan(&stored); {
	case db.IsNoRows(err):
	case err != nil:
		return nil, err
	}
	want, _ := hex.DecodeString(stored)
	got := ids.HashToken(strings.TrimSpace(setupToken))
	if len(want) == 0 || setupToken == "" || !ids.EqualBytes(want, got) {
		s.failed(meta.IP)
		s.record(ctx, withMeta(core.AuditEntry{Action: core.ActAuthSetup, Outcome: core.OutcomeFailure,
			ActorName: clip(strings.TrimSpace(in.Username), 64), Details: map[string]any{"reason": "bad_token"}}, meta))
		return nil, &core.Error{Code: core.ErrForbidden.Code, Status: core.ErrForbidden.Status,
			Message: "the setup token is not valid", Field: "setup_token"}
	}
	nu := core.NewUser{
		Username:    strings.TrimSpace(in.Username),
		DisplayName: strings.TrimSpace(in.DisplayName),
		Email:       strings.TrimSpace(in.Email),
		Role:        core.RoleOwner,
	}
	if nu.Username == "" {
		return nil, core.Invalid("username", "a username is required")
	}
	if err := s.CheckPasswordPolicy(in.Password, &core.User{Username: nu.Username, Email: nu.Email}); err != nil {
		return nil, err
	}
	if nu.PasswordHash, err = s.HashPassword(in.Password); err != nil {
		return nil, err
	}
	u, err := s.users.Bootstrap(ctx, nu)
	if err != nil {
		return nil, err
	}
	res, err := s.startSession(ctx, u, sessionSpec{userID: u.ID, level: core.AuthLevelFull, meta: meta},
		map[string]any{"method": "setup"}, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, metaSetupToken); err != nil {
				return err
			}
			return s.recordTx(ctx, tx, withMeta(asUser(core.AuditEntry{Action: core.ActAuthSetup}, u, core.ViaSession), meta))
		})
	if err != nil {
		return nil, err
	}
	res.EnrollRequired = s.requires2FA(u.Role, u.Permissions)
	return res, nil
}
