package auth

import (
	"context"
	"database/sql"
	"errors"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// txPasswordWriter is the transactional variant of Users.SetPasswordHash
// (the users service and the test fake implement it; it is not in core.Users
// yet). The new hash, the revocations it implies and the audit entry belong
// in one transaction: a crash between two of them would change the password
// while every other session of the account stays alive, with nothing in the
// audit log — the opposite of what ChangePassword and AdminSetPassword
// promise.
type txPasswordWriter interface {
	SetPasswordHashTx(ctx context.Context, tx *sql.Tx, by *core.Principal, id, phc string, mustChange bool) error
}

// setPasswordHash returns the function that stores the new hash inside the
// caller's transaction. A users service without the transactional variant
// falls back to the separate write (not atomic, but never nested: the
// database has a single writer, so SetPasswordHash cannot be called from
// inside a transaction).
func (s *Service) setPasswordHash(ctx context.Context, by *core.Principal, id, phc string,
	mustChange bool) (func(*sql.Tx) error, error) {
	if w, ok := s.users.(txPasswordWriter); ok {
		return func(tx *sql.Tx) error { return w.SetPasswordHashTx(ctx, tx, by, id, phc, mustChange) }, nil
	}
	if err := s.users.SetPasswordHash(ctx, by, id, phc, mustChange); err != nil {
		return nil, err
	}
	return func(*sql.Tx) error { return nil }, nil
}

// errElevate is the uniform answer to a failed step-up (403, so that web
// clients do not mistake it for an expired session).
func errElevate(field string) error {
	return &core.Error{Code: core.ErrForbidden.Code, Status: core.ErrForbidden.Status,
		Message: "could not confirm your identity", Field: field}
}

// errAccountLocked answers a step-up or a password change of a signed-in
// user whose account is locked out. It is checked before any credential, so
// it says nothing about the one that was sent, and it tells the truth
// instead of "the password is not correct": the caller already holds a
// session of the account (GET /me shows locked_until), so the uniform
// sign-in answer protects nothing here. 409 rather than 401/403/422, which
// the web forms turn into "wrong password".
func errAccountLocked(u *core.User) error {
	msg := "your account is temporarily locked after too many failed sign-in attempts; try again later or ask an administrator to unlock it"
	if u.LockedUntil != nil {
		msg = "your account is temporarily locked after too many failed sign-in attempts; try again after " +
			u.LockedUntil.UTC().Format("2006-01-02 15:04 MST") + " or ask an administrator to unlock it"
	}
	return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Message: msg}
}

// clearFailedLoginsSQL resets the failure counter after a credential check
// that succeeded outside a sign-in (step-up, password change): the lockout
// counts consecutive failures (auth.lockout_threshold), and a completed
// sign-in (Users.RecordLoginSuccess) is otherwise the only reset. The lock
// level and the last sign-in stay as they are — neither is a sign-in.
const clearFailedLoginsSQL = `UPDATE users SET failed_logins = 0 WHERE id = ? AND failed_logins > 0`

// revokeExceptions returns the session and the API token a credential reset
// by must not cut off: its own session, and its own token when by is acting
// on its own account with an (elevated) API token — otherwise the call would
// revoke the very credential making it.
func revokeExceptions(by *core.Principal, userID string) (keepSession, keepToken string) {
	if by == nil {
		return "", ""
	}
	switch by.Via {
	case core.ViaSession:
		keepSession = by.SessionID
	case core.ViaToken:
		if by.UserID == userID {
			keepToken = by.TokenID
		}
	}
	return keepSession, keepToken
}

// Elevate implements core.Auth: step-up with exactly one of the password,
// an authenticator code or a passkey assertion (FlowID from
// PasskeyLoginBegin). On success elevated_until = now + auth.stepup_min.
// Only fully authenticated browser sessions can elevate (API tokens cannot;
// the system principal always is). Failures count towards the lockout and
// the per-IP failure limit, a success resets the account's failure counter,
// and a locked account is refused up front (errAccountLocked). The web layer
// rotates the session token afterwards (RotateSession).
func (s *Service) Elevate(ctx context.Context, p *core.Principal, in core.ElevateInput) error {
	switch {
	case p == nil:
		return core.ErrUnauthorized
	case p.IsSystem():
		return nil
	case p.Via != core.ViaSession || p.SessionID == "":
		return core.Errorf(core.ErrForbidden, "only browser sessions can confirm their identity; API tokens cannot be elevated")
	case p.AuthLevel < core.AuthLevelFull:
		return core.ErrMFARequired
	}
	n := 0
	for _, set := range []bool{in.Password != "", in.TOTP != "", len(in.Passkey) > 0} {
		if set {
			n++
		}
	}
	if n != 1 {
		return core.Invalid("", "provide exactly one of password, totp or passkey")
	}
	meta := p.Meta()
	if err := s.failAllowed(meta.IP); err != nil {
		return err
	}
	u, err := s.activeUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	now := s.now()
	method, field := "password", "password"
	switch {
	case in.TOTP != "":
		method, field = core.MFATOTP, "totp"
	case len(in.Passkey) > 0:
		method, field = core.MFAPasskey, "passkey"
	}
	if u.Locked(now) {
		s.record(ctx, core.AuditEntry{Action: core.ActAuthElevate, Outcome: core.OutcomeFailure, TargetType: "session",
			TargetID: p.SessionID, Details: map[string]any{"method": method, "reason": "locked"}})
		return errAccountLocked(u)
	}
	var ok bool
	var consume func(tx *sql.Tx) error
	switch method {
	case "password":
		ok, _ = s.VerifyPassword(u.PasswordHash, in.Password)
	case core.MFATOTP:
		var step int64
		if step, ok, err = s.checkTOTP(ctx, u.ID, in.TOTP, true); err != nil {
			return err
		}
		consume = func(tx *sql.Tx) error { return consumeTOTPStep(ctx, tx, u.ID, step) }
	default:
		if !s.passkeysEnabled() {
			return core.Errorf(core.ErrForbidden, "passkeys are turned off on this server")
		}
		f := s.takeFlow(in.FlowID, flowLogin)
		if f != nil && f.userID == u.ID {
			a, err := s.verifyAssertion(ctx, f, in.Passkey)
			switch {
			// a.uv: step-up is the PIN / biometric check itself, so a bare
			// user-presence touch is not enough (the ceremony is begun with
			// VerificationRequired; this is the server-side backstop).
			case err == nil && a.user.ID == u.ID && a.uv:
				ok = true
				consume = func(tx *sql.Tx) error { return storeAssertion(ctx, tx, a, now) }
			case err != nil && !errors.Is(err, errPasskeyFailed):
				return err
			}
		}
	}
	if ok {
		until := now.Add(s.stepUpTTL())
		err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			if consume != nil {
				if err := consume(tx); err != nil {
					return err
				}
			}
			res, err := tx.ExecContext(ctx, `UPDATE sessions SET elevated_until = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
				db.Ms(until), p.SessionID, u.ID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errSignInExpired
			}
			if _, err := tx.ExecContext(ctx, clearFailedLoginsSQL, u.ID); err != nil {
				return err
			}
			return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActAuthElevate, TargetType: "session", TargetID: p.SessionID,
				Details: map[string]any{"method": method, "until": until}})
		})
		if !errors.Is(err, errFactorConsumed) {
			return err
		}
	}
	s.failed(meta.IP)
	s.record(ctx, core.AuditEntry{Action: core.ActAuthElevate, Outcome: core.OutcomeFailure, TargetType: "session",
		TargetID: p.SessionID, Details: map[string]any{"method": method}})
	s.countFailure(ctx, u, meta)
	return errElevate(field)
}

// ChangePassword implements core.Auth: verifies the current password,
// applies the policy to the new one, stores it and revokes every other
// session of the user (the current session stays; the web layer rotates its
// token). A wrong current password is a 422 on current_password and counts
// as a failed login; a correct one resets the failure counter. A locked
// account is refused up front (errAccountLocked).
func (s *Service) ChangePassword(ctx context.Context, p *core.Principal, current, next string) error {
	u, err := s.requireUser(ctx, p)
	if err != nil {
		return err
	}
	meta := p.Meta()
	if err := s.failAllowed(meta.IP); err != nil {
		return err
	}
	if u.Locked(s.now()) {
		s.record(ctx, core.AuditEntry{Action: core.ActUserPasswordChange, Outcome: core.OutcomeFailure,
			TargetType: "user", TargetID: u.ID, TargetName: u.Username, Details: map[string]any{"reason": "locked"}})
		return errAccountLocked(u)
	}
	if ok, _ := s.VerifyPassword(u.PasswordHash, current); !ok {
		s.failed(meta.IP)
		s.record(ctx, core.AuditEntry{Action: core.ActUserPasswordChange, Outcome: core.OutcomeFailure,
			TargetType: "user", TargetID: u.ID, TargetName: u.Username, Details: map[string]any{"reason": "bad_password"}})
		s.countFailure(ctx, u, meta)
		return core.Invalid("current_password", "the current password is not correct")
	}
	if _, err := s.env.DB.Exec(ctx, clearFailedLoginsSQL, u.ID); err != nil {
		s.log.Warn("reset failed logins", "user", u.ID, "err", err)
	}
	if next == current {
		return core.Invalid("new_password", "choose a password different from the current one")
	}
	if err := s.checkPolicy(next, u, "new_password"); err != nil {
		return err
	}
	phc, err := s.HashPassword(next)
	if err != nil {
		return err
	}
	writeHash, err := s.setPasswordHash(ctx, p, u.ID, phc, false)
	if err != nil {
		return err
	}
	keep := ""
	if p.Via == core.ViaSession {
		keep = p.SessionID
	}
	now := s.now()
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := writeHash(tx); err != nil {
			return err
		}
		n, err := revokeUserSessions(ctx, tx, u.ID, keep, now)
		if err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActUserPasswordChange, TargetType: "user", TargetID: u.ID,
			TargetName: u.Username, Details: map[string]any{"sessions_revoked": n}})
	})
	if err != nil {
		return err
	}
	s.dropUserCSRF(u.ID, keep)
	return nil
}

// AdminSetPassword implements core.Auth: sets the password of userID
// without knowing the current one (policy applies) and revokes all of that
// user's sessions and API tokens (except by's own). by must be the user or
// may manage their credentials (authorizeFor: users.credentials, only an
// owner for an owner account), and — since the current password is not
// checked — elevated in every case.
func (s *Service) AdminSetPassword(ctx context.Context, by *core.Principal, userID, pw string, mustChange bool) error {
	if err := s.authorizeFor(ctx, by, userID, core.ActUserPasswordReset); err != nil {
		return err
	}
	if !by.Elevated(s.now()) {
		return core.ErrElevationRequired
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.CheckPasswordPolicy(pw, u); err != nil {
		return err
	}
	phc, err := s.HashPassword(pw)
	if err != nil {
		return err
	}
	writeHash, err := s.setPasswordHash(ctx, by, u.ID, phc, mustChange)
	if err != nil {
		return err
	}
	keep, keepTok := revokeExceptions(by, u.ID)
	now := s.now()
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := writeHash(tx); err != nil {
			return err
		}
		n, err := revokeUserSessions(ctx, tx, u.ID, keep, now)
		if err != nil {
			return err
		}
		nt, err := revokeUserTokens(ctx, tx, u.ID, keepTok, now)
		if err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActUserPasswordReset, TargetType: "user", TargetID: u.ID,
			TargetName: u.Username,
			Details:    map[string]any{"must_change": mustChange, "sessions_revoked": n, "tokens_revoked": nt}})
	})
	if err != nil {
		return err
	}
	s.dropUserCSRF(u.ID, keep)
	return nil
}

// MFAStatus implements core.Auth.
func (s *Service) MFAStatus(ctx context.Context, userID string) (*core.MFAStatus, error) {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	m, err := s.loadMFA(ctx, userID)
	if err != nil {
		return nil, err
	}
	req, funnel := s.requires2FA(u.Role, u.Permissions), s.funnelRequired(ctx, userID)
	return &core.MFAStatus{
		TOTPEnabled: m.totp, TOTPPending: m.totpPending, RecoveryCodesLeft: m.recoveryLeft, PasskeyCount: m.passkeys,
		Required: req, FunnelRequired: funnel, EnrollRequired: (req || funnel) && !m.enabled(),
	}, nil
}

// ResetMFA implements core.Auth: removes the TOTP secret, the recovery
// codes and every passkey of userID and revokes the user's sessions and API
// tokens (except by's own). by must hold users.credentials (not even one's
// own account is reset without it: that is TOTPDisable and DeletePasskey),
// may manage the account (authorizeFor; an owner for an owner account) and
// be elevated.
func (s *Service) ResetMFA(ctx context.Context, by *core.Principal, userID string) error {
	if !by.Can(core.CapUsersCredentials) {
		return core.ErrForbidden
	}
	if err := s.authorizeFor(ctx, by, userID, core.ActUserMFAReset); err != nil {
		return err
	}
	if !by.Elevated(s.now()) {
		return core.ErrElevationRequired
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return err
	}
	keep, keepTok := revokeExceptions(by, u.ID)
	now := s.now()
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var removed int64
		for _, q := range []string{
			`DELETE FROM totp_secrets WHERE user_id = ?`,
			`DELETE FROM recovery_codes WHERE user_id = ?`,
			`DELETE FROM webauthn_credentials WHERE user_id = ?`,
		} {
			res, err := tx.ExecContext(ctx, q, u.ID)
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			removed += n
		}
		n, err := revokeUserSessions(ctx, tx, u.ID, keep, now)
		if err != nil {
			return err
		}
		nt, err := revokeUserTokens(ctx, tx, u.ID, keepTok, now)
		if err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActUserMFAReset, TargetType: "user", TargetID: u.ID,
			TargetName: u.Username,
			Details:    map[string]any{"factors_removed": removed, "sessions_revoked": n, "tokens_revoked": nt}})
	})
	if err != nil {
		return err
	}
	s.dropUserCSRF(u.ID, keep)
	return nil
}
