package auth

import (
	"context"
	"net/http"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ratelimit"
)

// Sign-in over Tailscale Funnel (DESIGN §10.6, "app" mode: the whole app on
// the server's public internet address). Everything here applies only to
// requests of the Funnel ingress listener (core.IngressFrom, or
// ReqMeta.Ingress for flows that only carry the request metadata); the LAN,
// the tailnet and Tailscale Serve are unaffected.
//
//   - With funnel.require_2fa (the default) only accounts with a second
//     factor (TOTP or a passkey) can sign in. A correct password of an
//     account without one gets the same 401 as a wrong password (a
//     distinct answer would confirm the password to anybody on the
//     internet); it is audited as auth.login outcome "denied", reason
//     funnel_requires_2fa. That one answer (badCredentials) names the
//     missing second factor and where to set it up, for every failure, so
//     the owner of a new account learns what to do and an attacker learns
//     nothing. Principals of such accounts that reach the Funnel address
//     anyway — a session cookie from FileParcel's own port (cookies ignore
//     ports), an invitation accepted over Funnel, a personal access token —
//     can only enroll a second factor (EnrollRequired; MFAStatus reports
//     FunnelRequired): they proved themselves with more than a password
//     typed on the internet (a single-use invitation counts, a shared
//     multi-use link does not), and the enrollment itself needs step-up.
//   - Wrong passwords and second-factor codes over Funnel never count
//     towards the account lockout (Users.RecordLoginFailure), so nobody on
//     the internet can lock an account out of the LAN. They take a token of
//     the per-account bucket ratelimit.BucketAuthFunnelUser instead (burst
//     10, 2 an hour); while it is empty, password sign-ins of that account
//     over Funnel get the uniform 401 whatever the password (audited
//     funnel_user_limited), and a wrong code ends the pending second-factor
//     session. The per-address failure limit (auth_fail) still applies.

// keyFunnelRequire2FA is the setting of package tsingress (a service
// package this one does not import); unregistered, 2FA is required.
const keyFunnelRequire2FA = "funnel.require_2fa"

// overFunnel reports whether ctx (or meta) belongs to a request of the
// Funnel ingress listener.
func overFunnel(ctx context.Context, meta core.ReqMeta) bool {
	if in := core.IngressFrom(ctx); in != nil {
		return in.Kind == core.IngressFunnel
	}
	return meta.Ingress == core.IngressFunnel
}

// funnelRequires2FA reports funnel.require_2fa.
func (s *Service) funnelRequires2FA() bool { return s.settingBool(keyFunnelRequire2FA, true) }

// hasMFA reports whether userID has a confirmed TOTP secret or a passkey.
func (s *Service) hasMFA(ctx context.Context, userID string) (bool, error) {
	var n int
	err := s.env.DB.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM totp_secrets WHERE user_id = ? AND confirmed_at IS NOT NULL)
		OR EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = ?)`, userID, userID).Scan(&n)
	return n != 0, err
}

// applyIngress applies the Funnel sign-in rule to the principal Authenticate
// found for r (session or token): over Funnel, with funnel.require_2fa, an
// account without a second factor may only enroll one. A failed lookup
// counts as "no second factor" (fail closed).
func (s *Service) applyIngress(r *http.Request, p *core.Principal) {
	if p == nil || p.UserID == "" || p.EnrollRequired || p.AuthLevel < core.AuthLevelFull ||
		!overFunnel(r.Context(), core.ReqMeta{}) || !s.funnelRequires2FA() {
		return
	}
	if ok, err := s.hasMFA(r.Context(), p.UserID); err != nil || !ok {
		if err != nil {
			s.log.Warn("funnel: second-factor lookup failed", "user", p.UserID, "err", err)
		}
		p.EnrollRequired = true
	}
}

// badCredentials is the answer of a failed password sign-in: over Funnel with
// funnel.require_2fa it is errFunnelCredentials, else errInvalidCredentials.
func (s *Service) badCredentials(ctx context.Context, meta core.ReqMeta) error {
	if overFunnel(ctx, meta) && s.funnelRequires2FA() {
		return errFunnelCredentials
	}
	return errInvalidCredentials
}

// funnelRequired reports whether the Funnel rule demands a second factor of
// userID for this request: over Funnel, with funnel.require_2fa, for the
// caller's own account (an administrator's view of somebody else's account
// shows that account's policy, not the address the administrator uses).
func (s *Service) funnelRequired(ctx context.Context, userID string) bool {
	p := core.PrincipalFrom(ctx)
	return p != nil && p.UserID == userID && overFunnel(ctx, core.ReqMeta{}) && s.funnelRequires2FA()
}

// funnelLogin runs right after the password check of a password sign-in
// (ok: whether the password matched). Over Funnel it refuses, with the
// uniform 401, every sign-in of an account whose failure bucket is empty,
// and a correct password of an account without a second factor while
// funnel.require_2fa is on — except the sign-in right after accepting an
// invitation (afterInvite): the invitation proved the person, and the new
// session can only set up a second factor there (applyIngress). Both count as a failed attempt of the client
// address (auth_fail), exactly as a wrong password would, so the answer
// tells nothing about the password; neither counts towards the account
// lockout. nil lets the sign-in go on.
func (s *Service) funnelLogin(ctx context.Context, u *core.User, ok, afterInvite bool, meta core.ReqMeta) error {
	if u == nil || !overFunnel(ctx, meta) {
		return nil
	}
	reason := ""
	switch {
	case s.limiter != nil && s.limiter.Tokens(ratelimit.BucketAuthFunnelUser, u.ID) < 1:
		reason = "funnel_user_limited"
	case ok && !afterInvite && u.Status == core.UserActive && !u.Locked(s.now()) && s.funnelRequires2FA():
		has, err := s.hasMFA(ctx, u.ID)
		if err != nil {
			return err
		}
		if !has {
			reason = "funnel_requires_2fa"
		}
	}
	if reason == "" {
		return nil
	}
	s.failed(meta.IP)
	e := core.AuditEntry{Action: core.ActAuthLogin, Outcome: core.OutcomeDenied,
		Details: map[string]any{"method": "password", "reason": reason, "ingress": core.IngressFunnel}}
	s.record(ctx, withMeta(asUser(e, u, core.ViaSession), meta))
	return s.badCredentials(ctx, meta)
}

// funnelFailure is the first step of countFailure: over Funnel a failed
// credential check takes a token of the account's Funnel bucket instead of
// counting towards the lockout, and true tells countFailure to stop there.
// When the bucket is empty, a pending second-factor session of the request
// ends (the password step has to be repeated, which the empty bucket then
// refuses).
func (s *Service) funnelFailure(ctx context.Context, u *core.User, meta core.ReqMeta) bool {
	if u == nil || !overFunnel(ctx, meta) {
		return false
	}
	if s.limiter == nil {
		return true
	}
	if allowed, _ := s.limiter.Allow(ratelimit.BucketAuthFunnelUser, u.ID); allowed {
		return true
	}
	if p := core.PrincipalFrom(ctx); p != nil && p.Via == core.ViaSession && p.SessionID != "" &&
		p.UserID == u.ID && p.AuthLevel < core.AuthLevelFull {
		if _, err := s.env.DB.Exec(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
			db.Ms(s.now()), p.SessionID); err != nil {
			s.log.Warn("funnel: revoke pending session", "err", err)
		}
		s.dropCSRF(p.SessionID)
	}
	return true
}
