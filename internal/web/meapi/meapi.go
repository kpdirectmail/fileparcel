// Package meapi owns /api/v1/me and /api/v1/me/* except /me/client-certs*
// (DESIGN §9.4, unit B). A = auth required, F = full (MFA done; default), E = elevated.
//
//	GET    /me                     (A) user, csrf, mfa, prefs, features, space ids, groups, staff → core.Me
//	                               (at AuthLevel 1 only csrf, mfa and a reduced user)
//	PATCH  /me/profile             core.ProfileUpdate → core.User (E when the e-mail address changes)
//	POST   /me/password            core.PasswordChangeInput → core.LoginResult {csrf} (session rotated, others revoked)
//	GET    /me/sessions            → Page[core.Session]
//	DELETE /me/sessions/{id}
//	POST   /me/sessions/revoke-others
//	GET    /me/mfa                 (A) → core.MFAStatus
//	POST   /me/totp/begin          (E) → core.TOTPEnrollment
//	POST   /me/totp/confirm        (E) core.CodeInput → core.RecoveryCodes (empty when unused codes exist)
//	DELETE /me/totp                (E)
//	POST   /me/recovery-codes      (E) → core.RecoveryCodes
//	GET    /me/passkeys            → Page[core.Passkey]
//	POST   /me/passkeys/begin      (E) → core.PasskeyBegin
//	POST   /me/passkeys/finish     (E) core.PasskeyFinishInput → core.Passkey + recovery_codes (first passkey)
//	PATCH  /me/passkeys/{id}       core.NameInput (own passkeys only, also for admins)
//	DELETE /me/passkeys/{id}       (E) (own passkeys only, also for admins)
//	GET    /me/tokens              → Page[core.APIToken]
//	POST   /me/tokens              core.TokenInput → core.TokenCreated (admin scope: E)
//	DELETE /me/tokens/{id}         (own tokens only, also for admins; any over the admin socket)
//	GET    /me/usage               → core.Usage
//
// Guards (security-relevant, see mw.RequireAuth / mw.RequireFull):
//   - mw.RequireAuth only for the read-only (A) routes GET /me and GET /me/mfa
//     (they must work at AuthLevel 1, e.g. the login page fetches the CSRF
//     token from GET /me between the password and the TOTP step);
//   - every other route, INCLUDING the enrollment routes POST
//     /me/totp/{begin,confirm} and POST /me/passkeys/{begin,finish}, uses
//     mw.RequireFull. RequireFull admits users with a pending 2FA enrollment
//     (EnrollRequired) to /me* but never a password-only (AuthLevel 1)
//     session of a user who already has 2FA — otherwise a stolen password
//     could register a new authenticator;
//   - (E) routes add mw.RequireElevated after RequireFull. The enrollment
//     routes are (E) too: a new authenticator or passkey satisfies step-up
//     (and a passkey signs in without the password), so a hijacked session
//     must not be able to add one. EnrollRequired sessions elevate with the
//     password (POST /auth/elevate is RequireAuth);
//   - password, authenticator, recovery-code, passkey and browser-session
//     management (/me/sessions*) are not available to API tokens (browser
//     sessions and the admin socket only), and neither are the identity
//     fields of PATCH /me/profile (e-mail, display name); a token may still
//     write its preferences, and list, create (narrower) and revoke
//     (no wider) tokens — the remote "fileparcel token" commands;
//   - a session changing its e-mail address (where the security alerts go)
//     needs step-up, checked in the handler since the same route saves the
//     display name and preferences; the previous address gets an
//     email_changed security alert.
package meapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/notify"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/pages"
)

type handlers struct{ d *app.Deps }

// Mount registers this package's routes on the /api/v1 router.
func Mount(api chi.Router, d *app.Deps) {
	h := &handlers{d: d}
	api.Group(func(r chi.Router) {
		r.Use(mw.NoStore, h.ready)

		r.Group(func(r chi.Router) {
			r.Use(mw.RequireAuth)
			r.Get("/me", h.me)
			r.Get("/me/mfa", h.mfa)
		})

		r.Group(func(r chi.Router) {
			r.Use(mw.RequireFull)
			r.Patch("/me/profile", h.profile)
			r.Get("/me/tokens", h.tokens)
			r.Post("/me/tokens", h.createToken)
			r.Delete("/me/tokens/{id}", h.revokeToken)
			r.Get("/me/usage", h.usage)

			// Credential and browser-session management: browser sessions and
			// the admin socket only. No token client needs the session routes,
			// and a leaked read-only token must not be able to read the
			// owner's addresses or sign every browser out.
			r.Group(func(r chi.Router) {
				r.Use(noTokens)
				r.Get("/me/sessions", h.sessions)
				r.Delete("/me/sessions/{id}", h.revokeSession)
				r.Post("/me/sessions/revoke-others", h.revokeOthers)
				r.Group(func(r chi.Router) {
					r.Use(mw.RateLimit(mw.BucketLogin, mw.PerUser))
					r.Post("/me/password", h.password)
				})
				r.Get("/me/passkeys", h.passkeys)
				r.Patch("/me/passkeys/{id}", h.renamePasskey)
				r.Group(func(r chi.Router) {
					r.Use(mw.RequireElevated)
					r.Post("/me/totp/begin", h.totpBegin)
					r.Post("/me/totp/confirm", h.totpConfirm)
					r.Post("/me/passkeys/begin", h.passkeyBegin)
					r.Post("/me/passkeys/finish", h.passkeyFinish)
					r.Delete("/me/totp", h.totpDisable)
					r.Post("/me/recovery-codes", h.recoveryCodes)
					r.Delete("/me/passkeys/{id}", h.deletePasskey)
				})
			})
		})
	})
}

// ready answers 503 when the services are missing (tests, broken wiring).
func (h *handlers) ready(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.d == nil || h.d.Env == nil || h.d.Auth == nil || h.d.Users == nil {
			httpx.Error(w, r, core.Errorf(core.ErrUnavailable, "account services are not available"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// noTokens refuses API-token principals (credential management needs a
// browser session or the admin socket).
func noTokens(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := mw.Principal(r); p != nil && p.Via == core.ViaToken {
			httpx.Error(w, r, core.Errorf(core.ErrForbidden, "not available with API tokens; use the web interface or the admin socket"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// userPrincipal returns the principal when it acts as a user (the bare
// system principal has no account; the CLI sends X-FP-As).
func userPrincipal(w http.ResponseWriter, r *http.Request) (*core.Principal, bool) {
	p := mw.Principal(r)
	if p == nil {
		httpx.Error(w, r, core.ErrUnauthorized)
		return nil, false
	}
	if p.UserID == "" {
		httpx.Error(w, r, core.Errorf(core.ErrInvalid, "this endpoint needs a user account (use --as USER)"))
		return nil, false
	}
	return p, true
}

// securityAlert e-mails the owner of userID that a new credential was added
// to that account (notify template "security_alert", category "security").
// Best effort: it only queues the message and never fails the request. kind is
// notify.AlertPasskeyAdded, notify.AlertTOTPAdded or notify.AlertTokenCreated;
// name is the passkey/token name (for notify.AlertEmailChanged, sent with
// sendAlert, the masked new address). p is the acting principal, reported as "actor" when the
// credential was created by someone else (an administrator through the admin
// socket); the recipient is always userID, never the caller.
func (h *handlers) securityAlert(r *http.Request, p *core.Principal, userID, kind, name string) {
	d := h.d
	if d == nil || d.Notify == nil || d.Users == nil || userID == "" || !d.Notify.Enabled() {
		return
	}
	u, err := d.Users.Get(r.Context(), userID)
	if err != nil || u == nil {
		return
	}
	h.sendAlert(r, p, u, u.Email, kind, name)
}

// sendAlert queues a security_alert about the account u to the address to
// (best effort, like securityAlert). It is separate because the alert about
// an e-mail change goes to the previous address, not to the one on record.
func (h *handlers) sendAlert(r *http.Request, p *core.Principal, u *core.User, to, kind, name string) {
	d := h.d
	if d == nil || d.Notify == nil || u == nil || to == "" || !d.Notify.Enabled() {
		return
	}
	data := map[string]any{"kind": kind, "username": u.Username, "name": name}
	if p != nil && p.UserID != u.ID && p.Username != "" {
		data["actor"] = p.Username
	}
	if p != nil && p.IP.IsValid() {
		data["ip"] = p.IP.String()
	}
	if err := d.Notify.Send(r.Context(), []string{to}, "security_alert", data); err != nil {
		h.logger().Warn("meapi: security alert not sent", "user", u.ID, "kind", kind, "err", err)
	}
}

func (h *handlers) logger() *slog.Logger {
	if h.d.Log != nil {
		return h.d.Log
	}
	return slog.Default()
}

// emptyJSON reports whether a raw JSON value is absent or null.
func emptyJSON(v json.RawMessage) bool {
	v = bytes.TrimSpace(v)
	return len(v) == 0 || bytes.Equal(v, []byte("null"))
}

// ---------- GET /me ----------

func (h *handlers) me(w http.ResponseWriter, r *http.Request) {
	ctx, p := r.Context(), mw.Principal(r)
	now := h.d.Now()
	out := core.Me{Via: p.Via, Features: pages.Features(h.d, p), Groups: []core.Group{}, MFAPending: p.AuthLevel < core.AuthLevelFull}
	if p.Elevated(now) && !p.IsSystem() {
		t := p.ElevatedUntil
		out.ElevatedUntil = &t
	}
	if p.UserID == "" { // bare system principal (admin socket without --as)
		out.User = &core.User{Username: p.Username, DisplayName: "System", Role: p.Role, RoleID: string(core.RoleSystem),
			RoleName: core.BuiltinRoleName(core.RoleSystem), Permissions: core.AllCaps, Status: core.UserActive}
		out.Prefs = json.RawMessage(`{}`)
		out.Staff = true
		httpx.OK(w, out)
		return
	}
	u, err := h.d.Users.Get(ctx, p.UserID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	out.User = u
	out.CSRF = h.d.Auth.CSRFToken(p)
	out.Prefs = u.Prefs
	if len(out.Prefs) == 0 {
		out.Prefs = json.RawMessage(`{}`)
	}
	if st, err := h.d.Auth.MFAStatus(ctx, p.UserID); err == nil {
		out.MFA = st
		u.MFAEnabled = st.TOTPEnabled || st.PasskeyCount > 0
	} else {
		h.logger().Warn("me: mfa status", "user", p.UserID, "err", err)
	}
	if out.MFAPending {
		// A password-only session has not crossed the second-factor boundary
		// yet: it gets what the login page needs to finish signing in (csrf,
		// mfa, who is signing in) and nothing else. Not the e-mail address
		// that receives the security alerts, not the role, the last-login
		// IP/time, the status, the quota or the lockout counters — and not
		// User.SpaceID, the derived field that would otherwise hand over the
		// very id withheld from Me.SpaceID below.
		out.User = &core.User{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName,
			MustChangePassword: u.MustChangePassword, MFAEnabled: u.MFAEnabled}
		out.Prefs = json.RawMessage(`{}`) // Me.Prefs is omitempty: keep the key
		httpx.OK(w, out)
		return
	}
	out.SpaceID = u.SpaceID
	out.Staff = p.ServerAccess()
	groups, err := h.d.Users.MyGroups(ctx, p)
	if err != nil {
		h.logger().Warn("me: groups", "user", p.UserID, "err", err)
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, g)
		if g.SpaceID != "" {
			if out.GroupSpaceIDs == nil {
				out.GroupSpaceIDs = map[string]string{}
			}
			out.GroupSpaceIDs[g.ID] = g.SpaceID
		}
	}
	httpx.OK(w, out)
}

// ---------- profile & password ----------

func (h *handlers) profile(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	in, err := httpx.Decode[core.ProfileUpdate](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	// The e-mail address receives the security alerts (a new passkey, a new
	// API token, an admin password/MFA reset) and the display name is what
	// the share and grant pickers show, so neither may be changed with an
	// API token — a leaked read-only token could redirect the very alerts
	// that would reveal it. Preferences stay writable.
	if p.Via == core.ViaToken && (in.Email != nil || in.DisplayName != nil) {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden,
			"changing the e-mail address or display name is not available with API tokens; use the web interface or the admin socket"))
		return
	}
	// For the same reason a browser session needs step-up to change the
	// address (a hijacked session could otherwise silently redirect the
	// alert about the passkey it adds next), and the previous address is
	// told. Only a real change counts: the profile form always sends the
	// address, and users.Update ignores a change of letter case too.
	ctx := r.Context()
	oldEmail, emailChanges := "", false
	if in.Email != nil {
		cur, err := h.d.Users.Get(ctx, p.UserID)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		oldEmail = cur.Email
		emailChanges = !strings.EqualFold(strings.TrimSpace(*in.Email), cur.Email)
		if emailChanges && !p.Elevated(h.d.Now()) {
			httpx.Error(w, r, core.ErrElevationRequired)
			return
		}
	}
	u, err := h.d.Users.Update(ctx, p, p.UserID, in.UserUpdate())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if emailChanges && u != nil && oldEmail != "" && !strings.EqualFold(oldEmail, u.Email) {
		h.sendAlert(r, p, u, oldEmail, notify.AlertEmailChanged, maskEmail(u.Email))
	}
	httpx.OK(w, u)
}

// maskEmail shortens an address for the alert sent to the previous one:
// enough to recognise it ("p***@example.org"), not a full copy for a mailbox
// that may no longer be the owner's. "" stays "" (the address was removed).
func maskEmail(s string) string {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" {
		return ""
	}
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + "***@" + domain
}

func (h *handlers) password(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	in, err := httpx.Decode[core.PasswordChangeInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.d.Auth.ChangePassword(ctx, p, in.CurrentPassword, in.NewPassword); err != nil {
		if errors.Is(err, core.ErrRateLimited) && w.Header().Get("Retry-After") == "" {
			w.Header().Set("Retry-After", "60")
		}
		httpx.Error(w, r, err)
		return
	}
	out := core.LoginResult{CSRF: h.d.Auth.CSRFToken(p)}
	res, err := h.d.Auth.RotateSession(ctx, p)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if res != nil && res.Token != "" {
		http.SetCookie(w, h.d.Auth.SessionCookie(res.Token, res.CookieExpires))
		out.CSRF = res.CSRF
	}
	if u, err := h.d.Users.Get(ctx, p.UserID); err == nil {
		out.User = u
	}
	httpx.OK(w, out)
}

// ---------- sessions ----------

func (h *handlers) sessions(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	list, err := h.d.Auth.ListSessions(r.Context(), p.UserID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

func (h *handlers) revokeSession(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.d.Auth.RevokeSession(r.Context(), p, p.UserID, id); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if p.Via == core.ViaSession && id == p.SessionID {
		http.SetCookie(w, h.d.Auth.SessionCookie("", time.Time{}))
	}
	httpx.NoContent(w)
}

func (h *handlers) revokeOthers(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	keep := ""
	if p.Via == core.ViaSession {
		keep = p.SessionID
	}
	if err := h.d.Auth.RevokeAllSessions(r.Context(), p, p.UserID, keep); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ---------- MFA ----------

func (h *handlers) mfa(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	st, err := h.d.Auth.MFAStatus(r.Context(), p.UserID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

func (h *handlers) totpBegin(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	e, err := h.d.Auth.TOTPBegin(r.Context(), p)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, e)
}

func (h *handlers) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	in, err := httpx.Decode[core.CodeInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	codes, err := h.d.Auth.TOTPConfirm(r.Context(), p, in.Code)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	h.securityAlert(r, p, p.UserID, notify.AlertTOTPAdded, "")
	httpx.OK(w, core.RecoveryCodes{RecoveryCodes: codes})
}

func (h *handlers) totpDisable(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	if err := h.d.Auth.TOTPDisable(r.Context(), p, p.UserID); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) recoveryCodes(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	codes, err := h.d.Auth.RegenerateRecovery(r.Context(), p)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.RecoveryCodes{RecoveryCodes: codes})
}

// ---------- passkeys ----------

func (h *handlers) passkeys(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	list, err := h.d.Auth.ListPasskeys(r.Context(), p.UserID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

func (h *handlers) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	opts, flowID, err := h.d.Auth.PasskeyRegisterBegin(r.Context(), p)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.PasskeyBegin{Options: opts, FlowID: flowID})
}

func (h *handlers) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	in, err := httpx.Decode[core.PasskeyFinishInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if in.FlowID == "" || emptyJSON(in.Credential) {
		httpx.Error(w, r, core.Invalid("credential", "flow_id and credential are required"))
		return
	}
	pk, err := h.d.Auth.PasskeyRegisterFinish(r.Context(), p, in.FlowID, in.Credential, in.Name)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	name := in.Name
	if pk != nil {
		name = pk.Name
	}
	h.securityAlert(r, p, p.UserID, notify.AlertPasskeyAdded, name)
	if pk == nil {
		httpx.Created(w, pk)
		return
	}
	// A passkey is not an out-of-band factor: turn auth.passkeys off (or
	// lose the authenticator) and an account whose only second factor is
	// this passkey cannot sign in any more. Hand out the first set of
	// recovery codes with it, shown once like POST /me/totp/confirm does.
	out := passkeyCreated{Passkey: pk}
	if m, ok := h.d.Auth.(recoveryMinter); ok {
		codes, err := m.EnsureRecoveryCodes(r.Context(), p)
		if err != nil {
			h.logger().Warn("passkey: recovery codes", "user", p.UserID, "err", err)
		}
		out.RecoveryCodes = codes
	}
	httpx.Created(w, out)
}

// recoveryMinter is implemented by the auth service: it mints the first set
// of recovery codes for an account that has a second factor but none left.
// It is not part of core.Auth, so it is reached through this small interface.
type recoveryMinter interface {
	EnsureRecoveryCodes(ctx context.Context, p *core.Principal) ([]string, error)
}

// passkeyCreated is the body of POST /me/passkeys/finish: core.Passkey plus
// the recovery codes minted with the first passkey (absent when the account
// already had some).
type passkeyCreated struct {
	*core.Passkey
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

func (h *handlers) renamePasskey(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	in, err := httpx.Decode[core.NameInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := h.d.Auth.RenamePasskey(r.Context(), p, chi.URLParam(r, "id"), in.Name); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) deletePasskey(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	if err := h.d.Auth.DeletePasskey(r.Context(), p, chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ---------- API tokens ----------

func (h *handlers) tokens(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	list, err := h.d.Auth.ListTokens(r.Context(), p.UserID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

func (h *handlers) createToken(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	in, err := httpx.Decode[core.TokenInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	// Only the trusted in-process channels (admin socket, offline CLI) may
	// name another user; over the network a token always belongs to the
	// caller. There is no /admin/tokens route, and honouring user_id here
	// would let any elevated administrator mint a credential for another
	// account and read/write its private files, bypassing
	// auth.admin_can_access_files. The CLI's --user goes through X-FP-As,
	// which already swaps p.UserID, so it never needs in.UserID.
	if in.UserID != "" && in.UserID != p.UserID && p.Via != core.ViaSocket && p.Via != core.ViaOffline {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "you can only create tokens for yourself"))
		return
	}
	t, secret, err := h.d.Auth.CreateToken(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	// The alert goes to the account that gained the credential, which is not
	// the caller when the admin socket creates a token for someone else.
	name, owner := in.Name, p.UserID
	if t != nil {
		name, owner = t.Name, t.UserID
	}
	h.securityAlert(r, p, owner, notify.AlertTokenCreated, name)
	httpx.Created(w, core.TokenCreated{Token: t, Secret: secret})
}

func (h *handlers) revokeToken(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	if err := h.d.Auth.RevokeToken(r.Context(), p, chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ---------- usage ----------

func (h *handlers) usage(w http.ResponseWriter, r *http.Request) {
	p, ok := userPrincipal(w, r)
	if !ok {
		return
	}
	if h.d.Files == nil {
		httpx.Error(w, r, core.ErrUnavailable)
		return
	}
	u, err := h.d.Files.Usage(r.Context(), p.UserID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, u)
}
