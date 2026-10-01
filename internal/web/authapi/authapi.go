// Package authapi owns /api/v1/auth/* (DESIGN §9.4, unit B):
//
//	GET  /auth/state                      public: instance name, setup_needed, passkeys enabled, rp_id, keys state,
//	                                      login message, password_min
//	POST /auth/login {username,password,remember} → LoginResult {user} or {mfa_required:true, methods:[…]}
//	POST /auth/totp {code}                (A: completes a pending login)
//	POST /auth/recovery {code}            (A: completes a pending login)
//	POST /auth/passkey/begin {username?}  → PasskeyBegin {options, flow_id}
//	POST /auth/passkey/finish {flow_id, credential, remember?} → LoginResult
//	POST /auth/logout                     (A)
//	POST /auth/elevate {password|totp|passkey+flow_id} (A) → ElevateResult {elevated_until, csrf}
//	POST /auth/setup {setup_token, username, password, email} → LoginResult (only while no users exist)
//	GET  /auth/invite/{token}             → the invitation (public view)
//	POST /auth/invite/{token}/accept {username, password, display_name, email} → LoginResult
//
// Every route that checks a secret (login, second factor, passkey finish,
// setup, accepting an invitation) is limited per client IP with
// mw.RateLimit(mw.BucketLogin, mw.PerIP); elevation per user. Starting a
// passkey ceremony and reading an invitation check no credential and have
// the larger mw.BucketLoginStart: the sign-in page starts a ceremony on every
// load (passkey autofill), which must not use up the allowance of the real
// attempts. Responses that establish or rotate a
// session set the __Host-fp_session cookie (Auth.SessionCookie) and carry
// the new CSRF token. Denied rate limits are 429 with Retry-After.
package authapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// failureRetryAfter is the Retry-After (seconds) sent with 429 errors from
// the service's failure limit (the middleware sets its own).
const failureRetryAfter = "60"

type handlers struct{ d *app.Deps }

// Mount registers this package's routes on the /api/v1 router.
func Mount(api chi.Router, d *app.Deps) {
	h := &handlers{d: d}
	api.Group(func(r chi.Router) {
		r.Use(mw.NoStore)
		r.Get("/auth/state", h.state)

		r.Group(func(r chi.Router) {
			r.Use(mw.RateLimit(mw.BucketLoginStart, mw.PerIP))
			r.Post("/auth/passkey/begin", h.passkeyBegin)
			r.Get("/auth/invite/{token}", h.invite)
		})
		r.Group(func(r chi.Router) {
			r.Use(mw.RateLimit(mw.BucketLogin, mw.PerIP))
			r.Post("/auth/login", h.login)
			r.Post("/auth/passkey/finish", h.passkeyFinish)
			r.Post("/auth/setup", h.setup)
			r.Post("/auth/invite/{token}/accept", h.acceptInvite)
			r.Group(func(r chi.Router) {
				r.Use(mw.RequireAuth)
				r.Post("/auth/totp", h.totp)
				r.Post("/auth/recovery", h.recovery)
			})
		})

		r.Group(func(r chi.Router) {
			r.Use(mw.RequireAuth)
			r.Post("/auth/logout", h.logout)
		})
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireAuth, mw.RateLimit(mw.BucketLogin, mw.PerUser))
			r.Post("/auth/elevate", h.elevate)
		})
	})
}

// ---------- helpers ----------

func (h *handlers) available(w http.ResponseWriter, r *http.Request) bool {
	if h.d == nil || h.d.Env == nil || h.d.Auth == nil {
		httpx.Error(w, r, core.Errorf(core.ErrUnavailable, "authentication is not available"))
		return false
	}
	return true
}

// fail writes err; service rate limits get a Retry-After header.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, core.ErrRateLimited) && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", failureRetryAfter)
	}
	httpx.Error(w, r, err)
}

// emptyJSON reports whether a raw JSON value is absent or null.
func emptyJSON(v json.RawMessage) bool {
	v = bytes.TrimSpace(v)
	return len(v) == 0 || bytes.Equal(v, []byte("null"))
}

// setSession sets the session cookie of a login result (if it carries a token).
func (h *handlers) setSession(w http.ResponseWriter, res *core.LoginResult) {
	if res != nil && res.Token != "" {
		http.SetCookie(w, h.d.Auth.SessionCookie(res.Token, res.CookieExpires))
	}
}

// clearSession deletes the session cookie.
func (h *handlers) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, h.d.Auth.SessionCookie("", time.Time{}))
}

func (h *handlers) logger() *slog.Logger {
	if h.d != nil && h.d.Env != nil && h.d.Log != nil {
		return h.d.Log
	}
	return slog.Default()
}

// RPID returns the WebAuthn RP ID used by the auth service (derived from the
// settings when the service does not expose it).
func RPID(d *app.Deps) string {
	if d == nil {
		return "fileparcel.local"
	}
	if d.Auth != nil {
		if id := d.Auth.RPID(); id != "" {
			return id
		}
	}
	if d.Env != nil && d.Settings != nil {
		if s := strings.TrimSpace(d.Settings.String("auth.webauthn_rp_id")); s != "" {
			return strings.ToLower(s)
		}
	}
	if d.Env != nil && d.Config != nil && d.Config.Server.Name != "" {
		return strings.ToLower(d.Config.Server.Name) + ".local"
	}
	return "fileparcel.local"
}

// ---------- handlers ----------

// defaultPasswordMin is the default of auth.password_min (auth.DefaultPasswordMin),
// reported by /auth/state when the setting cannot be read.
const defaultPasswordMin = 12

// state serves GET /auth/state (public).
func (h *handlers) state(w http.ResponseWriter, r *http.Request) {
	st := core.AuthState{Instance: "FileParcel", Passkeys: true, KeysState: core.KeyStateUninitialized, RPID: RPID(h.d),
		PasswordMin: defaultPasswordMin}
	if d := h.d; d != nil && d.Env != nil {
		if d.Settings != nil {
			if s := strings.TrimSpace(d.Settings.String("ui.instance_name")); s != "" {
				st.Instance = s
			}
			if _, err := d.Settings.Raw("auth.passkeys"); err == nil {
				st.Passkeys = d.Settings.Bool("auth.passkeys")
			}
			st.LoginMessage = d.Settings.String("ui.login_message")
			if n := d.Settings.Int("auth.password_min"); n > 0 {
				st.PasswordMin = n
			}
		}
		if d.Keys != nil {
			st.KeysState = d.Keys.State()
		}
		if d.Users != nil {
			if n, err := d.Users.Count(r.Context()); err == nil {
				st.SetupNeeded = n == 0
			}
		}
	}
	httpx.OK(w, st)
}

// login serves POST /auth/login.
func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	in, err := httpx.Decode[core.LoginInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	res, err := h.d.Auth.Login(r.Context(), in, httpx.Meta(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	h.setSession(w, res)
	httpx.OK(w, res)
}

// secondFactor serves POST /auth/totp and /auth/recovery.
func (h *handlers) secondFactor(w http.ResponseWriter, r *http.Request, recovery bool) {
	if !h.available(w, r) {
		return
	}
	in, err := httpx.Decode[core.CodeInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	verify := h.d.Auth.VerifyTOTP
	if recovery {
		verify = h.d.Auth.VerifyRecovery
	}
	res, err := verify(r.Context(), mw.Principal(r), in.Code)
	if err != nil {
		if errors.Is(err, core.ErrUnauthorized) {
			h.clearSession(w) // the pending sign-in is gone; start over
		}
		fail(w, r, err)
		return
	}
	h.setSession(w, res)
	httpx.OK(w, res)
}

func (h *handlers) totp(w http.ResponseWriter, r *http.Request)     { h.secondFactor(w, r, false) }
func (h *handlers) recovery(w http.ResponseWriter, r *http.Request) { h.secondFactor(w, r, true) }

// passkeyBegin serves POST /auth/passkey/begin.
func (h *handlers) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	in, err := httpx.Decode[core.PasskeyBeginInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	opts, flowID, err := h.d.Auth.PasskeyLoginBegin(r.Context(), in.Username)
	if err != nil {
		fail(w, r, err)
		return
	}
	httpx.OK(w, core.PasskeyBegin{Options: opts, FlowID: flowID})
}

// passkeyFinish serves POST /auth/passkey/finish.
func (h *handlers) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
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
	res, err := h.d.Auth.PasskeyLoginFinish(r.Context(), in.FlowID, in.Credential, in.Remember, mw.Principal(r), httpx.Meta(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	h.setSession(w, res)
	httpx.OK(w, res)
}

// logout serves POST /auth/logout: revokes the session and deletes the cookie.
func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	h.clearSession(w)
	if err := h.d.Auth.Logout(r.Context(), mw.Principal(r)); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// elevate serves POST /auth/elevate; the session token is rotated.
func (h *handlers) elevate(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	in, err := httpx.Decode[core.ElevateInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ctx, p := r.Context(), mw.Principal(r)
	if err := h.d.Auth.Elevate(ctx, p, in); err != nil {
		fail(w, r, err)
		return
	}
	out := core.ElevateResult{CSRF: h.d.Auth.CSRFToken(p)}
	res, err := h.d.Auth.RotateSession(ctx, p)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if res != nil {
		h.setSession(w, res)
		out.CSRF = res.CSRF
		if res.Session != nil && res.Session.ElevatedUntil != nil {
			out.ElevatedUntil = *res.Session.ElevatedUntil
		}
	}
	if out.ElevatedUntil.IsZero() && p.Via == core.ViaSession {
		if list, err := h.d.Auth.ListSessions(ctx, p.UserID); err == nil {
			for _, s := range list {
				if s.ID == p.SessionID && s.ElevatedUntil != nil {
					out.ElevatedUntil = *s.ElevatedUntil
				}
			}
		}
	}
	if out.ElevatedUntil.IsZero() {
		out.ElevatedUntil = p.ElevatedUntil
	}
	httpx.OK(w, out)
}

// setup serves POST /auth/setup (first owner account).
func (h *handlers) setup(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	in, err := httpx.Decode[core.NewUser](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	res, err := h.d.Auth.Setup(r.Context(), in.SetupToken, in, httpx.Meta(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	h.setSession(w, res)
	httpx.Created(w, res)
}

// publicInvite strips what an anonymous visitor must not see.
func publicInvite(inv *core.Invite) core.Invite {
	out := *inv
	out.CreatedBy, out.URL, out.TokenHash = "", "", nil
	out.GroupIDs = []string{}
	return out
}

// invite serves GET /auth/invite/{token}.
func (h *handlers) invite(w http.ResponseWriter, r *http.Request) {
	if h.d == nil || h.d.Env == nil || h.d.Users == nil {
		httpx.Error(w, r, core.ErrUnavailable)
		return
	}
	inv, err := h.d.Users.LookupInvite(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, publicInvite(inv))
}

// acceptInvite serves POST /auth/invite/{token}/accept: creates the account
// and signs it in (when signing in fails, the user can still sign in
// manually; the response then carries only the user).
func (h *handlers) acceptInvite(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	if h.d.Users == nil {
		httpx.Error(w, r, core.ErrUnavailable)
		return
	}
	in, err := httpx.Decode[core.AcceptInvite](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.Username == "" {
		httpx.Error(w, r, core.Invalid("username", "a username is required"))
		return
	}
	// The policy looks at the address the account will have: an invitation
	// that names one gives it to the account even when the field was left
	// empty (users.AcceptInvite refuses a different one). An unusable token
	// gets the same 404 here as from AcceptInvite.
	ctx, meta, token := r.Context(), httpx.Meta(r), chi.URLParam(r, "token")
	inv, err := h.d.Users.LookupInvite(ctx, token)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	email := in.Email
	if inv.Email != "" {
		email = inv.Email
	}
	if err := h.d.Auth.CheckPasswordPolicy(in.Password, &core.User{Username: in.Username, Email: email}); err != nil {
		httpx.Error(w, r, err)
		return
	}
	phc, err := h.d.Auth.HashPassword(in.Password)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	u, err := h.d.Users.AcceptInvite(ctx, token, in, phc, meta)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	// A single-use invitation is a personal link: it proves the person, so over Tailscale Funnel the first sign-in is
	// not refused for the missing second factor (the session then has to set one up). A shared, multi-use link does
	// not: its account first signs in at the home or VPN address.
	res, err := h.d.Auth.Login(ctx, core.LoginInput{Username: u.Username, Password: in.Password, AfterInvite: inv.MaxUses <= 1}, meta)
	if err != nil {
		h.logger().Warn("sign-in after accepting an invitation failed", "user", u.ID, "err", err)
		httpx.Created(w, core.LoginResult{User: u})
		return
	}
	h.setSession(w, res)
	httpx.Created(w, res)
}
