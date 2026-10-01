package authapi_test

import (
	"net/http"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ratelimit"
)

// TestOpeningTheSignInPageKeepsTheSignInAllowance: the sign-in page starts
// a passkey ceremony (conditional mediation) on every load and the invite
// page reads its invitation; neither checks a credential, so reloading them
// must not use up the per-IP allowance of the real attempts
// (ratelimit.login_per_min) — they have the larger login_start bucket, which
// is still bounded.
func TestOpeningTheSignInPageKeepsTheSignInAllowance(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "yuki", pw, core.RoleMember)
	e.Users.AddInvite("invtoken456", core.RoleMember, e.Clock.Now().Add(24*time.Hour))
	e.Settings.Put("ratelimit.login_per_min", 3)
	e.Limiter.ApplySettings()
	c := newClient(t, h)
	// More page loads than the sign-in allowance, well within the start allowance.
	for i := range 5 {
		decode[core.PasskeyBegin](t, c.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{}), http.StatusOK)
		if i < 2 {
			decode[core.Invite](t, c.do(http.MethodGet, "/auth/invite/invtoken456", nil), http.StatusOK)
		}
	}
	// The first real attempt goes through.
	c.login("yuki", pw)
	// The start bucket is bounded too: 3 × LoginStartFactor in all.
	d := newClient(t, h)
	d.ip = "192.0.2.77"
	for range 3 * ratelimit.LoginStartFactor {
		decode[core.PasskeyBegin](t, d.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{}), http.StatusOK)
	}
	errCode(t, d.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{}), http.StatusTooManyRequests, "rate_limited")
	errCode(t, d.do(http.MethodGet, "/auth/invite/invtoken456", nil), http.StatusTooManyRequests, "rate_limited")
	// …and it is not the sign-in allowance: the password still works from that address.
	d.login("yuki", pw)
}
