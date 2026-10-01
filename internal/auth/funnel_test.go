package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/auth"
	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
	"fileparcel/internal/ratelimit"
)

// Sign-in over Tailscale Funnel (DESIGN §10.6).

var funnelClient = netip.MustParseAddr("2001:db8:1:2::9")

// funnelMeta and funnelCtx describe a request of the Funnel ingress
// listener (as httpx.Meta and internal/server leave it).
var funnelMeta = core.ReqMeta{IP: funnelClient, UserAgent: "funnel-test", RequestID: "req-f", Ingress: core.IngressFunnel}

func funnelCtx(ctx context.Context, kind string) context.Context {
	return core.WithIngress(ctx, &core.IngressInfo{Kind: kind, ClientIP: funnelClient, Host: "node.tail.ts.net"})
}

// auditDetail reads one detail of an audit entry.
func auditDetail(e core.AuditEntry, key string) any {
	m, _ := e.Details.(map[string]any)
	return m[key]
}

func funnelLogin(e *authtest.Env, user, pass string) (*core.LoginResult, error) {
	return e.Auth.Login(funnelCtx(context.Background(), core.IngressFunnel), core.LoginInput{Username: user, Password: pass}, funnelMeta)
}

// ingressRequest is a request of kind's ingress listener carrying the
// session token or the API token.
func ingressRequest(kind, session, bearer string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.RemoteAddr = netip.AddrPortFrom(funnelClient, 0).String()
	if session != "" {
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if kind != "" {
		r = r.WithContext(funnelCtx(r.Context(), kind))
	}
	return r
}

func TestFunnelLoginRequiresSecondFactor(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	u := e.AddUser(t, "nomfa", pw, core.RoleMember)
	e.AddUser(t, "mfa", pw, core.RoleMember)
	secret, _ := enrollTOTP(t, e, "mfa")

	// A correct password of an account without 2FA: the same 401 as a
	// wrong one, audited as denied, not counted against the account.
	_, errRight := funnelLogin(e, "nomfa", pw)
	_, errWrong := funnelLogin(e, "nomfa", "wrong wrong wrong")
	_, errNobody := funnelLogin(e, "nobody-here", pw)
	if !isCode(errRight, core.ErrUnauthorized) || !isCode(errWrong, core.ErrUnauthorized) || errRight.Error() != errWrong.Error() ||
		errNobody == nil || errNobody.Error() != errRight.Error() {
		t.Fatalf("answers differ: %v / %v / %v", errRight, errWrong, errNobody)
	}
	// That one answer says what a new account has to do (it is the same for every failure, so it tells
	// nothing about the password); off Funnel the answer stays the plain one.
	if msg := errRight.Error(); !strings.Contains(msg, "two-factor authentication") || !strings.Contains(msg, "Settings → Security") {
		t.Fatalf("the Funnel answer does not explain the second factor: %q", msg)
	}
	_, errLAN := e.Auth.Login(context.Background(), core.LoginInput{Username: "nobody-here", Password: "wrong wrong wrong"}, core.ReqMeta{IP: funnelClient})
	if errLAN == nil || strings.Contains(errLAN.Error(), "two-factor") {
		t.Fatalf("LAN answer: %v", errLAN)
	}
	ents := e.Audit.Entries(core.ActAuthLogin, core.OutcomeDenied)
	if len(ents) != 1 || auditDetail(ents[0], "reason") != "funnel_requires_2fa" || ents[0].ActorID != u.ID ||
		ents[0].IP != funnelClient.String() {
		t.Fatalf("denied audit %+v", ents)
	}
	got, _ := e.Users.Get(context.Background(), u.ID)
	if got.FailedLogins != 0 || got.LockedUntil != nil {
		t.Fatalf("Funnel attempts counted against the account: %+v", got)
	}
	// The wrong password took a token of the account's Funnel bucket; the
	// correct one did not.
	if left := e.Limiter.Tokens(ratelimit.BucketAuthFunnelUser, u.ID); left < float64(ratelimit.AuthFunnelUserBurst)-1.01 ||
		left > float64(ratelimit.AuthFunnelUserBurst)-0.99 {
		t.Fatalf("funnel bucket left %v", left)
	}
	// The same account signs in over the LAN, and over Tailscale Serve.
	login(t, e, "nomfa", pw)
	if _, err := e.Auth.Login(funnelCtx(context.Background(), core.IngressServe), core.LoginInput{Username: "nomfa", Password: pw},
		core.ReqMeta{IP: funnelClient, Ingress: core.IngressServe}); err != nil {
		t.Fatalf("serve login: %v", err)
	}
	// An account with TOTP gets the second-factor step over Funnel.
	res, err := funnelLogin(e, "mfa", pw)
	if err != nil || !res.MFARequired {
		t.Fatalf("mfa account over funnel: %+v %v", res, err)
	}
	p, err := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, res.Token, ""))
	if err != nil || p == nil || p.AuthLevel != core.AuthLevelPassword {
		t.Fatalf("pending principal %+v %v", p, err)
	}
	full, err := e.Auth.VerifyTOTP(funnelCtx(context.Background(), core.IngressFunnel), p, code(t, secret, e.Clock.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if pf, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, full.Token, "")); !pf.Full() {
		t.Fatalf("full principal over funnel: %+v", pf)
	}
	// The sign-in right after accepting an invitation is not refused (the invitation proved the person); its
	// session can only set up a second factor over Funnel. Clients cannot claim it: the flag is not JSON.
	inv, err := e.Auth.Login(funnelCtx(context.Background(), core.IngressFunnel),
		core.LoginInput{Username: "nomfa", Password: pw, AfterInvite: true}, funnelMeta)
	if err != nil || inv.Token == "" || !inv.EnrollRequired {
		t.Fatalf("sign-in after an invitation over funnel: %+v %v", inv, err)
	}
	// the exception is audited
	if ok := func() bool {
		for _, a := range e.Audit.Entries(core.ActAuthLogin, core.OutcomeSuccess) {
			if auditDetail(a, "after_invite") == true && auditDetail(a, "ingress") == core.IngressFunnel {
				return true
			}
		}
		return false
	}(); !ok {
		t.Fatalf("the sign-in after an invitation over funnel is not audited as such: %+v", e.Audit.Entries(core.ActAuthLogin, core.OutcomeSuccess))
	}
	if pi, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, inv.Token, "")); pi == nil || pi.Full() || !pi.EnrollRequired {
		t.Fatalf("session after an invitation over funnel: %+v", pi)
	}
	var claimed core.LoginInput
	if err := json.Unmarshal([]byte(`{"username":"nomfa","AfterInvite":true,"after_invite":true}`), &claimed); err != nil || claimed.AfterInvite {
		t.Fatalf("AfterInvite came from JSON: %+v %v", claimed, err)
	}
	// funnel.require_2fa off: accounts without 2FA sign in over Funnel too, and a wrong password gets the plain
	// answer.
	e.Settings.Put("funnel.require_2fa", false)
	if _, err := funnelLogin(e, "nomfa", pw); err != nil {
		t.Fatalf("require_2fa off: %v", err)
	}
	if _, err := funnelLogin(e, "nomfa", "wrong wrong wrong"); err == nil || strings.Contains(err.Error(), "two-factor") {
		t.Fatalf("require_2fa off, wrong password: %v", err)
	}
}

func TestFunnelFailuresNeverLockTheAccount(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	u := e.AddUser(t, "vic", pw, core.RoleMember)
	enrollTOTP(t, e, "vic")
	for i := 0; i < ratelimit.AuthFunnelUserBurst; i++ {
		if _, err := funnelLogin(e, "vic", "guess guess guess"); !isCode(err, core.ErrUnauthorized) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	got, _ := e.Users.Get(context.Background(), u.ID)
	if got.FailedLogins != 0 || got.LockedUntil != nil || e.Audit.Count(core.ActAuthLockout, "") != 0 {
		t.Fatalf("Funnel failures reached the lockout: %+v", got)
	}
	// The bucket is empty: even the right password gets the uniform 401.
	_, err := funnelLogin(e, "vic", pw)
	if !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("limited account: %v", err)
	}
	var reasons []any
	for _, en := range e.Audit.Entries(core.ActAuthLogin, core.OutcomeDenied) {
		reasons = append(reasons, auditDetail(en, "reason"))
	}
	if len(reasons) != 1 || reasons[0] != "funnel_user_limited" {
		t.Fatalf("denied reasons %v", reasons)
	}
	// Over the LAN the account is fine.
	if res := login(t, e, "vic", pw); !res.MFARequired {
		t.Fatalf("LAN login: %+v", res)
	}
	// Two failures an hour come back.
	e.Clock.Advance(31 * time.Minute)
	if res, err := funnelLogin(e, "vic", pw); err != nil || !res.MFARequired {
		t.Fatalf("after half an hour: %+v %v", res, err)
	}
	// The LAN still counts failures towards the lockout.
	for range 3 {
		_, _ = e.Auth.Login(context.Background(), core.LoginInput{Username: "vic", Password: "nope nope nope"}, clientMeta)
	}
	if got, _ := e.Users.Get(context.Background(), u.ID); got.LockedUntil == nil {
		t.Fatal("LAN failures no longer lock the account")
	}
}

func TestFunnelMFAFailuresEndThePendingSession(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	u := e.AddUser(t, "wes", pw, core.RoleMember)
	secret, _ := enrollTOTP(t, e, "wes")
	res, err := funnelLogin(e, "wes", pw)
	if err != nil || !res.MFARequired {
		t.Fatalf("login: %+v %v", res, err)
	}
	p, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, res.Token, ""))
	bad := "111111"
	if bad == code(t, secret, e.Clock.Now()) {
		bad = "222222"
	}
	ctx := core.WithPrincipal(funnelCtx(context.Background(), core.IngressFunnel), p)
	for i := 0; i < ratelimit.AuthFunnelUserBurst; i++ {
		if _, err := e.Auth.VerifyTOTP(ctx, p, bad); !isCode(err, core.ErrInvalid) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	// Three wrong codes would have locked the account on the LAN.
	if got, _ := e.Users.Get(context.Background(), u.ID); got.FailedLogins != 0 || got.LockedUntil != nil {
		t.Fatalf("lockout counter moved: %+v", got)
	}
	if q, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, res.Token, "")); q == nil {
		t.Fatal("pending session ended before the bucket was empty")
	}
	// The failure that finds the bucket empty ends the pending session.
	if _, err := e.Auth.VerifyTOTP(ctx, p, bad); err == nil {
		t.Fatal("bad code accepted")
	}
	if q, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, res.Token, "")); q != nil {
		t.Fatal("pending session survived the empty Funnel bucket")
	}
}

func TestFunnelPrincipalsWithoutSecondFactor(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	u := e.AddUser(t, "sam", pw, core.RoleMember)
	e.AddUser(t, "tia", pw, core.RoleMember)
	enrollTOTP(t, e, "tia")
	// A session from FileParcel's own port reaches the Funnel address
	// (cookies ignore ports): there it may only enroll a second factor.
	sess := login(t, e, "sam", pw).Token
	for kind, want := range map[string]bool{"": true, core.IngressServe: true, core.IngressFunnel: false} {
		p, err := e.Auth.Authenticate(ingressRequest(kind, sess, ""))
		if err != nil || p == nil || p.Full() != want || p.EnrollRequired == want {
			t.Errorf("session via %q: %+v %v", kind, p, err)
		}
	}
	// The principal's address is the Funnel client's, not the socket's.
	p, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, sess, ""))
	if p.IP != funnelClient {
		t.Fatalf("principal IP %v", p.IP)
	}
	// Its own 2FA status says so (the web app then opens the set-up page right away instead of the file list);
	// off Funnel, and for somebody else's account, the account's own policy applies.
	overFunnel := core.WithPrincipal(funnelCtx(context.Background(), core.IngressFunnel), p)
	// (FunnelRequired, while Required stays the account's own policy, off here).
	if st, err := e.Auth.MFAStatus(overFunnel, u.ID); err != nil || !st.FunnelRequired || !st.EnrollRequired || st.Required {
		t.Fatalf("own status over funnel: %+v %v", st, err)
	}
	if st, err := e.Auth.MFAStatus(core.WithPrincipal(context.Background(), p), u.ID); err != nil || st.FunnelRequired || st.EnrollRequired {
		t.Fatalf("own status off funnel: %+v %v", st, err)
	}
	tia, _ := e.Users.GetByUsername(context.Background(), "tia")
	if st, err := e.Auth.MFAStatus(overFunnel, tia.ID); err != nil || st.FunnelRequired {
		t.Fatalf("another account's status over funnel: %+v %v", st, err)
	}
	// An account with a second factor is unaffected.
	res := login(t, e, "tia", pw)
	if pt, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, res.Token, "")); pt == nil || pt.EnrollRequired {
		t.Fatalf("pending tia: %+v", pt)
	}
	// Personal access tokens of an account without 2FA are not full over
	// Funnel either; the token records the Funnel client's address.
	full := authenticate(t, e, sess)
	_, secret, err := e.Auth.CreateToken(context.Background(), full, core.TokenInput{Name: "ci", Scopes: []string{"files:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if bp, err := e.Auth.Authenticate(ingressRequest("", "", secret)); err != nil || !bp.Full() {
		t.Fatalf("token over the LAN: %+v %v", bp, err)
	}
	bp, err := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, "", secret))
	if err != nil || bp == nil || bp.Full() || !bp.EnrollRequired || bp.IP != funnelClient {
		t.Fatalf("token over funnel: %+v %v", bp, err)
	}
	list, _ := e.Auth.ListTokens(context.Background(), u.ID)
	if len(list) != 1 || list[0].LastUsedIP != funnelClient.String() {
		t.Fatalf("token last_used_ip %+v", list)
	}
	// A bad token is still refused (no principal to adjust).
	if _, err := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, "", secret+"x")); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("bad token: %v", err)
	}
	// require_2fa off for Funnel: full again.
	e.Settings.Put("funnel.require_2fa", false)
	if p, _ := e.Auth.Authenticate(ingressRequest(core.IngressFunnel, sess, "")); !p.Full() {
		t.Fatalf("require_2fa off: %+v", p)
	}
}
