package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"fileparcel/internal/auth"
	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
)

func TestMain(m *testing.M) {
	restore := authtest.FastHashing()
	code := m.Run()
	restore()
	os.Exit(code)
}

const pw = "correct horse battery staple"

var clientMeta = core.ReqMeta{IP: netip.MustParseAddr("192.0.2.1"), UserAgent: "auth-test", RequestID: "req1"}

// request returns a request carrying the session token (if any).
func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	if token != "" {
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	return r
}

// authenticate resolves a session token (nil = anonymous).
func authenticate(t *testing.T, e *authtest.Env, token string) *core.Principal {
	t.Helper()
	p, err := e.Auth.Authenticate(request(token))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return p
}

func ctxWith(p *core.Principal) context.Context { return core.WithPrincipal(context.Background(), p) }

// elevated returns a copy of p inside a step-up window (as after POST
// /auth/elevate), which enrolling a second factor or a passkey needs.
func elevated(e *authtest.Env, p *core.Principal) *core.Principal {
	q := p.Clone()
	q.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	return q
}

func login(t *testing.T, e *authtest.Env, user, pass string) *core.LoginResult {
	t.Helper()
	res, err := e.Auth.Login(context.Background(), core.LoginInput{Username: user, Password: pass}, clientMeta)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	return res
}

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func isCode(err error, base *core.Error) bool { return errors.Is(err, base) }

// enrollTOTP signs u in (no MFA yet) and turns on TOTP (inside a step-up
// window); returns the secret and the recovery codes.
func enrollTOTP(t *testing.T, e *authtest.Env, username string) (string, []string) {
	t.Helper()
	res := login(t, e, username, pw)
	p := elevated(e, authenticate(t, e, res.Token))
	en, err := e.Auth.TOTPBegin(context.Background(), p)
	if err != nil {
		t.Fatalf("totp begin: %v", err)
	}
	if !strings.HasPrefix(en.OTPAuthURI, "otpauth://totp/") || !strings.HasPrefix(en.QRDataURI, "data:image/svg+xml;base64,") || en.Secret == "" {
		t.Fatalf("enrollment: %+v", en)
	}
	codes, err := e.Auth.TOTPConfirm(context.Background(), p, code(t, en.Secret, e.Clock.Now()))
	if err != nil {
		t.Fatalf("totp confirm: %v", err)
	}
	if len(codes) != auth.RecoveryCodeCount {
		t.Fatalf("got %d recovery codes", len(codes))
	}
	e.Clock.Advance(30 * time.Second) // the confirm code's step is used
	return en.Secret, codes
}

// ---------- passwords ----------

func TestPasswordHashVerifyRehash(t *testing.T) {
	e := authtest.New(t)
	phc, err := e.Auth.HashPassword(pw)
	if err != nil || !strings.HasPrefix(phc, "$argon2id$v=19$") {
		t.Fatalf("hash %q %v", phc, err)
	}
	if ok, re := e.Auth.VerifyPassword(phc, pw); !ok || re {
		t.Fatalf("verify: ok=%v rehash=%v", ok, re)
	}
	for _, bad := range []string{"", "wrong", strings.Repeat("x", auth.MaxPasswordBytes+1)} {
		if ok, _ := e.Auth.VerifyPassword(phc, bad); ok {
			t.Errorf("verified %q", bad)
		}
	}
	if ok, _ := e.Auth.VerifyPassword("", pw); ok {
		t.Error("empty hash verified")
	}
	if ok, _ := e.Auth.VerifyPassword("$argon2id$garbage", pw); ok {
		t.Error("malformed hash verified")
	}
	if _, err := e.Auth.HashPassword(strings.Repeat("x", auth.MaxPasswordBytes+1)); err == nil {
		t.Error("oversized password hashed")
	}

	// A hash with other parameters verifies, needs a rehash, and is replaced on login.
	old, err := crypt.HashPasswordParams(pw, crypt.Argon2Params{MemoryKiB: 128, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	if ok, re := e.Auth.VerifyPassword(old, pw); !ok || !re {
		t.Fatalf("old params: ok=%v rehash=%v", ok, re)
	}
	u := e.AddUser(t, "alice", "", core.RoleMember)
	if err := e.Users.SetPasswordHash(context.Background(), nil, u.ID, old, false); err != nil {
		t.Fatal(err)
	}
	login(t, e, "alice", pw)
	u2, _ := e.Users.Get(context.Background(), u.ID)
	if u2.PasswordHash == old {
		t.Fatal("hash was not upgraded on login")
	}
	if ok, re := e.Auth.VerifyPassword(u2.PasswordHash, pw); !ok || re {
		t.Fatalf("upgraded hash: ok=%v rehash=%v", ok, re)
	}
}

func TestPasswordPolicy(t *testing.T) {
	e := authtest.New(t)
	u := &core.User{Username: "alice", Email: "alice.smith@example.com"}
	tests := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"passphrase", pw, true},
		{"too short", "Xy7$kLp2", false},
		{"exactly the minimum", "Xy7$kLp2Qw9!", true},
		{"contains username", "my-ALICE-rocks-2026", false},
		{"contains e-mail local part", "hello alice.smith 42", false},
		{"common", "Password2024!", false},
		{"common leet", "P@ssw0rd123456", false},
		{"few distinct characters", "abababababababab", false},
		{"control character", "correct horse\x00battery", false},
		{"invalid utf-8", "correct horse \xff battery", false},
		{"too long", strings.Repeat("ab1-", 300), false},
		{"unicode counts runes", "ÄÖÜäöüßéèêëô", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := e.Auth.CheckPasswordPolicy(tc.pw, u)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && (!isCode(err, core.ErrInvalid) || core.AsError(err).Field != "password") {
				t.Fatalf("want 422 on field password, got %#v", core.AsError(err))
			}
		})
	}
	e.Settings.Put("auth.password_min", 20)
	if err := e.Auth.CheckPasswordPolicy("Xy7$kLp2Qw9!Zz", nil); err == nil {
		t.Fatal("auth.password_min not applied")
	}
}

// ---------- login, sessions, lockout ----------

func TestLoginWithoutMFA(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "bob", pw, core.RoleMember)
	res := login(t, e, "BOB", pw) // usernames are case-insensitive
	if res.MFARequired || res.User == nil || res.User.ID != u.ID || res.Token == "" || res.CSRF == "" || !res.CookieExpires.IsZero() {
		t.Fatalf("result: %+v", res)
	}
	if res.EnrollRequired {
		t.Fatal("members are not in the default 2FA policy")
	}
	p := authenticate(t, e, res.Token)
	if p == nil || p.UserID != u.ID || p.Via != core.ViaSession || p.AuthLevel != core.AuthLevelFull || !p.Full() {
		t.Fatalf("principal: %+v", p)
	}
	if got := e.Auth.CSRFToken(p); got != res.CSRF || !e.Auth.CheckCSRF(p, res.CSRF) {
		t.Fatalf("csrf %q vs %q", got, res.CSRF)
	}
	if e.Auth.CheckCSRF(p, res.CSRF+"x") || e.Auth.CheckCSRF(p, "") || e.Auth.CheckCSRF(&core.Principal{Via: core.ViaToken}, res.CSRF) {
		t.Fatal("bad CSRF accepted")
	}
	if n := e.Audit.Count(core.ActAuthLogin, core.OutcomeSuccess); n != 1 {
		t.Fatalf("auth.login audits: %d", n)
	}
	// admins must enroll under the default policy
	e.AddUser(t, "root", pw, core.RoleAdmin)
	res = login(t, e, "root", pw)
	if !res.EnrollRequired || !authenticate(t, e, res.Token).EnrollRequired {
		t.Fatal("admin without 2FA must get EnrollRequired")
	}
	e.Settings.Put("auth.require_2fa", "off")
	if authenticate(t, e, res.Token).EnrollRequired {
		t.Fatal("policy off: no enrollment")
	}
}

func TestLoginRevokesPreviousSession(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "bob", pw, core.RoleMember)
	first := login(t, e, "bob", pw)
	p := authenticate(t, e, first.Token)
	res, err := e.Auth.Login(ctxWith(p), core.LoginInput{Username: "bob", Password: pw}, clientMeta)
	if err != nil {
		t.Fatal(err)
	}
	if authenticate(t, e, first.Token) != nil {
		t.Fatal("the replaced session still works")
	}
	if authenticate(t, e, res.Token) == nil {
		t.Fatal("new session does not work")
	}
}

func TestLoginUniformFailures(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "bob", pw, core.RoleMember)
	dis := e.AddUser(t, "dis", pw, core.RoleMember)
	_ = e.Users.SetStatus(context.Background(), nil, dis.ID, core.UserDisabled)
	nopw := e.AddUser(t, "nopw", "", core.RoleMember)
	_ = nopw
	var msgs []string
	for _, in := range []core.LoginInput{
		{Username: "nobody", Password: pw},
		{Username: "bob", Password: "wrong password here"},
		{Username: "dis", Password: pw},
		{Username: "nopw", Password: pw},
		{Username: "", Password: pw},
		{Username: "bob", Password: ""},
	} {
		_, err := e.Auth.Login(context.Background(), in, core.ReqMeta{IP: netip.MustParseAddr("198.51.100.9")})
		if !isCode(err, core.ErrUnauthorized) {
			t.Fatalf("%+v: %v", in, err)
		}
		msgs = append(msgs, err.Error())
	}
	for _, m := range msgs {
		if m != msgs[0] {
			t.Fatalf("messages differ: %q", msgs)
		}
	}
	if e.Audit.Count(core.ActAuthLogin, core.OutcomeFailure) < 4 {
		t.Fatal("failures not audited")
	}
}

func TestLockoutBackoff(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	u := e.AddUser(t, "carol", pw, core.RoleMember)
	fail := func() {
		t.Helper()
		if _, err := e.Auth.Login(context.Background(), core.LoginInput{Username: "carol", Password: "nope nope nope"}, clientMeta); !isCode(err, core.ErrUnauthorized) {
			t.Fatalf("want 401, got %v", err)
		}
	}
	for range 3 {
		fail()
	}
	got, _ := e.Users.Get(context.Background(), u.ID)
	if got.LockedUntil == nil || !got.LockedUntil.Equal(e.Clock.Now().Add(15*time.Minute)) {
		t.Fatalf("locked until %v", got.LockedUntil)
	}
	if e.Audit.Count(core.ActAuthLockout, "") != 1 {
		t.Fatal("auth.lockout not audited")
	}
	// the right password does not help while locked, and the error is uniform
	if _, err := e.Auth.Login(context.Background(), core.LoginInput{Username: "carol", Password: pw}, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("locked login: %v", err)
	}
	e.Clock.Advance(15*time.Minute + time.Second)
	for range 3 {
		fail()
	}
	got, _ = e.Users.Get(context.Background(), u.ID)
	if !got.LockedUntil.Equal(e.Clock.Now().Add(30 * time.Minute)) {
		t.Fatalf("second lock should double: %v", got.LockedUntil.Sub(e.Clock.Now()))
	}
	e.Clock.Advance(31 * time.Minute)
	login(t, e, "carol", pw)
	got, _ = e.Users.Get(context.Background(), u.ID)
	if got.FailedLogins != 0 || got.LockLevel != 0 {
		t.Fatalf("success must reset the counters: %+v", got)
	}
}

// A brute-forced POST /auth/login arrives from a signed-out browser, so
// there is no context principal: the client address has to travel in the
// request meta, or the auth.lockout audit row and the "account locked"
// security e-mail (users.RecordLoginFailure) name no address at all —
// exactly the case they exist for.
func TestLockoutNamesTheClientAddress(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.AddUser(t, "wendy", pw, core.RoleMember)
	attacker := core.ReqMeta{IP: netip.MustParseAddr("203.0.113.9"), UserAgent: "curl/8", RequestID: "req-brute"}
	for range 3 {
		if _, err := e.Auth.Login(context.Background(), core.LoginInput{Username: "wendy", Password: "wrong wrong wrong"},
			attacker); !isCode(err, core.ErrUnauthorized) {
			t.Fatalf("want 401, got %v", err)
		}
	}
	ents := e.Audit.Entries(core.ActAuthLockout, "")
	if len(ents) != 1 {
		t.Fatalf("auth.lockout entries: %d", len(ents))
	}
	if ents[0].IP != "203.0.113.9" || ents[0].UserAgent != "curl/8" || ents[0].RequestID != "req-brute" {
		t.Fatalf("lockout lost the client: ip=%q ua=%q req=%q", ents[0].IP, ents[0].UserAgent, ents[0].RequestID)
	}
}

func TestFailureRateLimitPerIP(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("ratelimit.login_per_min", 3)
	e.Settings.Put("auth.lockout_threshold", 100)
	e.AddUser(t, "dave", pw, core.RoleMember)
	attacker := core.ReqMeta{IP: netip.MustParseAddr("203.0.113.5")}
	for range 3 {
		_, _ = e.Auth.Login(context.Background(), core.LoginInput{Username: "dave", Password: "guess guess guess"}, attacker)
	}
	if _, err := e.Auth.Login(context.Background(), core.LoginInput{Username: "dave", Password: pw}, attacker); !isCode(err, core.ErrRateLimited) {
		t.Fatalf("want rate limited, got %v", err)
	}
	login(t, e, "dave", pw) // other IP unaffected
	e.Clock.Advance(time.Minute)
	if _, err := e.Auth.Login(context.Background(), core.LoginInput{Username: "dave", Password: pw}, attacker); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "erin", pw, core.RoleMember)
	e.Settings.Put("auth.session_idle_min", 60)

	// idle expiry
	res := login(t, e, "erin", pw)
	e.Clock.Advance(59 * time.Minute)
	if authenticate(t, e, res.Token) == nil {
		t.Fatal("expired before the idle timeout")
	}
	e.Clock.Advance(59 * time.Minute) // activity above extended the idle window
	if authenticate(t, e, res.Token) == nil {
		t.Fatal("activity did not extend the idle window")
	}
	e.Clock.Advance(61 * time.Minute)
	if authenticate(t, e, res.Token) != nil {
		t.Fatal("idle session still valid")
	}

	// absolute expiry of a browser session: 24 h even with activity
	res = login(t, e, "erin", pw)
	for range 24 {
		e.Clock.Advance(59 * time.Minute)
		authenticate(t, e, res.Token)
	}
	e.Clock.Advance(time.Hour)
	if authenticate(t, e, res.Token) != nil {
		t.Fatal("browser session outlived 24 h")
	}

	// remember me: auth.session_max_days and a persistent cookie
	e.Settings.Put("auth.session_max_days", 2)
	r, err := e.Auth.Login(context.Background(), core.LoginInput{Username: "erin", Password: pw, Remember: true}, clientMeta)
	if err != nil {
		t.Fatal(err)
	}
	if !r.CookieExpires.Equal(e.Clock.Now().Add(48 * time.Hour)) {
		t.Fatalf("cookie expiry %v", r.CookieExpires)
	}
	if c := e.Auth.SessionCookie(r.Token, r.CookieExpires); c.MaxAge != 48*3600 {
		t.Fatalf("cookie max-age %d", c.MaxAge)
	}
	for range 48 {
		e.Clock.Advance(59 * time.Minute)
		authenticate(t, e, r.Token)
	}
	e.Clock.Advance(3 * time.Hour)
	if authenticate(t, e, r.Token) != nil {
		t.Fatal("remembered session outlived session_max_days")
	}

	// malformed and unknown cookies are anonymous
	for _, tok := range []string{"x", strings.Repeat("A", 43), "<script>"} {
		if authenticate(t, e, tok) != nil {
			t.Fatalf("token %q authenticated", tok)
		}
	}
}

func TestLogoutListAndRevokeSessions(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "fay", pw, core.RoleMember)
	other := e.AddUser(t, "gus", pw, core.RoleMember)
	a, b, c := login(t, e, "fay", pw), login(t, e, "fay", pw), login(t, e, "fay", pw)
	pa := authenticate(t, e, a.Token)
	list, err := e.Auth.ListSessions(ctxWith(pa), u.ID)
	if err != nil || len(list) != 3 {
		t.Fatalf("sessions: %v %d", err, len(list))
	}
	cur := 0
	for _, s := range list {
		if s.Current {
			cur++
			if s.ID != pa.SessionID {
				t.Fatal("wrong current session")
			}
		}
		if len(s.CSRFSecret) != 0 || s.IP != "192.0.2.1" || s.UserAgent != "auth-test" {
			t.Fatalf("session view: %+v", s)
		}
	}
	if cur != 1 {
		t.Fatalf("%d current sessions", cur)
	}
	pb := authenticate(t, e, b.Token)
	// another member cannot revoke fay's sessions
	pg := authenticate(t, e, login(t, e, "gus", pw).Token)
	if err := e.Auth.RevokeSession(ctxWith(pg), pg, u.ID, pb.SessionID); !isCode(err, core.ErrForbidden) {
		t.Fatalf("foreign revoke: %v", err)
	}
	if err := e.Auth.RevokeSession(ctxWith(pg), pg, other.ID, pb.SessionID); !isCode(err, core.ErrNotFound) {
		t.Fatalf("session of another user: %v", err)
	}
	if err := e.Auth.RevokeSession(ctxWith(pa), pa, u.ID, pb.SessionID); err != nil {
		t.Fatal(err)
	}
	if authenticate(t, e, b.Token) != nil || e.Auth.CheckCSRF(pb, b.CSRF) {
		t.Fatal("revoked session still valid")
	}
	if err := e.Auth.RevokeAllSessions(ctxWith(pa), pa, u.ID, pa.SessionID); err != nil {
		t.Fatal(err)
	}
	if authenticate(t, e, c.Token) != nil || authenticate(t, e, a.Token) == nil {
		t.Fatal("revoke-others revoked the wrong sessions")
	}
	if err := e.Auth.Logout(ctxWith(pa), pa); err != nil {
		t.Fatal(err)
	}
	if authenticate(t, e, a.Token) != nil {
		t.Fatal("logged-out session still valid")
	}
	if e.Audit.Count(core.ActAuthLogout, "") != 1 || e.Audit.Count(core.ActSessionRevoke, "") != 2 {
		t.Fatalf("audit: logout %d revoke %d", e.Audit.Count(core.ActAuthLogout, ""), e.Audit.Count(core.ActSessionRevoke, ""))
	}
	if err := e.Auth.Logout(context.Background(), &core.Principal{Via: core.ViaToken}); err != nil {
		t.Fatal("token logout must be a no-op")
	}
}

func TestTrustedPrincipalPassthrough(t *testing.T) {
	e := authtest.New(t)
	sys := core.SystemPrincipal(core.ViaSocket)
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctxWith(sys))
	r.Header.Set("Authorization", "Bearer garbage")
	p, err := e.Auth.Authenticate(r)
	if err != nil || p == nil || p.Via != core.ViaSocket || !p.IsSystem() || p == sys {
		t.Fatalf("got %+v %v", p, err)
	}
	// a session principal in the context is not trusted
	r = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctxWith(&core.Principal{UserID: "x", Via: core.ViaSession}))
	if p, _ := e.Auth.Authenticate(r); p != nil {
		t.Fatal("untrusted context principal returned")
	}
}

// ---------- TOTP & recovery ----------

func TestTOTPLoginFlow(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "hank", pw, core.RoleMember)
	secret, _ := enrollTOTP(t, e, "hank")

	res := login(t, e, "hank", pw)
	if !res.MFARequired || !slices.Equal(res.Methods, []string{core.MFATOTP, core.MFARecovery}) || res.User != nil {
		t.Fatalf("login: %+v", res)
	}
	p := authenticate(t, e, res.Token)
	if p.AuthLevel != core.AuthLevelPassword || p.Full() {
		t.Fatalf("pending principal: %+v", p)
	}
	// wrong code
	if _, err := e.Auth.VerifyTOTP(context.Background(), p, "000000"); !isCode(err, core.ErrInvalid) && code(t, secret, e.Clock.Now()) != "000000" {
		t.Fatalf("wrong code: %v", err)
	}
	good := code(t, secret, e.Clock.Now())
	full, err := e.Auth.VerifyTOTP(context.Background(), p, good)
	if err != nil {
		t.Fatal(err)
	}
	if full.User == nil || full.User.ID != u.ID || full.Token == res.Token || full.CSRF == res.CSRF {
		t.Fatalf("completion must rotate token and CSRF: %+v", full)
	}
	if authenticate(t, e, res.Token) != nil {
		t.Fatal("pre-MFA token still valid after rotation")
	}
	pf := authenticate(t, e, full.Token)
	if !pf.Full() || pf.SessionID != p.SessionID {
		t.Fatalf("full principal: %+v", pf)
	}
	if _, err := e.Auth.VerifyTOTP(context.Background(), pf, good); !isCode(err, core.ErrConflict) {
		t.Fatalf("second verify on a full session: %v", err)
	}
	// replay of the same code on a new login is rejected
	res2 := login(t, e, "hank", pw)
	p2 := authenticate(t, e, res2.Token)
	if _, err := e.Auth.VerifyTOTP(context.Background(), p2, good); !isCode(err, core.ErrInvalid) {
		t.Fatalf("replay: %v", err)
	}
	e.Clock.Advance(30 * time.Second)
	if _, err := e.Auth.VerifyTOTP(context.Background(), p2, code(t, secret, e.Clock.Now())); err != nil {
		t.Fatalf("next step: %v", err)
	}
	if e.Audit.Count(core.ActAuthMFA, core.OutcomeSuccess) != 2 || e.Audit.Count(core.ActAuthMFA, core.OutcomeFailure) < 1 {
		t.Fatal("auth.mfa audit")
	}

	// the pending window is 10 minutes
	res3 := login(t, e, "hank", pw)
	p3 := authenticate(t, e, res3.Token)
	e.Clock.Advance(auth.PendingTTL + time.Second)
	if authenticate(t, e, res3.Token) != nil {
		t.Fatal("pending session outlived PendingTTL")
	}
	if _, err := e.Auth.VerifyTOTP(context.Background(), p3, code(t, secret, e.Clock.Now())); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("expired pending: %v", err)
	}
	if _, err := e.Auth.VerifyTOTP(context.Background(), nil, "123456"); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("nil principal: %v", err)
	}
}

func TestTOTPFailuresLockAndEndPendingSession(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.AddUser(t, "ivy", pw, core.RoleMember)
	secret, _ := enrollTOTP(t, e, "ivy")
	res := login(t, e, "ivy", pw)
	p := authenticate(t, e, res.Token)
	bad := "111111"
	if bad == code(t, secret, e.Clock.Now()) {
		bad = "222222"
	}
	for range 3 {
		if _, err := e.Auth.VerifyTOTP(context.Background(), p, bad); err == nil {
			t.Fatal("bad code accepted")
		}
	}
	if authenticate(t, e, res.Token) != nil {
		t.Fatal("pending session survived the lockout")
	}
	if _, err := e.Auth.Login(context.Background(), core.LoginInput{Username: "ivy", Password: pw}, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("locked account signed in: %v", err)
	}
}

func TestRecoveryCodesSingleUse(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "jack", pw, core.RoleMember)
	_, codes := enrollTOTP(t, e, "jack")
	res := login(t, e, "jack", pw)
	p := authenticate(t, e, res.Token)
	// lower case and without the dash work too
	full, err := e.Auth.VerifyRecovery(context.Background(), p, strings.ToLower(strings.ReplaceAll(codes[0], "-", "")))
	if err != nil || full.Session.MFAMethod != core.MFARecovery {
		t.Fatalf("recovery: %v %+v", err, full)
	}
	st, _ := e.Auth.MFAStatus(context.Background(), p.UserID)
	if st.RecoveryCodesLeft != auth.RecoveryCodeCount-1 {
		t.Fatalf("codes left %d", st.RecoveryCodesLeft)
	}
	res = login(t, e, "jack", pw)
	p = authenticate(t, e, res.Token)
	for _, c := range []string{codes[0], "AAAA-AAAA", "not a code"} {
		if _, err := e.Auth.VerifyRecovery(context.Background(), p, c); !isCode(err, core.ErrInvalid) {
			t.Fatalf("code %q: %v", c, err)
		}
	}
	if _, err := e.Auth.VerifyRecovery(context.Background(), p, codes[1]); err != nil {
		t.Fatalf("second code: %v", err)
	}
}

func TestTOTPManagement(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "kim", pw, core.RoleMember)
	res := login(t, e, "kim", pw)
	p := authenticate(t, e, res.Token)
	pe := elevated(e, p)
	ctx := context.Background()
	if _, err := e.Auth.TOTPConfirm(ctx, pe, "123456"); !isCode(err, core.ErrConflict) {
		t.Fatalf("confirm before begin: %v", err)
	}
	en, err := e.Auth.TOTPBegin(ctx, pe)
	if err != nil {
		t.Fatal(err)
	}
	// begin again replaces the pending secret
	en2, err := e.Auth.TOTPBegin(ctx, pe)
	if err != nil || en2.Secret == en.Secret {
		t.Fatalf("second begin: %v", err)
	}
	st, _ := e.Auth.MFAStatus(ctx, u.ID)
	if !st.TOTPPending || st.TOTPEnabled {
		t.Fatalf("status %+v", st)
	}
	if _, err := e.Auth.TOTPConfirm(ctx, pe, code(t, en.Secret, e.Clock.Now())); !isCode(err, core.ErrInvalid) {
		t.Fatalf("old secret confirmed: %v", err)
	}
	if _, err := e.Auth.TOTPConfirm(ctx, pe, code(t, en2.Secret, e.Clock.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Auth.TOTPBegin(ctx, pe); !isCode(err, core.ErrConflict) {
		t.Fatalf("begin while enabled: %v", err)
	}
	// the stored secret is field-encrypted and bound to the user id
	var enc string
	if err := e.DB.QueryRow(ctx, `SELECT secret_enc FROM totp_secrets WHERE user_id = ?`, u.ID).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, en2.Secret) || !strings.HasPrefix(enc, "v1:") {
		t.Fatalf("secret stored in clear: %q", enc)
	}
	if _, err := e.Keys.OpenField("totp_secrets.secret_enc|usr_other", enc); err == nil {
		t.Fatal("AAD not bound to the user")
	}
	// disabling needs elevation
	if err := e.Auth.TOTPDisable(ctx, p, u.ID); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("disable without elevation: %v", err)
	}
	if _, err := e.Auth.RegenerateRecovery(ctx, p); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("regenerate without elevation: %v", err)
	}
	codes, err := e.Auth.RegenerateRecovery(ctx, pe)
	if err != nil || len(codes) != auth.RecoveryCodeCount {
		t.Fatalf("regenerate: %v", err)
	}
	other := e.AddUser(t, "lee", pw, core.RoleMember)
	po := authenticate(t, e, login(t, e, "lee", pw).Token)
	po.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	if err := e.Auth.TOTPDisable(ctx, po, u.ID); !isCode(err, core.ErrForbidden) {
		t.Fatalf("foreign disable: %v", err)
	}
	if err := e.Auth.TOTPDisable(ctx, pe, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.TOTPDisable(ctx, pe, u.ID); !isCode(err, core.ErrNotFound) {
		t.Fatalf("second disable: %v", err)
	}
	st, _ = e.Auth.MFAStatus(ctx, u.ID)
	if st.TOTPEnabled || st.RecoveryCodesLeft != 0 {
		t.Fatalf("after disable: %+v", st)
	}
	_ = other
	if e.Audit.Count(core.ActMFATOTPEnable, "") != 1 || e.Audit.Count(core.ActMFATOTPDisable, "") != 1 || e.Audit.Count(core.ActMFARecoveryRegenerate, "") != 1 {
		t.Fatal("mfa audit")
	}
	// locked keys
	e.Keys.SetLocked(true)
	if _, err := e.Auth.TOTPBegin(ctx, pe); !isCode(err, core.ErrKeysLocked) {
		t.Fatalf("locked keys: %v", err)
	}
}

// A confirmed authenticator satisfies step-up, so setting one up needs an
// open step-up window: otherwise a hijacked (never elevated) session could
// add its own and elevate with it. A user who still has to enroll
// (EnrollRequired) steps up with the password first.
func TestTOTPEnrollmentNeedsStepUp(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.AddUser(t, "rhea", pw, core.RoleAdmin) // in the default 2FA policy
	res := login(t, e, "rhea", pw)
	p := authenticate(t, e, res.Token)
	ctx := context.Background()
	if !p.EnrollRequired {
		t.Fatal("admin without 2FA must get EnrollRequired")
	}
	if _, err := e.Auth.TOTPBegin(ctx, p); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("begin without step-up: %v", err)
	}
	en, err := e.Auth.TOTPBegin(ctx, elevated(e, p))
	if err != nil {
		t.Fatal(err)
	}
	// a window that closed during the setup refuses the confirmation and
	// keeps the pending secret, so the same code works after stepping up
	c := code(t, en.Secret, e.Clock.Now())
	if _, err := e.Auth.TOTPConfirm(ctx, p, c); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("confirm without step-up: %v", err)
	}
	if st, _ := e.Auth.MFAStatus(ctx, p.UserID); st.TOTPEnabled || !st.TOTPPending {
		t.Fatalf("status %+v", st)
	}
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{Password: pw}); err != nil {
		t.Fatalf("an enrolling user steps up with the password: %v", err)
	}
	p = authenticate(t, e, res.Token)
	codes, err := e.Auth.TOTPConfirm(ctx, p, c)
	if err != nil || len(codes) != auth.RecoveryCodeCount {
		t.Fatalf("confirm after step-up: %d codes, %v", len(codes), err)
	}
	if p = authenticate(t, e, res.Token); p.EnrollRequired {
		t.Fatal("still EnrollRequired after enrolling")
	}
}

// ---------- elevation, passwords ----------

func TestElevate(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	u := e.AddUser(t, "max", pw, core.RoleMember)
	secret, _ := enrollTOTP(t, e, "max")
	res := login(t, e, "max", pw)
	p := authenticate(t, e, res.Token)
	ctx := context.Background()
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{Password: pw}); !isCode(err, core.ErrMFARequired) {
		t.Fatalf("pending session elevated: %v", err)
	}
	full, err := e.Auth.VerifyTOTP(ctx, p, code(t, secret, e.Clock.Now()))
	if err != nil {
		t.Fatal(err)
	}
	e.Clock.Advance(30 * time.Second)
	p = authenticate(t, e, full.Token)
	if p.Elevated(e.Clock.Now()) {
		t.Fatal("elevated without step-up")
	}
	for _, in := range []core.ElevateInput{{}, {Password: pw, TOTP: "123456"}} {
		if err := e.Auth.Elevate(ctx, p, in); !isCode(err, core.ErrInvalid) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{Password: "wrong wrong wrong"}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("wrong password: %v", err)
	}
	if got, _ := e.Users.Get(ctx, u.ID); got.FailedLogins != 1 {
		t.Fatalf("failed elevation must count: %d", got.FailedLogins)
	}
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{Password: pw}); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.Users.Get(ctx, u.ID); got.FailedLogins != 0 {
		t.Fatalf("a successful step-up must reset the failure counter: %d", got.FailedLogins)
	}
	p = authenticate(t, e, full.Token)
	if !p.Elevated(e.Clock.Now()) || !p.ElevatedUntil.Equal(e.Clock.Now().Add(10*time.Minute)) {
		t.Fatalf("elevated until %v", p.ElevatedUntil)
	}
	e.Clock.Advance(11 * time.Minute)
	p = authenticate(t, e, full.Token)
	if p.Elevated(e.Clock.Now()) {
		t.Fatal("elevation outlived auth.stepup_min")
	}
	c := code(t, secret, e.Clock.Now())
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{TOTP: c}); err != nil {
		t.Fatalf("totp elevation: %v", err)
	}
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{TOTP: c}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("replayed totp elevation: %v", err)
	}
	// rotation keeps the CSRF token and the elevation
	rot, err := e.Auth.RotateSession(ctx, p)
	if err != nil || rot.Token == full.Token || rot.CSRF != full.CSRF || rot.Session.ElevatedUntil == nil {
		t.Fatalf("rotate: %v %+v", err, rot)
	}
	if authenticate(t, e, full.Token) != nil || !authenticate(t, e, rot.Token).Elevated(e.Clock.Now()) {
		t.Fatal("rotation")
	}
	if r, err := e.Auth.RotateSession(ctx, &core.Principal{Via: core.ViaToken}); r != nil || err != nil {
		t.Fatal("rotating a token principal must be a no-op")
	}
	// tokens cannot elevate; the system principal always is
	if err := e.Auth.Elevate(ctx, &core.Principal{UserID: u.ID, Via: core.ViaToken, AuthLevel: 2}, core.ElevateInput{Password: pw}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("token elevation: %v", err)
	}
	if err := e.Auth.Elevate(ctx, core.SystemPrincipal(core.ViaSocket), core.ElevateInput{}); err != nil {
		t.Fatal(err)
	}
	if e.Audit.Count(core.ActAuthElevate, core.OutcomeSuccess) != 2 || e.Audit.Count(core.ActAuthElevate, core.OutcomeFailure) != 2 {
		t.Fatalf("elevate audit %d/%d", e.Audit.Count(core.ActAuthElevate, core.OutcomeSuccess), e.Audit.Count(core.ActAuthElevate, core.OutcomeFailure))
	}
}

func TestChangePassword(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "nina", pw, core.RoleMember)
	a, b := login(t, e, "nina", pw), login(t, e, "nina", pw)
	pa := authenticate(t, e, a.Token)
	ctx := context.Background()
	const next = "a much better passphrase 2026"
	err := e.Auth.ChangePassword(ctx, pa, "wrong", next)
	if ae := core.AsError(err); ae == nil || ae.Field != "current_password" || ae.Status != 422 {
		t.Fatalf("wrong current: %#v", ae)
	}
	if got, _ := e.Users.Get(ctx, u.ID); got.FailedLogins != 1 {
		t.Fatalf("a wrong current password must count: %d", got.FailedLogins)
	}
	if err := e.Auth.ChangePassword(ctx, pa, pw, pw); !isCode(err, core.ErrInvalid) {
		t.Fatalf("same password: %v", err)
	}
	// the right current password proves the credential, even when the new
	// one is refused: the lockout counts consecutive failures
	if got, _ := e.Users.Get(ctx, u.ID); got.FailedLogins != 0 {
		t.Fatalf("a correct current password must reset the failure counter: %d", got.FailedLogins)
	}
	if err := e.Auth.ChangePassword(ctx, pa, pw, "password123456"); core.AsError(err) == nil || core.AsError(err).Field != "new_password" {
		t.Fatalf("policy: %v", err)
	}
	if err := e.Auth.ChangePassword(ctx, pa, pw, next); err != nil {
		t.Fatal(err)
	}
	if authenticate(t, e, a.Token) == nil || authenticate(t, e, b.Token) != nil {
		t.Fatal("password change must keep the current session and revoke the others")
	}
	login(t, e, "nina", next)
	if e.Audit.Count(core.ActUserPasswordChange, core.OutcomeSuccess) != 1 {
		t.Fatal("audit")
	}

	// admin reset
	admin := e.AddUser(t, "boss", pw, core.RoleAdmin)
	pb := authenticate(t, e, login(t, e, "boss", pw).Token)
	s := login(t, e, "nina", next)
	if err := e.Auth.AdminSetPassword(ctx, pb, u.ID, "brand new passphrase 77", true); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("reset without elevation: %v", err)
	}
	pb.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	pn := authenticate(t, e, s.Token)
	if err := e.Auth.AdminSetPassword(ctx, pn, admin.ID, "hijack the admin account", false); !isCode(err, core.ErrForbidden) {
		t.Fatalf("member resets admin: %v", err)
	}
	if err := e.Auth.AdminSetPassword(ctx, pb, u.ID, "brand new passphrase 77", true); err != nil {
		t.Fatal(err)
	}
	if authenticate(t, e, s.Token) != nil {
		t.Fatal("reset must revoke the user's sessions")
	}
	r := login(t, e, "nina", "brand new passphrase 77")
	if !r.MustChangePassword {
		t.Fatal("must_change_password not reported")
	}
}

// A password change is one promise: the new password takes effect and every
// other session of the account is cut off, with a line in the audit log. It
// therefore has to be one transaction — if the revocations fail, the
// password must not have changed, or the account would be left with a new
// password and the attacker's old session still open and nothing recorded.
func TestPasswordChangeIsAtomic(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "nils", pw, core.RoleMember)
	ctx := context.Background()
	mine, other := login(t, e, "nils", pw), login(t, e, "nils", pw)
	p := authenticate(t, e, mine.Token)
	const next = "a much better passphrase 2026"

	// Break the second half of the work: revoking the other sessions.
	if _, err := e.DB.Exec(ctx, `CREATE TRIGGER no_revoke BEFORE UPDATE OF revoked_at ON sessions
		BEGIN SELECT RAISE(ABORT, 'revocation failed'); END`); err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.ChangePassword(ctx, p, pw, next); err == nil {
		t.Fatal("ChangePassword succeeded although the revocations failed")
	}
	if _, err := e.DB.Exec(ctx, `DROP TRIGGER no_revoke`); err != nil {
		t.Fatal(err)
	}
	cur, err := e.Users.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.Auth.VerifyPassword(cur.PasswordHash, pw); !ok {
		t.Fatal("the password changed although the transaction failed")
	}
	if ok, _ := e.Auth.VerifyPassword(cur.PasswordHash, next); ok {
		t.Fatal("the new password took effect without the revocations")
	}
	if authenticate(t, e, other.Token) == nil {
		t.Fatal("the other session was revoked by a failed change")
	}
	if e.Audit.Count(core.ActUserPasswordChange, core.OutcomeSuccess) != 0 {
		t.Fatal("a failed password change was audited as a success")
	}

	// The same change now succeeds as a whole.
	if err := e.Auth.ChangePassword(ctx, p, pw, next); err != nil {
		t.Fatal(err)
	}
	if authenticate(t, e, other.Token) != nil {
		t.Fatal("other session still alive")
	}
	login(t, e, "nils", next)
	if e.Audit.Count(core.ActUserPasswordChange, core.OutcomeSuccess) != 1 {
		t.Fatal("audit")
	}

	// The admin reset has the same shape (sessions and API tokens).
	e.AddUser(t, "root", pw, core.RoleAdmin)
	pa := authenticate(t, e, login(t, e, "root", pw).Token)
	pa.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	if _, err := e.DB.Exec(ctx, `CREATE TRIGGER no_revoke BEFORE UPDATE OF revoked_at ON sessions
		BEGIN SELECT RAISE(ABORT, 'revocation failed'); END`); err != nil {
		t.Fatal(err)
	}
	const reset = "reset passphrase 99"
	if err := e.Auth.AdminSetPassword(ctx, pa, u.ID, reset, true); err == nil {
		t.Fatal("AdminSetPassword succeeded although the revocations failed")
	}
	if _, err := e.DB.Exec(ctx, `DROP TRIGGER no_revoke`); err != nil {
		t.Fatal(err)
	}
	if cur, err = e.Users.Get(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.Auth.VerifyPassword(cur.PasswordHash, reset); ok {
		t.Fatal("the admin reset changed the password although the transaction failed")
	}
}

// The lockout counts consecutive failures (auth.lockout_threshold): a
// successful step-up proves the credential just as a sign-in does, so typos
// in the step-up dialog, each followed by the right answer, never add up to
// a lock (nor raise the lock level).
func TestStepUpSuccessResetsFailureCounter(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	u := e.AddUser(t, "otto", pw, core.RoleMember)
	secret, _ := enrollTOTP(t, e, "otto")
	ctx := context.Background()
	res := login(t, e, "otto", pw)
	full, err := e.Auth.VerifyTOTP(ctx, authenticate(t, e, res.Token), code(t, secret, e.Clock.Now()))
	if err != nil {
		t.Fatal(err)
	}
	p := authenticate(t, e, full.Token)
	for i := range 5 {
		if err := e.Auth.Elevate(ctx, p, core.ElevateInput{Password: "wrong wrong wrong"}); !isCode(err, core.ErrForbidden) {
			t.Fatalf("wrong password: %v", err)
		}
		in := core.ElevateInput{Password: pw}
		if i == 4 { // the last round confirms with the authenticator app
			e.Clock.Advance(30 * time.Second)
			in = core.ElevateInput{TOTP: code(t, secret, e.Clock.Now())}
		}
		if err := e.Auth.Elevate(ctx, p, in); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	got, _ := e.Users.Get(ctx, u.ID)
	if got.Locked(e.Clock.Now()) || got.LockLevel != 0 || got.FailedLogins != 0 {
		t.Fatalf("alternating typos locked the account: failed=%d level=%d until=%v", got.FailedLogins, got.LockLevel, got.LockedUntil)
	}
	if e.Audit.Count(core.ActAuthLockout, "") != 0 {
		t.Fatal("auth.lockout recorded")
	}
}

// While an account is locked out, its signed-in user can neither step up
// nor change the password, and is told so (409) instead of "the password is
// not correct". The lock is checked before any credential, so a session
// thief learns nothing about a guess, and a guess that was never checked
// costs no failure from the IP's budget.
func TestChangePasswordAndElevateWhileLocked(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1) // one counted failure per IP and minute
	u := e.AddUser(t, "lars", pw, core.RoleMember)
	res := login(t, e, "lars", pw)
	p := authenticate(t, e, res.Token)
	ctx := context.Background()
	for i := range 3 { // someone guesses at the sign-in page, from three addresses
		attacker := core.ReqMeta{IP: netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)})}
		if _, err := e.Auth.Login(ctx, core.LoginInput{Username: "lars", Password: "guess guess guess"}, attacker); !isCode(err, core.ErrUnauthorized) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if got, _ := e.Users.Get(ctx, u.ID); !got.Locked(e.Clock.Now()) {
		t.Fatal("the account is not locked")
	}
	const next = "a much better passphrase 2026"
	for _, cur := range []string{pw, "wrong wrong wrong"} {
		err := e.Auth.ChangePassword(ctx, p, cur, next)
		if ae := core.AsError(err); !isCode(err, core.ErrConflict) || ae.Field != "" || !strings.Contains(ae.Message, "locked") {
			t.Fatalf("password change with %q while locked: %#v", cur, ae)
		}
	}
	for _, en := range e.Audit.Entries(core.ActUserPasswordChange, core.OutcomeFailure) {
		if d, _ := en.Details.(map[string]any); d["reason"] != "locked" {
			t.Fatalf("password change failure audited as %v", en.Details)
		}
	}
	// (with a budget of one failure, a counted attempt above would have
	// turned every later one into 429)
	for _, in := range []core.ElevateInput{{Password: pw}, {Password: "wrong wrong wrong"}} {
		if err := e.Auth.Elevate(ctx, p, in); !isCode(err, core.ErrConflict) {
			t.Fatalf("step-up while locked: %v", err)
		}
	}
	if authenticate(t, e, res.Token).Elevated(e.Clock.Now()) {
		t.Fatal("elevated while locked")
	}
	if got, _ := e.Users.Get(ctx, u.ID); got.FailedLogins != 0 || got.LockLevel != 1 {
		t.Fatalf("attempts while locked counted: failed=%d level=%d", got.FailedLogins, got.LockLevel)
	}
	// nothing changed: once the lock is over the old password still works
	e.Clock.Advance(15*time.Minute + time.Second)
	if err := e.Auth.ChangePassword(ctx, authenticate(t, e, res.Token), pw, next); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}

func TestResetMFA(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "olga", pw, core.RoleMember)
	enrollTOTP(t, e, "olga")
	e.AddUser(t, "boss", pw, core.RoleOwner)
	e.Settings.Put("auth.require_2fa", "off")
	pb := authenticate(t, e, login(t, e, "boss", pw).Token)
	ctx := context.Background()
	if err := e.Auth.ResetMFA(ctx, pb, u.ID); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("not elevated: %v", err)
	}
	pb.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	if err := e.Auth.ResetMFA(ctx, &core.Principal{UserID: u.ID, Role: core.RoleMember, Via: core.ViaSession, ElevatedUntil: pb.ElevatedUntil}, u.ID); !isCode(err, core.ErrForbidden) {
		t.Fatalf("member reset: %v", err)
	}
	if err := e.Auth.ResetMFA(ctx, pb, u.ID); err != nil {
		t.Fatal(err)
	}
	st, _ := e.Auth.MFAStatus(ctx, u.ID)
	if st.TOTPEnabled || st.RecoveryCodesLeft != 0 || st.PasskeyCount != 0 {
		t.Fatalf("status %+v", st)
	}
	if res := login(t, e, "olga", pw); res.MFARequired {
		t.Fatal("MFA still required after reset")
	}
	if e.Audit.Count(core.ActUserMFAReset, "") != 1 {
		t.Fatal("audit")
	}
}

// ---------- API tokens ----------

func bearer(t *testing.T, e *authtest.Env, secret string) (*core.Principal, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	return e.Auth.Authenticate(r)
}

func TestTokens(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	u := e.AddUser(t, "pat", pw, core.RoleMember)
	admin := e.AddUser(t, "root", pw, core.RoleOwner)
	p := authenticate(t, e, login(t, e, "pat", pw).Token)
	ctx := context.Background()

	tok, secret, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: " ci ", Scopes: []string{"files:read", "shares"}})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Name != "ci" || !strings.HasPrefix(secret, auth.TokenPrefix+strings.TrimPrefix(tok.ID, "tok_")+"_") || tok.Elevated {
		t.Fatalf("token %+v %q", tok, secret)
	}
	bp, err := bearer(t, e, secret)
	if err != nil || bp.UserID != u.ID || bp.Via != core.ViaToken || bp.TokenID != tok.ID || !bp.Full() ||
		!bp.HasScope("files:read") || bp.HasScope("files:write") || bp.Elevated(e.Clock.Now()) {
		t.Fatalf("bearer principal %+v %v", bp, err)
	}
	if e.Auth.CSRFToken(bp) != "" {
		t.Fatal("tokens have no CSRF token")
	}
	list, _ := e.Auth.ListTokens(ctx, u.ID)
	if len(list) != 1 || list[0].LastUsedAt == nil || list[0].LastUsedIP != "192.0.2.1" {
		t.Fatalf("list %+v", list)
	}
	var stored []byte
	_ = e.DB.QueryRow(ctx, `SELECT token_hash FROM api_tokens WHERE id = ?`, tok.ID).Scan(&stored)
	if len(stored) != 32 || strings.Contains(string(stored), secret) {
		t.Fatal("token must be stored hashed")
	}

	// bad bearer values
	for _, h := range []string{secret + "x", "fpt_nope"} {
		if _, err := bearer(t, e, h); !isCode(err, core.ErrUnauthorized) {
			t.Fatalf("%q: %v", h, err)
		}
	}
	// Other Authorization headers are no FileParcel credential and are
	// ignored (a reverse proxy's outer Basic gate, whose credentials the
	// browser attaches to every request, or a proxy's own bearer token):
	// anonymous without a cookie, the session with one.
	sess := login(t, e, "pat", pw)
	for _, h := range []string{"Basic dXNlcjpwYXNz", "Bearer " + strings.Replace(secret, "fpt_", "fpx_", 1), "Bearer eyJhbGciOi.x.y", "Negotiate"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", h)
		if got, err := e.Auth.Authenticate(r); got != nil || err != nil {
			t.Fatalf("%q without a cookie: %+v %v", h, got, err)
		}
		r = request(sess.Token)
		r.Header.Set("Authorization", h)
		if got, err := e.Auth.Authenticate(r); err != nil || got == nil || got.Via != core.ViaSession || got.UserID != u.ID {
			t.Fatalf("%q with a session cookie: %+v %v", h, got, err)
		}
	}
	// an fpt_ token still wins over the cookie, and a bad one stays an error
	r := request(sess.Token)
	r.Header.Set("Authorization", "Bearer fpt_bogus")
	if _, err := e.Auth.Authenticate(r); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("bad token with a session cookie: %v", err)
	}

	// validation
	for _, in := range []core.TokenInput{
		{Name: "", Scopes: []string{"files:read"}},
		{Name: "x", Scopes: nil},
		{Name: "x", Scopes: []string{"elevated"}},
		{Name: "x", Scopes: []string{"admin"}}, // member cannot hold admin
		{Name: "x", Scopes: []string{"files:read"}, ExpiresAt: ptr(e.Clock.Now().Add(-time.Hour))},
	} {
		if _, _, err := e.Auth.CreateToken(ctx, p, in); !isCode(err, core.ErrInvalid) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	// a token can only mint narrower tokens
	if _, _, err := e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "w", Scopes: []string{"files:write"}}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("escalation: %v", err)
	}
	if _, _, err := e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "r", Scopes: []string{"files:read"}}); err != nil {
		t.Fatalf("narrower token: %v", err)
	}
	// not for other users unless admin
	if _, _, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "x", Scopes: []string{"files:read"}, UserID: admin.ID}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("foreign token: %v", err)
	}

	// expiry and revocation
	short, ssecret, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "short", Scopes: []string{"files:read"}, ExpiresAt: ptr(e.Clock.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	e.Clock.Advance(time.Hour)
	if _, err := bearer(t, e, ssecret); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("expired token: %v", err)
	}
	// over the network an administrator revokes its own tokens only (see
	// TestOthersTokensOnlyOverTheSocket); the admin socket revokes any
	pa := authenticate(t, e, login(t, e, "root", pw).Token)
	if err := e.Auth.RevokeToken(ctx, pa, tok.ID); !isCode(err, core.ErrNotFound) {
		t.Fatalf("owner session revoked another user's token: %v", err)
	}
	if err := e.Auth.RevokeToken(ctx, core.SystemPrincipal(core.ViaSocket), tok.ID); err != nil {
		t.Fatal("the admin socket may revoke any token")
	}
	pOther := &core.Principal{UserID: "usr_x", Role: core.RoleMember, Via: core.ViaSession}
	if err := e.Auth.RevokeToken(ctx, pOther, short.ID); !isCode(err, core.ErrNotFound) {
		t.Fatalf("foreign revoke: %v", err)
	}
	if err := e.Auth.RevokeToken(ctx, p, tok.ID); err != nil {
		t.Fatal("revoking twice is a no-op")
	}
	if _, err := bearer(t, e, secret); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("revoked token: %v", err)
	}
	// disabled users' tokens stop working
	_, s2, _ := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "d", Scopes: []string{"files:read"}})
	_ = e.Users.SetStatus(ctx, nil, u.ID, core.UserDisabled)
	if _, err := bearer(t, e, s2); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("disabled user: %v", err)
	}
	if e.Audit.Count(core.ActTokenCreate, "") != 4 || e.Audit.Count(core.ActTokenRevoke, "") != 1 {
		t.Fatalf("audit create %d revoke %d", e.Audit.Count(core.ActTokenCreate, ""), e.Audit.Count(core.ActTokenRevoke, ""))
	}
}

func TestAdminAndElevatedTokens(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	e.AddUser(t, "root", pw, core.RoleOwner)
	member := e.AddUser(t, "mem", pw, core.RoleMember)
	p := authenticate(t, e, login(t, e, "root", pw).Token)
	ctx := context.Background()
	in := core.TokenInput{Name: "ops", Scopes: []string{"admin"}, Elevated: true, ExpiresAt: ptr(e.Clock.Now().Add(7 * 24 * time.Hour))}
	if _, _, err := e.Auth.CreateToken(ctx, p, in); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("admin scope without step-up: %v", err)
	}
	p.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	for _, bad := range []core.TokenInput{
		{Name: "ops", Scopes: []string{"admin"}, Elevated: true},
		{Name: "ops", Scopes: []string{"admin"}, Elevated: true, ExpiresAt: ptr(e.Clock.Now().Add(31 * 24 * time.Hour))},
		{Name: "ops", Scopes: []string{"files:read"}, Elevated: true, ExpiresAt: ptr(e.Clock.Now().Add(time.Hour))},
	} {
		if _, _, err := e.Auth.CreateToken(ctx, p, bad); !isCode(err, core.ErrInvalid) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	tok, secret, err := e.Auth.CreateToken(ctx, p, in)
	if err != nil || !tok.Elevated || !slices.Equal(tok.Scopes, []string{"admin"}) {
		t.Fatalf("elevated token %+v %v", tok, err)
	}
	bp, err := bearer(t, e, secret)
	if err != nil || !bp.IsAdmin() || !bp.HasScope(core.ScopeAdmin) || !bp.Elevated(e.Clock.Now()) || !bp.ElevatedUntil.Equal(*tok.ExpiresAt) {
		t.Fatalf("elevated bearer %+v %v", bp, err)
	}
	if _, _, err := e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "x", Scopes: []string{"admin"}, Elevated: true, ExpiresAt: in.ExpiresAt}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("token minting elevated token: %v", err)
	}
	// … nor a (plain) admin-scope token that outlives its 30-day cap: its
	// children expire with it at the latest
	if _, _, err := e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "x", Scopes: []string{"admin"},
		ExpiresAt: ptr(e.Clock.Now().Add(8 * 24 * time.Hour))}); !isCode(err, core.ErrInvalid) {
		t.Fatalf("admin token outliving its elevated creator: %v", err)
	}
	child, _, err := e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "x", Scopes: []string{"admin"}})
	if err != nil || child.Elevated || child.ExpiresAt == nil || !child.ExpiresAt.Equal(*tok.ExpiresAt) {
		t.Fatalf("admin token minted by an elevated token: %+v %v", child, err)
	}
	// "30 days" by a browser clock running slightly ahead is clamped to 30
	// days of ours; anything clearly longer is still refused
	limit := e.Clock.Now().Add(auth.MaxElevatedTokenTTL)
	ahead, _, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "ahead", Scopes: []string{"admin"}, Elevated: true,
		ExpiresAt: ptr(limit.Add(2 * time.Second))})
	if err != nil || ahead.ExpiresAt == nil || !ahead.ExpiresAt.Equal(limit.Truncate(time.Millisecond)) {
		t.Fatalf("elevated token 2 s past 30 days: %+v %v", ahead, err)
	}
	if _, _, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "long", Scopes: []string{"admin"}, Elevated: true,
		ExpiresAt: ptr(limit.Add(6 * time.Minute))}); !isCode(err, core.ErrInvalid) {
		t.Fatalf("elevated token 6 min past 30 days: %v", err)
	}
	// an elevated admin (or the socket) creates tokens for other users
	ot, _, err := e.Auth.CreateToken(ctx, core.SystemPrincipal(core.ViaSocket), core.TokenInput{Name: "cli", Scopes: []string{"files:read"}, UserID: member.ID})
	if err != nil || ot.UserID != member.ID {
		t.Fatalf("socket token for member: %+v %v", ot, err)
	}
	if _, _, err := e.Auth.CreateToken(ctx, core.SystemPrincipal(core.ViaSocket), core.TokenInput{Name: "cli", Scopes: []string{"files:read"}}); !isCode(err, core.ErrInvalid) {
		t.Fatalf("system principal without user: %v", err)
	}
}

// A token cannot outlive the token that mints it: otherwise a leaked
// short-lived token could be swapped for a permanent one that also survives
// its expiry and revocation.
func TestTokenCannotOutliveItsCreator(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	e.AddUser(t, "pat", pw, core.RoleMember)
	p := authenticate(t, e, login(t, e, "pat", pw).Token)
	ctx := context.Background()
	read := []string{core.ScopeFilesRead}
	parent, psecret, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "ci", Scopes: read, ExpiresAt: ptr(e.Clock.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	bp, err := bearer(t, e, psecret)
	if err != nil {
		t.Fatal(err)
	}
	// a later expiry is refused …
	_, _, err = e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "x", Scopes: read, ExpiresAt: ptr(e.Clock.Now().Add(2 * time.Hour))})
	if ae := core.AsError(err); !isCode(err, core.ErrInvalid) || ae.Field != "expires_at" {
		t.Fatalf("child outliving its creator: %v", err)
	}
	// … no expiry means the creator's, and an earlier one is kept
	child, csecret, err := e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "child", Scopes: read})
	if err != nil || child.ExpiresAt == nil || !child.ExpiresAt.Equal(*parent.ExpiresAt) {
		t.Fatalf("child without an expiry: %+v %v", child, err)
	}
	soon := e.Clock.Now().Add(30 * time.Minute).Truncate(time.Millisecond)
	if short, _, err := e.Auth.CreateToken(ctx, bp, core.TokenInput{Name: "short", Scopes: read, ExpiresAt: &soon}); err != nil ||
		short.ExpiresAt == nil || !short.ExpiresAt.Equal(soon) {
		t.Fatalf("child expiring first: %+v %v", short, err)
	}
	e.Clock.Advance(time.Hour)
	for _, s := range []string{psecret, csecret} {
		if _, err := bearer(t, e, s); !isCode(err, core.ErrUnauthorized) {
			t.Fatalf("token alive after its creator expired: %v", err)
		}
	}
	// a token without an expiry still mints tokens without one (the remote
	// CLI's `token create`), and a session is not bound at all
	_, fsecret, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "forever", Scopes: read})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := bearer(t, e, fsecret)
	if err != nil {
		t.Fatal(err)
	}
	if c, _, err := e.Auth.CreateToken(ctx, fp, core.TokenInput{Name: "c", Scopes: read}); err != nil || c.ExpiresAt != nil {
		t.Fatalf("child of a token without expiry: %+v %v", c, err)
	}
}

// Over the network the id-addressed credential operations (DELETE
// /me/tokens/{id}, PATCH/DELETE /me/passkeys/{id}) act on the caller's own
// credentials only, administrators included; other users' credentials go
// through /admin/users (which also revokes the sessions and alerts the
// owner) or the admin socket.
func TestOthersTokensOnlyOverTheSocket(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	e.AddUser(t, "root", pw, core.RoleOwner)
	e.AddUser(t, "mem", pw, core.RoleMember)
	ctx := context.Background()
	pm := authenticate(t, e, login(t, e, "mem", pw).Token)
	tok, secret, err := e.Auth.CreateToken(ctx, pm, core.TokenInput{Name: "ci", Scopes: []string{core.ScopeFilesRead}})
	if err != nil {
		t.Fatal(err)
	}
	po := elevated(e, authenticate(t, e, login(t, e, "root", pw).Token))
	own, osecret, err := e.Auth.CreateToken(ctx, po, core.TokenInput{Name: "ops", Scopes: []string{core.ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	bo, err := bearer(t, e, osecret)
	if err != nil {
		t.Fatal(err)
	}
	for name, by := range map[string]*core.Principal{"owner session": po, "admin-scope token": bo} {
		if err := e.Auth.RevokeToken(ctx, by, tok.ID); !isCode(err, core.ErrNotFound) {
			t.Errorf("%s revoked a member's token: %v", name, err)
		}
	}
	if _, err := bearer(t, e, secret); err != nil {
		t.Fatalf("the member's token was revoked: %v", err)
	}
	if err := e.Auth.RevokeToken(ctx, core.SystemPrincipal(core.ViaOffline), tok.ID); err != nil {
		t.Fatalf("offline CLI: %v", err)
	}
	if _, err := bearer(t, e, secret); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("revoked over the socket: %v", err)
	}
	if err := e.Auth.RevokeToken(ctx, po, own.ID); err != nil {
		t.Fatalf("own token: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

// ---------- setup ----------

func TestSetup(t *testing.T) {
	e := authtest.New(t)
	ctx := context.Background()
	tok, err := e.Auth.SetupToken(ctx)
	if err != nil || len(tok) < 40 {
		t.Fatalf("setup token %q %v", tok, err)
	}
	tok2, _ := e.Auth.SetupToken(ctx) // a new token replaces the old one
	var stored string
	_ = e.DB.QueryRow(ctx, `SELECT value FROM meta WHERE key = 'setup_token_hash'`).Scan(&stored)
	if stored == "" || strings.Contains(stored, tok2) {
		t.Fatal("setup token must be stored hashed")
	}
	in := core.NewUser{Username: "owner", Password: pw, Email: "o@example.test", Role: core.RoleMember}
	for _, bad := range []string{"", tok, "wrong"} {
		_, err := e.Auth.Setup(ctx, bad, in, clientMeta)
		if ae := core.AsError(err); ae == nil || ae.Status != 403 || ae.Field != "setup_token" {
			t.Fatalf("token %q: %v", bad, err)
		}
	}
	if _, err := e.Auth.Setup(ctx, tok2, core.NewUser{Username: "owner", Password: "short"}, clientMeta); !isCode(err, core.ErrInvalid) {
		t.Fatalf("weak password: %v", err)
	}
	res, err := e.Auth.Setup(ctx, tok2, in, clientMeta)
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Role != core.RoleOwner || res.Token == "" || !res.EnrollRequired {
		t.Fatalf("setup result %+v", res)
	}
	if p := authenticate(t, e, res.Token); p == nil || p.Role != core.RoleOwner {
		t.Fatal("setup session")
	}
	if _, err := e.Auth.Setup(ctx, tok2, core.NewUser{Username: "evil", Password: pw}, clientMeta); !isCode(err, core.ErrConflict) {
		t.Fatalf("second setup: %v", err)
	}
	if _, err := e.Auth.SetupToken(ctx); !isCode(err, core.ErrConflict) {
		t.Fatalf("token after setup: %v", err)
	}
	if err := e.DB.QueryRow(ctx, `SELECT value FROM meta WHERE key = 'setup_token_hash'`).Scan(&stored); !db.IsNoRows(err) {
		t.Fatal("setup token not deleted")
	}
	if e.Audit.Count(core.ActAuthSetup, core.OutcomeSuccess) != 1 || e.Audit.Count(core.ActAuthSetup, core.OutcomeFailure) != 3 {
		t.Fatal("setup audit")
	}
}

// ---------- managing other users' credentials ----------

func TestOwnerCredentialsProtected(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	ctx := context.Background()
	owner := e.AddUser(t, "olive", pw, core.RoleOwner)
	e.AddUser(t, "adam", pw, core.RoleAdmin)
	member := e.AddUser(t, "mel", pw, core.RoleMember)
	ownerSess := login(t, e, "olive", pw)
	po := authenticate(t, e, ownerSess.Token)
	pa := authenticate(t, e, login(t, e, "adam", pw).Token)
	pm := authenticate(t, e, login(t, e, "mel", pw).Token)
	until := e.Clock.Now().Add(time.Minute)
	po.ElevatedUntil, pa.ElevatedUntil, pm.ElevatedUntil = until, until, until
	tok, _, err := e.Auth.CreateToken(ctx, po, core.TokenInput{Name: "o", Scopes: []string{core.ScopeFilesRead}})
	if err != nil {
		t.Fatal(err)
	}

	// an administrator cannot take over an owner account …
	for name, err := range map[string]error{
		"password":     e.Auth.AdminSetPassword(ctx, pa, owner.ID, "the admin's chosen password", false),
		"reset mfa":    e.Auth.ResetMFA(ctx, pa, owner.ID),
		"totp disable": e.Auth.TOTPDisable(ctx, pa, owner.ID),
		"revoke all":   e.Auth.RevokeAllSessions(ctx, pa, owner.ID, ""),
		"revoke one":   e.Auth.RevokeSession(ctx, pa, owner.ID, ownerSess.Session.ID),
	} {
		if !isCode(err, core.ErrForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := e.Auth.CreateToken(ctx, pa, core.TokenInput{Name: "x", Scopes: []string{core.ScopeFilesRead}, UserID: owner.ID}); !isCode(err, core.ErrForbidden) {
		t.Errorf("token for owner: %v", err)
	}
	if err := e.Auth.RevokeToken(ctx, pa, tok.ID); !isCode(err, core.ErrNotFound) {
		t.Errorf("revoke owner token: %v", err)
	}
	if authenticate(t, e, ownerSess.Token) == nil {
		t.Fatal("the owner session was revoked")
	}
	// … members cannot touch anyone else …
	if err := e.Auth.RevokeAllSessions(ctx, pm, owner.ID, ""); !isCode(err, core.ErrForbidden) {
		t.Errorf("member revokes owner sessions: %v", err)
	}
	// … but administrators manage members, and owners everyone.
	if err := e.Auth.RevokeAllSessions(ctx, pa, member.ID, ""); err != nil {
		t.Errorf("admin revokes member sessions: %v", err)
	}
	if err := e.Auth.AdminSetPassword(ctx, po, member.ID, "owner resets the member", false); err != nil {
		t.Errorf("owner resets member: %v", err)
	}
	sys := core.SystemPrincipal(core.ViaSocket)
	if err := e.Auth.RevokeToken(ctx, sys, tok.ID); err != nil {
		t.Errorf("system revokes a token: %v", err)
	}
	if err := e.Auth.RevokeAllSessions(ctx, pa, "usr_does_not_exist", ""); !isCode(err, core.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}

// An operator resetting a compromised account's password or 2FA must cut off
// its API tokens too — they outlive the sessions otherwise, so the attacker
// keeps a (possibly admin-scoped, possibly elevated) credential.
func TestCredentialResetRevokesAPITokens(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	u := e.AddUser(t, "vic", pw, core.RoleMember)
	e.AddUser(t, "boss", pw, core.RoleOwner)
	ctx := context.Background()
	pv := authenticate(t, e, login(t, e, "vic", pw).Token)
	_, secret, err := e.Auth.CreateToken(ctx, pv, core.TokenInput{Name: "leaked", Scopes: []string{"files:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bearer(t, e, secret); err != nil {
		t.Fatalf("fresh token: %v", err)
	}
	pb := authenticate(t, e, login(t, e, "boss", pw).Token)
	pb.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	if err := e.Auth.AdminSetPassword(ctx, pb, u.ID, "another good passphrase", false); err != nil {
		t.Fatal(err)
	}
	if _, err := bearer(t, e, secret); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("token survived the password reset: %v", err)
	}
	// the same for a 2FA reset
	pv = authenticate(t, e, login(t, e, "vic", "another good passphrase").Token)
	_, secret2, err := e.Auth.CreateToken(ctx, pv, core.TokenInput{Name: "leaked2", Scopes: []string{"files:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.ResetMFA(ctx, pb, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := bearer(t, e, secret2); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("token survived the 2FA reset: %v", err)
	}
	// the operator's own tokens are untouched, and so is anybody else's
	_, bossSecret, err := e.Auth.CreateToken(ctx, pb, core.TokenInput{Name: "ops", Scopes: []string{"files:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.AdminSetPassword(ctx, pb, u.ID, "yet another good passphrase", false); err != nil {
		t.Fatal(err)
	}
	if _, err := bearer(t, e, bossSecret); err != nil {
		t.Fatalf("the operator's own token was revoked: %v", err)
	}
}

// An admin acting with an elevated API token on its own account must not
// revoke the very token making the call.
func TestAdminSetPasswordKeepsTheCallersOwnToken(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	u := e.AddUser(t, "root", pw, core.RoleOwner)
	ctx := context.Background()
	p := authenticate(t, e, login(t, e, "root", pw).Token)
	p.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	_, secret, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "ops", Scopes: []string{"admin"}, Elevated: true,
		ExpiresAt: ptr(e.Clock.Now().Add(7 * 24 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := e.Auth.CreateToken(ctx, p, core.TokenInput{Name: "old", Scopes: []string{"files:read"}})
	if err != nil {
		t.Fatal(err)
	}
	bp, err := bearer(t, e, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.AdminSetPassword(ctx, bp, u.ID, "another good passphrase", false); err != nil {
		t.Fatal(err)
	}
	if _, err := bearer(t, e, secret); err != nil {
		t.Fatalf("the calling token was revoked: %v", err)
	}
	if _, err := bearer(t, e, other); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("the account's other token survived: %v", err)
	}
}

func TestAdminSetPasswordNeedsElevationForSelf(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "sam", pw, core.RoleMember)
	p := authenticate(t, e, login(t, e, "sam", pw).Token)
	ctx := context.Background()
	// setting one's own password without the current one needs step-up
	if err := e.Auth.AdminSetPassword(ctx, p, u.ID, "another good passphrase", false); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("not elevated: %v", err)
	}
	p.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	if err := e.Auth.AdminSetPassword(ctx, p, u.ID, "another good passphrase", false); err != nil {
		t.Fatal(err)
	}
	login(t, e, "sam", "another good passphrase")
}

func TestLockoutAuditedOnce(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.AddUser(t, "tina", pw, core.RoleMember)
	for range 5 {
		_, _ = e.Auth.Login(context.Background(), core.LoginInput{Username: "tina", Password: "wrong wrong"}, clientMeta)
	}
	if n := e.Audit.Count(core.ActAuthLockout, ""); n != 1 {
		t.Fatalf("auth.lockout recorded %d times", n)
	}
	var locked int
	for _, en := range e.Audit.Entries(core.ActAuthLogin, core.OutcomeFailure) {
		if d, ok := en.Details.(map[string]any); ok && d["locked_until"] != nil {
			locked++
		}
	}
	if locked != 1 {
		t.Fatalf("login failures carrying locked_until: %d", locked)
	}
}
