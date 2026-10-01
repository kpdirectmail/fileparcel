package auth_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/auth"
	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
)

const origin = "https://fileparcel.local:8443"

// registerPasskey registers a passkey from authenticator a for principal p
// (inside a step-up window, which registering needs).
func registerPasskey(t *testing.T, e *authtest.Env, a *authtest.Authenticator, p *core.Principal, name string) *core.Passkey {
	t.Helper()
	ctx := context.Background()
	p = elevated(e, p)
	opts, flow, err := e.Auth.PasskeyRegisterBegin(ctx, p)
	if err != nil {
		t.Fatalf("register begin: %v", err)
	}
	resp, err := a.Create(opts)
	if err != nil {
		t.Fatalf("authenticator create: %v", err)
	}
	pk, err := e.Auth.PasskeyRegisterFinish(ctx, p, flow, resp, name)
	if err != nil {
		t.Fatalf("register finish: %v", err)
	}
	return pk
}

// assert runs a login ceremony: begin (with ctx principal p and username),
// the authenticator's assertion, and returns the flow id and response.
func assert(t *testing.T, e *authtest.Env, a *authtest.Authenticator, p *core.Principal, username string) (string, []byte) {
	t.Helper()
	ctx := context.Background()
	if p != nil {
		ctx = ctxWith(p)
	}
	opts, flow, err := e.Auth.PasskeyLoginBegin(ctx, username)
	if err != nil {
		t.Fatalf("login begin: %v", err)
	}
	resp, err := a.Get(opts)
	if err != nil {
		t.Fatalf("authenticator get: %v", err)
	}
	return flow, resp
}

func TestPasskeyRegistrationAndPasswordlessLogin(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "quinn", pw, core.RoleMember)
	a := &authtest.Authenticator{Origin: origin, UV: true}
	p := authenticate(t, e, login(t, e, "quinn", pw).Token)
	ctx := context.Background()

	if e.Auth.RPID() != "fileparcel.local" {
		t.Fatalf("rp id %q", e.Auth.RPID())
	}
	pk := registerPasskey(t, e, a, p, "  ")
	if pk.Name != "Passkey" || pk.UserID != u.ID || pk.RPID != "fileparcel.local" || pk.SignCount != 0 {
		t.Fatalf("passkey %+v", pk)
	}
	if e.Audit.Count(core.ActPasskeyAdd, "") != 1 {
		t.Fatal("passkey.add audit")
	}
	// the credential is stored field-encrypted
	var enc string
	_ = e.DB.QueryRow(ctx, `SELECT credential_enc FROM webauthn_credentials WHERE id = ?`, pk.ID).Scan(&enc)
	if !strings.HasPrefix(enc, "v1:") || strings.Contains(enc, "publicKey") {
		t.Fatalf("credential stored in clear: %q", enc)
	}
	// registering the same authenticator again is excluded
	p = elevated(e, p)
	opts, flow, err := e.Auth.PasskeyRegisterBegin(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	var co struct {
		PublicKey struct {
			Exclude []json.RawMessage   `json:"excludeCredentials"`
			RP      struct{ ID string } `json:"rp"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &co); err != nil || len(co.PublicKey.Exclude) != 1 || co.PublicKey.RP.ID != "fileparcel.local" {
		t.Fatalf("creation options %s", opts)
	}
	if _, err := a.Create(opts); err == nil {
		t.Fatal("excluded credential registered")
	}
	// a flow is single-use and bound to its user
	other := e.AddUser(t, "rick", pw, core.RoleMember)
	po := elevated(e, authenticate(t, e, login(t, e, "rick", pw).Token))
	b := &authtest.Authenticator{Origin: origin, UV: true}
	resp, _ := b.Create(opts)
	if _, err := e.Auth.PasskeyRegisterFinish(ctx, po, flow, resp, "x"); !isCode(err, core.ErrInvalid) {
		t.Fatalf("foreign flow: %v", err)
	}
	if _, err := e.Auth.PasskeyRegisterFinish(ctx, p, flow, resp, "x"); !isCode(err, core.ErrInvalid) {
		t.Fatalf("reused flow: %v", err)
	}
	_ = other

	// passwordless (discoverable) login
	flow, resp = assert(t, e, a, nil, "")
	res, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta)
	if err != nil {
		t.Fatalf("passwordless login: %v", err)
	}
	if res.User.ID != u.ID || res.Session.MFAMethod != core.MFAPasskey || res.Session.AuthLevel != core.AuthLevelFull {
		t.Fatalf("login result %+v", res)
	}
	if pp := authenticate(t, e, res.Token); pp == nil || !pp.Full() {
		t.Fatal("passkey session")
	}
	list, _ := e.Auth.ListPasskeys(ctx, u.ID)
	if len(list) != 1 || list[0].SignCount != 1 || list[0].LastUsedAt == nil {
		t.Fatalf("sign count not stored: %+v", list)
	}
	// the flow cannot be replayed
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("replayed flow: %v", err)
	}
	// a username restricts which account may finish
	flow, resp = assert(t, e, a, nil, "rick")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("username mismatch: %v", err)
	}
	flow, resp = assert(t, e, a, nil, "QUINN")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); err != nil {
		t.Fatalf("username match: %v", err)
	}
	// passwordless sign-in needs user verification
	a.UV = false
	flow, resp = assert(t, e, a, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("no UV: %v", err)
	}
	a.UV = true
	// wrong origin
	a.Origin = "https://evil.example"
	flow, resp = assert(t, e, a, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("wrong origin: %v", err)
	}
	a.Origin = origin
	// expired flow
	flow, resp = assert(t, e, a, nil, "")
	e.Clock.Advance(auth.FlowTTL + time.Second)
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("expired flow: %v", err)
	}
	// malformed response
	flow, _ = assert(t, e, a, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, []byte(`{"id":"x"}`), false, nil, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("malformed: %v", err)
	}
}

func TestPasskeyCloneDetection(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "sam", pw, core.RoleMember)
	a := &authtest.Authenticator{Origin: origin, UV: true}
	registerPasskey(t, e, a, authenticate(t, e, login(t, e, "sam", pw).Token), "Key")
	ctx := context.Background()
	flow, resp := assert(t, e, a, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); err != nil {
		t.Fatal(err)
	}
	a.FreezeCounter = true // counter stays at 1: a cloned key
	flow, resp = assert(t, e, a, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); !isCode(err, core.ErrUnauthorized) {
		t.Fatalf("clone accepted: %v", err)
	}
}

func TestPasskeyAsSecondFactorAndElevation(t *testing.T) {
	e := authtest.New(t)
	u := e.AddUser(t, "tess", pw, core.RoleMember)
	a := &authtest.Authenticator{Origin: origin} // no UV: fine as a second factor
	p := authenticate(t, e, login(t, e, "tess", pw).Token)
	pk := registerPasskey(t, e, a, p, "Phone")
	ctx := context.Background()

	res := login(t, e, "tess", pw)
	if !res.MFARequired || len(res.Methods) != 1 || res.Methods[0] != core.MFAPasskey {
		t.Fatalf("login %+v", res)
	}
	p1 := authenticate(t, e, res.Token)
	opts, flow, err := e.Auth.PasskeyLoginBegin(ctxWith(p1), "")
	if err != nil {
		t.Fatal(err)
	}
	var ro struct {
		PublicKey struct {
			Allow []json.RawMessage `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(opts, &ro) != nil || len(ro.PublicKey.Allow) != 1 {
		t.Fatalf("second-factor options must list the user's credentials: %s", opts)
	}
	resp, err := a.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	full, err := e.Auth.PasskeyLoginFinish(ctxWith(p1), flow, resp, false, p1, clientMeta)
	if err != nil {
		t.Fatalf("second factor: %v", err)
	}
	if full.Session.ID != p1.SessionID || full.Token == res.Token || full.Session.MFAMethod != core.MFAPasskey {
		t.Fatalf("completion %+v", full.Session)
	}
	pf := authenticate(t, e, full.Token)

	// step-up with the passkey: a bare user-presence touch is not enough…
	flow, resp = assert(t, e, a, pf, "tess")
	if err := e.Auth.Elevate(ctx, pf, core.ElevateInput{Passkey: resp, FlowID: flow}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("elevation without user verification: %v", err)
	}
	pf = authenticate(t, e, full.Token)
	if pf.Elevated(e.Clock.Now()) {
		t.Fatal("elevated by a passkey without user verification")
	}
	// …and the ceremony of a full session asks for it up front.
	opts, flow, err = e.Auth.PasskeyLoginBegin(ctxWith(pf), "tess")
	if err != nil {
		t.Fatal(err)
	}
	var uvo struct {
		PublicKey struct {
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(opts, &uvo) != nil || uvo.PublicKey.UserVerification != "required" {
		t.Fatalf("step-up options must require user verification: %s", opts)
	}
	// with the PIN / biometric check that very ceremony succeeds
	a.UV = true
	if resp, err = a.Get(opts); err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.Elevate(ctx, pf, core.ElevateInput{Passkey: resp, FlowID: flow}); err != nil {
		t.Fatalf("passkey elevation: %v", err)
	}
	pf = authenticate(t, e, full.Token)
	if !pf.Elevated(e.Clock.Now()) {
		t.Fatal("not elevated")
	}
	// a flow of another ceremony (or none) fails
	if err := e.Auth.Elevate(ctx, pf, core.ElevateInput{Passkey: resp, FlowID: flow}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("reused elevation flow: %v", err)
	}

	// management
	if err := e.Auth.RenamePasskey(ctx, pf, pk.ID, "  Work phone "); err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.RenamePasskey(ctx, pf, pk.ID, ""); !isCode(err, core.ErrInvalid) {
		t.Fatalf("empty name: %v", err)
	}
	stranger := &core.Principal{UserID: "usr_stranger", Role: core.RoleMember, Via: core.ViaSession, ElevatedUntil: e.Clock.Now().Add(time.Hour)}
	if err := e.Auth.RenamePasskey(ctx, stranger, pk.ID, "mine"); !isCode(err, core.ErrNotFound) {
		t.Fatalf("foreign rename: %v", err)
	}
	if err := e.Auth.DeletePasskey(ctx, stranger, pk.ID); !isCode(err, core.ErrNotFound) {
		t.Fatalf("foreign delete: %v", err)
	}
	list, _ := e.Auth.ListPasskeys(ctx, u.ID)
	if len(list) != 1 || list[0].Name != "Work phone" {
		t.Fatalf("list %+v", list)
	}
	e.Clock.Advance(11 * time.Minute)
	pf = authenticate(t, e, full.Token)
	if err := e.Auth.DeletePasskey(ctx, pf, pk.ID); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("delete without elevation: %v", err)
	}
	pf.ElevatedUntil = e.Clock.Now().Add(time.Minute)
	if err := e.Auth.DeletePasskey(ctx, pf, pk.ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.Auth.MFAStatus(ctx, u.ID); st.PasskeyCount != 0 {
		t.Fatal("passkey not deleted")
	}
	if login(t, e, "tess", pw).MFARequired {
		t.Fatal("MFA still required without factors")
	}
	if e.Audit.Count(core.ActPasskeyRemove, "") != 1 {
		t.Fatal("passkey.remove audit")
	}
}

// stubMDNS is a core.MDNS reporting a fixed status (the collision-renamed
// name of DESIGN §10.5).
type stubMDNS struct{ st core.MDNSStatus }

func (m *stubMDNS) Status() core.MDNSStatus         { return m.st }
func (m *stubMDNS) Name() string                    { return m.st.Name }
func (m *stubMDNS) Republish(context.Context) error { return nil }
func (m *stubMDNS) Start(ctx context.Context) error { return nil }
func (m *stubMDNS) Stop() error                     { return nil }

// After an mDNS name collision the certificate SANs follow the renamed host
// (netinfo.mdnsName → certs); the RP ID must follow it too, or every passkey
// ceremony fails in the browser at the only reachable origin.
func TestRPIDFollowsRenamedMDNSName(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "nell", pw, core.RoleMember)
	e.Settings.Put("mdns.name", "fileparcel") // the configured name loses…
	m := &stubMDNS{st: core.MDNSStatus{Name: "fileparcel-2.local", State: core.MDNSPublished, Backend: "avahi"}}
	if err := e.Auth.Bind(&core.Services{MDNS: m}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if got := e.Auth.RPID(); got != "fileparcel-2.local" {
		t.Fatalf("rp id %q, want the published name", got)
	}
	// a full ceremony works at the renamed origin
	a := &authtest.Authenticator{Origin: "https://fileparcel-2.local:8443", UV: true}
	p := authenticate(t, e, login(t, e, "nell", pw).Token)
	pk := registerPasskey(t, e, a, p, "Key")
	if pk.RPID != "fileparcel-2.local" {
		t.Fatalf("credential rp id %q", pk.RPID)
	}
	flow, resp := assert(t, e, a, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(context.Background(), flow, resp, false, nil, clientMeta); err != nil {
		t.Fatalf("login at the renamed origin: %v", err)
	}
	// mDNS off (or not published at all): the configured name is used again
	m.st = core.MDNSStatus{Name: "fileparcel.local", State: core.MDNSOff}
	if got := e.Auth.RPID(); got != "fileparcel.local" {
		t.Fatalf("mdns off: rp id %q", got)
	}
	// the operator's pin always wins
	m.st = core.MDNSStatus{Name: "fileparcel-2.local", State: core.MDNSPublished}
	e.Settings.Put("auth.webauthn_rp_id", "files.example.com")
	if got := e.Auth.RPID(); got != "files.example.com" {
		t.Fatalf("pinned rp id %q", got)
	}
}

// EnsureRecoveryCodes gives an account that has only a passkey the
// out-of-band factor it lacks (POST /me/passkeys/finish calls it), without
// ever replacing codes the user may already have written down.
func TestEnsureRecoveryCodes(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "pia", pw, core.RoleMember)
	ctx := context.Background()
	p := authenticate(t, e, login(t, e, "pia", pw).Token)

	if codes, err := e.Auth.EnsureRecoveryCodes(ctx, p); err != nil || codes != nil {
		t.Fatalf("without a second factor: %v %v", codes, err)
	}
	registerPasskey(t, e, &authtest.Authenticator{Origin: origin, UV: true}, p, "Key")
	// Before the codes exist this is an account that turning auth.passkeys
	// off would lock out; the settings handler counts them to warn first.
	if n, err := e.Auth.PasskeyOnlyAccounts(ctx); err != nil || n != 1 {
		t.Fatalf("passkey-only accounts: %d %v", n, err)
	}
	codes, err := e.Auth.EnsureRecoveryCodes(ctx, p)
	if err != nil || len(codes) != auth.RecoveryCodeCount {
		t.Fatalf("first passkey: %d codes, %v", len(codes), err)
	}
	if n, err := e.Auth.PasskeyOnlyAccounts(ctx); err != nil || n != 0 {
		t.Fatalf("with recovery codes: %d %v", n, err)
	}
	if again, err := e.Auth.EnsureRecoveryCodes(ctx, p); err != nil || again != nil {
		t.Fatalf("codes already exist: %v %v", again, err)
	}
	// Turning passkeys off no longer strands the account.
	e.Settings.Put("auth.passkeys", false)
	res := login(t, e, "pia", pw)
	if !res.MFARequired || !slices.Contains(res.Methods, core.MFARecovery) {
		t.Fatalf("methods %v", res.Methods)
	}
	full, err := e.Auth.VerifyRecovery(ctx, authenticate(t, e, res.Token), codes[0])
	if err != nil || full.Session.AuthLevel != core.AuthLevelFull {
		t.Fatalf("recovery login: %v", err)
	}
}

// The normal deployment shape is an RP ID of example.test served at
// files.example.test: the browser sends the subdomain origin, and the UI
// offers the passkey button on every subdomain of the RP ID (DESIGN §18.1).
// The ceremony must therefore be accepted at the names this server is
// configured to serve, without listing them in auth.webauthn_origins.
func TestPasskeyCeremonyAtAServedSubdomain(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "sam", pw, core.RoleMember)
	e.Settings.Put("auth.webauthn_rp_id", "example.test")
	e.Settings.Put("tls.extra_sans", []string{"files.example.test"})
	a := &authtest.Authenticator{Origin: "https://files.example.test:8443", UV: true}
	p := authenticate(t, e, login(t, e, "sam", pw).Token)
	pk := registerPasskey(t, e, a, p, "Laptop")
	if pk.RPID != "example.test" {
		t.Fatalf("credential rp id %q", pk.RPID)
	}
	flow, resp := assert(t, e, a, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(context.Background(), flow, resp, false, nil, clientMeta); err != nil {
		t.Fatalf("login at the served subdomain: %v", err)
	}
	// A name this server does not serve stays out.
	b := &authtest.Authenticator{Origin: "https://evil.example.test:8443", UV: true}
	p = elevated(e, p)
	opts, flowID, err := e.Auth.PasskeyRegisterBegin(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := b.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Auth.PasskeyRegisterFinish(context.Background(), p, flowID, cred, "Evil"); !isCode(err, core.ErrInvalid) {
		t.Fatalf("unserved origin accepted: %v", err)
	}
}

func TestPasskeySettings(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "uma", pw, core.RoleMember)
	a := &authtest.Authenticator{Origin: origin, UV: true}
	p := authenticate(t, e, login(t, e, "uma", pw).Token)
	registerPasskey(t, e, a, p, "Key")
	ctx := context.Background()

	// begin for the own user without credentials on this RP: 404
	e.Settings.Put("auth.webauthn_rp_id", "files.example.com")
	e.Settings.Put("auth.webauthn_origins", []string{"https://files.example.com"})
	if _, _, err := e.Auth.PasskeyLoginBegin(ctxWith(p), ""); !isCode(err, core.ErrNotFound) {
		t.Fatalf("no credentials for the new RP: %v", err)
	}
	opts, _, err := e.Auth.PasskeyLoginBegin(ctx, "")
	if err != nil || !strings.Contains(string(opts), `"rpId":"files.example.com"`) {
		t.Fatalf("rebuilt config: %s %v", opts, err)
	}
	if _, err := a.Get(opts); err == nil {
		t.Fatal("credential of the old RP ID used")
	}
	// a passkey registered for the new RP works with the configured origin
	b := &authtest.Authenticator{Origin: "https://files.example.com", UV: true}
	registerPasskey(t, e, b, p, "New")
	flow, resp := assert(t, e, b, nil, "")
	if _, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); err != nil {
		t.Fatalf("new RP login: %v", err)
	}
	e.Settings.Put("auth.passkeys", false)
	if _, _, err := e.Auth.PasskeyLoginBegin(ctx, ""); !isCode(err, core.ErrForbidden) {
		t.Fatalf("disabled begin: %v", err)
	}
	if _, _, err := e.Auth.PasskeyRegisterBegin(ctx, p); !isCode(err, core.ErrForbidden) {
		t.Fatalf("disabled register: %v", err)
	}
	if res := login(t, e, "uma", pw); !res.MFARequired || len(res.Methods) != 0 {
		t.Fatalf("passkeys disabled: login must still need MFA, methods %v", res.Methods)
	}
}

// A passkey signs in on its own and satisfies step-up, so registering one
// needs an open step-up window: otherwise a hijacked (never elevated)
// session could plant its own and keep — and elevate — its way back in,
// even after a password change.
func TestPasskeyRegistrationNeedsStepUp(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.AddUser(t, "vera", pw, core.RoleMember)
	res := login(t, e, "vera", pw)
	p := authenticate(t, e, res.Token)
	ctx := context.Background()
	a := &authtest.Authenticator{Origin: origin, UV: true}
	if _, _, err := e.Auth.PasskeyRegisterBegin(ctx, p); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("begin without step-up: %v", err)
	}
	// a window that closed during the ceremony refuses the finish without
	// using up the flow, so the same request can be retried after step-up
	opts, flow, err := e.Auth.PasskeyRegisterBegin(ctx, elevated(e, p))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Auth.PasskeyRegisterFinish(ctx, p, flow, resp, "Key"); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("finish without step-up: %v", err)
	}
	if st, _ := e.Auth.MFAStatus(ctx, p.UserID); st.PasskeyCount != 0 {
		t.Fatal("passkey registered without step-up")
	}
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{Password: pw}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Auth.PasskeyRegisterFinish(ctx, authenticate(t, e, res.Token), flow, resp, "Key"); err != nil {
		t.Fatalf("finish after step-up: %v", err)
	}

	// A user who still has to enroll (EnrollRequired) steps up with the
	// password and then registers the passkey.
	e.AddUser(t, "wade", pw, core.RoleAdmin) // in the default 2FA policy
	res = login(t, e, "wade", pw)
	p = authenticate(t, e, res.Token)
	if !p.EnrollRequired {
		t.Fatal("admin without 2FA must get EnrollRequired")
	}
	if _, _, err := e.Auth.PasskeyRegisterBegin(ctx, p); !isCode(err, core.ErrElevationRequired) {
		t.Fatalf("enrolling begin without step-up: %v", err)
	}
	if err := e.Auth.Elevate(ctx, p, core.ElevateInput{Password: pw}); err != nil {
		t.Fatalf("an enrolling user steps up with the password: %v", err)
	}
	p = authenticate(t, e, res.Token)
	b := &authtest.Authenticator{Origin: origin, UV: true}
	if opts, flow, err = e.Auth.PasskeyRegisterBegin(ctx, p); err != nil {
		t.Fatal(err)
	}
	if resp, err = b.Create(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Auth.PasskeyRegisterFinish(ctx, p, flow, resp, "Key"); err != nil {
		t.Fatalf("enrolling finish after step-up: %v", err)
	}
	if authenticate(t, e, res.Token).EnrollRequired {
		t.Fatal("still EnrollRequired after enrolling")
	}
}

// "Keep me signed in" applies to a passwordless passkey sign-in as it does
// to a password one; as the second factor the passkey keeps the choice made
// at the password step.
func TestPasskeySignInRemember(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.session_max_days", 2)
	e.AddUser(t, "rosa", pw, core.RoleMember)
	a := &authtest.Authenticator{Origin: origin, UV: true}
	registerPasskey(t, e, a, authenticate(t, e, login(t, e, "rosa", pw).Token), "Key")
	ctx := context.Background()

	flow, resp := assert(t, e, a, nil, "")
	res, err := e.Auth.PasskeyLoginFinish(ctx, flow, resp, true, nil, clientMeta)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Session.Remember || !res.CookieExpires.Equal(e.Clock.Now().Add(48*time.Hour)) {
		t.Fatalf("remembered passkey sign-in: remember=%v cookie=%v", res.Session.Remember, res.CookieExpires)
	}
	flow, resp = assert(t, e, a, nil, "")
	if res, err = e.Auth.PasskeyLoginFinish(ctx, flow, resp, false, nil, clientMeta); err != nil {
		t.Fatal(err)
	}
	if res.Session.Remember || !res.CookieExpires.IsZero() || !res.Session.ExpiresAt.Equal(e.Clock.Now().Add(auth.BrowserSessionTTL)) {
		t.Fatalf("browser-session passkey sign-in: remember=%v cookie=%v expires=%v", res.Session.Remember, res.CookieExpires, res.Session.ExpiresAt)
	}

	// second factor after a password sign-in without "remember me"
	pending := login(t, e, "rosa", pw)
	if !pending.MFARequired {
		t.Fatal("passkey not asked as the second factor")
	}
	p1 := authenticate(t, e, pending.Token)
	flow, resp = assert(t, e, a, p1, "")
	full, err := e.Auth.PasskeyLoginFinish(ctxWith(p1), flow, resp, true, p1, clientMeta)
	if err != nil {
		t.Fatal(err)
	}
	if full.Session.Remember || !full.CookieExpires.IsZero() {
		t.Fatalf("second factor changed the password step's choice: remember=%v cookie=%v", full.Session.Remember, full.CookieExpires)
	}
}

// Over the network an administrator manages its own passkeys only; the
// admin socket keeps the administrator rule (see
// TestOthersTokensOnlyOverTheSocket).
func TestOthersPasskeysOnlyOverTheSocket(t *testing.T) {
	e := authtest.New(t)
	e.Settings.Put("auth.require_2fa", "off")
	u := e.AddUser(t, "mia", pw, core.RoleMember)
	e.AddUser(t, "root", pw, core.RoleOwner)
	pk := registerPasskey(t, e, &authtest.Authenticator{Origin: origin, UV: true}, authenticate(t, e, login(t, e, "mia", pw).Token), "Phone")
	ctx := context.Background()
	po := elevated(e, authenticate(t, e, login(t, e, "root", pw).Token))
	if err := e.Auth.RenamePasskey(ctx, po, pk.ID, "pwned"); !isCode(err, core.ErrNotFound) {
		t.Fatalf("owner renamed a member's passkey: %v", err)
	}
	if err := e.Auth.DeletePasskey(ctx, po, pk.ID); !isCode(err, core.ErrNotFound) {
		t.Fatalf("owner deleted a member's passkey: %v", err)
	}
	if list, _ := e.Auth.ListPasskeys(ctx, u.ID); len(list) != 1 || list[0].Name != "Phone" {
		t.Fatalf("passkeys %+v", list)
	}
	if err := e.Auth.DeletePasskey(ctx, core.SystemPrincipal(core.ViaSocket), pk.ID); err != nil {
		t.Fatalf("admin socket: %v", err)
	}
}

// Setting up an authenticator app on an account whose passkey already
// handed out recovery codes keeps those codes: only RegenerateRecovery
// (which needs step-up) replaces them. An account without unused codes
// gets its first set.
func TestTOTPEnrollmentKeepsRecoveryCodes(t *testing.T) {
	e := authtest.New(t)
	e.AddUser(t, "pia", pw, core.RoleMember)
	e.AddUser(t, "quin", pw, core.RoleMember)
	ctx := context.Background()
	p := elevated(e, authenticate(t, e, login(t, e, "pia", pw).Token))
	registerPasskey(t, e, &authtest.Authenticator{Origin: origin, UV: true}, p, "Key")
	old, err := e.Auth.EnsureRecoveryCodes(ctx, p)
	if err != nil || len(old) != auth.RecoveryCodeCount {
		t.Fatalf("first passkey: %d codes, %v", len(old), err)
	}
	en, err := e.Auth.TOTPBegin(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := e.Auth.TOTPConfirm(ctx, p, code(t, en.Secret, e.Clock.Now()))
	if err != nil || codes != nil {
		t.Fatalf("authenticator app replaced the recovery codes: %v %v", codes, err)
	}
	if st, _ := e.Auth.MFAStatus(ctx, p.UserID); !st.TOTPEnabled || st.RecoveryCodesLeft != auth.RecoveryCodeCount {
		t.Fatalf("status %+v", st)
	}
	res := login(t, e, "pia", pw)
	if _, err := e.Auth.VerifyRecovery(ctx, authenticate(t, e, res.Token), old[0]); err != nil {
		t.Fatalf("a code written down at the passkey step: %v", err)
	}

	// a passkey without codes yet: the authenticator app mints the first set
	q := elevated(e, authenticate(t, e, login(t, e, "quin", pw).Token))
	registerPasskey(t, e, &authtest.Authenticator{Origin: origin, UV: true}, q, "Key")
	if en, err = e.Auth.TOTPBegin(ctx, q); err != nil {
		t.Fatal(err)
	}
	if codes, err = e.Auth.TOTPConfirm(ctx, q, code(t, en.Secret, e.Clock.Now())); err != nil || len(codes) != auth.RecoveryCodeCount {
		t.Fatalf("first recovery codes: %d, %v", len(codes), err)
	}
}
