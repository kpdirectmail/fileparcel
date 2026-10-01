package securityapi

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// ---------- fake certs ----------

type fakeCerts struct {
	mu sync.Mutex

	calls []string
	err   map[string]error // per method name

	force       bool
	constrained bool
	certPEM     string
	keyPEM      string

	issued    []core.ClientCertInput
	issuer    *core.Principal
	revoked   []string
	revokeBy  []*core.Principal
	certs     []core.ClientCert
	p12       []byte
	uncovered []string
}

// UncoveredNames is the optional interface GET /admin/certs uses to report
// names the local CA may not sign.
func (f *fakeCerts) UncoveredNames() []string { return f.uncovered }

func newFakeCerts() *fakeCerts {
	return &fakeCerts{err: map[string]error{}, p12: []byte("PKCS12-BYTES\x00\x01\x02")}
}

func (f *fakeCerts) call(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	return f.err[name]
}

func (f *fakeCerts) called(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == name {
			n++
		}
	}
	return n
}

func (f *fakeCerts) TLSConfig() *tls.Config { return &tls.Config{} }
func (f *fakeCerts) Status(context.Context) (*core.CertStatus, error) {
	if err := f.call("Status"); err != nil {
		return nil, err
	}
	return &core.CertStatus{CA: &core.CertInfo{Subject: "CN=FileParcel Local CA"}, MTLSMode: "off"}, nil
}
func (f *fakeCerts) CAExport(format string) ([]byte, string, string, error) {
	if err := f.call("CAExport"); err != nil {
		return nil, "", "", err
	}
	switch format {
	case "pem":
		return []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "application/x-pem-file", "fileparcel-ca.pem", nil
	case "der":
		return []byte{0x30, 0x82, 0x01, 0x00}, "application/x-x509-ca-cert", "fileparcel-ca.crt", nil
	case "mobileconfig":
		return []byte("<?xml version=\"1.0\"?><plist/>"), "application/x-apple-aspen-config", "fileparcel-ca.mobileconfig", nil
	}
	return nil, "", "", core.Invalid("format", "bad format")
}
func (f *fakeCerts) Fingerprint() string { return "AA:BB" }
func (f *fakeCerts) RenewLocal(_ context.Context, force bool) error {
	f.mu.Lock()
	f.force = force
	f.mu.Unlock()
	return f.call("RenewLocal")
}
func (f *fakeCerts) RegenerateCA(_ context.Context, _ *core.Principal, constrained bool) error {
	f.mu.Lock()
	f.constrained = constrained
	f.mu.Unlock()
	return f.call("RegenerateCA")
}
func (f *fakeCerts) SetCustom(_ context.Context, _ *core.Principal, certPEM, keyPEM []byte) error {
	f.mu.Lock()
	f.certPEM, f.keyPEM = string(certPEM), string(keyPEM)
	f.mu.Unlock()
	return f.call("SetCustom")
}
func (f *fakeCerts) ClearCustom(context.Context, *core.Principal) error { return f.call("ClearCustom") }
func (f *fakeCerts) ApplyACME(context.Context) error                    { return f.call("ApplyACME") }
func (f *fakeCerts) FetchTailscale(context.Context) error               { return f.call("FetchTailscale") }
func (f *fakeCerts) HTTPChallenge(next http.Handler) http.Handler       { return next }
func (f *fakeCerts) PubliclyTrusted(string) bool                        { return false }
func (f *fakeCerts) IssueClient(_ context.Context, by *core.Principal, in core.ClientCertInput) (*core.ClientCert, []byte, error) {
	if err := f.call("IssueClient"); err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = append(f.issued, in)
	f.issuer = by
	cc := core.ClientCert{ID: "ccr_" + strings.Repeat("x", 26), UserID: in.UserID, Username: "alice", Name: in.Name,
		Serial: "0A", NotAfter: time.Now().Add(24 * time.Hour), IssuedAt: time.Now()}
	f.certs = append(f.certs, cc)
	return &cc, slices.Clone(f.p12), nil
}
func (f *fakeCerts) ListClient(_ context.Context, q core.PageReq, userID string) (core.Page[core.ClientCert], error) {
	if err := f.call("ListClient"); err != nil {
		return core.Page[core.ClientCert]{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	items := []core.ClientCert{}
	for _, c := range f.certs {
		if userID == "" || c.UserID == userID {
			items = append(items, c)
		}
	}
	return core.Page[core.ClientCert]{Items: items}, nil
}
func (f *fakeCerts) RevokeClient(_ context.Context, by *core.Principal, id, reason string) error {
	if err := f.call("RevokeClient"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.certs {
		if c.ID == id {
			if by != nil && !by.Can(core.CapCertsManage) && by.UserID != c.UserID {
				return core.NotFoundf("client certificate not found")
			}
			f.revoked = append(f.revoked, id+"|"+reason)
			f.revokeBy = append(f.revokeBy, by)
			return nil
		}
	}
	return core.NotFoundf("client certificate not found")
}
func (f *fakeCerts) CheckClient(context.Context, *tls.ConnectionState) (*core.ClientCert, error) {
	return nil, core.ErrUnauthorized
}
func (f *fakeCerts) Init(context.Context) error  { return nil }
func (f *fakeCerts) Start(context.Context) error { return nil }

// ---------- fake keys ----------

type fakeKeys struct {
	mu     sync.Mutex
	state  core.KeyState
	pass   string
	calls  []string
	err    map[string]error
	ctxP   *core.Principal // principal in the context of the last Unlock
	rotate []string
}

func newFakeKeys(state core.KeyState) *fakeKeys {
	return &fakeKeys{state: state, pass: "correct horse", err: map[string]error{}}
}

func (k *fakeKeys) call(name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, name)
	return k.err[name]
}

func (k *fakeKeys) called(name string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Contains(k.calls, name)
}

func (k *fakeKeys) State() core.KeyState {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.state
}
func (k *fakeKeys) Init(context.Context, bool, []byte) (string, error) { return "", core.ErrConflict }
func (k *fakeKeys) Unlock(ctx context.Context, pass []byte) error {
	if err := k.call("Unlock"); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ctxP = core.PrincipalFrom(ctx)
	if string(pass) != k.pass {
		return core.Errorf(core.ErrUnauthorized, "wrong passphrase or recovery key")
	}
	k.state = core.KeyStateUnlocked
	return nil
}
func (k *fakeKeys) Lock(context.Context) error {
	if err := k.call("Lock"); err != nil {
		return err
	}
	k.mu.Lock()
	k.state = core.KeyStateLocked
	k.mu.Unlock()
	return nil
}
func (k *fakeKeys) Status(context.Context) (*core.KeyStatus, error) {
	return &core.KeyStatus{State: k.State(), Mode: core.KeyModeSealed, CipherName: "aes-256-gcm", KEKs: []core.KEKInfo{}}, nil
}
func (k *fakeKeys) NewDEK([]byte) ([]byte, []byte, string, error) {
	return nil, nil, "", core.ErrKeysLocked
}
func (k *fakeKeys) UnwrapDEK([]byte, string, []byte) ([]byte, error) { return nil, core.ErrKeysLocked }
func (k *fakeKeys) SealField(string, []byte) (string, error)         { return "", core.ErrKeysLocked }
func (k *fakeKeys) OpenField(string, string) ([]byte, error)         { return nil, core.ErrKeysLocked }
func (k *fakeKeys) MAC(string, ...[]byte) []byte                     { return nil }
func (k *fakeKeys) Seal(_ context.Context, p []byte) error {
	if len(p) == 0 {
		return core.Invalid("passphrase", "empty")
	}
	return k.call("Seal")
}
func (k *fakeKeys) Unseal(_ context.Context, p []byte) error {
	if string(p) != k.pass {
		return core.Errorf(core.ErrUnauthorized, "wrong passphrase")
	}
	return k.call("Unseal")
}
func (k *fakeKeys) ChangePassphrase(_ context.Context, oldP, newP []byte) error {
	if string(oldP) != k.pass {
		return core.Errorf(core.ErrUnauthorized, "wrong passphrase")
	}
	if err := k.call("ChangePassphrase"); err != nil {
		return err
	}
	k.mu.Lock()
	k.pass = string(newP)
	k.mu.Unlock()
	return nil
}
func (k *fakeKeys) RotateKEK(_ context.Context, purpose string, _ func(int64, int64)) error {
	k.mu.Lock()
	k.rotate = append(k.rotate, "kek:"+purpose)
	k.mu.Unlock()
	return k.call("RotateKEK")
}
func (k *fakeKeys) RotateMaster(context.Context) error {
	k.mu.Lock()
	k.rotate = append(k.rotate, "master")
	k.mu.Unlock()
	return k.call("RotateMaster")
}
func (k *fakeKeys) ExportRecovery(context.Context) (string, error) {
	if err := k.call("ExportRecovery"); err != nil {
		return "", err
	}
	return "FPRK-TEST-1234", nil
}
func (k *fakeKeys) Cipher() core.CipherID { return core.CipherAES256GCM }

// ---------- fake jobs ----------

type enqueued struct {
	kind   string
	params string
	by     *core.Principal
}

type fakeJobs struct {
	mu  sync.Mutex
	q   []enqueued
	err error
}

func (j *fakeJobs) Register(string, core.JobFunc, core.JobOptions) {}
func (j *fakeJobs) Enqueue(_ context.Context, kind string, params any, by *core.Principal) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.err != nil {
		return "", j.err
	}
	b, _ := json.Marshal(params)
	j.q = append(j.q, enqueued{kind: kind, params: string(b), by: by})
	return "job_test0000000000000000000001", nil
}
func (j *fakeJobs) Get(context.Context, string) (*core.Job, error) { return nil, core.ErrNotFound }
func (j *fakeJobs) List(context.Context, core.JobQuery) (core.Page[core.Job], error) {
	return core.Page[core.Job]{}, nil
}
func (j *fakeJobs) Cancel(context.Context, string) error                  { return nil }
func (j *fakeJobs) Schedule(string, string, string, any) error            { return nil }
func (j *fakeJobs) Unschedule(string)                                     {}
func (j *fakeJobs) Schedules(context.Context) ([]core.JobSchedule, error) { return nil, nil }
func (j *fakeJobs) Start(context.Context) error                           { return nil }
func (j *fakeJobs) Stop(context.Context) error                            { return nil }

// ---------- fake users ----------

// fakeUsers implements the two Users methods this package calls; the
// embedded nil interface makes any other call panic (a test failure).
type fakeUsers struct {
	core.Users
	count  int
	byName map[string]*core.User
}

func (u *fakeUsers) Count(context.Context) (int, error) { return u.count, nil }
func (u *fakeUsers) GetByUsername(_ context.Context, name string) (*core.User, error) {
	if x, ok := u.byName[strings.ToLower(name)]; ok {
		return x, nil
	}
	return nil, core.NotFoundf("user not found")
}

// ---------- fake settings ----------

type fakeSettings struct {
	mu sync.Mutex
	m  map[string]any
}

func (s *fakeSettings) set(key string, v any) {
	s.mu.Lock()
	s.m[key] = v
	s.mu.Unlock()
}
func (s *fakeSettings) get(key string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key]
}
func (s *fakeSettings) Raw(key string) (json.RawMessage, error) { return json.Marshal(s.get(key)) }
func (s *fakeSettings) Int(key string) int64                    { n, _ := s.get(key).(int64); return n }
func (s *fakeSettings) Bool(key string) bool                    { b, _ := s.get(key).(bool); return b }
func (s *fakeSettings) String(key string) string                { x, _ := s.get(key).(string); return x }
func (s *fakeSettings) Strings(key string) []string             { x, _ := s.get(key).([]string); return x }
func (s *fakeSettings) Duration(string) time.Duration           { return 0 }
func (s *fakeSettings) Secret(string) (string, error)           { return "", nil }
func (s *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, core.ErrNotImplemented
}
func (s *fakeSettings) Reset(context.Context, *core.Principal, string) error { return nil }
func (s *fakeSettings) Catalog(context.Context) ([]core.SettingView, error)  { return nil, nil }

// ---------- fake network ----------

// fakeNetwork lists canned interfaces (keys.web_unlock=lan reads them).
type fakeNetwork struct {
	core.Network
	ifs []core.NetInterface
	err error
}

func (n *fakeNetwork) Interfaces(context.Context) ([]core.NetInterface, error) { return n.ifs, n.err }

// ---------- fake audit ----------

type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
	actors  []*core.Principal
}

func (a *fakeAudit) Record(ctx context.Context, e core.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	a.actors = append(a.actors, core.PrincipalFrom(ctx))
}
func (a *fakeAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}
func (a *fakeAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, nil
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error)                { return nil, nil }
func (a *fakeAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error { return nil }
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error)                    { return 0, nil }

func (a *fakeAudit) find(action string) []core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []core.AuditEntry
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (a *fakeAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// ---------- harness ----------

// Test principals, selected per request with the X-Test-As header (set by
// the testPrincipal middleware before Authenticate, like the admin socket's
// ConnContext; Authenticate keeps a context principal).
const headerTestAs = "X-Test-As"

var testNow = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func testPrincipal(name string) *core.Principal {
	elevated := testNow.Add(10 * time.Minute)
	switch name {
	case "admin":
		return &core.Principal{UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Via: core.ViaToken,
			Scopes: []string{core.ScopeAdmin}, AuthLevel: core.AuthLevelFull}
	case "admin-elevated":
		return &core.Principal{UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Via: core.ViaToken,
			Scopes: []string{core.ScopeAdmin}, AuthLevel: core.AuthLevelFull, ElevatedUntil: elevated}
	case "member":
		return &core.Principal{UserID: "usr_alice", Username: "alice", Role: core.RoleMember, Via: core.ViaToken,
			Scopes: core.AllScopes, AuthLevel: core.AuthLevelFull, ElevatedUntil: elevated}
	case "bob":
		return &core.Principal{UserID: "usr_bob", Username: "bob", Role: core.RoleMember, Via: core.ViaToken,
			Scopes: core.AllScopes, AuthLevel: core.AuthLevelFull}
	case "enrolling":
		return &core.Principal{UserID: "usr_carol", Username: "carol", Role: core.RoleMember, Via: core.ViaToken,
			Scopes: core.AllScopes, AuthLevel: core.AuthLevelFull, EnrollRequired: true}
	case "mfa-pending":
		return &core.Principal{UserID: "usr_dave", Username: "dave", Role: core.RoleAdmin, Via: core.ViaToken,
			Scopes: []string{core.ScopeAdmin}, AuthLevel: core.AuthLevelPassword}
	case "certmgr", "certmgr-files":
		// A member-based custom role with certs.manage ("Certificates"),
		// over an elevated admin-scope token, or a token without that scope.
		p := &core.Principal{UserID: "usr_carl", Username: "carl", Role: core.RoleMember,
			RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na", RoleName: "Certificate managers", Via: core.ViaToken,
			Scopes: []string{core.ScopeAdmin}, AuthLevel: core.AuthLevelFull, ElevatedUntil: elevated}
		if name == "certmgr-files" {
			p.Scopes = []string{core.ScopeFilesRead}
		}
		p.SetCaps(core.MemberCaps.With(core.CapCertsManage))
		return p
	case "socket":
		return core.SystemPrincipal(core.ViaSocket)
	case "socket-as-alice":
		return &core.Principal{UserID: "usr_alice", Username: "alice", Role: core.RoleMember, Via: core.ViaSocket,
			AuthLevel: core.AuthLevelFull, ElevatedUntil: testNow.Add(time.Hour)}
	case "offline":
		return core.SystemPrincipal(core.ViaOffline)
	}
	return nil
}

func injectTestPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := testPrincipal(r.Header.Get(headerTestAs)); p != nil {
			r = r.WithContext(core.WithPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

type harness struct {
	d        *app.Deps
	certs    *fakeCerts
	keys     *fakeKeys
	jobs     *fakeJobs
	users    *fakeUsers
	settings *fakeSettings
	audit    *fakeAudit
	h        http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	hs := &harness{
		certs:    newFakeCerts(),
		keys:     newFakeKeys(core.KeyStateUnlocked),
		jobs:     &fakeJobs{},
		users:    &fakeUsers{count: 2, byName: map[string]*core.User{"alice": {ID: "usr_alice", Username: "alice"}}},
		settings: &fakeSettings{m: map[string]any{}},
		audit:    &fakeAudit{},
	}
	env := &core.Env{Clock: core.ClockFunc(func() time.Time { return testNow }), Keys: hs.keys, Settings: hs.settings, Audit: hs.audit}
	hs.d = &app.Deps{Env: env, Mode: app.ModeNetwork, Certs: hs.certs, Jobs: hs.jobs, Users: hs.users}
	hs.h = newRouter(hs.d)
	return hs
}

// newRouter mirrors web.NewRouter for this package's routes.
func newRouter(d *app.Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP, injectTestPrincipal)
	api := chi.NewRouter()
	Mount(api, d)
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.RateLimit(mw.BucketAPI, mw.PerIP), mw.Authenticate, mw.CSRF).Mount("/api/v1", api)
	MountRoot(r, d)
	return r
}

type reqOpt func(*http.Request)

func as(name string) reqOpt { return func(r *http.Request) { r.Header.Set(headerTestAs, name) } }
func from(addr string) reqOpt {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

// do sends a request; body (if not nil and not a string) is JSON-encoded.
func (hs *harness) do(t *testing.T, method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = strings.NewReader(string(data))
	}
	req := httptest.NewRequest(method, path, rd)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

// errCode returns the error code of an API error response ("" otherwise).
func errCode(rec *httptest.ResponseRecorder) string {
	var e httpx.ErrorResponse
	if json.Unmarshal(rec.Body.Bytes(), &e) != nil {
		return ""
	}
	return e.Error.Code
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T from %q: %v", v, rec.Body.String(), err)
	}
	return v
}
