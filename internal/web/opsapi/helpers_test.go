package opsapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/web/mw"
)

// ---------- fakes ----------

type fakeJobs struct {
	mu        sync.Mutex
	jobs      map[string]*core.Job
	enqueued  []string // kinds
	canceled  []string
	running   bool
	schedules []core.JobSchedule
	kinds     map[string]bool
}

func newFakeJobs() *fakeJobs {
	return &fakeJobs{jobs: map[string]*core.Job{}, kinds: map[string]bool{
		core.JobMaintSessions: true, core.JobMaintDBOptimize: true, core.JobBackupPrune: true,
		core.JobBackupCreate: true, core.JobBackupVerify: true,
	}}
}

func (f *fakeJobs) add(j core.Job) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs[j.ID] = &j
}

func (f *fakeJobs) Register(string, core.JobFunc, core.JobOptions) {}
func (f *fakeJobs) Enqueue(ctx context.Context, kind string, params any, by *core.Principal) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueued = append(f.enqueued, kind)
	id := fmt.Sprintf("job_%026d", len(f.enqueued))
	return id, nil
}
func (f *fakeJobs) Get(ctx context.Context, id string) (*core.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if j, ok := f.jobs[id]; ok {
		c := *j
		return &c, nil
	}
	return nil, core.NotFoundf("job not found")
}
func (f *fakeJobs) List(ctx context.Context, q core.JobQuery) (core.Page[core.Job], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []core.Job
	for _, j := range f.jobs {
		if q.Kind != "" && j.Kind != q.Kind {
			continue
		}
		out = append(out, *j)
	}
	return core.NewPage(out, ""), nil
}
func (f *fakeJobs) Cancel(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.jobs[id]; !ok {
		return core.NotFoundf("job not found")
	}
	f.canceled = append(f.canceled, id)
	return nil
}
func (f *fakeJobs) Schedule(name, cron, kind string, params any) error { return nil }
func (f *fakeJobs) Unschedule(string)                                  {}
func (f *fakeJobs) Schedules(context.Context) ([]core.JobSchedule, error) {
	return f.schedules, nil
}
func (f *fakeJobs) Start(context.Context) error { return nil }
func (f *fakeJobs) Stop(context.Context) error  { return nil }
func (f *fakeJobs) Registered(kind string) bool { return f.kinds[kind] }
func (f *fakeJobs) Running() bool               { return f.running }

type fakeBackups struct {
	core.Backups
	mu          sync.Mutex
	items       []core.Backup
	file        string // served by Download
	calls       []string
	config      core.BackupConfig
	exportedAt  *time.Time
	lastCreds   core.RestoreCreds
	lastImport  []byte
	lastInput   core.BackupInput
	lastVerifyD bool
	listErr     error
}

func (f *fakeBackups) call(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeBackups) called(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == s {
			return true
		}
	}
	return false
}

func (f *fakeBackups) List(ctx context.Context, q core.PageReq) (core.Page[core.Backup], error) {
	if f.listErr != nil {
		return core.Page[core.Backup]{}, f.listErr
	}
	return core.NewPage(f.items, ""), nil
}
func (f *fakeBackups) Get(ctx context.Context, id string) (*core.Backup, error) {
	for _, b := range f.items {
		if b.ID == id {
			c := b
			return &c, nil
		}
	}
	return nil, core.NotFoundf("backup not found")
}
func (f *fakeBackups) Create(ctx context.Context, by *core.Principal, in core.BackupInput) (string, error) {
	f.call("create")
	f.lastInput = in
	return "job_create", nil
}
func (f *fakeBackups) CreateSync(ctx context.Context, by *core.Principal, in core.BackupInput) (*core.Backup, error) {
	f.call("createsync")
	return &core.Backup{ID: "bak_sync", State: core.BackupReady, Scope: in.Scope}, nil
}
func (f *fakeBackups) Delete(ctx context.Context, by *core.Principal, id string) error {
	f.call("delete:" + id)
	return nil
}
func (f *fakeBackups) Verify(ctx context.Context, by *core.Principal, id string, deep bool) (string, error) {
	f.call("verify:" + id)
	f.lastVerifyD = deep
	return "job_verify", nil
}
func (f *fakeBackups) Download(ctx context.Context, id string) (io.ReadCloser, int64, string, error) {
	b, err := f.Get(ctx, id)
	if err != nil {
		return nil, 0, "", err
	}
	fh, err := os.Open(f.file)
	if err != nil {
		return nil, 0, "", err
	}
	st, _ := fh.Stat()
	return fh, st.Size(), b.FileName, nil
}
func (f *fakeBackups) Import(ctx context.Context, by *core.Principal, r io.Reader) (*core.Backup, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	f.lastImport = b
	f.call("import")
	return &core.Backup{ID: "bak_imported", State: core.BackupReady, Trigger: core.TriggerImport, Size: int64(len(b))}, nil
}
func (f *fakeBackups) ScheduleRestore(ctx context.Context, by *core.Principal, id string, c core.RestoreCreds) error {
	f.call("restore:" + id)
	f.lastCreds = c
	return nil
}
func (f *fakeBackups) Config(context.Context) (*core.BackupConfig, error) {
	c := f.config
	return &c, nil
}
func (f *fakeBackups) SetConfig(ctx context.Context, by *core.Principal, c core.BackupConfig) error {
	f.call("setconfig")
	f.config = c
	f.config.HasPassphrase = c.Passphrase != nil && *c.Passphrase != ""
	f.config.Passphrase = nil
	return nil
}
func (f *fakeBackups) GenerateIdentity(ctx context.Context, by *core.Principal) (string, string, error) {
	f.call("generate")
	return "age1recipient", "AGE-SECRET-KEY-1TEST", nil
}
func (f *fakeBackups) ExportIdentity(ctx context.Context, by *core.Principal) (string, string, error) {
	f.call("export")
	return "age1recipient", "AGE-SECRET-KEY-1TEST", nil
}
func (f *fakeBackups) IdentityExportedAt(context.Context) *time.Time { return f.exportedAt }

type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
	lastQ   core.AuditQuery
	failExp bool
	failMid bool // fail after the first rows went out
}

func (a *fakeAudit) Record(ctx context.Context, e core.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
}
func (a *fakeAudit) RecordTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}
func (a *fakeAudit) Query(ctx context.Context, q core.AuditQuery) (core.Page[core.AuditRecord], error) {
	a.mu.Lock()
	a.lastQ = q
	a.mu.Unlock()
	return core.NewPage([]core.AuditRecord{{Seq: 1, ID: "aud_1", Action: "auth.login", Outcome: "success",
		Details: json.RawMessage(`{}`)}}, ""), nil
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error) {
	return &core.AuditVerify{OK: true, Checked: 1, FirstSeq: 1, LastSeq: 1}, nil
}
func (a *fakeAudit) Export(ctx context.Context, q core.AuditQuery, format string, w io.Writer) error {
	if a.failExp {
		return core.Errorf(core.ErrUnavailable, "export failed")
	}
	_, err := io.WriteString(w, "seq,action\n1,auth.login\n")
	if err == nil && a.failMid {
		// A first page big enough to get past net/http's response buffer,
		// then a read error, as audit.Export fails on a later page.
		_, err = io.WriteString(w, strings.Repeat("2,auth.login\n", 2000))
		if err == nil {
			err = core.Errorf(core.ErrUnavailable, "db gone")
		}
	}
	return err
}
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error) { return 0, nil }

func (a *fakeAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

func (a *fakeAudit) count(action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

type fakeKeys struct {
	core.Keys
	state core.KeyState
	mode  string
	rec   bool
}

func (k *fakeKeys) State() core.KeyState { return k.state }
func (k *fakeKeys) Status(context.Context) (*core.KeyStatus, error) {
	return &core.KeyStatus{State: k.state, Mode: k.mode, RecoveryConfigured: k.rec}, nil
}

type fakeCerts struct {
	core.Certs
	st *core.CertStatus
}

func (c *fakeCerts) Status(context.Context) (*core.CertStatus, error) { return c.st, nil }

type fakeMDNS struct {
	core.MDNS
	st core.MDNSStatus
}

func (m *fakeMDNS) Status() core.MDNSStatus { return m.st }

type fakeNetwork struct {
	core.Network
	pol core.AccessPolicy
	ifs []core.NetInterface
}

func (n *fakeNetwork) Policy() core.AccessPolicy { return n.pol }
func (n *fakeNetwork) URLs(context.Context) ([]core.AccessURL, error) {
	return []core.AccessURL{{URL: "https://192.168.1.10:8443"}}, nil
}
func (n *fakeNetwork) Interfaces(context.Context) ([]core.NetInterface, error) { return n.ifs, nil }

type fakeUsers struct {
	core.Users
	users []core.User
}

func (u *fakeUsers) Count(context.Context) (int, error) { return len(u.users), nil }
func (u *fakeUsers) List(ctx context.Context, q core.UserQuery) (core.Page[core.User], error) {
	var out []core.User
	for _, x := range u.users {
		if (q.Role == "" || x.Role == q.Role) && (q.RoleID == "" || x.RoleID == q.RoleID) &&
			(q.Status == "" || x.Status == q.Status) {
			out = append(out, x)
		}
	}
	return core.NewPage(out, ""), nil
}

type fakeAuth struct {
	core.Auth
	mfa  map[string]*core.MFAStatus
	errs map[string]error
}

func (a *fakeAuth) MFAStatus(ctx context.Context, id string) (*core.MFAStatus, error) {
	if err := a.errs[id]; err != nil {
		return nil, err
	}
	if s, ok := a.mfa[id]; ok {
		return s, nil
	}
	return &core.MFAStatus{}, nil
}

// ---------- environment ----------

type testEnv struct {
	t       *testing.T
	h       *home.Home
	d       *app.Deps
	jobs    *fakeJobs
	backups *fakeBackups
	audit   *fakeAudit
	keys    *fakeKeys
	certs   *fakeCerts
	mdns    *fakeMDNS
	net     *fakeNetwork
	users   *fakeUsers
	auth    *fakeAuth
	bus     *events.Bus
	now     time.Time
	handler http.Handler
}

// Test principals (X-Test-As header).
var principals = map[string]*core.Principal{
	"alice": {UserID: "usr_alice", Username: "alice", Role: core.RoleMember, Via: core.ViaSession, AuthLevel: 2},
	"bob":   {UserID: "usr_bob", Username: "bob", Role: core.RoleMember, Via: core.ViaSession, AuthLevel: 2},
	"admin": {UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2},
	"elevated": {UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2,
		ElevatedUntil: time.Now().Add(time.Hour)},
	"mfa":      {UserID: "usr_alice", Username: "alice", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 1},
	"token":    {UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeFilesRead}},
	"adminTok": {UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeAdmin}},
	"system":   core.SystemPrincipal(core.ViaSocket),
}

func newTestEnv(t *testing.T, mode app.Mode) *testEnv {
	t.Helper()
	h, err := home.New(filepath.Join(t.TempDir(), "home"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default(config.NewInstallID())
	if err := cfg.SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	if cfg, err = config.Load(h); err != nil {
		t.Fatal(err)
	}
	dbh, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dbh.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	te := &testEnv{t: t, h: h, jobs: newFakeJobs(), audit: &fakeAudit{}, bus: events.New(),
		keys:  &fakeKeys{state: core.KeyStateUnlocked, mode: core.KeyModePlain},
		mdns:  &fakeMDNS{st: core.MDNSStatus{State: core.MDNSPublished, Name: "fileparcel.local", Backend: "avahi"}},
		net:   &fakeNetwork{pol: core.AccessPolicy{Mode: "allowlist", Allow: []string{"192.168.1.0/24"}}},
		users: &fakeUsers{}, auth: &fakeAuth{mfa: map[string]*core.MFAStatus{}},
		now: time.Now().UTC()}
	te.backups = &fakeBackups{config: core.BackupConfig{Enabled: true, ScheduleMeta: "0 3 * * *", ScheduleFull: "0 4 * * 0",
		Encryption: core.BackupX25519, Recipients: []string{"age1x"}, HasIdentity: true}}
	leaf := &core.CertInfo{Subject: "fileparcel.local", NotBefore: te.now.Add(-time.Hour), NotAfter: te.now.Add(300 * 24 * time.Hour)}
	ca := &core.CertInfo{Subject: "FileParcel CA", NotBefore: te.now.Add(-time.Hour), NotAfter: te.now.Add(3000 * 24 * time.Hour)}
	te.certs = &fakeCerts{st: &core.CertStatus{Leaf: leaf, CA: ca}}
	env := &core.Env{Home: h, Config: cfg, DB: dbh, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock: core.ClockFunc(func() time.Time { return te.now }), Bus: te.bus, Keys: te.keys, Audit: te.audit}
	env.Build.Version = "v9"
	env.Build.Date = "2026-01-01T00:00:00Z"
	te.d = &app.Deps{Env: env, Mode: mode, Jobs: te.jobs, Backups: te.backups, Certs: te.certs, MDNS: te.mdns,
		Network: te.net, Users: te.users, Auth: te.auth}
	te.handler = testRouter(te.d)
	detectFirewalls = func(context.Context) []svc.Firewall { return nil }
	builtinMDNSLikely = func() bool { return false }
	t.Cleanup(func() {
		te.bus.Close()
		_ = dbh.Close()
	})
	return te
}

// testRouter mounts the package on /api/v1 like web.NewRouter, with the
// principal taken from the X-Test-As header.
func testRouter(d *app.Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead)
	api := chi.NewRouter()
	Mount(api, d)
	r.With(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if p := principals[req.Header.Get("X-Test-As")]; p != nil {
				p = p.Clone()
				p.IP = netip.MustParseAddr("192.168.1.10")
				req = req.WithContext(core.WithPrincipal(req.Context(), p))
			}
			next.ServeHTTP(w, req)
		})
	}).Mount("/api/v1", api)
	return r
}

type resp struct {
	code int
	hdr  http.Header
	body []byte
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
}

func (r resp) errCode() string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(r.body, &e)
	return e.Error.Code
}

// do performs a request as principal who ("" = anonymous).
func (te *testEnv) do(method, path, who string, body io.Reader, hdr ...string) resp {
	te.t.Helper()
	req := httptest.NewRequest(method, "/api/v1"+path, body)
	if who != "" {
		req.Header.Set("X-Test-As", who)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	te.handler.ServeHTTP(rec, req)
	return resp{code: rec.Code, hdr: rec.Header(), body: rec.Body.Bytes()}
}

func jsonBody(v any) io.Reader {
	b, _ := json.Marshal(v)
	return strings.NewReader(string(b))
}
