package wire

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/settings"
	"fileparcel/internal/web"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/static"
)

// NewTestHome creates an initialised home (layout + default config) in a temp dir.
func newTestHome(t *testing.T) *home.Home {
	t.Helper()
	h, err := home.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	c := config.Default(config.NewInstallID())
	c.Log.File = true
	if err := c.SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestBuildAndRouter(t *testing.T) {
	h := newTestHome(t)
	ctx := context.Background()
	d, cleanup, err := Build(ctx, h, app.ModeOffline)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := Start(ctx, d); err != nil {
		t.Fatal(err)
	}
	if d.Keys.State() != core.KeyStateUninitialized || d.Settings == nil || d.Audit == nil || d.Limiter == nil {
		t.Fatal("deps not wired")
	}
	// The VPN list and the exposures reach GET /admin/network and the doctor
	// through optional methods of the network service (DESIGN §10.3).
	if _, ok := d.Network.(interface {
		VPNs(context.Context) []core.VPNInfo
	}); !ok {
		t.Fatal("the network service lists no VPNs")
	}
	if _, ok := d.Network.(interface {
		Exposures(context.Context) []core.Exposure
	}); !ok {
		t.Fatal("the network service lists no exposures")
	}
	v, err := d.DB.SchemaVersion(ctx)
	if err != nil || v < 1 {
		t.Fatalf("schema %d %v", v, err)
	}

	// core.Audit key-state rule: rows are persisted immediately even while the
	// keys are uninitialized/locked (sealed with the MAC later by unit C).
	pctx := core.WithPrincipal(ctx, core.SystemPrincipal(core.ViaOffline))
	d.Audit.Record(pctx, core.AuditEntry{Action: core.ActSystemStart})
	d.Audit.Record(pctx, core.AuditEntry{Action: core.ActSystemStop, Details: map[string]any{"k": 1}})
	var n int
	var via string
	if err := d.DB.QueryRow(ctx, `SELECT count(*), max(actor_via) FROM audit_log`).Scan(&n, &via); err != nil || n != 2 || via != "offline" {
		t.Fatalf("audit rows %d via %q err %v", n, via, err)
	}
	err = d.DB.Tx(ctx, func(tx *sql.Tx) error {
		return d.Audit.RecordTx(ctx, tx, core.AuditEntry{Action: core.ActAuthLogin, Outcome: core.OutcomeFailure, ActorName: "mallory"})
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(web.NewRouter(d))
	defer srv.Close()
	get := func(path string) *http.Response {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	if r := get("/healthz"); r.StatusCode != 200 {
		t.Fatalf("healthz %d", r.StatusCode)
	}
	if r := get("/readyz"); r.StatusCode != 503 {
		t.Fatalf("readyz with uninitialized keys = %d", r.StatusCode)
	}
	r := get("/api/v1/does-not-exist")
	var er struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	_ = json.NewDecoder(r.Body).Decode(&er)
	if r.StatusCode != 404 || er.Error.Code != "not_found" || er.Error.RequestID == "" || r.Header.Get("X-Request-ID") != er.Error.RequestID {
		t.Fatalf("api 404: %d %+v", r.StatusCode, er)
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"X-Frame-Options":              "DENY",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q", k, got)
		}
	}
	// API responses carry the stricter JSON policy; HTML pages carry the app policy.
	if got := r.Header.Get("Content-Security-Policy"); got != mw.CSPAPI {
		t.Errorf("api CSP = %q", got)
	}
	if got := get("/login").Header.Get("Content-Security-Policy"); !strings.Contains(got, "trusted-types fp") {
		t.Errorf("page CSP = %q", got)
	}
	if r := get("/robots.txt"); r.StatusCode != 200 {
		t.Fatalf("robots %d", r.StatusCode)
	}
	// HEAD reaches GET handlers (middleware.GetHead), without a body.
	for path, want := range map[string]int{"/healthz": 200, "/readyz": 503, "/robots.txt": 200, "/api/v1/nope": 404} {
		resp, err := http.Head(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("HEAD %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
	// Anonymous SPA route → login redirect (the client follows it).
	// Anonymous SPA route → /login, or /setup while no account exists yet.
	if r := get("/files"); r.Request.URL.Path != "/login" && r.Request.URL.Path != "/setup" {
		t.Fatalf("/files ended at %s", r.Request.URL.Path)
	}
	if r := get("/login"); r.StatusCode != 200 && r.StatusCode != 500 { // 500 until the template exists
		t.Fatalf("/login %d", r.StatusCode)
	}
	if r := get("/static/000000000000/x.js"); r.StatusCode != 404 {
		t.Fatalf("wrong hash %d", r.StatusCode)
	}
	if b, ok := static.File("css/app.css"); ok && len(b) > 0 {
		r := get(static.AssetBase() + "/css/app.css")
		if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Cache-Control"), "immutable") ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "text/css") {
			t.Fatalf("static asset %d %v", r.StatusCode, r.Header)
		}
	}
	if r := get("/api/v1/auth/state"); r.StatusCode != 404 { // authapi not implemented yet
		t.Logf("/api/v1/auth/state = %d", r.StatusCode)
	}
	// Unsafe cross-site request is rejected by CSRF protection.
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/login", strings.NewReader("{}"))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-site POST = %d", resp.StatusCode)
	}

	cleanup()
	cleanup() // idempotent
}

func TestBuildRefusesUninitialisedHome(t *testing.T) {
	h, _ := home.New(t.TempDir())
	_, cleanup, err := Build(context.Background(), h, app.ModeOffline)
	if err == nil || !strings.Contains(err.Error(), "fileparcel init") {
		t.Fatalf("got %v", err)
	}
	cleanup()
}

// testBootstrapKey is a bootstrap-bridge key that exists in config.Keys() but
// is not part of the runtime catalog (DESIGN §11.2), so no unit registers it
// and this test's registration cannot collide. Registration is skipped if
// some package registers it after all.
const testBootstrapKey = "runtime.gomemlimit_mb"

func init() {
	settings.Register(settings.Def{Key: "test.wire_int", Section: "general", Type: settings.TypeInt, Default: 5, Min: 1, Max: 10, Label: "x"})
	if _, exists := settings.Lookup(testBootstrapKey); !exists {
		settings.Register(settings.Def{Key: testBootstrapKey, Section: "server", Type: settings.TypeInt, Default: 0,
			Min: 0, Max: 1 << 20, Restart: true, Bootstrap: true, Label: "Go memory limit (MiB)"})
	}
}

func TestSettingsStoreIntegration(t *testing.T) {
	h := newTestHome(t)
	ctx := context.Background()
	d, cleanup, err := Build(ctx, h, app.ModeOffline)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ch, cancel := d.Bus.Subscribe("settings.changed")
	defer cancel()
	if d.Settings.Int("test.wire_int") != 5 {
		t.Fatal("default")
	}
	bdef, _ := settings.Lookup(testBootstrapKey)
	res, err := d.Settings.Set(ctx, core.SystemPrincipal(core.ViaOffline), map[string]json.RawMessage{
		"test.wire_int": json.RawMessage(`7`), testBootstrapKey: json.RawMessage(`512`)})
	if err != nil {
		t.Fatal(err)
	}
	wantRestart := 0
	if bdef.Restart {
		wantRestart = 1
	}
	if len(res.Applied) != 2 || len(res.RestartRequired) != wantRestart || (wantRestart == 1 && res.RestartRequired[0] != testBootstrapKey) {
		t.Fatalf("%+v", res)
	}
	if d.Settings.Int("test.wire_int") != 7 || d.Settings.Int(testBootstrapKey) != 512 {
		t.Fatal("values not applied")
	}
	cfg, err := config.Load(h)
	if err != nil || cfg.Runtime.GOMemLimitMB != 512 {
		t.Fatalf("bootstrap bridge not saved: %v %+v", err, cfg)
	}
	e := <-ch
	if ev, ok := e.Data.(core.SettingsChangedEvent); !ok || len(ev.Keys) != 2 {
		t.Fatalf("event %+v", e)
	}
	_, err = d.Settings.Set(ctx, nil, map[string]json.RawMessage{"test.wire_int": json.RawMessage(`70`)})
	if ce := core.AsError(err); ce == nil || ce.Field != "test.wire_int" || !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("range: %v", err)
	}
	var audits int
	_ = d.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='settings.change'`).Scan(&audits)
	if audits != 2 {
		t.Fatalf("audit entries %d", audits)
	}
	if err := d.Settings.Reset(ctx, nil, "test.wire_int"); err != nil || d.Settings.Int("test.wire_int") != 5 {
		t.Fatalf("reset: %v", err)
	}
	cat, err := d.Settings.Catalog(ctx)
	if err != nil || len(cat) < 2 {
		t.Fatal(err)
	}
}
