package certs

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/settings"
	"fileparcel/internal/tslocal"
)

// ---------- Tailscale ----------

// fakeTailscaled serves the LocalAPI cert endpoint on a Unix socket.
func fakeTailscaled(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	// A Linux abstract socket: short, and no file in the (possibly long) temp dir.
	sock := "@fp-tailscaled-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if runtime.GOOS != "linux" {
		sock = filepath.Join(t.TempDir(), "tailscaled.sock")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// withTailscale points the certificate fetch at the given sockets and CLIs.
func withTailscale(t *testing.T, sockets []string, clis ...string) {
	t.Helper()
	old := tsClient
	tsClient = func() *tslocal.Client { return &tslocal.Client{Sockets: sockets, CLIs: clis} }
	t.Cleanup(func() { tsClient = old })
}

func TestFetchTailscaleLocalAPI(t *testing.T) {
	te := newTestEnv(t)
	te.net.ts = &core.TailscaleInfo{Running: true, DNSName: "files.tail1234.ts.net."}
	te.settings.set(KeyTailscaleCert, true)
	svc := te.initService(t)
	pub := newTestCA(t, "ts root")
	cp, kp, leaf := pub.leaf(t, leafOpts{names: []string{"files.tail1234.ts.net"},
		notBefore: te.clock.Now().Add(-time.Hour), notAfter: te.clock.Now().Add(90 * 24 * time.Hour)})
	var gotPath, gotHost string
	sock := fakeTailscaled(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotHost = r.URL.RequestURI(), r.Host
		_, _ = w.Write(append(append([]byte{}, kp...), cp...)) // key first, like tailscaled
	})
	withTailscale(t, []string{"/nonexistent/tailscaled.sock", sock}, "/nonexistent/tailscale")

	if err := svc.FetchTailscale(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/localapi/v0/cert/files.tail1234.ts.net?type=pair" || gotHost != "local-tailscaled.sock" {
		t.Fatalf("request %s host %s", gotPath, gotHost)
	}
	if ts := svc.snapshot().tailscale; ts == nil || !ts.Leaf.Equal(leaf) {
		t.Fatal("tailscale certificate not installed")
	}
	if fi, err := os.Stat(svc.path(fileTSKey)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("tailscale key file: %v", err)
	}
	if e := te.audit.find(core.ActCertTailscale); len(e) != 1 || e[0].Outcome != "" || e[0].TargetName != "files.tail1234.ts.net" {
		t.Fatalf("audit %+v", e)
	}
	if svc.tailscaleNeedsRefresh(context.Background()) {
		t.Fatal("fresh certificate needs refresh")
	}
	te.clock.add(80 * 24 * time.Hour)
	if !svc.tailscaleNeedsRefresh(context.Background()) {
		t.Fatal("certificate 10 days before expiry does not need a refresh")
	}
	// Reloaded from disk by New.
	if svc2 := te.service(t); svc2.snapshot().tailscale == nil {
		t.Fatal("tailscale certificate not loaded by New")
	}
	st, _ := svc.Status(context.Background())
	if st.Tailscale == nil || st.Tailscale.Source != core.CertSourceTailscale {
		t.Fatalf("status %+v", st.Tailscale)
	}
}

// Renaming the node or the tailnet changes the MagicDNS name. The refresh
// check only looked at expiry and network.changed only at the leaf, so the
// old-name certificate stayed and the new ts.net name was served the local
// leaf (not publicly trusted) for up to ~76 days, with a clean status.
func TestTailscaleRefetchedAfterRename(t *testing.T) {
	te := newTestEnv(t)
	te.net.ts = &core.TailscaleInfo{Running: true, DNSName: "old.tail1.ts.net."}
	te.settings.set(KeyTailscaleCert, true)
	svc := te.initService(t)
	pub := newTestCA(t, "ts root")
	sock := fakeTailscaled(t, func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/localapi/v0/cert/")
		cp, kp, _ := pub.leaf(t, leafOpts{names: []string{name},
			notBefore: te.clock.Now().Add(-time.Hour), notAfter: te.clock.Now().Add(90 * 24 * time.Hour)})
		_, _ = w.Write(append(kp, cp...))
	})
	withTailscale(t, []string{sock}, "/nonexistent/tailscale")
	ctx := context.Background()
	if err := svc.FetchTailscale(ctx); err != nil {
		t.Fatal(err)
	}
	if svc.tailscaleNeedsRefresh(ctx) {
		t.Fatal("a fresh certificate for the current name needs a refresh")
	}

	te.net.ts = &core.TailscaleInfo{Running: true, DNSName: "new.tail1.ts.net."}
	if !svc.tailscaleNeedsRefresh(ctx) {
		t.Fatal("a certificate for the old MagicDNS name does not need a refresh")
	}
	svc.apply(ctx, pending{leaf: true}) // what network.changed requests
	if ts := svc.snapshot().tailscale; ts == nil || ts.Leaf.VerifyHostname("new.tail1.ts.net") != nil {
		t.Fatal("the certificate was not refetched for the new name")
	}
	if got := svc.ServedSource("new.tail1.ts.net"); got != core.CertSourceTailscale {
		t.Fatalf("new name served from %q", got)
	}

	// Tailscale stopped: the name is unknown, which is not a reason to fetch.
	te.net.ts = nil
	if svc.tailscaleNeedsRefresh(ctx) {
		t.Fatal("a stopped tailscaled makes a fresh certificate need a refresh")
	}
}

// Turning the Tailscale certificate off left the last fetch error and the
// stored (no longer served or renewed) certificate in the status: the nav
// kept warning about a "certificate problem" and eventually about an
// expired certificate nobody was served.
func TestTailscaleStatusFollowsSetting(t *testing.T) {
	te := newTestEnv(t)
	te.net.ts = &core.TailscaleInfo{Running: true, DNSName: "box.tail1.ts.net."}
	te.settings.set(KeyTailscaleCert, true)
	svc := te.initService(t)
	ctx := context.Background()
	deny := fakeTailscaled(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "HTTPS certificates are not enabled", http.StatusInternalServerError)
	})
	withTailscale(t, []string{deny}, "/nonexistent/tailscale")
	if err := svc.FetchTailscale(ctx); err == nil {
		t.Fatal("fetch must fail")
	}
	if st, _ := svc.Status(ctx); st.TailscaleError == "" {
		t.Fatal("the error is not reported while enabled")
	}
	te.settings.set(KeyTailscaleCert, false)
	if st, _ := svc.Status(ctx); st.TailscaleError != "" {
		t.Fatalf("error still reported after turning it off: %q", st.TailscaleError)
	}
	svc.apply(ctx, pending{tailscale: true}) // settings.changed{tailscale.cert_enabled}
	te.settings.set(KeyTailscaleCert, true)
	if st, _ := svc.Status(ctx); st.TailscaleError != "" {
		t.Fatalf("the old error came back on re-enable: %q", st.TailscaleError)
	}

	// A stored certificate is reported only while it is in use.
	pub := newTestCA(t, "ts root")
	cp, kp, _ := pub.leaf(t, leafOpts{names: []string{"box.tail1.ts.net"},
		notBefore: te.clock.Now().Add(-time.Hour), notAfter: te.clock.Now().Add(90 * 24 * time.Hour)})
	ok := fakeTailscaled(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(append(kp, cp...)) })
	withTailscale(t, []string{ok}, "/nonexistent/tailscale")
	if err := svc.FetchTailscale(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := svc.Status(ctx); st.Tailscale == nil {
		t.Fatal("certificate not reported while enabled")
	}
	te.settings.set(KeyTailscaleCert, false)
	if st, _ := svc.Status(ctx); st.Tailscale != nil {
		t.Fatal("an unused certificate is reported")
	}
}

func TestFetchTailscaleErrors(t *testing.T) {
	te := newTestEnv(t)
	te.settings.set(KeyTailscaleCert, true)
	svc := te.initService(t)
	// Not running and no configured name.
	withTailscale(t, nil, "/nonexistent/tailscale")
	if err := svc.FetchTailscale(context.Background()); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("no tailscale: %v", err)
	}
	// Permission denied by tailscaled: the error carries the operator hint.
	te.settings.set(KeyTailscaleName, "box.tail1.ts.net")
	sock := fakeTailscaled(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "access denied", http.StatusForbidden)
	})
	withTailscale(t, []string{sock}, "/nonexistent/tailscale")
	err := svc.FetchTailscale(context.Background())
	if !errors.Is(err, core.ErrUnavailable) || !strings.Contains(err.Error(), "--operator") {
		t.Fatalf("403: %v", err)
	}
	if st, _ := svc.Status(context.Background()); st.TailscaleError == "" {
		t.Fatal("tailscale error not reported in the status")
	}
	// A certificate for another name is refused.
	pub := newTestCA(t, "ts")
	cp, kp, _ := pub.leaf(t, leafOpts{names: []string{"other.tail1.ts.net"}})
	sock2 := fakeTailscaled(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(append(kp, cp...)) })
	withTailscale(t, []string{sock2}, "/nonexistent/tailscale")
	if err := svc.FetchTailscale(context.Background()); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("wrong name: %v", err)
	}
	if e := te.audit.find(core.ActCertTailscale); len(e) != 2 || e[1].Outcome != core.OutcomeFailure {
		t.Fatalf("failure audits %+v", e)
	}
}

func TestFetchTailscaleCLIFallback(t *testing.T) {
	te := newTestEnv(t)
	te.settings.set(KeyTailscaleName, "box.tail1.ts.net")
	svc := te.initService(t)
	pub := newTestCA(t, "ts")
	cp, kp, leaf := pub.leaf(t, leafOpts{names: []string{"box.tail1.ts.net"},
		notBefore: te.clock.Now().Add(-time.Hour), notAfter: te.clock.Now().Add(90 * 24 * time.Hour)})
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(certFile, cp, 0o600)
	_ = os.WriteFile(keyFile, kp, 0o600)
	// A fake "tailscale cert --cert-file X --key-file Y name" script.
	script := filepath.Join(dir, "tailscale")
	body := "#!/bin/sh\n[ \"$1\" = cert ] || exit 3\n[ \"$6\" = box.tail1.ts.net ] || exit 4\ncp " + certFile + " \"$3\"\ncp " + keyFile + " \"$5\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	// The first candidate does not exist (like the macOS app-bundle CLI on
	// Linux): the next one is used.
	withTailscale(t, nil, "/nonexistent/tailscale", script)
	if err := svc.FetchTailscale(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ts := svc.snapshot().tailscale; ts == nil || !ts.Leaf.Equal(leaf) {
		t.Fatal("CLI certificate not installed")
	}
	entries, _ := os.ReadDir(filepath.Dir(svc.path(fileTSCert)))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".fetch-") {
			t.Fatal("temporary directory left behind")
		}
	}
}

// The certificate fetch looked only in the Linux socket paths and for a
// "tailscale" on PATH, while detection (netinfo) also knows the macOS
// socket and app-bundle CLI: the admin page offered a certificate on macOS
// that could then not be fetched. Both now use tslocal.Default (whose
// platform lists tslocal's tests compare with core's), which reaches no
// daemon at all under `go test`.
func TestTailscaleCandidatesMatchDetection(t *testing.T) {
	t.Setenv(tslocal.EnvSocket, "")
	if c := tsClient(); c.Installed() || len(c.Sockets) != 0 || len(c.CLIs) != 0 {
		t.Fatalf("certificate fetch client under test: %+v", c)
	}
	t.Setenv(tslocal.EnvSocket, "/tmp/fake.sock")
	if c := tsClient(); !slices.Equal(c.Sockets, []string{"/tmp/fake.sock"}) {
		t.Fatalf("certificate fetch ignores %s: %+v", tslocal.EnvSocket, c)
	}
}

// ---------- ACME configuration ----------

func TestApplyACMEConfiguration(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	ctx := context.Background()
	if err := svc.ApplyACME(ctx); err != nil {
		t.Fatalf("disabled: %v", err)
	}
	te.settings.set(KeyACMEEnabled, true)
	if err := svc.ApplyACME(ctx); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("no domains: %v", err)
	}
	if st, _ := svc.Status(ctx); st.ACMEError == "" || !st.ACMEEnabled {
		t.Fatalf("status %+v", st)
	}
	te.settings.set(KeyACMEDomains, []string{"files.example.com", "*.example.com"})
	te.settings.set(KeyACMEChallenge, ChallengeHTTP)
	if err := svc.ApplyACME(ctx); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("wildcard with http challenge: %v", err)
	}
	te.settings.set(KeyACMEChallenge, ChallengeDNS)
	if err := svc.ApplyACME(ctx); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("dns without credentials: %v", err)
	}
	te.settings.set(KeyACMECreds, `{"zone_token":"x"}`)
	if err := svc.ApplyACME(ctx); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("cloudflare without api_token: %v", err)
	}
	te.settings.set(KeyACMECreds, `{"api_token":"t0ken"}`)
	// Valid, but the server is not running: validated only, nothing started.
	if err := svc.ApplyACME(ctx); err != nil {
		t.Fatalf("valid configuration offline: %v", err)
	}
	if svc.acme.Load() != nil {
		t.Fatal("ACME started although Start never ran")
	}
	cfg, enabled, err := svc.readACMEConfig()
	if err != nil || !enabled || cfg.CA != acmeDirectory("staging") || !slicesEqual(cfg.Domains, []string{"*.example.com", "files.example.com"}) {
		t.Fatalf("config %+v %v %v", cfg, enabled, err)
	}
	// http challenge needs the HTTP port.
	te.settings.set(KeyACMEDomains, []string{"files.example.com"})
	te.settings.set(KeyACMEChallenge, ChallengeHTTP)
	te.env.Config.Server.HTTPPort = 0
	cfg, _, _ = svc.readACMEConfig()
	if _, err := svc.newACMEState(cfg); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("http challenge without HTTP port: %v", err)
	}
}

func slicesEqual(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func TestDNSProvider(t *testing.T) {
	tests := []struct {
		provider, creds string
		ok              bool
	}{
		{ProviderCloudflare, `{"api_token":"a"}`, true},
		{ProviderCloudflare, `{}`, false},
		{ProviderCloudflare, `not json`, false},
		{ProviderRFC2136, `{"server":"ns:53","key_name":"k","key":"c2VjcmV0"}`, true},
		{ProviderRFC2136, `{"server":"ns:53","key_name":"k"}`, false},
		{"route53", `{}`, false},
	}
	for _, tc := range tests {
		_, err := dnsProvider(tc.provider, tc.creds)
		if (err == nil) != tc.ok {
			t.Errorf("%s %s: %v", tc.provider, tc.creds, err)
		}
		if err != nil && strings.Contains(err.Error(), "c2VjcmV0") {
			t.Error("error leaks the credentials")
		}
	}
}

func TestACMEDirectory(t *testing.T) {
	if acmeDirectory("production") == acmeDirectory("staging") || acmeDirectory("https://ca.example/dir") != "https://ca.example/dir" {
		t.Fatal("acme.ca mapping")
	}
}

func TestHTTPChallengePassesThrough(t *testing.T) {
	te := newTestEnv(t)
	svc := te.service(t)
	called := false
	h := svc.HTTPChallenge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	req, _ := http.NewRequest(http.MethodGet, "http://x/.well-known/acme-challenge/abc", nil)
	h.ServeHTTP(nopWriter{}, req)
	if !called {
		t.Fatal("request not passed to next without ACME")
	}
}

type nopWriter struct{}

func (nopWriter) Header() http.Header         { return http.Header{} }
func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopWriter) WriteHeader(int)             {}

// ---------- settings ----------

func TestSettingsRegistered(t *testing.T) {
	for _, k := range []string{KeyExtraSANs, KeyHSTS, KeyMinVersion, KeyLeafDays, KeyACMEEnabled, KeyACMEEmail, KeyACMEDomains,
		KeyACMECA, KeyACMEChallenge, KeyACMEProvider, KeyACMECreds, KeyTailscaleCert, KeyTailscaleName, KeyMTLSMode,
		KeyMTLSExempt, KeyMTLSSelfService} {
		if _, ok := settings.Lookup(k); !ok {
			t.Errorf("%s not registered", k)
		}
	}
	if d, _ := settings.Lookup(KeyACMECreds); !d.Secret {
		t.Error("acme.dns_credentials must be secret")
	}
	check := func(key string, v any, ok bool) {
		t.Helper()
		d, _ := settings.Lookup(key)
		raw, _ := json.Marshal(v)
		if _, _, err := d.Decode(raw); (err == nil) != ok {
			t.Errorf("%s = %v: err %v, want ok=%v", key, v, err, ok)
		}
	}
	check(KeyExtraSANs, []string{"nas.home.arpa", "10.0.0.2", "*.x.local"}, true)
	check(KeyExtraSANs, []string{"bad name"}, false)
	check(KeyACMECA, "production", true)
	check(KeyACMECA, "https://acme.example/directory", true)
	check(KeyACMECA, "http://acme.example/directory", false)
	check(KeyACMEDomains, []string{"files.example.com"}, true)
	check(KeyACMEDomains, []string{"localhost"}, false)
	check(KeyACMECreds, `{"api_token":"x"}`, true)
	check(KeyACMECreds, `[1]`, false)
	check(KeyTailscaleName, "box.tail.ts.net", true)
	check(KeyTailscaleName, "box", false)
	check(KeyLeafDays, 900, false)
	check(KeyMinVersion, "1.1", false)
}

// ---------- lifecycle ----------

type fakeJobs struct {
	mu        sync.Mutex
	kinds     map[string]core.JobFunc
	schedules map[string]string
	fail      bool
}

func (j *fakeJobs) Register(kind string, fn core.JobFunc, _ core.JobOptions) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.kinds == nil {
		j.kinds = map[string]core.JobFunc{}
	}
	j.kinds[kind] = fn
}
func (j *fakeJobs) Enqueue(context.Context, string, any, *core.Principal) (string, error) {
	return "", nil
}
func (j *fakeJobs) Get(context.Context, string) (*core.Job, error) { return nil, nil }
func (j *fakeJobs) List(context.Context, core.JobQuery) (core.Page[core.Job], error) {
	return core.Page[core.Job]{}, nil
}
func (j *fakeJobs) Cancel(context.Context, string) error { return nil }
func (j *fakeJobs) Schedule(name, cron, kind string, _ any) error {
	if j.fail {
		return errors.New("no db")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.schedules == nil {
		j.schedules = map[string]string{}
	}
	j.schedules[name] = cron + " " + kind
	return nil
}
func (j *fakeJobs) Unschedule(string)                                     {}
func (j *fakeJobs) Schedules(context.Context) ([]core.JobSchedule, error) { return nil, nil }
func (j *fakeJobs) Start(context.Context) error                           { return nil }
func (j *fakeJobs) Stop(context.Context) error                            { return nil }

type fakeHandle struct{}

func (fakeHandle) ID() string                    { return "job_x" }
func (fakeHandle) Params(any) error              { return nil }
func (fakeHandle) Progress(int64, int64, string) {}
func (fakeHandle) SetResult(any)                 {}

func TestRegisterJobs(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	j := &fakeJobs{}
	if err := svc.RegisterJobs(j); err != nil {
		t.Fatal(err)
	}
	if j.kinds[core.JobCertsRenewCheck] == nil || j.schedules[core.JobCertsRenewCheck] != renewSchedule+" "+core.JobCertsRenewCheck {
		t.Fatalf("registration %+v %+v", j.kinds, j.schedules)
	}
	if !svc.jobsScheduled.Load() {
		t.Fatal("jobsScheduled not set")
	}
	te.net.setNames("renamed.local")
	if err := j.kinds[core.JobCertsRenewCheck](context.Background(), fakeHandle{}); err != nil {
		t.Fatal(err)
	}
	if svc.snapshot().leaf.Leaf.VerifyHostname("renamed.local") != nil {
		t.Fatal("renew job did not reissue the leaf")
	}
	// A failing schedule falls back to the internal timer.
	svc2 := te.service(t)
	if err := svc2.RegisterJobs(&fakeJobs{fail: true}); err != nil || svc2.jobsScheduled.Load() {
		t.Fatal("schedule failure must not be fatal")
	}
}

func TestStartWatchesEvents(t *testing.T) {
	old := watchDebounce
	watchDebounce = 20 * time.Millisecond
	defer func() { watchDebounce = old }()

	te := newTestEnv(t)
	svc := te.initService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout waiting for %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	covers := func(name string) func() bool {
		return func() bool { return svc.snapshot().leaf.Leaf.VerifyHostname(name) == nil }
	}
	te.net.setNames("moved.local")
	te.env.Bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	waitFor("network.changed reissue", covers("moved.local"))

	te.settings.set(KeyExtraSANs, []string{"extra.local"})
	te.env.Bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{KeyExtraSANs}}})
	waitFor("settings.changed reissue", covers("extra.local"))

	// Locked: the change waits for keys.state unlocked. It used to be dropped
	// (pendingRenew was never set), so nothing was reissued on unlock.
	te.keys.setState(core.KeyStateLocked)
	te.net.setNames("later.local")
	te.env.Bus.Publish(events.Event{Topic: events.TopicMDNSChanged})
	waitFor("the locked change to be remembered", svc.pendingRenew.Load)
	if covers("later.local")() {
		t.Fatal("leaf reissued while locked")
	}
	te.keys.setState(core.KeyStateUnlocked)
	te.env.Bus.Publish(events.Event{Topic: events.TopicKeysState, Data: core.KeysStateEvent{State: core.KeyStateUnlocked}})
	waitFor("reissue after unlock", covers("later.local"))

	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseWithoutStart(t *testing.T) {
	te := newTestEnv(t)
	svc := te.service(t)
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
}
