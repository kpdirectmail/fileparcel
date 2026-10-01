package mw

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// ingressFake is the policy side of core.Ingress (the rest panics).
type ingressFake struct {
	core.Ingress
	mu  sync.Mutex
	pol map[string]core.IngressPolicy
}

func (f *ingressFake) Policy(kind string) core.IngressPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pol[kind]
}

func (f *ingressFake) set(kind string, p core.IngressPolicy) {
	f.mu.Lock()
	f.pol[kind] = p
	f.mu.Unlock()
}

// gateNet is a Network with a deny list (Denied, like netinfo) and an
// access policy.
type gateNet struct {
	fakeNet
	deny    []netip.Prefix
	allowed func(netip.Addr) bool
}

func (n gateNet) Denied(ip netip.Addr) bool {
	for _, p := range n.deny {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
func (n gateNet) Allowed(ip netip.Addr) bool { return !n.Denied(ip) && n.allowed(ip) }

// checkNet has no Denied: IngressGate falls back to CheckPolicy.
type checkNet struct {
	fakeNet
	deny []string
}

func (n checkNet) Policy() core.AccessPolicy {
	return core.AccessPolicy{Mode: core.AccessAllowlist, Deny: n.deny}
}
func (n checkNet) CheckPolicy(p core.AccessPolicy, ip netip.Addr) (bool, error) {
	if p.Mode != core.AccessAny {
		return false, nil
	}
	for _, d := range p.Deny {
		if netip.MustParsePrefix(d).Contains(ip) {
			return false, nil
		}
	}
	return true, nil
}

// gateEnv is a test environment with an Ingress and the root chain of
// web/router.go around a recording handler.
type gateEnv struct {
	*testEnv
	ing   *ingressFake
	net   *gateNet
	h     http.Handler
	mu    sync.Mutex
	seen  []*http.Request
	block chan struct{} // when set, the application handler waits on it
}

const (
	notFoundBody = "the uniform 404 page"
	tsName       = "node.tail.ts.net"
)

func newGateEnv(t *testing.T) *gateEnv {
	t.Helper()
	e := &gateEnv{testEnv: newEnv(t)}
	e.ing = &ingressFake{pol: map[string]core.IngressPolicy{
		core.IngressFunnel: {Mode: core.FunnelShares, DNSName: tsName, Port: 443, Require2FA: true},
		core.IngressServe:  {Mode: core.FunnelApp, DNSName: tsName, Port: 8443},
	}}
	e.net = &gateNet{allowed: func(ip netip.Addr) bool { return netip.MustParsePrefix("100.64.0.0/10").Contains(ip) }}
	e.d.Ingress = e.ing
	e.d.Network = e.net
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, notFoundBody)
	})
	page := func(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		io.WriteString(w, "page "+code+": "+msg)
	}
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.seen = append(e.seen, r)
		block := e.block
		e.mu.Unlock()
		if block != nil {
			<-block
		}
		io.WriteString(w, "app")
	})
	e.h = ResolveClientIP(AccessLog(ProxiedPolicy(HostCheck(SecurityHeaders(IngressGate(notFound, page)(SealedGate(app)))))))
	return e
}

// ingressReq builds a request of kind's ingress listener from client ip
// (as internal/server's ingressHandler leaves it).
func ingressReq(kind, method, target, ip string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	a := netip.MustParseAddr(ip)
	r.RemoteAddr = netip.AddrPortFrom(a, 0).String()
	r.Host = tsName
	return r.WithContext(core.WithIngress(r.Context(), &core.IngressInfo{Kind: kind, ClientIP: a, Host: tsName}))
}

func (e *gateEnv) do(r *http.Request) *httptest.ResponseRecorder { return serve(e.d, e.h, r) }

// reached reports whether the last request reached the application.
func (e *gateEnv) reached(n int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.seen) > n
}

func (e *gateEnv) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.seen)
}

func (e *gateEnv) last() *http.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.seen[len(e.seen)-1]
}

func TestIngressGateSharesMode(t *testing.T) {
	e := newGateEnv(t)
	client := "203.0.113.9"
	for _, tc := range []struct{ method, path string }{
		{"GET", "/s/AbCdEfGhIjKlMnOpQrStUv"}, {"POST", "/s/x/api/password"}, {"GET", "/s/x/api/list?node=a"},
		{"PUT", "/s/x/api/uploads/u1/parts/1"}, {"DELETE", "/s/x/api/upload-batches/b1"}, {"GET", "/s/x/"},
		{"GET", "/static/h/js/app.js"}, {"HEAD", "/static/abc123/css/app.css"}, {"GET", "/theme.css"},
		{"GET", "/favicon.ico"}, {"GET", "/robots.txt"}, {"GET", "/manifest.webmanifest"},
	} {
		n := e.count()
		rec := e.do(ingressReq(core.IngressFunnel, tc.method, tc.path, client))
		if rec.Code != 200 || !e.reached(n) {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
			t.Errorf("%s %s: X-Robots-Tag %q", tc.method, tc.path, rec.Header().Get("X-Robots-Tag"))
		}
	}
	// Everything else is the uniform 404: the page, or the API's JSON (the
	// router's answer for an unknown endpoint; internal/wire compares the
	// real pages).
	apiError := func(rec *httptest.ResponseRecorder) (string, string) {
		var er struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &er)
		return er.Error.Code, er.Error.Message
	}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/login"}, {"GET", "/files"}, {"GET", "/admin"}, {"GET", "/trust"}, {"GET", "/trust/ca.crt"},
		{"GET", "/healthz"}, {"GET", "/readyz"}, {"GET", "/sw.js"}, {"GET", "/setup"}, {"GET", "/unlock"},
		{"GET", "/invite/abc"}, {"POST", "/share-target"}, {"GET", "/.well-known/security.txt"},
		{"GET", "/s/x/../../api/v1/me"}, {"GET", "/s/x%2F..%2Fapi"}, {"GET", "/s/x%5C..%5Capi"}, {"GET", "//s/x"},
		{"GET", "/s/"}, {"GET", "/s"}, {"GET", "/static/h/"}, {"GET", "/static/"}, {"POST", "/static/h/a.js"},
		{"POST", "/theme.css"}, {"GET", "/theme.css/x"},
		{"GET", "/api/v1/me"}, {"POST", "/api/v1/auth/login"}, {"GET", "/api/v1/admin/users"}, {"GET", "/api/v1/auth/state"},
		{"GET", "/api/v1/system/status"}, {"GET", "/api/"},
	} {
		n := e.count()
		rec := e.do(ingressReq(core.IngressFunnel, tc.method, tc.path, client))
		if rec.Code != http.StatusNotFound || e.reached(n) {
			t.Errorf("%s %s: %d (reached=%v)", tc.method, tc.path, rec.Code, e.reached(n))
			continue
		}
		if strings.HasPrefix(tc.path, "/api/") {
			if c, m := apiError(rec); c != "not_found" || m != "no such API endpoint" {
				t.Errorf("%s %s: API body %s", tc.method, tc.path, rec.Body.String())
			}
		} else if rec.Body.String() != notFoundBody {
			t.Errorf("%s %s: body %q", tc.method, tc.path, rec.Body.String())
		}
		if err := CheckSecurityHeaders(rec.Header(), map[bool]HeaderKind{true: HeadersAPI, false: HeadersPage}[strings.HasPrefix(tc.path, "/api/")]); err != nil {
			t.Errorf("%s %s: %v", tc.method, tc.path, err)
		}
	}

	// Credentials are stripped; the public share cookies stay.
	r := ingressReq(core.IngressFunnel, "POST", "/s/x/api/upload-batches", client)
	r.Header.Set("Authorization", "Bearer fpt_x_y")
	r.Header.Set(HeaderCSRF, "t0k")
	r.Header.Add("Cookie", "__Host-fp_session=sess; __Host-fp_s_12345678=share; theme=dark")
	r.Header.Add("Cookie", "__Host-fp_uv_abcdefgh=visitor;s=1")
	if rec := e.do(r); rec.Code != 200 {
		t.Fatalf("share request with credentials: %d", rec.Code)
	}
	got := e.last()
	var names []string
	for _, c := range got.Cookies() {
		names = append(names, c.Name+"="+c.Value)
	}
	if !slices.Equal(names, []string{"__Host-fp_s_12345678=share", "__Host-fp_uv_abcdefgh=visitor"}) ||
		got.Header.Get("Authorization") != "" || got.Header.Get(HeaderCSRF) != "" {
		t.Fatalf("credentials kept: cookies %v auth %q csrf %q", names, got.Header.Get("Authorization"), got.Header.Get(HeaderCSRF))
	}
	r = ingressReq(core.IngressFunnel, "GET", "/s/x", client)
	r.Header.Set("Cookie", "__Host-fp_session=sess")
	if e.do(r); e.last().Header.Get("Cookie") != "" {
		t.Fatalf("session cookie kept: %q", e.last().Header.Get("Cookie"))
	}

	// Fail closed: policy off (or no ingress service, or an unknown kind).
	e.ing.set(core.IngressFunnel, core.IngressPolicy{Mode: core.FunnelOff})
	n := e.count()
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", client)); rec.Code != 404 || e.reached(n) {
		t.Fatalf("policy off: %d", rec.Code)
	}
	e.ing.set(core.IngressFunnel, core.IngressPolicy{Mode: "weird", DNSName: tsName, Port: 443})
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", client)); rec.Code != 404 || e.reached(n) {
		t.Fatalf("unknown mode: %d", rec.Code)
	}
	if rec := e.do(ingressReq("magic", "GET", "/s/x", client)); rec.Code != 404 || e.reached(n) {
		t.Fatalf("unknown kind: %d", rec.Code)
	}
	e.d.Ingress = nil
	if rec := e.do(ingressReq(core.IngressServe, "GET", "/", "100.101.102.104")); rec.Code != 404 || e.reached(n) {
		t.Fatalf("no ingress service: %d", rec.Code)
	}
	// Direct requests are untouched.
	if rec := e.do(httptest.NewRequest("GET", "/login", nil)); rec.Code != 200 || !e.reached(n) || rec.Header().Get("X-Robots-Tag") != "" {
		t.Fatalf("direct request: %d", rec.Code)
	}
}

func TestIngressGateAppMode(t *testing.T) {
	e := newGateEnv(t)
	e.ing.set(core.IngressFunnel, core.IngressPolicy{Mode: core.FunnelApp, DNSName: tsName, Port: 443, Require2FA: true})
	client := "2001:db8:1:2::9"
	blocked := []string{"/setup", "/unlock", "/trust", "/trust/ca.crt", "/trust/", "/api/v1/auth/setup", "/api/v1/system/unlock",
		"/share-target", "/setup/"}
	admin := []string{"/admin", "/admin/", "/admin/users", "/api/v1/admin/users", "/api/v1/admin", "/api/v1/admin/network/funnel"}
	open := []string{"/", "/login", "/files", "/files/abc", "/api/v1/me", "/api/v1/auth/login", "/api/v1/auth/state", "/s/x",
		"/invite/abc", "/settings/security", "/api/v1/system/status", "/administrator"}
	check := func(allowAdmin bool) {
		t.Helper()
		for _, p := range append(append(slices.Clone(blocked), admin...), open...) {
			n := e.count()
			method := "GET"
			if p == "/share-target" || p == "/api/v1/auth/setup" || p == "/api/v1/system/unlock" {
				method = "POST"
			}
			rec := e.do(ingressReq(core.IngressFunnel, method, p, client))
			refused := slices.Contains(blocked, p) || (!allowAdmin && slices.Contains(admin, p))
			switch {
			case refused && (rec.Code != http.StatusForbidden || e.reached(n)):
				t.Errorf("allow_admin=%v %s: %d, want 403", allowAdmin, p, rec.Code)
			case refused && strings.HasPrefix(p, "/api/"):
				if code(t, rec) != "forbidden" || !strings.Contains(rec.Body.String(), "not available over the public Funnel address") {
					t.Errorf("%s: %s", p, rec.Body.String())
				}
			case refused:
				if rec.Body.String() != "page forbidden: "+funnelBlockedMessage {
					t.Errorf("%s: %q", p, rec.Body.String())
				}
			case rec.Code != 200 || !e.reached(n):
				t.Errorf("allow_admin=%v %s: %d, want the app", allowAdmin, p, rec.Code)
			}
		}
	}
	check(false)
	e.ing.set(core.IngressFunnel, core.IngressPolicy{Mode: core.FunnelApp, DNSName: tsName, Port: 443, AllowAdmin: true, Require2FA: true})
	check(true)
	// Credentials are not touched in app mode.
	r := ingressReq(core.IngressFunnel, "GET", "/api/v1/me", client)
	r.Header.Set("Cookie", "__Host-fp_session=sess")
	r.Header.Set("Authorization", "Bearer fpt_x_y")
	if e.do(r); e.last().Header.Get("Cookie") != "__Host-fp_session=sess" || e.last().Header.Get("Authorization") == "" {
		t.Fatal("app mode stripped credentials")
	}
	// Serve is the whole app, administration included.
	for _, p := range append(append(slices.Clone(blocked), admin...), open...) {
		n := e.count()
		if rec := e.do(ingressReq(core.IngressServe, "GET", p, "100.101.102.104")); rec.Code != 200 || !e.reached(n) {
			t.Errorf("serve %s: %d", p, rec.Code)
		}
	}
}

func TestIngressGateAccessPolicy(t *testing.T) {
	e := newGateEnv(t)
	e.net.deny = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:bad::/48")}
	for _, tc := range []struct {
		kind, ip string
		want     int
	}{
		{core.IngressFunnel, "203.0.113.9", 200},     // the internet: not in the allow list, but Funnel applies the deny list only
		{core.IngressFunnel, "198.51.100.7", 403},    // denied
		{core.IngressFunnel, "2001:db8:bad::1", 403}, // denied (IPv6)
		{core.IngressServe, "100.101.102.104", 200},  // tailnet peer allowed
		{core.IngressServe, "203.0.113.9", 403},      // Serve applies the full policy
		{core.IngressServe, "198.51.100.7", 403},
	} {
		n := e.count()
		rec := e.do(ingressReq(tc.kind, "GET", "/s/x", tc.ip))
		if rec.Code != tc.want || e.reached(n) != (tc.want == 200) {
			t.Errorf("%s %s: %d, want %d", tc.kind, tc.ip, rec.Code, tc.want)
		}
		if tc.want == 403 && (rec.Header().Get("Connection") != "close" || !strings.Contains(rec.Body.String(), "access policy")) {
			t.Errorf("%s %s: %v %q", tc.kind, tc.ip, rec.Header(), rec.Body.String())
		}
	}
	// JSON on API paths.
	rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x/api", "198.51.100.7"))
	if rec.Code != 403 || code(t, rec) != "forbidden" {
		t.Fatalf("denied API: %d %s", rec.Code, rec.Body.String())
	}
	// A network service without Denied: the deny list through CheckPolicy.
	e.d.Network = checkNet{deny: []string{"198.51.100.0/24"}}
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "198.51.100.7")); rec.Code != 403 {
		t.Fatalf("CheckPolicy fallback, denied: %d", rec.Code)
	}
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "203.0.113.9")); rec.Code != 200 {
		t.Fatalf("CheckPolicy fallback, allowed: %d", rec.Code)
	}
	// ProxiedPolicy leaves ingress requests to IngressGate even when a
	// trusted proxy list is configured.
	e.d.Network = e.net
	e.d.Config.Server.TrustedProxies = []string{"0.0.0.0/0", "::/0"}
	n := e.count()
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "203.0.113.9")); rec.Code != 200 || !e.reached(n) {
		t.Fatalf("ProxiedPolicy on an ingress request: %d", rec.Code)
	}
}

func TestIngressGateRateLimits(t *testing.T) {
	e := newGateEnv(t)
	e.d.Limiter.Configure(BucketFunnel, 1, 2)
	e.d.Limiter.Configure(BucketFunnelGlobal, 1, 5)
	get := func(kind, ip string) int { return e.do(ingressReq(kind, "GET", "/s/x", ip)).Code }
	// Two addresses of one IPv6 /64 are one internet client.
	if get(core.IngressFunnel, "2001:db8:1:2::1") != 200 || get(core.IngressFunnel, "2001:db8:1:2::ffff") != 200 {
		t.Fatal("first requests refused")
	}
	rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "2001:db8:1:2:aaaa::1"))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || code(t, rec) != "rate_limited" {
		t.Fatalf("third request of the /64: %d %v", rec.Code, rec.Header())
	}
	// Another /64 and IPv4 clients have buckets of their own ...
	if get(core.IngressFunnel, "2001:db8:1:3::1") != 200 || get(core.IngressFunnel, "203.0.113.9") != 200 {
		t.Fatal("other clients limited")
	}
	// ... until the global bucket (5) is empty.
	if got := get(core.IngressFunnel, "203.0.113.10"); got != 200 {
		t.Fatalf("fifth request: %d", got)
	}
	if got := get(core.IngressFunnel, "203.0.113.11"); got != http.StatusTooManyRequests {
		t.Fatalf("global bucket: %d", got)
	}
	// Serve has no Funnel buckets.
	for i := 0; i < 5; i++ {
		if got := get(core.IngressServe, "100.101.102.104"); got != 200 {
			t.Fatalf("serve limited: %d", got)
		}
	}
	// The key function: /64 over Funnel only.
	key := func(kind, ip string) string { return PerIP(ingressReq(kind, "GET", "/", ip)) }
	if key(core.IngressFunnel, "2001:db8::1") != "2001:db8::/64" || key(core.IngressServe, "fd7a:115c:a1e0::1") != "fd7a:115c:a1e0::1" ||
		key(core.IngressFunnel, "203.0.113.9") != "203.0.113.9" {
		t.Fatalf("PerIP keys: %s %s %s", key(core.IngressFunnel, "2001:db8::1"), key(core.IngressServe, "fd7a:115c:a1e0::1"),
			key(core.IngressFunnel, "203.0.113.9"))
	}
	if k := PerIP(httptest.NewRequest("GET", "/", nil)); k != "192.0.2.1" {
		t.Fatalf("direct PerIP %s", k)
	}
}

func TestIngressGateInFlightCaps(t *testing.T) {
	saved := ingressLimits
	t.Cleanup(func() { ingressLimits = saved })
	ingressLimits.client, ingressLimits.kind, ingressLimits.wait = 1, 2, 100*time.Millisecond
	e := newGateEnv(t)
	release := make(chan struct{})
	e.block = release
	started := make(chan int, 4)
	bg := func(kind, ip string) {
		go func() { started <- e.do(ingressReq(kind, "GET", "/s/x", ip)).Code }()
	}
	waitReached := func(n int) {
		t.Helper()
		for i := 0; i < 200 && e.count() < n; i++ {
			time.Sleep(5 * time.Millisecond)
		}
		if e.count() < n {
			t.Fatalf("%d requests reached the app, want %d", e.count(), n)
		}
	}
	bg(core.IngressFunnel, "2001:db8:1:2::1")
	waitReached(1)
	// The same client (same /64) waits for its slot, then gets 503.
	began := time.Now()
	rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "2001:db8:1:2::2"))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "5" || time.Since(began) < 90*time.Millisecond {
		t.Fatalf("per-client cap: %d after %v", rec.Code, time.Since(began))
	}
	// Another client gets the kind's second slot; a third one none.
	bg(core.IngressFunnel, "203.0.113.9")
	waitReached(2)
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "203.0.113.10")); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("kind cap: %d", rec.Code)
	}
	// Serve counts on its own.
	bg(core.IngressServe, "100.101.102.104")
	waitReached(3)
	// A waiting request gets the slot when it frees up.
	e.mu.Lock()
	e.block = nil
	e.mu.Unlock()
	waiter := make(chan int, 1)
	go func() { waiter <- e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "2001:db8:1:2::3")).Code }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	for i := 0; i < 3; i++ {
		if c := <-started; c != 200 {
			t.Fatalf("held request: %d", c)
		}
	}
	// (the waiter may also find the kind cap still full for an instant)
	if c := <-waiter; c != 200 && c != http.StatusServiceUnavailable {
		t.Fatalf("waiter: %d", c)
	}
	e.clientsIdle(t)
}

// clientsIdle checks that the per-client slots were all given back.
func (e *gateEnv) clientsIdle(t *testing.T) {
	t.Helper()
	// Every request finished: a fresh request gets both slots at once.
	began := time.Now()
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "2001:db8:1:2::1")); rec.Code != 200 || time.Since(began) > 50*time.Millisecond {
		t.Fatalf("slots not released: %d after %v", rec.Code, time.Since(began))
	}
}

func TestIngressGateMTLSAndSealed(t *testing.T) {
	e := newGateEnv(t)
	e.s.set("mtls.mode", "required")
	e.s.set("mtls.exempt_shares", true)
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "203.0.113.9")); rec.Code != 200 {
		t.Fatalf("exempt share over funnel: %d", rec.Code)
	}
	rec := e.do(ingressReq(core.IngressServe, "GET", "/files", "100.101.102.104"))
	if rec.Code != 403 || rec.Body.String() != ClientCertNotice {
		t.Fatalf("mtls page: %d %q", rec.Code, rec.Body.String())
	}
	if rec := e.do(ingressReq(core.IngressServe, "GET", "/api/v1/me", "100.101.102.104")); rec.Code != 403 || code(t, rec) != "forbidden" {
		t.Fatalf("mtls api: %d", rec.Code)
	}
	e.s.set("mtls.exempt_shares", false)
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "203.0.113.9")); rec.Code != 403 {
		t.Fatalf("share without exemption: %d", rec.Code)
	}
	e.s.set("mtls.mode", "optional")

	// Keys locked: Funnel never goes to /unlock.
	e.d.Keys = fakeKeys{state: core.KeyStateLocked}
	rec = e.do(ingressReq(core.IngressFunnel, "GET", "/s/x", "203.0.113.9"))
	if rec.Code != 503 || rec.Body.String() != "page keys_locked: "+sealedMessage || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("sealed share page: %d %q", rec.Code, rec.Body.String())
	}
	for _, tc := range []struct{ method, path string }{{"GET", "/s/x/api"}, {"POST", "/s/x/api/password"}} {
		rec := e.do(ingressReq(core.IngressFunnel, tc.method, tc.path, "203.0.113.9"))
		if rec.Code != 503 || code(t, rec) != "keys_locked" {
			t.Errorf("sealed %s %s: %d", tc.method, tc.path, rec.Code)
		}
	}
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/static/h/a.js", "203.0.113.9")); rec.Code != 200 {
		t.Fatalf("static while sealed: %d", rec.Code)
	}
	e.ing.set(core.IngressFunnel, core.IngressPolicy{Mode: core.FunnelApp, DNSName: tsName, Port: 443})
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/files", "203.0.113.9")); rec.Code != 503 {
		t.Fatalf("sealed app page over funnel: %d", rec.Code)
	}
	if rec := e.do(ingressReq(core.IngressFunnel, "GET", "/unlock", "203.0.113.9")); rec.Code != 403 {
		t.Fatalf("unlock over funnel: %d", rec.Code)
	}
	// Serve keeps the redirect (keys.web_unlock judges the tailnet address).
	if rec := e.do(ingressReq(core.IngressServe, "GET", "/files", "100.101.102.104")); rec.Code != http.StatusSeeOther {
		t.Fatalf("sealed page over serve: %d", rec.Code)
	}
	// SealedGate by itself never redirects a Funnel request either.
	rec = serve(e.d, SealedGate(http.HandlerFunc(ok)), ingressReq(core.IngressFunnel, "GET", "/files", "203.0.113.9"))
	if rec.Code != 503 || code(t, rec) != "keys_locked" {
		t.Fatalf("SealedGate alone: %d %v", rec.Code, rec.Header())
	}
}

func TestIngressHostCheckHSTSAndLog(t *testing.T) {
	e := newGateEnv(t)
	e.s.set("network.strict_host", true)
	e.ing.set(core.IngressFunnel, core.IngressPolicy{Mode: core.FunnelApp, DNSName: "renamed.tail.ts.net", Port: 443})
	r := ingressReq(core.IngressFunnel, "GET", "/login", "203.0.113.9")
	r.Host = "renamed.tail.ts.net"
	if rec := e.do(r); rec.Code != 200 {
		t.Fatalf("strict host, ingress: %d", rec.Code)
	}
	direct := httptest.NewRequest("GET", "/login", nil)
	direct.Host = "renamed.tail.ts.net"
	if rec := e.do(direct); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("strict host, direct: %d", rec.Code)
	}

	// HSTS: auto → only when FileParcel serves a publicly trusted
	// certificate for the MagicDNS name.
	hsts := func(r *http.Request) string { return e.do(r).Header().Get("Strict-Transport-Security") }
	if got := hsts(ingressReq(core.IngressFunnel, "GET", "/login", "203.0.113.9")); got != "" {
		t.Fatalf("HSTS without a trusted certificate: %q", got)
	}
	e.d.Certs = fakeCerts{public: map[string]bool{"renamed.tail.ts.net": true}}
	if got := hsts(ingressReq(core.IngressFunnel, "GET", "/login", "203.0.113.9")); got != HSTSValue {
		t.Fatalf("HSTS with a trusted certificate: %q", got)
	}
	if got := hsts(ingressReq(core.IngressServe, "GET", "/login", "100.101.102.104")); got != "" {
		t.Fatalf("HSTS for serve's name (node.tail.ts.net): %q", got)
	}
	e.s.set("tls.hsts", "on")
	if got := hsts(ingressReq(core.IngressServe, "GET", "/login", "100.101.102.104")); got != HSTSValue {
		t.Fatalf("tls.hsts on: %q", got)
	}
	e.s.set("tls.hsts", "off")
	if got := hsts(ingressReq(core.IngressFunnel, "GET", "/login", "203.0.113.9")); got != "" {
		t.Fatalf("tls.hsts off: %q", got)
	}
	e.s.set("tls.hsts", "auto")
	if got := hsts(httptest.NewRequest("GET", "/login", nil)); got != "" {
		t.Fatalf("plain direct request: %q", got)
	}
	tr := httptest.NewRequest("GET", "https://renamed.tail.ts.net/login", nil)
	tr.TLS = &tls.ConnectionState{ServerName: "renamed.tail.ts.net"}
	tr.Host = "renamed.tail.ts.net"
	e.s.set("network.strict_host", false)
	if got := hsts(tr); got != HSTSValue {
		t.Fatalf("direct TLS request: %q", got)
	}

	// The access log names the ingress (and Serve's tailnet login).
	r = ingressReq(core.IngressServe, "GET", "/files", "100.101.102.104")
	r = r.WithContext(core.WithIngress(r.Context(), &core.IngressInfo{Kind: core.IngressServe,
		ClientIP: netip.MustParseAddr("100.101.102.104"), TSUser: "alice@example.com\n"}))
	e.do(r)
	logs := e.logs.String()
	if !strings.Contains(logs, "ingress=funnel") || !strings.Contains(logs, "ingress=serve ts_user=alice@example.com?") ||
		!strings.Contains(logs, "ip=100.101.102.104") {
		t.Fatalf("access log: %s", logs)
	}
}

func TestResolveClientIPIngressAndLocalProxy(t *testing.T) {
	e := newGateEnv(t)
	d := e.d
	var got string
	h := ResolveClientIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = ClientIP(r).String() }))
	sig := func() int64 { return httpx.ProxySignals.LocalProxy.Snapshot().Count }

	// Ingress: the listener's client, trusted proxies ignored.
	d.Config.Server.TrustedProxies = []string{"0.0.0.0/0", "::/0"}
	r := ingressReq(core.IngressFunnel, "GET", "/", "203.0.113.9")
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	before := sig()
	serve(d, h, r)
	if got != "203.0.113.9" || sig() != before {
		t.Fatalf("ingress client %s (signal %d→%d)", got, before, sig())
	}
	// A configured proxy is not a signal.
	r = httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	serve(d, h, r)
	if got != "198.51.100.1" || sig() != before {
		t.Fatalf("trusted proxy: %s (signal %d→%d)", got, before, sig())
	}
	d.Config.Server.TrustedProxies = nil

	for _, tc := range []struct {
		name, remote string
		hdr          map[string]string
		signal       bool
	}{
		{"loopback proxy", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "198.51.100.1", "X-Forwarded-Host": "Files.Example.org:443"}, true},
		{"IPv6 loopback proxy", "[::1]:5000", map[string]string{"X-Forwarded-For": "198.51.100.1"}, true},
		{"proxy on an own address", "192.168.1.10:5000", map[string]string{"X-Forwarded-For": "198.51.100.1"}, true},
		{"tailscale serve on another node", "100.99.1.2:5000", map[string]string{"X-Forwarded-For": "100.99.1.3",
			"Tailscale-User-Login": "bob@example.com"}, true},
		{"LAN client with XFF", "192.168.1.20:5000", map[string]string{"X-Forwarded-For": "198.51.100.1"}, false},
		{"loopback without XFF", "127.0.0.1:5000", nil, false},
		{"tailscale header without XFF", "100.99.1.2:5000", map[string]string{"Tailscale-User-Login": "bob@example.com"}, false},
		// Any LAN client can send both headers: no warning for it.
		{"forged tailscale header from the LAN", "192.168.1.20:5000", map[string]string{"X-Forwarded-For": "198.51.100.1",
			"Tailscale-User-Login": "bob@example.com"}, false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		for k, v := range tc.hdr {
			r.Header.Set(k, v)
		}
		before := sig()
		serve(d, h, r)
		if (sig() == before+1) != tc.signal {
			t.Errorf("%s: signal %d→%d", tc.name, before, sig())
		}
		if want := netip.MustParseAddrPort(tc.remote).Addr().String(); got != want {
			t.Errorf("%s: client %s, want the peer %s", tc.name, got, want)
		}
	}
	if s := httpx.ProxySignals.LocalProxy.Snapshot(); s.Host == "" || time.Since(s.Last) > time.Minute {
		t.Fatalf("signal snapshot %+v", s)
	}
	// In-process callers never count.
	r = withP(httptest.NewRequest("GET", "/", nil), core.SystemPrincipal(core.ViaSocket))
	r.RemoteAddr = "@"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	before = sig()
	serve(d, h, r)
	if sig() != before {
		t.Fatal("socket request counted as a proxy")
	}
}

func TestIngressHelpers(t *testing.T) {
	for p, want := range map[string]bool{
		"/s/x": true, "/s/x/": true, "/": true, "/a/b/": true, "/s/x/../y": false, "/s//x": false, "/./x": false, "/s/x/.": false,
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		if got := cleanPath(r); got != want {
			t.Errorf("cleanPath(%q) = %v", p, got)
		}
	}
	for _, raw := range []string{"/s/x%2fy", "/s/x%2Fy", "/s/x%5cy", "/s/x%5Cy"} {
		r := httptest.NewRequest("GET", raw, nil)
		if cleanPath(r) {
			t.Errorf("cleanPath(%q) accepted", raw)
		}
	}
	if !cleanPath(httptest.NewRequest("GET", "/s/a%20b", nil)) {
		t.Error("an encoded space is fine")
	}
	for _, tc := range []struct {
		path       string
		allowAdmin bool
		want       bool
	}{
		{"/admin", false, true}, {"/admin", true, false}, {"/administrator", false, false}, {"/api/v1/adminx", false, false},
		{"/trust/x", true, true}, {"/trusted", false, false}, {"/setup/", true, true}, {"/", false, false},
	} {
		if got := funnelBlocked(tc.path, tc.allowAdmin); got != tc.want {
			t.Errorf("funnelBlocked(%q, %v) = %v", tc.path, tc.allowAdmin, got)
		}
	}
	for _, p := range []string{"/", "/trust", "/healthz", "/readyz", "/favicon.ico", "/robots.txt", "/theme.css",
		"/.well-known/security.txt", "/s/x", "/trust/ca.crt", "/static/h/a.js"} {
		if MTLSExempt(p) != (p != "/") {
			t.Errorf("MTLSExempt(%q)", p)
		}
	}
	// The per-client slots of an unused client disappear.
	var c clientSlots
	c.m = map[string]*clientSlot{}
	rel, ok := c.acquire(context.Background(), "k", 1, time.Millisecond)
	if !ok {
		t.Fatal("first slot")
	}
	if _, ok := c.acquire(context.Background(), "k", 1, time.Millisecond); ok {
		t.Fatal("second slot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := c.acquire(ctx, "k", 1, time.Hour); ok {
		t.Fatal("cancelled wait")
	}
	rel()
	if len(c.m) != 0 {
		t.Fatalf("slots left: %v", c.m)
	}
}
