package mw

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// policyNet is a Network whose access policy is allowed.
type policyNet struct {
	fakeNet
	allowed func(netip.Addr) bool
}

func (n policyNet) Allowed(ip netip.Addr) bool { return n.allowed(ip) }

func TestProxiedPolicy(t *testing.T) {
	e := newEnv(t)
	d := e.d
	lan := netip.MustParsePrefix("192.168.1.0/24")
	denied := netip.MustParseAddr("198.51.100.7")
	// allowlist 192.168.1.0/24, deny 198.51.100.7 (loopback always allowed).
	policy := func(ip netip.Addr) bool { return ip.IsLoopback() || (ip != denied && lan.Contains(ip)) }
	d.Network = policyNet{allowed: func(ip netip.Addr) bool { return policy(ip) }}
	reached := false
	h := ResolveClientIP(AccessLog(ProxiedPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))))
	try := func(path, remote string, xff ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		for _, x := range xff {
			r.Header.Add("X-Forwarded-For", x)
		}
		reached = false
		return serve(d, h, r)
	}

	// Without trusted proxies X-Forwarded-For is ignored: the loopback peer
	// passes (it was checked at Accept).
	if rec := try("/", "127.0.0.1:5000", denied.String()); rec.Code != 200 || !reached {
		t.Fatalf("no trusted proxies: %d", rec.Code)
	}

	d.Config.Server.TrustedProxies = []string{"127.0.0.1"}
	// A denied client behind a same-host proxy is refused, and logged.
	rec := try("/", "127.0.0.1:5000", denied.String())
	if rec.Code != 403 || reached || !strings.Contains(rec.Body.String(), "access policy") ||
		rec.Header().Get("Connection") != "close" {
		t.Fatalf("denied client: %d %q reached=%v", rec.Code, rec.Body.String(), reached)
	}
	if err := CheckSecurityHeaders(rec.Header(), HeadersPage); err != nil {
		t.Error(err)
	}
	if logs := e.logs.String(); !strings.Contains(logs, "status=403") || !strings.Contains(logs, denied.String()) {
		t.Errorf("refusal not in the access log: %s", logs)
	}
	// ... with the JSON error shape on API paths.
	if rec := try("/api/v1/me", "127.0.0.1:5000", denied.String()); rec.Code != 403 || code(t, rec) != "forbidden" || reached {
		t.Fatalf("denied API client: %d %q", rec.Code, rec.Body.String())
	}
	// A client outside the allow list is refused too (the policy means the
	// same thing with and without a proxy).
	if rec := try("/", "127.0.0.1:5000", "203.0.113.5"); rec.Code != 403 || reached {
		t.Fatalf("client outside the allow list: %d", rec.Code)
	}
	// An allowed client, and the proxy itself (no X-Forwarded-For), pass.
	if rec := try("/", "127.0.0.1:5000", "192.168.1.10"); rec.Code != 200 || !reached {
		t.Fatalf("allowed client: %d", rec.Code)
	}
	if rec := try("/", "127.0.0.1:5000"); rec.Code != 200 || !reached {
		t.Fatalf("proxy without X-Forwarded-For: %d", rec.Code)
	}
	// An untrusted peer's X-Forwarded-For is ignored (its own address was
	// checked at Accept).
	if rec := try("/", "192.168.1.20:5000", denied.String()); rec.Code != 200 || !reached {
		t.Fatalf("untrusted peer: %d", rec.Code)
	}
	// In-process callers always pass.
	r := withP(httptest.NewRequest("GET", "/api/v1/me", nil), core.SystemPrincipal(core.ViaSocket))
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", denied.String())
	reached = false
	if rec := serve(d, h, r); rec.Code != 200 || !reached {
		t.Fatalf("socket: %d", rec.Code)
	}
	// Mode "any": everyone passes but the deny list still applies.
	policy = func(ip netip.Addr) bool { return ip != denied }
	if rec := try("/", "127.0.0.1:5000", "203.0.113.5"); rec.Code != 200 || !reached {
		t.Fatalf("any: %d", rec.Code)
	}
	if rec := try("/", "127.0.0.1:5000", denied.String()); rec.Code != 403 || reached {
		t.Fatalf("any + deny: %d", rec.Code)
	}
}
