package tslocal

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// Under `go test` the default client can reach no tailscaled at all: the
// development machine's daemon accepts writes from its operator, so a stray
// test could publish a test server on the internet (DESIGN §17).
func TestDefaultIsInertUnderTest(t *testing.T) {
	t.Setenv(EnvSocket, "")
	c := Default()
	if len(c.Sockets) != 0 || len(c.CLIs) != 0 || c.Transport() != "" || c.Installed() {
		t.Fatalf("default client under test: %+v", c)
	}
	t.Setenv(EnvSocket, "/tmp/fake-tailscaled.sock")
	c = Default()
	if !slices.Equal(c.Sockets, []string{"/tmp/fake-tailscaled.sock"}) || len(c.CLIs) != 0 {
		t.Fatalf("with %s: %+v", EnvSocket, c)
	}
	// Outside tests: the shared platform lists (netinfo and certs used to
	// keep their own copies).
	c = defaultClient("", false)
	if !slices.Equal(c.Sockets, core.TailscaleSockets()) || !slices.Equal(c.CLIs, core.TailscaleCLIs()) {
		t.Fatalf("platform defaults: %+v", c)
	}
	if c = defaultClient("/x.sock", false); !slices.Equal(c.Sockets, []string{"/x.sock"}) || c.CLIs != nil {
		t.Fatalf("env socket outside tests keeps the CLI: %+v", c)
	}
	if c.ReadTimeout != DefaultReadTimeout || c.WriteTimeout != DefaultWriteTimeout {
		t.Fatalf("timeouts %+v", c)
	}
}

func TestPortAllowed(t *testing.T) {
	for _, tc := range []struct {
		list      string
		port      int
		ok, wrong bool
	}{
		{"443,8443,10000", 443, true, false},
		{"443,8443,10000", 10000, true, false},
		{"443", 8443, false, false},
		{"1-1024", 443, true, false},
		{"1-1024", 8443, false, false},
		{"8000-9000,443", 8443, true, false},
		{",,443,", 443, true, false},
		{"x-9", 443, false, true},
		{"443,1-y", 8443, false, true},
	} {
		ok, wrong := portAllowed(tc.list, tc.port)
		if ok != tc.ok || wrong != tc.wrong {
			t.Errorf("portAllowed(%q, %d) = %v, %v", tc.list, tc.port, ok, wrong)
		}
	}
}

func TestHTTPErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{412, "etag mismatch", ErrETagMismatch},
		{403, "serve config denied", ErrPermission},
		{401, "must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket", ErrUnixForbidden},
		{500, `{"error":"updating config: Unable to turn on Funnel while shields-up is enabled"}`, ErrShieldsUp},
		{500, `{"error":"updating config: can't reconfigure tailscaled when using a config file; config file is locked"}`, ErrConfigLocked},
		{500, `{"error":"updating config: listener already exists for port 443"}`, ErrPortInUse},
		{500, `{"error":"updating config: foreground listener already exists for port 443"}`, ErrPortInUse},
		{500, `{"error":"updating config: want to serve \"https\", but port 443 is already serving \"tcp\""}`, ErrPortInUse},
		{500, `{"error":"updating config: netMap is nil"}`, ErrNotConnected},
		{500, `{"error":"updating config: netMap SelfNode is nil"}`, ErrNotConnected},
		{503, "no netmap", ErrNotConnected},
	} {
		err := httpError(tc.status, []byte(tc.body))
		if !errors.Is(err, tc.want) {
			t.Errorf("%d %q → %v, want %v", tc.status, tc.body, err, tc.want)
		}
	}
	// 403 "invalid localapi request" is not a permission problem.
	var ae *APIError
	if err := httpError(http.StatusForbidden, []byte("invalid localapi request\n")); !errors.As(err, &ae) ||
		errors.Is(err, ErrPermission) || ae.Status != 403 || ae.Body != "invalid localapi request" {
		t.Fatalf("invalid localapi request → %v", err)
	}
	if err := httpError(500, []byte(`{"error":"something else"}`)); !errors.As(err, &ae) || ae.Body != "something else" {
		t.Fatalf("other 500 → %v", err)
	}
	long := strings.Repeat("é", 400)
	if err := httpError(500, []byte(long)); !errors.As(err, &ae) || len(ae.Body) > maxErrBody || !strings.HasPrefix(long, ae.Body) {
		t.Fatalf("body not clipped on a rune boundary: %d bytes", len(ae.Body))
	}
}

func TestJoinDistinct(t *testing.T) {
	const complaint = `invalid domain "nosuch.tail1234.ts.net"; must be one of ["files.tail1234.ts.net"]`
	joined := joinDistinct([]error{
		errors.New("tailscaled LocalAPI: HTTP 500: " + complaint),
		errors.New("tailscaled LocalAPI: HTTP 500: " + complaint),
		errors.New("tailscale cert --cert-file c --key-file k x: exit status 1: " + complaint),
	})
	if n := strings.Count(joined.Error(), complaint); n != 1 {
		t.Fatalf("%d copies: %v", n, joined)
	}
	joined = joinDistinct([]error{errors.New("dial /run/tailscale/tailscaled.sock: connection refused"),
		errors.New("tailscale CLI not found: exec: \"tailscale\": executable file not found in $PATH")})
	if !strings.Contains(joined.Error(), "connection refused") || !strings.Contains(joined.Error(), "not found in $PATH") {
		t.Fatalf("distinct errors were collapsed: %v", joined)
	}
}

func TestSelfHosted(t *testing.T) {
	for u, want := range map[string]bool{
		"": false, "https://controlplane.tailscale.com": false, "https://login.tailscale.com/": false,
		"https://hs.example.org": true, "https://CONTROLPLANE.tailscale.com": false, "::bad": false,
	} {
		if SelfHosted(u) != want {
			t.Errorf("SelfHosted(%q)", u)
		}
	}
}
