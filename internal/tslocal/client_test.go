package tslocal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/tslocal"
	"fileparcel/internal/tslocal/tslocaltest"
)

func TestStatusAndPrefs(t *testing.T) {
	f := tslocaltest.New(t)
	exp := time.Date(2027, 3, 13, 1, 9, 45, 0, time.UTC)
	n := tslocaltest.DefaultNode()
	n.DNSName, n.KeyExpiry = "Files.Tail1234.ts.net.", &exp
	f.SetNode(n)
	f.SetPrefs(`{"ControlURL":"https://hs.example.org","OperatorUser":"alice","ShieldsUp":true,"WantRunning":true,"Unknown":1}`)
	c := f.Client()
	if c.Transport() != "localapi" || !c.Installed() {
		t.Fatalf("transport %q", c.Transport())
	}
	ctx := context.Background()
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running() || !st.TUN || st.Version != "1.102.4" || st.NodeID() != "nTESTNODE1CNTRL" ||
		st.Self.KeyExpiry == nil || !st.Self.KeyExpiry.Equal(exp) || len(st.IPs()) != 2 {
		t.Fatalf("status %+v self %+v", st, st.Self)
	}
	if !st.HasCap("https") || !st.HasCap("funnel") || st.HasCap("nope") {
		t.Fatal("capabilities")
	}
	// Exactly as the tailscale CLI builds HostPort keys: dot trimmed, case kept.
	if got := st.HostPortName(); got != "Files.Tail1234.ts.net" {
		t.Fatalf("HostPortName %q", got)
	}
	if got := st.DNSName(); got != "files.tail1234.ts.net" {
		t.Fatalf("DNSName %q", got)
	}
	if got := st.FunnelPorts(); !slices.Equal(got, []int{443, 8443, 10000}) {
		t.Fatalf("FunnelPorts %v", got)
	}
	p, err := c.Prefs(ctx)
	if err != nil || p.ControlURL != "https://hs.example.org" || p.OperatorUser != "alice" || !p.ShieldsUp || !p.WantRunning {
		t.Fatalf("prefs %+v, %v", p, err)
	}
	// The request asked for no peers and carried the LocalAPI host only.
	for _, r := range f.Requests() {
		if r.Host != "local-tailscaled.sock" || r.Origin != "" || r.Referer != "" {
			t.Fatalf("request %+v", r)
		}
		if r.Path == "/localapi/v0/status" && r.Query != "peers=false" {
			t.Fatalf("status query %q", r.Query)
		}
	}
}

func TestFunnelPorts(t *testing.T) {
	status := func(caps ...string) *tslocal.Status {
		st := &tslocal.Status{Self: &tslocal.SelfStatus{CapMap: map[string]json.RawMessage{}}}
		for _, c := range caps {
			st.Self.CapMap[c] = nil
		}
		return st
	}
	const base = "https://tailscale.com/cap/funnel-ports"
	for _, tc := range []struct {
		caps []string
		want []int
	}{
		{nil, []int{}},
		{[]string{"funnel"}, []int{}},
		{[]string{base + "?ports=443"}, []int{443}},
		{[]string{base + "?ports=443,8443,10000"}, []int{443, 8443, 10000}},
		{[]string{base + "?ports=8000-9000,10000"}, []int{8443, 10000}},
		{[]string{base + "?ports=1-65535"}, []int{443, 8443, 10000}},
		{[]string{base + "?ports=443,bad-1"}, []int{}}, // malformed range: nothing
		{[]string{base + "?ports="}, []int{}},
		{[]string{base + "/x?ports=443"}, []int{}}, // not exactly the capability
		{[]string{base + "?ports=22,80"}, []int{}},
	} {
		if got := status(tc.caps...).FunnelPorts(); !slices.Equal(got, tc.want) {
			t.Errorf("%v → %v, want %v", tc.caps, got, tc.want)
		}
	}
	// The deprecated Capabilities list counts as well.
	st := &tslocal.Status{Self: &tslocal.SelfStatus{Capabilities: []string{"https", base + "?ports=8443"}}}
	if !st.HasCap("https") || !slices.Equal(st.FunnelPorts(), []int{8443}) {
		t.Fatalf("Capabilities: %v", st.FunnelPorts())
	}
	var nilStatus *tslocal.Status
	if nilStatus.HasCap("https") || len(nilStatus.FunnelPorts()) != 0 || nilStatus.HostPortName() != "" {
		t.Fatal("nil status")
	}
}

func TestServeConfigNullAndETag(t *testing.T) {
	f := tslocaltest.New(t)
	c := f.Client()
	ctx := context.Background()
	sc, err := c.ServeConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !sc.Empty() || sc.ETag != f.ETag() || len(sc.Entries()) != 0 {
		t.Fatalf("empty config %+v", sc)
	}
	sc.SetEntry("node.tail.ts.net:443", 443, "unix:/h/run/ts-funnel.sock", true)
	if err := c.SetServeConfig(ctx, sc); err != nil {
		t.Fatal(err)
	}
	want := `{"AllowFunnel":{"node.tail.ts.net:443":true},"TCP":{"443":{"HTTPS":true}},` +
		`"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"unix:/h/run/ts-funnel.sock"}}}}}`
	if got := f.Config(); got != want {
		t.Fatalf("posted\n%s\nwant\n%s", got, want)
	}
	posts := f.Posts()
	if len(posts) != 1 || posts[0].IfMatch == "" || posts[0].IfMatch != sc.ETag {
		t.Fatalf("If-Match not sent: %+v", posts)
	}
	// A second write with the stale ETag is refused by the daemon.
	if err := c.SetServeConfig(ctx, sc); !errors.Is(err, tslocal.ErrETagMismatch) {
		t.Fatalf("stale etag: %v", err)
	}
	// Without an ETag nothing is sent at all.
	n := len(f.Posts())
	if err := c.SetServeConfig(ctx, &tslocal.ServeConfig{}); err == nil || len(f.Posts()) != n {
		t.Fatalf("empty ETag: %v, posts %d → %d", err, n, len(f.Posts()))
	}
	if err := c.SetServeConfig(ctx, nil); err == nil {
		t.Fatal("nil config accepted")
	}
}

// Everything FileParcel does not model is written back exactly as read.
func TestServeConfigRoundTripPreservesForeignParts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "serve-config-foreign.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sc tslocal.ServeConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	out, err := sc.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var in, got map[string]json.RawMessage
	_ = json.Unmarshal(bytes.TrimSpace(raw), &in)
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if len(in) != len(got) {
		t.Fatalf("top-level keys %d → %d", len(in), len(got))
	}
	for _, k := range []string{"Services", "Foreground", "FutureKey"} {
		if !bytes.Equal(in[k], got[k]) {
			t.Errorf("%s changed:\n%s\n%s", k, in[k], got[k])
		}
	}
	// Adding FileParcel's entry leaves every other entry byte for byte.
	sc.SetEntry("node.tail.ts.net:443", 443, "unix:/h/run/ts-funnel.sock", true)
	out, _ = sc.MarshalJSON()
	_ = json.Unmarshal(out, &got)
	var inWeb, gotWeb, inTCP, gotTCP map[string]json.RawMessage
	_ = json.Unmarshal(in["Web"], &inWeb)
	_ = json.Unmarshal(got["Web"], &gotWeb)
	_ = json.Unmarshal(in["TCP"], &inTCP)
	_ = json.Unmarshal(got["TCP"], &gotTCP)
	for k, v := range inWeb {
		if !bytes.Equal(v, gotWeb[k]) {
			t.Errorf("Web[%s] changed", k)
		}
	}
	for k, v := range inTCP {
		if !bytes.Equal(v, gotTCP[k]) {
			t.Errorf("TCP[%s] changed", k)
		}
	}
	if string(gotTCP["443"]) != `{"HTTPS":true}` || !strings.Contains(string(gotWeb["node.tail.ts.net:443"]), "ts-funnel.sock") {
		t.Fatalf("entry not added: %s", out)
	}
	for _, k := range []string{"Services", "Foreground", "FutureKey"} {
		if !bytes.Equal(in[k], got[k]) {
			t.Errorf("%s changed by SetEntry", k)
		}
	}
	// Removing it restores the original document.
	owned := func(p string) bool { return p == "unix:/h/run/ts-funnel.sock" }
	if !sc.RemoveEntry("node.tail.ts.net:443", 443, owned) {
		t.Fatal("not removed")
	}
	var orig tslocal.ServeConfig
	_ = json.Unmarshal(raw, &orig)
	if !sc.Equal(&orig) {
		a, _ := sc.MarshalJSON()
		b, _ := orig.MarshalJSON()
		t.Fatalf("after remove\n%s\nwant\n%s", a, b)
	}
}

func TestEntries(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "serve-config-foreign.json"))
	var sc tslocal.ServeConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	type key struct{ hp, mount, target string }
	got := map[key]tslocal.ServeEntry{}
	for _, e := range sc.Entries() {
		got[key{e.HostPort, e.Mount, e.Target()}] = e
	}
	check := func(k key, fn func(tslocal.ServeEntry) bool) {
		t.Helper()
		e, ok := got[k]
		if !ok || !fn(e) {
			t.Errorf("%+v: %+v (present %v)", k, e, ok)
		}
	}
	check(key{"node.tail.ts.net:8443", "/", "http://127.0.0.1:3000"}, func(e tslocal.ServeEntry) bool {
		return e.Funnel && !e.Foreground && e.Port == 8443 && !e.UsesLocalPath()
	})
	check(key{"node.tail.ts.net:8443", "/docs", "path:/srv/docs"}, func(e tslocal.ServeEntry) bool { return e.UsesLocalPath() })
	check(key{"", "", "tcp:127.0.0.1:22"}, func(e tslocal.ServeEntry) bool { return e.Port == 10000 })
	check(key{"node.tail.ts.net:4443", "/", "https+insecure://localhost:8443"}, func(e tslocal.ServeEntry) bool {
		return e.Foreground && e.Funnel
	})
	check(key{"web.tail.ts.net:443", "/", "http://127.0.0.1:8081"}, func(e tslocal.ServeEntry) bool { return e.Service == "svc:web" })
	if len(got) != 5 {
		t.Fatalf("%d entries: %+v", len(got), got)
	}
}

func TestSetAndRemoveEntry(t *testing.T) {
	const hp, other = "node.tail.ts.net:443", "Node.tail.ts.net:443"
	owned := func(p string) bool { return strings.HasPrefix(p, "unix:/h/") }
	sc := &tslocal.ServeConfig{}
	sc.SetEntry(hp, 443, "unix:/h/run/ts-serve.sock", false)
	before, _ := sc.MarshalJSON()
	// Idempotent: the same entry again changes nothing.
	sc.SetEntry(hp, 443, "unix:/h/run/ts-serve.sock", false)
	if after, _ := sc.MarshalJSON(); !bytes.Equal(before, after) {
		t.Fatalf("SetEntry not idempotent:\n%s\n%s", before, after)
	}
	// Switching the kind sets and clears AllowFunnel.
	sc.SetEntry(hp, 443, "unix:/h/run/ts-funnel.sock", true)
	if !sc.FunnelOn(hp) {
		t.Fatal("funnel flag")
	}
	sc.SetEntry(hp, 443, "unix:/h/run/ts-serve.sock", false)
	if sc.FunnelOn(hp) {
		t.Fatal("funnel flag kept for serve")
	}
	if p, https := sc.Proxy(hp, 443); p != "unix:/h/run/ts-serve.sock" || !https {
		t.Fatalf("Proxy %q %v", p, https)
	}
	// Another HostPort on the same port keeps TCP[443] when FileParcel's goes.
	var fg tslocal.ServeConfig
	_ = json.Unmarshal([]byte(`{"Web":{"`+other+`":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9"}}}}}`), &fg)
	sc.Web[other] = fg.Web[other]
	if !sc.RemoveEntry(hp, 443, owned) {
		t.Fatal("not removed")
	}
	if _, ok := sc.TCP["443"]; !ok {
		t.Fatal("TCP[443] removed while another HostPort uses it")
	}
	if _, ok := sc.Web[hp]; ok {
		t.Fatal("Web entry left")
	}
	// A foreign mount on FileParcel's HostPort stays, and so do Web and TCP.
	sc = &tslocal.ServeConfig{}
	sc.SetEntry(hp, 443, "unix:/h/run/ts-funnel.sock", true)
	var w map[string]any
	_ = json.Unmarshal(sc.Web[hp], &w)
	w["Handlers"].(map[string]any)["/other"] = map[string]any{"Proxy": "http://127.0.0.1:5000"}
	sc.Web[hp], _ = json.Marshal(w)
	if !sc.RemoveEntry(hp, 443, owned) {
		t.Fatal("not removed")
	}
	if p, _ := sc.Proxy(hp, 443); p != "" {
		t.Fatalf("mount / left: %q", p)
	}
	if _, ok := sc.Web[hp]; !ok || !sc.FunnelOn(hp) {
		t.Fatal("the foreign mount's Web entry or Funnel flag was removed")
	}
	if _, ok := sc.TCP["443"]; !ok {
		t.Fatal("TCP removed under a foreign mount")
	}
	// A foreign proxy on "/" is never removed.
	sc = &tslocal.ServeConfig{}
	sc.SetEntry(hp, 443, "http://127.0.0.1:3000", false)
	if sc.RemoveEntry(hp, 443, owned) {
		t.Fatal("foreign entry removed")
	}
	// TCP[port] that is not exactly HTTPS is never removed.
	sc = &tslocal.ServeConfig{}
	sc.SetEntry(hp, 443, "unix:/h/run/ts-funnel.sock", true)
	sc.TCP["443"] = json.RawMessage(`{"HTTPS":true,"ProxyProtocol":1}`)
	sc.RemoveEntry(hp, 443, owned)
	if _, ok := sc.TCP["443"]; !ok {
		t.Fatal("non-exact TCP handler removed")
	}
}

func TestConflict(t *testing.T) {
	const hp = "node.tail.ts.net:443"
	owned := func(p string) bool { return p == "unix:/h/run/ts-funnel.sock" }
	parse := func(s string) *tslocal.ServeConfig {
		var sc tslocal.ServeConfig
		if err := json.Unmarshal([]byte(s), &sc); err != nil {
			t.Fatal(err)
		}
		return &sc
	}
	for name, tc := range map[string]struct {
		cfg    string
		want   bool
		target string
	}{
		"empty": {`null`, false, ""},
		"own entry": {`{"TCP":{"443":{"HTTPS":true}},"Web":{"` + hp + `":{"Handlers":{"/":{"Proxy":"unix:/h/run/ts-funnel.sock"}}}}}`,
			false, ""},
		"other port": {`{"TCP":{"8443":{"TCPForward":"127.0.0.1:22"}}}`, false, ""},
		"foreground port": {`{"Foreground":{"s1":{"TCP":{"443":{"HTTPS":true}},"Web":{"x:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:1"}}}}}}}`,
			true, "foreground"},
		"foreground hostport": {`{"Foreground":{"s1":{"Web":{"` + hp + `":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:1"}}}}}}}`,
			true, "http://127.0.0.1:1"},
		"http":          {`{"TCP":{"443":{"HTTP":true}}}`, true, "plain-HTTP"},
		"tcp forward":   {`{"TCP":{"443":{"TCPForward":"127.0.0.1:22"}}}`, true, "tcp:127.0.0.1:22"},
		"terminate tls": {`{"TCP":{"443":{"TCPForward":"127.0.0.1:22","TerminateTLS":"x"}}}`, true, "tcp:"},
		"foreign mount": {`{"TCP":{"443":{"HTTPS":true}},"Web":{"` + hp + `":{"Handlers":{"/":{"Proxy":"unix:/h/run/ts-funnel.sock"},"/x":{"Path":"/srv"}}}}}`,
			true, "path:/srv (mount /x)"},
		"foreign root": {`{"TCP":{"443":{"HTTPS":true}},"Web":{"` + hp + `":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}}`,
			true, "http://127.0.0.1:3000"},
	} {
		target, conflict := parse(tc.cfg).Conflict(hp, 443, owned)
		if conflict != tc.want || !strings.Contains(target, tc.target) {
			t.Errorf("%s: %q %v", name, target, conflict)
		}
	}
}

func TestLocalAPIErrorsFromDaemon(t *testing.T) {
	f := tslocaltest.New(t)
	c := f.Client()
	ctx := context.Background()
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusForbidden, "serve config denied", tslocal.ErrPermission},
		{http.StatusUnauthorized, "must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket", tslocal.ErrUnixForbidden},
		{http.StatusInternalServerError, `{"error":"updating config: Unable to turn on Funnel while shields-up is enabled"}`, tslocal.ErrShieldsUp},
		{http.StatusInternalServerError, `{"error":"updating config: netMap is nil"}`, tslocal.ErrNotConnected},
	} {
		sc, err := c.ServeConfig(ctx)
		if err != nil {
			t.Fatal(err)
		}
		f.FailNextPost(tc.status, tc.body)
		if err := c.SetServeConfig(ctx, sc); !errors.Is(err, tc.want) {
			t.Errorf("%d %s → %v", tc.status, tc.body, err)
		}
	}
	// Origin/Referer are never sent (tailscaled refuses them).
	for _, r := range f.Requests() {
		if r.Origin != "" || r.Referer != "" || r.Host != "local-tailscaled.sock" {
			t.Fatalf("%+v", r)
		}
	}
	// query-feature.
	f.SetQueryFeature(`{"Complete":false,"Text":"Funnel is not enabled","URL":"https://login.tailscale.com/f/funnel?node=x"}`)
	q, err := c.QueryFeature(ctx, "funnel")
	if err != nil || q.Complete || !strings.HasPrefix(q.URL, "https://login.tailscale.com/") {
		t.Fatalf("query-feature %+v %v", q, err)
	}
	var qr tslocaltest.Request
	for _, r := range f.Requests() {
		if r.Path == "/localapi/v0/query-feature" {
			qr = r
		}
	}
	if qr.Method != http.MethodPost || qr.Query != "feature=funnel" {
		t.Fatalf("query-feature request %+v", qr)
	}
}

func TestNoDaemon(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	// No socket, no CLI: not installed.
	c := &tslocal.Client{Sockets: []string{filepath.Join(dir, "missing.sock")}}
	if _, err := c.Status(ctx); !errors.Is(err, tslocal.ErrNotInstalled) || !errors.Is(err, tslocal.ErrNoDaemon) {
		t.Fatalf("status: %v", err)
	}
	if _, err := c.ServeConfig(ctx); !errors.Is(err, tslocal.ErrNotInstalled) {
		t.Fatalf("serve config: %v", err)
	}
	if c.SocketOwnerUID() != -1 || c.Installed() {
		t.Fatal("owner of a missing socket")
	}
	// A socket file nobody listens on: tailscaled is not running.
	dead := filepath.Join(shortDir(t), "dead.sock")
	ln, err := net.Listen("unix", dead)
	if err != nil {
		t.Skip(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	c = &tslocal.Client{Sockets: []string{dead}}
	if c.Transport() != "localapi" {
		t.Fatalf("transport %q", c.Transport())
	}
	if _, err := c.Status(ctx); !errors.Is(err, tslocal.ErrNoDaemon) || errors.Is(err, tslocal.ErrNotInstalled) {
		t.Fatalf("dead socket: %v", err)
	}
	if _, err := c.ServeConfig(ctx); !errors.Is(err, tslocal.ErrNoDaemon) {
		t.Fatalf("dead socket serve config: %v", err)
	}
	if uid := c.SocketOwnerUID(); uid != os.Getuid() {
		t.Fatalf("socket owner %d", uid)
	}
}

// shortDir is a temporary directory with a short path (Unix socket paths
// are limited to ~104 bytes).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "fptl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// fakeCLI writes a tailscale stand-in that logs its arguments.
func fakeCLI(t *testing.T, script string) (bin, argLog string) {
	t.Helper()
	dir := t.TempDir()
	argLog = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "tailscale")
	body := "#!/bin/sh\necho \"$*\" >> " + argLog + "\n" + script
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argLog
}

func TestCLIFallback(t *testing.T) {
	st := tslocaltest.StatusJSON(tslocaltest.DefaultNode())
	cfg, _ := os.ReadFile(filepath.Join("testdata", "serve-config-cli.json"))
	bin, argLog := fakeCLI(t, `case "$1" in
status) case "$*" in *peers*) echo 'flag provided but not defined: -peers' >&2; exit 2;; esac
  cat <<'EOF'
`+st+`
EOF
;;
debug) echo '{"ControlURL":"https://controlplane.tailscale.com","OperatorUser":"null"}' ;;
serve) if [ "$2" = status ]; then cat <<'EOF'
`+string(cfg)+`
EOF
  elif [ "$5" = off ]; then exit 0; else echo "serve ok"; fi ;;
funnel) echo "funnel ok" ;;
esac
`)
	// Tests build the client directly: FILEPARCEL_TAILSCALE_SOCKET disables the CLI.
	c := &tslocal.Client{Sockets: []string{filepath.Join(t.TempDir(), "none.sock")}, CLIs: []string{"/nonexistent/tailscale", bin}}
	if c.Transport() != "cli" {
		t.Fatalf("transport %q", c.Transport())
	}
	ctx := context.Background()
	s, err := c.Status(ctx)
	if err != nil || !s.Running() || s.HostPortName() != "node.tail.ts.net" {
		t.Fatalf("status via CLI: %+v %v", s, err)
	}
	if p, err := c.Prefs(ctx); err != nil || p.OperatorUser != "null" {
		t.Fatalf("prefs via CLI: %+v %v", p, err)
	}
	sc, err := c.ServeConfig(ctx)
	if err != nil || sc.ETag != "" {
		t.Fatalf("serve status via CLI: %v", err)
	}
	if p, _ := sc.Proxy("node.tail.ts.net:443", 443); p != "http://127.0.0.1:3000" {
		t.Fatalf("indented CLI output parsed: %q", p)
	}
	// Writing needs the LocalAPI: nothing is attempted.
	sc.ETag = "x"
	if err := c.SetServeConfig(ctx, sc); err == nil {
		t.Fatal("SetServeConfig over the CLI transport")
	}
	if err := c.ServeCLI(ctx, true, 443, "unix:/h/run/ts-funnel.sock"); err != nil {
		t.Fatal(err)
	}
	if err := c.ServeCLI(ctx, false, 8443, "http://127.0.0.1:18444"); err != nil {
		t.Fatal(err)
	}
	if err := c.ServeOffCLI(ctx, 10000); err != nil {
		t.Fatal(err)
	}
	log, _ := os.ReadFile(argLog)
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	want := []string{
		"status --json --peers=false", "status --json", "debug prefs", "serve status --json",
		"funnel --bg --yes --https=443 --set-path=/ unix:/h/run/ts-funnel.sock",
		"serve --bg --yes --https=8443 --set-path=/ http://127.0.0.1:18444",
		"serve --yes --https=10000 --set-path=/ off",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("argv\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if got := tslocal.OffCommand(443, true); got != "sudo tailscale serve --yes --https=443 --set-path=/ off" {
		t.Fatalf("OffCommand %q", got)
	}
}

func TestCLIErrorsTimeoutAndLimits(t *testing.T) {
	ctx := context.Background()
	bin, _ := fakeCLI(t, `case "$1" in
serve) echo "sending serve config: 401 Unauthorized: must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket" >&2; exit 1;;
funnel) echo "error: Unable to turn on Funnel while shields-up is enabled" >&2; exit 1;;
big) head -c 9000000 /dev/zero; exit 0;;
noisy) head -c 20000 /dev/zero >&2; echo x; exit 0;;
sleep) sleep 5;;
esac
`)
	c := &tslocal.Client{CLIs: []string{bin}}
	if err := c.ServeCLI(ctx, false, 443, "unix:/x"); !errors.Is(err, tslocal.ErrUnixForbidden) {
		t.Fatalf("serve: %v", err)
	}
	if err := c.ServeCLI(ctx, true, 443, "unix:/x"); !errors.Is(err, tslocal.ErrShieldsUp) {
		t.Fatalf("funnel: %v", err)
	}
	if _, err := c.RunCLI(ctx, 5*time.Second, "big"); err == nil {
		t.Fatal("more than 8 MiB of output accepted")
	}
	if out, err := c.RunCLI(ctx, 5*time.Second, "noisy"); err != nil || strings.TrimSpace(string(out)) != "x" {
		t.Fatalf("stderr beyond the limit must not fail the command: %q %v", out, err)
	}
	start := time.Now()
	if _, err := c.RunCLI(ctx, 200*time.Millisecond, "sleep"); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout: %v after %v", err, time.Since(start))
	}
	if _, err := (&tslocal.Client{}).RunCLI(ctx, time.Second, "x"); err == nil {
		t.Fatal("no CLI")
	}
}

func TestCertPair(t *testing.T) {
	f := tslocaltest.New(t)
	pair := []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n" +
		"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n")
	var asked string
	f.SetCert(func(name string) (int, []byte) { asked = name; return 200, pair })
	c := f.Client()
	cp, kp, err := c.CertPair(context.Background(), "node.tail.ts.net")
	if err != nil {
		t.Fatal(err)
	}
	if asked != "node.tail.ts.net" || strings.Count(string(cp), "BEGIN CERTIFICATE") != 2 || !strings.Contains(string(kp), "PRIVATE KEY") {
		t.Fatalf("pair %q / %q", cp, kp)
	}
	var q string
	for _, r := range f.Requests() {
		if strings.HasPrefix(r.Path, "/localapi/v0/cert/") {
			q = r.Query
		}
	}
	if q != "type=pair" {
		t.Fatalf("query %q", q)
	}
	// Refused by every socket and by the CLI with the same sentence: said once.
	const complaint = `invalid domain "nosuch.tail.ts.net"; must be one of ["node.tail.ts.net"]`
	f.SetCert(func(string) (int, []byte) { return 500, []byte(complaint) })
	bin, _ := fakeCLI(t, "echo '"+complaint+"' >&2\nexit 1\n")
	c2 := &tslocal.Client{Sockets: []string{f.Path, f.Path}, CLIs: []string{bin}, TempDir: t.TempDir()}
	_, _, err = c2.CertPair(context.Background(), "nosuch.tail.ts.net")
	if err == nil || strings.Count(err.Error(), complaint) != 1 {
		t.Fatalf("repeated complaint: %v", err)
	}
	var ae *tslocal.APIError
	if !errors.As(err, &ae) || ae.Status != 500 {
		t.Fatalf("APIError lost: %v", err)
	}
	if _, _, err := tslocal.SplitPEMPair([]byte("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("certificate without key accepted")
	}
}
