package wire

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/server"
	"fileparcel/internal/svc/provision"
	"fileparcel/internal/tslocal/tslocaltest"
	"fileparcel/internal/web"
	"fileparcel/internal/web/httpx"
)

// The foreign serve entry the fake tailscaled starts with (another program
// on port 10000); FileParcel must leave it alone.
const foreignEntry = `{"TCP":{"10000":{"HTTPS":true}},"Web":{"node.tail.ts.net:10000":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}}`

// funnelServer is a real server on a provisioned temp home whose tailscaled
// is a fake (FILEPARCEL_TAILSCALE_SOCKET): the admin socket, the main
// HTTPS listener and the Funnel socket as tailscaled would dial it.
type funnelServer struct {
	t     *testing.T
	h     *home.Home
	d     *app.Deps
	fake  *tslocaltest.Fake
	admin *http.Client // admin socket (system principal, like the CLI)
	main  *http.Client // main HTTPS listener
	https string
	stop  func()
}

func startFunnelServer(t *testing.T) *funnelServer {
	t.Helper()
	fake := tslocaltest.New(t)
	fake.SetConfig(foreignEntry)
	t.Setenv("FILEPARCEL_TAILSCALE_SOCKET", fake.Path)
	ctx := context.Background()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	p, err := provision.PrepareHome(t.TempDir(), provision.ConfigOptions{HTTPSPort: port, HTTPPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	// Loopback only, and nothing announced on the local network.
	p.Config.Server.Bind = []string{"127.0.0.1"}
	if err := p.Config.SaveTo(p.Home.Config()); err != nil {
		t.Fatal(err)
	}
	od, ocleanup, err := Build(ctx, p.Home, app.ModeOffline)
	if err != nil {
		t.Fatal(err)
	}
	sys := core.SystemPrincipal(core.ViaOffline)
	if _, err := provision.Provision(ctx, od, provision.Options{Admin: "admin", AdminPassword: "Integration-" + strconv.Itoa(port) + "-pw",
		Access: core.AccessPrivate, SkipBackupIdentity: true}); err != nil {
		ocleanup()
		t.Fatal(err)
	}
	if _, err := od.Settings.Set(core.WithPrincipal(ctx, sys), sys, map[string]json.RawMessage{"mdns.mode": json.RawMessage(`"off"`)}); err != nil {
		ocleanup()
		t.Fatal(err)
	}
	ocleanup()

	d, cleanup, err := Build(ctx, p.Home, app.ModeNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err := Start(ctx, d); err != nil {
		cleanup()
		t.Fatal(err)
	}
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- server.Run(sctx, d, web.NewRouter(d), server.Options{Cleanup: cleanup}) }()
	fs := &funnelServer{t: t, h: p.Home, d: d, fake: fake, https: "https://127.0.0.1:" + strconv.Itoa(port)}
	fs.stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(server.ShutdownTimeout + 10*time.Second):
			t.Error("the server did not stop")
		}
	}
	t.Cleanup(fs.stop)

	pemData, _, _, err := d.Certs.CAExport("pem")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	fs.main = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fs.admin = unixClient(p.Home.Socket())
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := fs.admin.Get("http://localhost/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case err := <-done:
			t.Fatalf("the server stopped: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fs
}

// unixClient speaks HTTP over a Unix socket.
func unixClient(path string) *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}}
}

// call sends a JSON request and decodes a 2xx answer into out.
func call(t *testing.T, c *http.Client, method, url string, hdr map[string]string, body, out any) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, url, err, raw)
		}
	}
	return resp.StatusCode, raw, resp.Header
}

// adminCall is a request over the admin socket.
func (fs *funnelServer) adminCall(method, path string, body, out any) (int, []byte) {
	fs.t.Helper()
	code, raw, _ := call(fs.t, fs.admin, method, "http://localhost/api/v1"+path, nil, body, out)
	return code, raw
}

// funnelCall is what tailscaled forwards for an internet visitor.
func (fs *funnelServer) funnelCall(method, path string, hdr map[string]string, body, out any) (int, []byte) {
	fs.t.Helper()
	h := map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Host": "node.tail.ts.net",
		"X-Forwarded-Proto": "https", "Tailscale-Funnel-Request": "?1"}
	for k, v := range hdr {
		h[k] = v
	}
	code, raw, _ := call(fs.t, unixClient(filepath.Join(fs.h.RunDir(), "ts-funnel.sock")), method, "http://localhost"+path, h, body, out)
	return code, raw
}

// password is the test password of a user (policy: not containing the name).
func password(user string) string { return "Correct-horse-battery-" + strconv.Itoa(len(user)) + "x" }

// sameJSON compares two JSON documents by value.
func sameJSON(t *testing.T, got, want string) bool {
	t.Helper()
	var a, b any
	if err := json.Unmarshal([]byte(got), &a); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatalf("%v: %s", err, want)
	}
	return reflect.DeepEqual(a, b)
}

// TestFunnelEndToEnd drives Tailscale Funnel through a real server with a
// fake tailscaled (DESIGN §10.6): enabling writes FileParcel's entry next to
// a foreign one (with If-Match); tailscaled's connection to the Funnel
// socket reaches a share with the visitor's address; the app and sessions
// stay out of reach; the deny list applies; "app" mode refuses a password
// sign-in without 2FA without counting it; the main listener refuses the
// Funnel header; disabling closes the socket and restores tailscaled.
func TestFunnelEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a server")
	}
	fs := startFunnelServer(t)
	ctx := context.Background()

	// People and a public link (a member's folder).
	for _, u := range []string{"alice", "bob"} {
		if code, raw := fs.adminCall(http.MethodPost, "/admin/users", map[string]any{"username": u, "password": password(u),
			"role": "member"}, nil); code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("create %s: %d %s", u, code, raw)
		}
	}
	alice, err := fs.d.Users.GetByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	ap := &core.Principal{UserID: alice.ID, Username: alice.Username, Role: alice.Role, Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
	spaces, err := fs.d.Files.Spaces(ctx, ap)
	if err != nil || len(spaces) == 0 {
		t.Fatalf("spaces %v %v", spaces, err)
	}
	folder, err := fs.d.Files.Mkdir(ctx, ap, spaces[0].RootID, "public")
	if err != nil {
		t.Fatal(err)
	}
	share, token, err := fs.d.Shares.Create(ctx, ap, core.ShareInput{Kind: core.ShareLink, NodeID: folder.ID, NoExpiry: true})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Enable: FileParcel's entry joins the foreign one, written with If-Match.
	etag := fs.fake.ETag()
	var st core.IngressStatus
	if code, raw := fs.adminCall(http.MethodPut, "/admin/network/funnel", core.FunnelInput{Mode: core.FunnelShares}, nil); code != http.StatusUnprocessableEntity ||
		!strings.Contains(string(raw), "confirm") {
		t.Fatalf("enable without confirmation: %d %s", code, raw)
	}
	if code, raw := fs.adminCall(http.MethodPut, "/admin/network/funnel", core.FunnelInput{Mode: core.FunnelShares, Confirm: "public"}, &st); code != http.StatusOK ||
		st.Funnel.State != core.IngressStateActive || st.Funnel.URL != "https://node.tail.ts.net/" {
		t.Fatalf("enable: %d %s", code, raw)
	}
	sock := filepath.Join(fs.h.RunDir(), "ts-funnel.sock")
	want := `{"TCP":{"443":{"HTTPS":true},"10000":{"HTTPS":true}},"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"unix:` + sock +
		`"}}},"node.tail.ts.net:10000":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}},"AllowFunnel":{"node.tail.ts.net:443":true}}`
	if !sameJSON(t, fs.fake.Config(), want) {
		t.Fatalf("serve config:\n got %s\nwant %s", fs.fake.Config(), want)
	}
	posts := fs.fake.Posts()
	if len(posts) != 1 || posts[0].IfMatch != etag {
		t.Fatalf("writes %+v (etag %s)", posts, etag)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("funnel socket %v %v", fi, err)
	}
	if !fs.d.Ingress.InternetLinks() {
		t.Fatal("share links are not internet links")
	}

	// 2. tailscaled forwards a visitor: the share answers and logs the visitor.
	if code, raw := fs.funnelCall(http.MethodGet, "/s/"+token, nil, nil, nil); code != http.StatusOK || !strings.Contains(string(raw), `id="fp-boot"`) {
		t.Fatalf("share page over funnel: %d %.300s", code, raw)
	}
	var info core.PublicShareInfo
	if code, raw := fs.funnelCall(http.MethodGet, "/s/"+token+"/api", nil, nil, &info); code != http.StatusOK || info.Node == nil {
		t.Fatalf("share API over funnel: %d %s", code, raw)
	}
	log, err := fs.d.Shares.AccessLog(ctx, ap, share.ID, core.PageReq{})
	if err != nil || len(log.Items) == 0 || log.Items[0].IP != "203.0.113.9" {
		t.Fatalf("share access log %+v %v", log.Items, err)
	}

	// 3. A session cookie reaches nothing of the app over Funnel.
	var login core.LoginResult
	code, raw, hdr := call(t, fs.main, http.MethodPost, fs.https+"/api/v1/auth/login", nil,
		map[string]string{"username": "alice", "password": password("alice")}, &login)
	if code != http.StatusOK {
		t.Fatalf("login on the main listener: %d %s", code, raw)
	}
	var cookie string
	for _, c := range (&http.Response{Header: hdr}).Cookies() {
		if c.Name == "__Host-fp_session" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if code, raw, _ := call(t, fs.main, http.MethodGet, fs.https+"/api/v1/me", map[string]string{"Cookie": cookie}, nil, nil); cookie == "" ||
		code != http.StatusOK {
		t.Fatalf("session on the main listener: %d %s", code, raw)
	}
	if code, raw := fs.funnelCall(http.MethodGet, "/api/v1/me", map[string]string{"Cookie": cookie}, nil, nil); code != http.StatusNotFound ||
		!strings.Contains(string(raw), "no such API endpoint") {
		t.Fatalf("/api/v1/me over funnel: %d %s", code, raw)
	}

	// 4. The deny list applies to the visitor's address.
	pol := fs.d.Network.Policy()
	if code, raw := fs.adminCall(http.MethodPut, "/admin/network/policy", core.PolicyInput{Mode: pol.Mode, Allow: pol.Allow,
		Deny: []string{"203.0.113.9"}}, nil); code != http.StatusOK {
		t.Fatalf("deny: %d %s", code, raw)
	}
	if code, _ := fs.funnelCall(http.MethodGet, "/s/"+token, nil, nil, nil); code != http.StatusForbidden {
		t.Fatalf("denied visitor: %d", code)
	}
	if code, raw := fs.adminCall(http.MethodPut, "/admin/network/policy", core.PolicyInput{Mode: pol.Mode, Allow: pol.Allow, Deny: []string{}}, nil); code != http.StatusOK {
		t.Fatalf("undeny: %d %s", code, raw)
	}

	// 5. "app" mode: a password sign-in without 2FA gets the uniform 401 and
	// does not count against the account.
	if code, raw := fs.adminCall(http.MethodPut, "/admin/network/funnel", core.FunnelInput{Mode: core.FunnelApp, Confirm: "public"}, &st); code != http.StatusOK ||
		st.Funnel.Mode != core.FunnelApp {
		t.Fatalf("app mode: %d %s", code, raw)
	}
	codeNo2FA, rawNo2FA := fs.funnelCall(http.MethodPost, "/api/v1/auth/login", nil,
		map[string]string{"username": "bob", "password": password("bob")}, nil)
	codeWrong, rawWrong := fs.funnelCall(http.MethodPost, "/api/v1/auth/login", nil,
		map[string]string{"username": "nobody-here", "password": password("bob")}, nil)
	var e1, e2 httpx.ErrorResponse
	_ = json.Unmarshal(rawNo2FA, &e1)
	_ = json.Unmarshal(rawWrong, &e2)
	if codeNo2FA != http.StatusUnauthorized || codeWrong != codeNo2FA || e1.Error.Code != e2.Error.Code || e1.Error.Message != e2.Error.Message {
		t.Fatalf("sign-in without 2FA over funnel: %d %s (unknown user: %d %s)", codeNo2FA, rawNo2FA, codeWrong, rawWrong)
	}
	bob, err := fs.d.Users.GetByUsername(ctx, "bob")
	if err != nil || bob.FailedLogins != 0 || bob.LockedUntil != nil {
		t.Fatalf("bob after the refused sign-in: %+v %v", bob, err)
	}
	recs, err := fs.d.Audit.Query(ctx, core.AuditQuery{Action: core.ActAuthLogin, Outcome: core.OutcomeDenied})
	found := false
	for _, r := range recs.Items {
		found = found || (r.IP == "203.0.113.9" && strings.Contains(string(r.Details), "funnel_requires_2fa"))
	}
	if err != nil || !found {
		t.Fatalf("no auth.login denied funnel_requires_2fa entry: %+v %v", recs.Items, err)
	}

	// 6. The main listener refuses what a hand-made Funnel forwards to it.
	if code, raw, _ := call(t, fs.main, http.MethodGet, fs.https+"/", map[string]string{"Tailscale-Funnel-Request": "?1"}, nil, nil); code != http.StatusForbidden ||
		!strings.Contains(string(raw), "fileparcel network funnel enable") {
		t.Fatalf("funnel header on the main listener: %d %s", code, raw)
	}

	// 7. Disable: the socket goes, tailscaled is back to what it had.
	if code, raw := fs.adminCall(http.MethodPut, "/admin/network/funnel", core.FunnelInput{Mode: core.FunnelOff}, &st); code != http.StatusOK ||
		st.Funnel.State != core.IngressStateOff {
		t.Fatalf("disable: %d %s", code, raw)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("funnel socket after disable: %v", err)
	}
	if !sameJSON(t, fs.fake.Config(), foreignEntry) {
		t.Fatalf("serve config after disable: %s", fs.fake.Config())
	}
	if fs.d.Ingress.InternetLinks() {
		t.Fatal("internet links after disable")
	}
	var acts []string
	all, _ := fs.d.Audit.Query(ctx, core.AuditQuery{Action: core.ActNetworkFunnel})
	for _, r := range all.Items {
		acts = append(acts, r.Outcome)
	}
	if len(acts) < 3 {
		t.Fatalf("network.funnel audit entries: %v", acts)
	}
}
