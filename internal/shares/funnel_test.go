package shares

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ratelimit"
)

// Share links and passwords over Tailscale Funnel (DESIGN §10.6).

// baseIngress is the part of core.Ingress that shares uses.
type baseIngress struct {
	core.Ingress
	base string
}

func (i *baseIngress) PublicBaseURL() string { return i.base }

func TestLinksUseTheFunnelAddress(t *testing.T) {
	f := setup(t)
	ing := &baseIngress{}
	if err := f.svc.Bind(&core.Services{Notify: f.Notify, Uploads: f.uploads, Ingress: ing}); err != nil {
		t.Fatal(err)
	}
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	link := func(s *core.Share) string {
		t.Helper()
		got, err := f.svc.Get(f.ctx, alice, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.URL
	}
	// Funnel not active: relative.
	s, tok := f.create(alice, core.ShareInput{NodeID: file.ID})
	if s.URL != "/s/"+tok || link(s) != "/s/"+tok {
		t.Fatalf("relative link %q %q", s.URL, link(s))
	}
	// Funnel active: the internet address (also for a new link).
	ing.base = "https://node.tail.ts.net"
	if got := link(s); got != "https://node.tail.ts.net/s/"+tok {
		t.Fatalf("funnel link %q", got)
	}
	s2, tok2 := f.create(alice, core.ShareInput{NodeID: file.ID})
	if s2.URL != "https://node.tail.ts.net/s/"+tok2 {
		t.Fatalf("new funnel link %q", s2.URL)
	}
	ing.base = "https://node.tail.ts.net:8443/"
	if got := link(s); got != "https://node.tail.ts.net:8443/s/"+tok {
		t.Fatalf("funnel link with a port %q", got)
	}
	// server.public_url wins.
	f.Env.Env.Config.Server.PublicURL = "https://files.example.test"
	defer func() { f.Env.Env.Config.Server.PublicURL = "" }()
	if got := link(s); got != "https://files.example.test/s/"+tok {
		t.Fatalf("public_url link %q", got)
	}
}

func TestFunnelSharePasswordLimits(t *testing.T) {
	f := setup(t)
	f.Limiter.Configure(ratelimit.BucketShare, 1000, 1000)
	f.Settings.Put("ratelimit.login_per_min", 1000)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	_, tok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "open sesame"})
	s, _, _ := f.svc.Resolve(f.ctx, tok)
	funnel := func(i int) core.ReqMeta {
		return core.ReqMeta{IP: netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), Ingress: core.IngressFunnel}
	}
	lan := core.ReqMeta{IP: netip.MustParseAddr("192.168.1.20")}
	// Right passwords never use the Funnel bucket up.
	for i := range 30 {
		if err := f.svc.CheckPassword(f.ctx, s, "open sesame", funnel(i)); err != nil {
			t.Fatalf("visitor %d: %v", i, err)
		}
	}
	// 20 wrong ones from the internet (all from different addresses) ...
	for i := range ratelimit.FunnelSharePWBurst {
		wantCode(t, f.svc.CheckPassword(f.ctx, s, "guess", funnel(100+i)), core.ErrUnauthorized)
	}
	// ... block the share's password over Funnel, without a verification.
	verified := 0
	verify := f.svc.verifyPassword
	f.svc.verifyPassword = func(ctx context.Context, phc, pw string) (bool, bool, error) {
		verified++
		return verify(ctx, phc, pw)
	}
	wantCode(t, f.svc.CheckPassword(f.ctx, s, "open sesame", funnel(200)), core.ErrRateLimited)
	if verified != 0 {
		t.Fatal("a refused attempt ran the password verification")
	}
	// The LAN and the tailnet are unaffected, and so is another share.
	if err := f.svc.CheckPassword(f.ctx, s, "open sesame", lan); err != nil {
		t.Fatalf("LAN visitor: %v", err)
	}
	_, tok2 := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "another one"})
	s2, _, _ := f.svc.Resolve(f.ctx, tok2)
	if err := f.svc.CheckPassword(f.ctx, s2, "another one", funnel(200)); err != nil {
		t.Fatalf("other share: %v", err)
	}
	// 20 an hour come back.
	f.Clock.Advance(4 * time.Minute)
	if err := f.svc.CheckPassword(f.ctx, s, "open sesame", funnel(200)); err != nil {
		t.Fatalf("after a few minutes: %v", err)
	}
}

// Over Funnel an IPv6 client is limited per /64; on the LAN per address.
func TestFunnelSharePasswordPerPrefix(t *testing.T) {
	f := setup(t)
	f.Limiter.Configure(ratelimit.BucketShare, 1000, 1000)
	f.Settings.Put("ratelimit.login_per_min", 3)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	_, tok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "open sesame"})
	s, _, _ := f.svc.Resolve(f.ctx, tok)
	v6 := func(last byte, ingress string) core.ReqMeta {
		return core.ReqMeta{IP: netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 15: last}), Ingress: ingress}
	}
	for i := range 3 {
		wantCode(t, f.svc.CheckPassword(f.ctx, s, "nope", v6(byte(i+1), core.IngressFunnel)), core.ErrUnauthorized)
	}
	wantCode(t, f.svc.CheckPassword(f.ctx, s, "open sesame", v6(9, core.IngressFunnel)), core.ErrRateLimited)
	// The same addresses over the LAN (or Serve) are separate clients.
	if err := f.svc.CheckPassword(f.ctx, s, "open sesame", v6(9, "")); err != nil {
		t.Fatalf("LAN: %v", err)
	}
	if err := f.svc.CheckPassword(f.ctx, s, "open sesame", v6(10, core.IngressServe)); err != nil {
		t.Fatalf("serve: %v", err)
	}
	// The access log keeps the full address.
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ? AND ip = ?`, s.ID, v6(9, "").IP.String()); n < 2 {
		t.Fatalf("access log rows for the client = %d", n)
	}
}

func TestIsPublicCookie(t *testing.T) {
	for name, want := range map[string]bool{
		CookieName("shr_01j0000000000000abcdefgh"): true,
		VisitorCookiePrefix + "abcdefgh":           true,
		"__Host-fp_session":                        false,
		"__Host-fp_s":                              false,
		"fp_s_abcdefgh":                            false,
		"__host-fp_s_abcdefgh":                     false,
		"theme":                                    false,
		"":                                         false,
	} {
		if got := IsPublicCookie(name); got != want {
			t.Errorf("IsPublicCookie(%q) = %v", name, got)
		}
	}
}
