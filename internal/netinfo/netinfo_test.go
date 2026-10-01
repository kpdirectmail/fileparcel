package netinfo

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/tslocal"
)

// fakeSource is a mutable interface list.
type fakeSource struct {
	mu   sync.Mutex
	list []rawIface
}

func (f *fakeSource) get() ([]rawIface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.list), nil
}

func (f *fakeSource) set(l []rawIface) {
	f.mu.Lock()
	f.list = l
	f.mu.Unlock()
}

func hostList() []rawIface {
	return []rawIface{
		{Name: "lo", Index: 1, Flags: net.FlagUp | net.FlagLoopback, MTU: 65536, Addrs: pfx("127.0.0.1/8", "::1/128")},
		{Name: "eth0", Index: 2, Flags: net.FlagBroadcast | net.FlagMulticast, MTU: 1500},
		{Name: "eth2", Index: 4, Flags: up, MTU: 1500, Addrs: pfx("192.168.1.10/24", "2001:db8:f030:b300::6/64", "fe80::21a6:f0d3:d370:7841/64")},
		{Name: "wlan0", Index: 6, Flags: up, MTU: 1500, Wireless: true},
		{Name: "tailscale0", Index: 7, Flags: net.FlagUp | net.FlagPointToPoint | net.FlagMulticast, MTU: 1280,
			Addrs: pfx("100.64.0.10/32", "fd7a:115c:a1e0::a/128", "fe80::3d4d:caba:3a46:fb51/64")},
		{Name: "docker0", Index: 8, Flags: up, MTU: 1500, Addrs: pfx("172.17.0.1/16")},
	}
}

// fakeCerts reports every name ending in .ts.net as publicly trusted.
type fakeCerts struct{ core.Certs }

func (fakeCerts) PubliclyTrusted(name string) bool {
	return len(name) > 7 && name[len(name)-7:] == ".ts.net"
}

func newTestService(t *testing.T, env *core.Env, src *fakeSource, tsSock string) *Service {
	t.Helper()
	s, err := New(env)
	if err != nil {
		t.Fatal(err)
	}
	s.goos = "linux"
	s.source = src.get
	s.ts.tl = &tslocal.Client{}
	if tsSock != "" {
		s.ts.tl.Sockets = []string{tsSock}
	}
	s.ts.mayConfigure = func(*tslocal.Prefs) bool { return false }
	// No host probes: the classification must not depend on this machine's
	// routes, binaries or processes.
	s.probe = &hostProbe{}
	s.cloudflared = nil
	s.sysHost.lookup = func(context.Context) string { return "FileShare.local." }
	s.hostname = func() (string, error) { return "Null", nil }
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestServiceInterfacesAndNames(t *testing.T) {
	env, _ := testEnv(t)
	src := &fakeSource{list: hostList()}
	s := newTestService(t, env, src, fakeLocalAPI(t, "https://hs.example.org", "", nil))
	ctx := context.Background()

	ifs, err := s.Interfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, ni := range ifs {
		kinds[ni.Name] = ni.Kind
		if ni.Addrs == nil {
			t.Errorf("%s: nil addrs", ni.Name)
		}
	}
	want := map[string]string{"lo": core.IfLoopback, "eth0": core.IfLAN, "eth2": core.IfLAN, "wlan0": core.IfWiFi,
		"tailscale0": core.IfHeadscale, "docker0": core.IfContainer}
	for n, k := range want {
		if kinds[n] != k {
			t.Errorf("%s: %s want %s", n, kinds[n], k)
		}
	}

	ips := s.IPs()
	wantIPs := []string{"192.168.1.10", "2001:db8:f030:b300::6", "100.64.0.10", "fd7a:115c:a1e0::a"}
	var got []string
	for _, a := range ips {
		got = append(got, a.String())
	}
	if !slices.Equal(got, wantIPs) {
		t.Fatalf("IPs %v", got)
	}

	names := s.Hostnames()
	wantNames := []string{"fileparcel.local", "fileshare.local", "null", "null.local", "files.tail1234.ts.net"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("Hostnames %v", names)
	}
	info, err := s.Tailscale(ctx)
	if err != nil || info.Kind != core.IfHeadscale || !info.Running {
		t.Fatalf("tailscale %+v %v", info, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Tailscale(cctx); err == nil {
		t.Fatal("cancelled ctx")
	}
}

func TestServiceURLsFollowMDNSAndSettings(t *testing.T) {
	env, _ := testEnv(t)
	cfg := config.Default(config.NewInstallID())
	cfg.Server.HTTPSPort = 9443
	env.Config = cfg
	src := &fakeSource{list: hostList()}
	s := newTestService(t, env, src, fakeLocalAPI(t, "https://controlplane.tailscale.com", "", nil))
	if err := s.Bind(&core.Services{Certs: fakeCerts{}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	urls, err := s.URLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string]core.AccessURL{}
	for _, u := range urls {
		if _, dup := byKind[u.Kind]; !dup {
			byKind[u.Kind] = u
		}
	}
	if u := byKind[core.URLKindMagicDNS]; u.URL != "https://files.tail1234.ts.net:9443/" || !u.Trusted || !u.Recommended || u.Interface != "tailscale0" {
		t.Fatalf("magicdns %+v", u)
	}
	if u, ok := byKind[core.URLKindMDNS]; ok {
		t.Fatalf("mdns listed before it is published: %+v", u)
	}
	if u := byKind[core.URLKindHostname]; u.URL != "https://fileshare.local:9443/" {
		t.Fatalf("hostname %+v", u)
	}

	// mdns.changed with a collision-renamed, published name.
	env.Bus.Publish(events.Event{Topic: events.TopicMDNSChanged, Data: core.MDNSStatus{Name: "fileparcel-2.local", State: core.MDNSPublished, Backend: "avahi"}})
	waitFor(t, func() bool {
		urls, _ := s.URLs(ctx)
		for _, u := range urls {
			if u.Kind == core.URLKindMDNS {
				return u.URL == "https://fileparcel-2.local:9443/" && u.Recommended
			}
		}
		return false
	})
	if n := s.Hostnames(); n[0] != "fileparcel-2.local" || !slices.Contains(n, "fileparcel.local") {
		t.Fatalf("hostnames after mdns.changed %v", n)
	}

	// server.public_url and tls.extra_sans / extra hosts.
	_, err = env.Settings.Set(ctx, nil, map[string]json.RawMessage{KeyExtraHosts: json.RawMessage(`["files.lan","*.lan"]`)})
	if err != nil {
		t.Fatal(err)
	}
	urls, _ = s.URLs(ctx)
	if urls[len(urls)-1].URL != "https://files.lan:9443/" || urls[len(urls)-1].Kind != core.URLKindExtra {
		t.Fatalf("extra: %+v", urls[len(urls)-1])
	}
	if n := s.Hostnames(); !slices.Contains(n, "files.lan") || !slices.Contains(n, "*.lan") {
		t.Fatalf("extra hosts in SAN names: %v", n)
	}
}

func TestNetworkChangedPublishing(t *testing.T) {
	env, _ := testEnv(t)
	src := &fakeSource{list: hostList()}
	s := newTestService(t, env, src, "")
	s.poll = 20 * time.Millisecond
	ch, unsub := env.Bus.Subscribe(events.TopicNetworkChanged)
	defer unsub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	// No change -> no event.
	select {
	case e := <-ch:
		t.Fatalf("unexpected %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
	// Changes on a container interface or a down interface are ignored.
	l := hostList()
	l[5].Addrs = pfx("172.18.0.1/16")
	l[1].Addrs = pfx("10.9.9.9/8")
	src.set(l)
	select {
	case e := <-ch:
		t.Fatalf("unexpected %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
	// A new LAN address is published once.
	l = hostList()
	l[5].Addrs = pfx("172.18.0.1/16")
	l[1].Addrs = pfx("10.9.9.9/8")
	l[3].Addrs = pfx("192.168.50.2/24")
	src.set(l)
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("network.changed not published")
	}
	select {
	case e := <-ch:
		t.Fatalf("published twice: %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
	if !slices.Contains(s.IPs(), netip.MustParseAddr("192.168.50.2")) {
		t.Fatal("snapshot not updated")
	}
	// network.extra_hosts changes the SAN names -> network.changed.
	if _, err := env.Settings.Set(ctx, nil, map[string]json.RawMessage{KeyExtraHosts: json.RawMessage(`["nas.home.arpa"]`)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("network.changed not published for extra hosts")
	}
	// mdns.changed never triggers network.changed (mdns republishes on it).
	env.Bus.Publish(events.Event{Topic: events.TopicMDNSChanged, Data: &core.MDNSStatus{Name: "x-2.local", State: core.MDNSPublished}})
	select {
	case e := <-ch:
		t.Fatalf("loop risk: %+v", e)
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// A failed first enumeration is reported by Interfaces (so `fileparcel init`
// warns instead of silently storing a loopback-only allow list); names and
// URLs keep working, and a later success clears the error.
func TestInterfacesReportEnumerationFailure(t *testing.T) {
	env, _ := testEnv(t)
	src := &fakeSource{list: hostList()}
	s := newTestService(t, env, src, "")
	boom := errors.New("netlinkrib: permission denied")
	s.source = func() ([]rawIface, error) { return nil, boom }
	ctx := context.Background()
	if ifs, err := s.Interfaces(ctx); !errors.Is(err, boom) || ifs != nil {
		t.Fatalf("Interfaces = %v, %v", ifs, err)
	}
	if urls, err := s.URLs(ctx); err != nil || urls == nil {
		t.Fatalf("URLs = %v, %v", urls, err)
	}
	if !slices.Contains(s.Hostnames(), "fileshare.local") {
		t.Fatalf("Hostnames %v", s.Hostnames())
	}
	s.source = src.get
	ifs, err := s.Interfaces(ctx)
	if err != nil || len(ifs) != len(hostList()) {
		t.Fatalf("after recovery: %v, %v", ifs, err)
	}
	// Once a list was read, a failing enumeration keeps serving it.
	s.source = func() ([]rawIface, error) { return nil, boom }
	if ifs, err := s.Interfaces(ctx); err != nil || len(ifs) != len(hostList()) {
		t.Fatalf("stale: %v, %v", ifs, err)
	}
}

// A tailscaled that stops answering keeps the MagicDNS name in the SAN names
// (no network.changed, no leaf reissue without it) during tsGrace.
func TestTailscaleFailureKeepsMagicDNSName(t *testing.T) {
	env, _ := testEnv(t)
	src := &fakeSource{list: hostList()}
	s := newTestService(t, env, src, fakeLocalAPI(t, "https://controlplane.tailscale.com", "", nil))
	now := time.Unix(1000, 0)
	s.ts.now = func() time.Time { return now }
	ctx := context.Background()
	before := s.refresh(ctx, false, false)
	if !slices.Contains(s.Hostnames(), "files.tail1234.ts.net") {
		t.Fatalf("Hostnames %v", s.Hostnames())
	}
	s.ts.tl = &tslocal.Client{Sockets: []string{"/nonexistent/ts.sock"}}
	now = now.Add(tsCacheTTL + time.Second)
	after := s.refresh(ctx, false, false)
	if after.ts.Running || after.ts.Error == "" {
		t.Fatalf("failure not reported: %+v", after.ts)
	}
	if after.fp != before.fp || !slices.Contains(s.Hostnames(), "files.tail1234.ts.net") {
		t.Fatalf("MagicDNS name dropped: %v", s.Hostnames())
	}
}

func TestCloseWithoutStartAndNilEnv(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !s.Allowed(netip.MustParseAddr("::ffff:127.0.0.1")) || s.Allowed(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("default policy must be loopback only")
	}
	if p := s.Policy(); p.Mode != core.AccessAllowlist || p.Allow == nil || p.Deny == nil {
		t.Fatalf("%+v", p)
	}
	if _, err := s.SetPolicy(context.Background(), nil, core.AccessPolicy{Mode: "any"}, netip.Addr{}, false); err == nil {
		t.Fatal("SetPolicy without settings must fail")
	}
}

func TestSystemInterfaces(t *testing.T) {
	l, err := systemInterfaces()
	if err != nil {
		t.Skip(err)
	}
	var lo bool
	for _, r := range l {
		if r.Flags&net.FlagLoopback != 0 {
			lo = true
			for _, p := range r.Addrs {
				if !p.IsValid() || p.Addr().Zone() != "" {
					t.Errorf("bad prefix %v", p)
				}
			}
		}
	}
	if !lo {
		t.Skip("no loopback interface")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fakeMDNS is a bound mDNS service whose status the test drives.
type fakeMDNS struct {
	core.MDNS
	mu sync.Mutex
	st core.MDNSStatus
}

func (m *fakeMDNS) set(st core.MDNSStatus) {
	m.mu.Lock()
	m.st = st
	m.mu.Unlock()
}

func (m *fakeMDNS) Status() core.MDNSStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st
}

// TestURLsFollowTheBoundMDNSService: with the mDNS service bound, URLs and
// Hostnames read its status directly instead of waiting for mdns.changed to
// be delivered — the startup banner asks for the URLs the moment publishing
// settles, and a scheduling tick of lag would drop the .local name from it.
func TestURLsFollowTheBoundMDNSService(t *testing.T) {
	env, _ := testEnv(t)
	cfg := config.Default(config.NewInstallID())
	cfg.Server.HTTPSPort = 9443
	env.Config = cfg
	s := newTestService(t, env, &fakeSource{list: hostList()}, "")
	m := &fakeMDNS{st: core.MDNSStatus{Mode: "auto", State: core.MDNSPublishing, Name: "fileparcel.local"}}
	if err := s.Bind(&core.Services{Certs: fakeCerts{}, MDNS: m}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	mdnsURL := func() (core.AccessURL, bool) {
		t.Helper()
		urls, err := s.URLs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range urls {
			if u.Kind == core.URLKindMDNS {
				return u, true
			}
		}
		return core.AccessURL{}, false
	}

	if u, ok := mdnsURL(); ok {
		t.Fatalf("listed while still publishing: %+v", u)
	}
	// Published under a collision-renamed name, with no event at all.
	m.set(core.MDNSStatus{Mode: "auto", Backend: "avahi", State: core.MDNSPublished, Name: "fileparcel-3.local"})
	u, ok := mdnsURL()
	if !ok || u.URL != "https://fileparcel-3.local:9443/" || !u.Recommended {
		t.Fatalf("after publish: %+v (listed %v)", u, ok)
	}
	// The published name leads, but the CONFIGURED <name>.local stays in the
	// SAN names: a rename (an mDNS service-instance clash used to cause one)
	// must never drop it from the leaf, or the configured URL stops working
	// and the WebAuthn RP ID falls outside the certificate.
	n := s.Hostnames()
	if n[0] != "fileparcel-3.local" || !slices.Contains(n, "fileparcel.local") {
		t.Fatalf("hostnames %v", n)
	}
	// Publishing switched off: the name is not advertised any more.
	m.set(core.MDNSStatus{Mode: "off", State: core.MDNSOff, Name: "fileparcel.local"})
	if u, ok := mdnsURL(); ok {
		t.Fatalf("listed with mdns.mode=off: %+v", u)
	}
}

// fakeIngressURLs is a core.Ingress that only reports access URLs.
type fakeIngressURLs struct {
	core.Ingress
	urls []core.AccessURL
}

func (f fakeIngressURLs) AccessURLs() []core.AccessURL { return f.urls }

// TestURLsIncludeTheIngressAddresses: with the Funnel/Serve service bound,
// its published addresses (Serve, Funnel in app mode) follow the public URL
// and come before MagicDNS; nothing is added while it reports none.
func TestURLsIncludeTheIngressAddresses(t *testing.T) {
	env, _ := testEnv(t)
	s := newTestService(t, env, &fakeSource{list: hostList()}, "")
	ctx := context.Background()
	before, err := s.URLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Bind(&core.Services{Ingress: fakeIngressURLs{}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.URLs(ctx); !slices.Equal(got, before) {
		t.Fatalf("an idle ingress changed the URLs:\n%v\n%v", got, before)
	}
	serve := core.AccessURL{URL: "https://node.tail.ts.net/", Kind: core.URLKindTailscaleServe,
		Label: "Tailscale Serve (tailnet, no port)", Trusted: true, Recommended: true}
	funnel := core.AccessURL{URL: "https://node.tail.ts.net:8443/", Kind: core.URLKindFunnel,
		Label: "Internet (Tailscale Funnel)", Trusted: true}
	if err := s.Bind(&core.Services{Ingress: fakeIngressURLs{urls: []core.AccessURL{funnel, serve}}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.URLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(before)+2 || got[0] != funnel || got[1] != serve || !slices.Equal(got[2:], before) {
		t.Fatalf("urls %v", got)
	}
}
