package netinfo

import (
	"testing"

	"fileparcel/internal/core"
)

func iface(name, kind string, isVPN bool, addrs ...string) core.NetInterface {
	return core.NetInterface{Name: name, Kind: kind, Label: kindLabels[kind], Up: true, Addrs: pfx(addrs...), IsVPN: isVPN}
}

func TestBuildURLs(t *testing.T) {
	ifs := []core.NetInterface{
		iface("lo", core.IfLoopback, false, "127.0.0.1/8", "::1/128"),
		iface("tailscale0", core.IfTailscale, true, "100.64.0.10/32", "fd7a:115c:a1e0::a/128", "fe80::3d4d:caba:3a46:fb51/64"),
		iface("eth2", core.IfLAN, false, "192.168.1.10/24", "2001:db8:f030:b300:393:9548:676a:9ded/64", "fe80::21a6:f0d3:d370:7841/64"),
		iface("docker0", core.IfContainer, false, "172.17.0.1/16"),
		iface("wlan0", core.IfWiFi, false, "169.254.10.10/16"),
	}
	down := iface("eth0", core.IfLAN, false, "10.0.0.5/8")
	down.Up = false
	ifs = append(ifs, down)

	urls := buildURLs(urlInput{
		port: 8443, ifaces: ifs, mdnsName: "fileparcel.local", mdnsPublished: true, sysHost: "fileshare.local",
		magicDNS: "files.tail1234.ts.net", magicKind: core.IfTailscale, magicIface: "tailscale0",
		extra:   []string{"files.example.org", "*.example.org", "10.1.1.1", "fileparcel.local", "bad_host-.x", ""},
		trusted: func(h string) bool { return h == "files.tail1234.ts.net" },
	})
	want := []struct {
		url, kind, iface string
		trusted, rec     bool
	}{
		{"https://files.tail1234.ts.net:8443/", core.URLKindMagicDNS, "tailscale0", true, true},
		{"https://fileparcel.local:8443/", core.URLKindMDNS, "", false, true},
		{"https://fileshare.local:8443/", core.URLKindHostname, "", false, false},
		{"https://192.168.1.10:8443/", core.URLKindIP, "eth2", false, true},
		{"https://[2001:db8:f030:b300:393:9548:676a:9ded]:8443/", core.URLKindIP, "eth2", false, false},
		{"https://100.64.0.10:8443/", core.URLKindIP, "tailscale0", false, false},
		{"https://[fd7a:115c:a1e0::a]:8443/", core.URLKindIP, "tailscale0", false, false},
		{"https://files.example.org:8443/", core.URLKindExtra, "", false, false},
	}
	if len(urls) != len(want) {
		for _, u := range urls {
			t.Logf("%+v", u)
		}
		t.Fatalf("got %d urls, want %d", len(urls), len(want))
	}
	for i, w := range want {
		u := urls[i]
		if u.URL != w.url || u.Kind != w.kind || u.Interface != w.iface || u.Trusted != w.trusted || u.Recommended != w.rec || u.Label == "" {
			t.Errorf("%d: got %+v want %+v", i, u, w)
		}
	}
	if urls[3].Label != "LAN (eth2)" {
		t.Errorf("label %q", urls[3].Label)
	}

	// Public URL first, port 443 omitted, an unpublished mDNS name is not
	// listed at all (nothing answers to it), VPN-only host recommends its
	// first IP.
	in := urlInput{
		port: 443, ifaces: []core.NetInterface{iface("wg0", core.IfWireGuard, true, "10.8.0.1/24")},
		mdnsName: "fp.local", publicURL: "https://files.example.org/base",
	}
	urls = buildURLs(in)
	if len(urls) != 2 || urls[0].Kind != core.URLKindPublic || urls[0].URL != "https://files.example.org/base" || !urls[0].Recommended {
		t.Fatalf("public: %+v", urls)
	}
	if urls[1].URL != "https://10.8.0.1/" || !urls[1].Recommended {
		t.Fatalf("vpn ip: %+v", urls[1])
	}

	// Published: the name is listed, right after the public URL, recommended.
	in.mdnsPublished = true
	urls = buildURLs(in)
	if len(urls) != 3 || urls[1].Kind != core.URLKindMDNS || urls[1].URL != "https://fp.local/" || !urls[1].Recommended {
		t.Fatalf("published mdns: %+v", urls)
	}
	// The system responder's name is listed even when it equals FileParcel's
	// own mDNS name while that one is not published (mdns.mode=off, a failed
	// publication): Avahi/Bonjour still answers it. Once published, the name
	// is listed once, as the mDNS entry.
	lan := []core.NetInterface{iface("eth0", core.IfLAN, false, "192.168.1.10/24")}
	urls = buildURLs(urlInput{port: 8443, ifaces: lan, mdnsName: "fileparcel.local", sysHost: "fileparcel.local"})
	if len(urls) != 2 || urls[0].URL != "https://fileparcel.local:8443/" || urls[0].Kind != core.URLKindHostname ||
		urls[0].Recommended || urls[1].Kind != core.URLKindIP {
		t.Fatalf("unpublished sysHost: %+v", urls)
	}
	urls = buildURLs(urlInput{port: 8443, ifaces: lan, mdnsName: "fileparcel.local", mdnsPublished: true, sysHost: "fileparcel.local"})
	if len(urls) != 2 || urls[0].URL != "https://fileparcel.local:8443/" || urls[0].Kind != core.URLKindMDNS ||
		!urls[0].Recommended || urls[1].Kind != core.URLKindIP {
		t.Fatalf("published sysHost: %+v", urls)
	}
	if got := buildURLs(urlInput{port: 8443}); got == nil || len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
	if hostPort("::1", 443) != "[::1]" || hostPort("a.local", 8443) != "a.local:8443" || hostPort("fe80::1", 8443) != "[fe80::1]:8443" {
		t.Fatal("hostPort")
	}
}

func TestValidDNSName(t *testing.T) {
	for s, want := range map[string]bool{
		"fileparcel.local": true, "a": true, "*.example.org": false, "-a.b": false, "a-.b": false, "a..b": false,
		"xn--bcher-kva.example": true, "a b": false, "": false,
	} {
		if got := validDNSName(s, false); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
	if !validDNSName("*.example.org", true) || validDNSName("*.*.example.org", true) {
		t.Fatal("wildcard")
	}
}
