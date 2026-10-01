package core

import (
	"context"
	"net/netip"
	"testing"
)

func TestIPLimitKey(t *testing.T) {
	cases := []struct {
		ip       string
		internet bool
		want     string
	}{
		{"203.0.113.9", true, "203.0.113.9"},
		{"203.0.113.9", false, "203.0.113.9"},
		{"::ffff:203.0.113.9", true, "203.0.113.9"}, // v4-mapped: the IPv4 address
		{"::ffff:192.168.1.5", false, "192.168.1.5"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", true, "2001:db8:1:2::/64"}, // internet IPv6: the /64
		{"2001:db8:1:2::1", true, "2001:db8:1:2::/64"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", false, "2001:db8:1:2:aaaa:bbbb:cccc:dddd"},
		{"fd7a:115c:a1e0::1", false, "fd7a:115c:a1e0::1"}, // tailnet: per address
		{"fe80::1%eth0", false, "fe80::1"},
		{"fe80::1%eth0", true, "fe80::/64"},
	}
	for _, c := range cases {
		if got := IPLimitKey(netip.MustParseAddr(c.ip), c.internet); got != c.want {
			t.Errorf("IPLimitKey(%s, %v) = %q, want %q", c.ip, c.internet, got, c.want)
		}
	}
	// Two addresses of one /64 share the key over the internet only.
	a, b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::ffff:1")
	if IPLimitKey(a, true) != IPLimitKey(b, true) || IPLimitKey(a, false) == IPLimitKey(b, false) {
		t.Fatal("/64 grouping")
	}
	if IPLimitKey(netip.Addr{}, true) != (netip.Addr{}).String() {
		t.Fatal("invalid address")
	}
}

func TestWithIngress(t *testing.T) {
	ctx := context.Background()
	if IngressFrom(ctx) != nil {
		t.Fatal("no ingress on a plain context")
	}
	in := &IngressInfo{Kind: IngressFunnel, ClientIP: netip.MustParseAddr("203.0.113.9"), Public: true, Host: "box.tail.ts.net"}
	ctx = WithIngress(ctx, in)
	if IngressFrom(ctx) != in {
		t.Fatal("IngressFrom")
	}
	// Independent of the principal key.
	ctx = WithPrincipal(ctx, &Principal{UserID: "usr_1"})
	if IngressFrom(ctx) != in || PrincipalFrom(ctx).UserID != "usr_1" {
		t.Fatal("context keys collide")
	}
	if IngressFrom(WithIngress(context.Background(), nil)) != nil {
		t.Fatal("nil ingress")
	}
}
