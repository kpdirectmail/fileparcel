package opsapi

import (
	"net/netip"
	"testing"
)

func TestAnyInTailnetAndSubnet(t *testing.T) {
	seen := []netip.Addr{netip.MustParseAddr("192.168.1.23"), netip.MustParseAddr("100.101.5.7")}
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	other := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if !anyIn(seen, lan) || anyIn(seen, other) {
		t.Fatal("subnet matching")
	}
	if !anyIn(seen, tailnetRanges) {
		t.Fatal("a tailnet client counts for the tailscale interface")
	}
	if anyIn([]netip.Addr{netip.MustParseAddr("203.0.113.9")}, tailnetRanges) {
		t.Fatal("an internet address is not a tailnet client")
	}
}
