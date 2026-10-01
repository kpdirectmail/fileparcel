package netinfo

import (
	"context"
	"net/netip"
	"testing"
)

func TestIsLocal(t *testing.T) {
	env, _ := testEnv(t)
	s := newTestService(t, env, &fakeSource{list: hostList()}, "")
	ip := netip.MustParseAddr
	// Before the first snapshot only loopback is known (never blocks).
	if !s.IsLocal(ip("127.0.0.1")) || !s.IsLocal(ip("::1")) || !s.IsLocal(ip("127.8.9.10")) || s.IsLocal(ip("192.168.1.10")) {
		t.Fatal("before the first snapshot")
	}
	s.refresh(context.Background(), false, false)
	for addr, want := range map[string]bool{
		"192.168.1.10": true, "::ffff:192.168.1.10": true, "2001:db8:f030:b300::6": true,
		"fe80::21a6:f0d3:d370:7841%eth2": true, "100.64.0.10": true, "172.17.0.1": true, // any interface, containers too
		"192.168.1.7": false, "8.8.8.8": false, "100.81.123.14": false,
	} {
		if got := s.IsLocal(ip(addr)); got != want {
			t.Errorf("IsLocal(%s) = %v", addr, got)
		}
	}
	if s.IsLocal(netip.Addr{}) {
		t.Fatal("invalid address")
	}
}
