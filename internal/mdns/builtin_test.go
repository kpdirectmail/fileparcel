package mdns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"fileparcel/internal/core"
)

func loopbackIface(t *testing.T) net.Interface {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 && ifc.Flags&net.FlagUp != 0 {
			return ifc
		}
	}
	t.Skip("no loopback interface")
	return net.Interface{}
}

func randLabel(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// mdnsQuery sends a legacy (non-5353 source port) multicast query on the
// loopback interface and returns the first response that satisfies ok.
// Legacy queries are answered by unicast to the source (RFC 6762 §6.7).
func mdnsQuery(t *testing.T, lo net.Interface, name string, typ dnsmessage.Type, ok func(*dnsmessage.Message) bool) *dnsmessage.Message {
	return mdnsQueryFor(t, lo, name, typ, 4*time.Second, ok)
}

func mdnsQueryFor(t *testing.T, lo net.Interface, name string, typ dnsmessage.Type, wait time.Duration, ok func(*dnsmessage.Message) bool) *dnsmessage.Message {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pc := ipv4.NewPacketConn(c)
	if err := pc.SetMulticastInterface(&lo); err != nil {
		t.Skipf("multicast on loopback unsupported: %v", err)
	}
	_ = pc.SetMulticastLoopback(true)
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}
	pkt, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}
	buf := make([]byte, 9000)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if _, err := pc.WriteTo(pkt, nil, dst); err != nil {
			t.Fatalf("send query: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				break
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || !m.Response {
				continue
			}
			if ok(&m) {
				return &m
			}
		}
	}
	return nil
}

func TestBuiltinResponderLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("binds UDP 5353")
	}
	lo := loopbackIface(t)
	host := randLabel("fptest-")
	events := make(chan backendEvent, 4)
	b := newBuiltinBackend(slog.Default(), func(ev backendEvent) { events <- ev })
	b.probe = false
	p := publication{
		Host: host, Instance: "FileParcel test " + host[len(host)-8:], Port: 9443, TXT: []string{"path=/", "fp=1"},
		Ifaces:   []ifaceAddrs{{Name: lo.Name, Index: lo.Index, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}},
		Loopback: true,
	}
	if err := b.publish(context.Background(), 7, p); err != nil {
		t.Skipf("cannot start the builtin responder here: %v", err)
	}
	defer b.close()
	select {
	case ev := <-events:
		if ev.gen != 7 || ev.state != core.MDNSPublished {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no published event")
	}
	fqdn := host + ".local."

	// A record.
	m := mdnsQuery(t, lo, fqdn, dnsmessage.TypeA, func(m *dnsmessage.Message) bool {
		for _, a := range m.Answers {
			if a.Header.Type == dnsmessage.TypeA && strings.EqualFold(a.Header.Name.String(), fqdn) {
				return true
			}
		}
		return false
	})
	if m == nil {
		t.Fatalf("no A answer for %s", fqdn)
	}
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok && netip.AddrFrom4(r.A).String() != "127.0.0.1" {
			t.Fatalf("A = %v", netip.AddrFrom4(r.A))
		}
	}

	// PTR _https._tcp.local → our instance, with SRV/TXT/A as additionals.
	instFQDN := ""
	m = mdnsQuery(t, lo, "_https._tcp.local.", dnsmessage.TypePTR, func(m *dnsmessage.Message) bool {
		for _, a := range m.Answers {
			if r, ok := a.Body.(*dnsmessage.PTRResource); ok && strings.Contains(r.PTR.String(), host[len(host)-8:]) {
				instFQDN = r.PTR.String()
				return true
			}
		}
		return false
	})
	if m == nil {
		t.Fatal("no PTR answer for _https._tcp.local")
	}
	var srv *dnsmessage.SRVResource
	var txt *dnsmessage.TXTResource
	for _, r := range append(m.Answers, m.Additionals...) {
		switch body := r.Body.(type) {
		case *dnsmessage.SRVResource:
			srv = body
		case *dnsmessage.TXTResource:
			txt = body
		}
	}
	if srv == nil || srv.Port != 9443 || !strings.EqualFold(srv.Target.String(), fqdn) {
		t.Fatalf("SRV %+v (instance %s)", srv, instFQDN)
	}
	if txt == nil || strings.Join(txt.TXT, ",") != "path=/,fp=1" {
		t.Fatalf("TXT %+v", txt)
	}

	// SRV asked directly for the instance.
	m = mdnsQuery(t, lo, instFQDN, dnsmessage.TypeSRV, func(m *dnsmessage.Message) bool {
		for _, a := range m.Answers {
			if s, ok := a.Body.(*dnsmessage.SRVResource); ok && s.Port == 9443 {
				return true
			}
		}
		return false
	})
	if m == nil {
		t.Fatalf("no SRV answer for %s", instFQDN)
	}

	// After unpublish the name is no longer answered.
	b.unpublish()
	if m := mdnsQueryFor(t, lo, fqdn, dnsmessage.TypeA, time.Second, func(m *dnsmessage.Message) bool { return len(m.Answers) > 0 }); m != nil {
		t.Fatal("still answering after unpublish")
	}
}

func TestBuiltinProbeDetectsCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("binds UDP 5353")
	}
	lo := loopbackIface(t)
	host := randLabel("fpcoll-")
	loIf := func(addr string) []ifaceAddrs {
		return []ifaceAddrs{{Name: lo.Name, Index: lo.Index, Addrs: []netip.Addr{netip.MustParseAddr(addr)}}}
	}
	// "Another host" answers for the name with an address that is not ours.
	other := newBuiltinBackend(slog.Default(), func(backendEvent) {})
	other.probe = false
	if err := other.publish(context.Background(), 1, publication{Host: host, Instance: "Other " + host, Port: 443,
		Ifaces: loIf("192.0.2.10"), Loopback: true}); err != nil {
		t.Skipf("cannot start the builtin responder here: %v", err)
	}
	defer other.close()

	ours := newBuiltinBackend(slog.Default(), func(backendEvent) {})
	defer ours.close()
	err := ours.publish(context.Background(), 1, publication{Host: host, Instance: "Ours " + host, Port: 8443,
		Ifaces: loIf("127.0.0.1"), Loopback: true})
	if err != errCollision {
		t.Fatalf("probe: got %v, want errCollision", err)
	}
	// A free name passes the probe and is published.
	if err := ours.publish(context.Background(), 2, publication{Host: host + "-2", Instance: "Ours " + host, Port: 8443,
		Ifaces: loIf("127.0.0.1"), Loopback: true}); err != nil {
		t.Fatal(err)
	}
}

// A second responder answering our service instance with another port or
// target (another FileParcel on this machine) is an instance collision, not
// a host one: only the instance is renamed and <name>.local is kept.
func TestBuiltinProbeDetectsInstanceCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("binds UDP 5353")
	}
	lo := loopbackIface(t)
	hostA, hostB := randLabel("fpinsta-"), randLabel("fpinstb-")
	inst := "FileParcel on " + randLabel("box")
	loIf := []ifaceAddrs{{Name: lo.Name, Index: lo.Index, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}
	other := newBuiltinBackend(slog.Default(), func(backendEvent) {})
	other.probe = false
	if err := other.publish(context.Background(), 1, publication{Host: hostA, Instance: inst, Port: 443,
		TXT: []string{"path=/"}, Ifaces: loIf, Loopback: true}); err != nil {
		t.Skipf("cannot start the builtin responder here: %v", err)
	}
	defer other.close()

	ours := newBuiltinBackend(slog.Default(), func(backendEvent) {})
	defer ours.close()
	for _, host := range []string{hostB, hostA} { // another host label; the same one (same machine, same name)
		err := ours.publish(context.Background(), 1, publication{Host: host, Instance: inst, Port: 8443,
			TXT: []string{"path=/"}, Ifaces: loIf, Loopback: true})
		if !errors.Is(err, errInstanceCollision) {
			t.Fatalf("%s: got %v, want errInstanceCollision", host, err)
		}
	}
	// The renamed instance is free.
	if err := ours.publish(context.Background(), 2, publication{Host: hostB, Instance: instanceName(inst, 2), Port: 8443,
		TXT: []string{"path=/"}, Ifaces: loIf, Loopback: true}); err != nil {
		t.Fatal(err)
	}
	ours.unpublish()
	// The same instance, port and target is a stale record of ours, not a clash.
	if err := ours.publish(context.Background(), 3, publication{Host: hostA, Instance: inst, Port: 443,
		TXT: []string{"path=/"}, Ifaces: loIf, Loopback: true}); err != nil {
		t.Fatalf("own record: %v", err)
	}
}
