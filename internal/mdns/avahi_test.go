package mdns

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/settings"
)

// Avahi integration tests talk to the host's avahi-daemon over the system
// D-Bus. They only run with FILEPARCEL_TEST_AVAHI=1 and publish short-lived,
// randomly named records that are withdrawn at the end.

func requireAvahi(t *testing.T) {
	t.Helper()
	if os.Getenv("FILEPARCEL_TEST_AVAHI") != "1" {
		t.Skip("set FILEPARCEL_TEST_AVAHI=1 to run the Avahi integration test")
	}
	if !avahiAvailable(context.Background()) {
		t.Fatal("FILEPARCEL_TEST_AVAHI=1 but avahi-daemon is not on the system bus")
	}
}

// lanIPv4 returns an up, non-loopback interface with a private IPv4 address.
func lanIPv4(t *testing.T) (net.Interface, netip.Addr) {
	t.Helper()
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagMulticast == 0 ||
			strings.HasPrefix(ifc.Name, "tailscale") || strings.HasPrefix(ifc.Name, "docker") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() && ip.Unmap().IsPrivate() {
					return ifc, ip.Unmap()
				}
			}
		}
	}
	t.Skip("no LAN interface with a private IPv4 address")
	return net.Interface{}, netip.Addr{}
}

// getentHosts resolves name through NSS (nss-mdns → avahi-daemon).
func getentHosts(name string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "hosts", name).Output()
	return strings.TrimSpace(string(out)), err == nil
}

func waitGetent(t *testing.T, name string, want bool) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, ok := getentHosts(name)
		if ok == want {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("getent hosts %s: resolved=%v (%q), want %v", name, ok, out, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// resolveService asks avahi-daemon to resolve our service instance.
func resolveService(t *testing.T, instance string) (host string, port uint16, txt [][]byte) {
	t.Helper()
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var (
		iface, proto, aproto int32
		name, typ, domain    string
		addr                 string
		flags                uint32
	)
	call := conn.Object(avahiName, "/").Call(avahiServerIface+".ResolveService", 0, avahiIfUnspec, avahiProtoUnspec,
		instance, ServiceType, "local", avahiProtoUnspec, uint32(0))
	if call.Err != nil {
		t.Fatalf("ResolveService: %v", call.Err)
	}
	if err := call.Store(&iface, &proto, &name, &typ, &domain, &host, &aproto, &addr, &port, &txt, &flags); err != nil {
		t.Fatal(err)
	}
	return host, port, txt
}

// TestAvahiWatchAttributesCollisions covers the signal watcher without a
// D-Bus connection: the address records and the DNS-SD service live in
// separate entry groups precisely so an asynchronous COLLISION can be
// attributed. A conflict on the service group must never rename
// <name>.local (and with it the certificate SANs and the WebAuthn RP ID).
func TestAvahiWatchAttributesCollisions(t *testing.T) {
	const addr, svc = dbus.ObjectPath("/Client1/EntryGroup1"), dbus.ObjectPath("/Client1/EntryGroup2")
	evs := make(chan backendEvent, 16)
	b := &avahiBackend{log: slog.New(slog.DiscardHandler), emit: func(ev backendEvent) { evs <- ev }}
	sigs := make(chan *dbus.Signal, 16)
	b.wg.Add(1)
	go b.watch(sigs)
	defer func() { close(sigs); b.wg.Wait() }()
	send := func(path dbus.ObjectPath, state int32) {
		sigs <- &dbus.Signal{Path: path, Name: avahiGroupIface + ".StateChanged", Body: []any{state, ""}}
	}
	next := func() backendEvent {
		t.Helper()
		select {
		case ev := <-evs:
			return ev
		case <-time.After(2 * time.Second):
			t.Fatal("no backend event")
			return backendEvent{}
		}
	}

	b.cur.Store(&avahiGroupRef{gen: 7, addr: addr, svc: svc})
	send("/Client1/EntryGroup9", avahiGroupCollision) // another client's group
	// Established only once BOTH groups are: the service must not be
	// announced as published while its addresses are still registering.
	send(addr, avahiGroupEstablish)
	send(svc, avahiGroupCollision)
	if ev := next(); ev.state != stateInstanceCollision || ev.gen != 7 {
		t.Fatalf("service group collision: %+v, want an instance collision", ev)
	}
	send(addr, avahiGroupCollision)
	if ev := next(); ev.state != core.MDNSCollision {
		t.Fatalf("address group collision: %+v, want a host name collision", ev)
	}
	send(svc, avahiGroupEstablish)
	if ev := next(); ev.state != core.MDNSPublished {
		t.Fatalf("both groups established: %+v", ev)
	}

	// Without address records (the name is avahi-daemon's own host name)
	// the service group alone establishes the publication.
	b.cur.Store(&avahiGroupRef{gen: 8, svc: svc})
	send(svc, avahiGroupEstablish)
	if ev := next(); ev.state != core.MDNSPublished || ev.gen != 8 {
		t.Fatalf("own-host publication: %+v", ev)
	}
	send(svc, avahiGroupCollision)
	if ev := next(); ev.state != stateInstanceCollision {
		t.Fatalf("own-host collision: %+v", ev)
	}
}

func TestAvahiBackendIntegration(t *testing.T) {
	requireAvahi(t)
	ifc, ip := lanIPv4(t)
	host := randLabel("fptest-")
	events := make(chan backendEvent, 16)
	b := newAvahiBackend(slog.Default(), func(ev backendEvent) { events <- ev })
	defer b.close()
	p := publication{Host: host, Instance: "FileParcel test " + host, Port: 8443, TXT: []string{"path=/", "fp=1"},
		Ifaces: []ifaceAddrs{{Name: ifc.Name, Index: ifc.Index, Addrs: []netip.Addr{ip}}}}
	if err := b.publish(context.Background(), 1, p); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for published := false; !published; {
		select {
		case ev := <-events:
			if ev.gen != 1 {
				t.Fatalf("gen %+v", ev)
			}
			switch ev.state {
			case core.MDNSPublished:
				published = true
			case core.MDNSPublishing:
			default:
				t.Fatalf("unexpected %+v", ev)
			}
		case <-deadline:
			t.Fatal("not established")
		}
	}
	out := waitGetent(t, host+".local", true)
	if !strings.HasPrefix(out, ip.String()) {
		t.Fatalf("getent: %q, want %s", out, ip)
	}
	srvHost, port, txt := resolveService(t, p.Instance)
	if !strings.EqualFold(srvHost, host+".local") || port != 8443 {
		t.Fatalf("service: host %s port %d", srvHost, port)
	}
	var txts []string
	for _, x := range txt {
		txts = append(txts, string(x))
	}
	if !strings.Contains(strings.Join(txts, ","), "path=/") || !strings.Contains(strings.Join(txts, ","), "fp=1") {
		t.Fatalf("txt %q", txts)
	}

	// A second local publisher of the same service instance collides on the
	// INSTANCE only — its host label is free, so the supervisor must not
	// rename it (Avahi shares address records locally: ALLOW_MULTIPLE).
	b2 := newAvahiBackend(slog.Default(), func(backendEvent) {})
	defer b2.close()
	p2 := p
	p2.Host = host + "-other"
	if err := b2.publish(context.Background(), 1, p2); !errors.Is(err, errInstanceCollision) {
		t.Fatalf("second publisher: %v, want errInstanceCollision", err)
	}
	if errors.Is(b2.publish(context.Background(), 2, p2), errCollision) {
		t.Fatal("a service instance clash was reported as a host name collision")
	}

	// Withdrawn after unpublish.
	b.unpublish()
	waitGetent(t, host+".local", false)
}

func TestAvahiServiceIntegration(t *testing.T) {
	requireAvahi(t)
	ifc, ip := lanIPv4(t)
	name := randLabel("fpsvc-")

	// Occupy the service instance "FileParcel on <host>" first (as a second
	// FileParcel on the same machine would) so the service has to rename.
	blocker := newAvahiBackend(slog.Default(), func(backendEvent) {})
	defer blocker.close()
	if err := blocker.publish(context.Background(), 1, publication{Host: name + "-blocker", Instance: "FileParcel on " + name, Port: 1,
		Ifaces: []ifaceAddrs{{Name: ifc.Name, Index: ifc.Index, Addrs: []netip.Addr{ip}}}}); err != nil {
		t.Fatal(err)
	}

	env := &core.Env{Bus: events.New(), Clock: core.SystemClock{}}
	cfg := config.Default(config.NewInstallID())
	env.Config = cfg
	st, err := settings.New(env)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	env.Settings = st
	if _, err := st.Set(context.Background(), nil, map[string]json.RawMessage{
		KeyName: json.RawMessage(`"` + name + `"`), KeyMode: json.RawMessage(`"avahi"`),
		KeyInterfaces: json.RawMessage(`"` + ifc.Name + `"`)}); err != nil {
		t.Fatal(err)
	}
	nw := &fakeNet{ifs: []core.NetInterface{{Name: ifc.Name, Kind: core.IfLAN, Up: true,
		Addrs: []netip.Prefix{netip.PrefixFrom(ip, 24)}}}}
	svc, _ := New(env, nw)
	svc.hostname = func() (string, error) { return name, nil }
	ch, cancel := env.Bus.Subscribe(events.TopicMDNSChanged)
	defer cancel()
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()
	// Only the service instance renames: the configured <name>.local is
	// what the certificate, the URLs and the WebAuthn RP ID are built from.
	want := name + ".local"
	deadline := time.After(15 * time.Second)
	for done := false; !done; {
		select {
		case e := <-ch:
			s := e.Data.(core.MDNSStatus)
			if s.State == core.MDNSPublished && s.Name == want {
				done = true
			}
			if s.State == core.MDNSCollision {
				t.Fatalf("a service instance clash renamed the host: %+v", s)
			}
			if s.State == core.MDNSError {
				t.Logf("status %+v", s)
			}
		case <-deadline:
			t.Fatalf("not published as %s: %+v", want, svc.Status())
		}
	}
	if svc.Name() != want || svc.Status().Backend != BackendAvahi {
		t.Fatalf("%s %+v", svc.Name(), svc.Status())
	}
	if host, port, _ := resolveService(t, "FileParcel on "+name+" (2)"); !strings.EqualFold(host, want) || port == 0 {
		t.Fatalf("renamed instance resolves to %s:%d, want %s", host, port, want)
	}
	waitGetent(t, want, true)
	if err := svc.Republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	waitGetent(t, want, false)
}
