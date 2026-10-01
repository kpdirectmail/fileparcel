package mdns

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func testPublication() publication {
	return publication{Host: "fileparcel", Instance: "FileParcel on mac", Port: 8443, TXT: []string{"path=/", "fp=1"},
		Ifaces: []ifaceAddrs{
			{Name: "en0", Index: 4, Addrs: []netip.Addr{netip.MustParseAddr("fd00::5"), netip.MustParseAddr("192.168.1.20")}},
		}}
}

func TestDNSSDArgs(t *testing.T) {
	args, err := dnssdArgs(testPublication())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-P", "FileParcel on mac", "_https._tcp", "local", "8443", "fileparcel.local", "192.168.1.20", "path=/", "fp=1"}
	if !slices.Equal(args, want) {
		t.Fatalf("%q", args)
	}
	if _, err := dnssdArgs(publication{Host: "x"}); err == nil {
		t.Fatal("no address accepted")
	}
	for line, want := range map[string]string{
		" 9:44:21.123  Got a reply for service FileParcel on mac._https._tcp.local.: Name now registered and active": core.MDNSPublished,
		// What dns-sd really prints on kDNSServiceErr_NameConflict.
		" 9:44:21.123  Got a reply for record fileparcel.local: Name in use, please choose another":                      core.MDNSCollision,
		" 9:44:21.123  Got a reply for service FileParcel on mac._https._tcp.local.: Name in use, please choose another": stateInstanceCollision,
		// Unattributed fallbacks.
		"Name conflict":                         dnssdConflict,
		"DNSService call failed -65548":         dnssdConflict,
		"Registering Service FileParcel on mac": "",
	} {
		if got := classifyDNSSDLine(line); got != want {
			t.Errorf("%q: %q", line, got)
		}
	}
}

// fakeDNSSD writes a dns-sd stand-in script and returns its path.
func fakeDNSSD(t *testing.T, body string) (script, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script = filepath.Join(dir, "dns-sd")
	content := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\n" + body
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, argsFile
}

func recvEvent(t *testing.T, ch <-chan backendEvent) backendEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no backend event")
	}
	return backendEvent{}
}

func TestDNSSDBackendSupervision(t *testing.T) {
	events := make(chan backendEvent, 8)
	b := newDNSSDBackend(slog.Default(), func(ev backendEvent) { events <- ev })

	// Registered, then kept running until unpublished.
	script, argsFile := fakeDNSSD(t, "echo 'Registering Service'\necho 'Got a reply: Name now registered and active'\nexec sleep 60\n")
	b.cmd = script
	if err := b.publish(context.Background(), 1, testPublication()); err != nil {
		t.Fatal(err)
	}
	if ev := recvEvent(t, events); ev.gen != 1 || ev.state != core.MDNSPublished {
		t.Fatalf("%+v", ev)
	}
	raw, _ := os.ReadFile(argsFile)
	if got := strings.Split(strings.TrimSpace(string(raw)), "\n"); got[0] != "-P" || got[1] != "FileParcel on mac" || got[5] != "fileparcel.local" {
		t.Fatalf("args %q", got)
	}
	start := time.Now()
	b.unpublish()
	if d := time.Since(start); d > dnssdStopGrace+time.Second {
		t.Fatalf("stop took %v", d)
	}
	select {
	case ev := <-events:
		t.Fatalf("intentional stop reported: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}

	// A conflict line that does not say which name is taken, on a
	// publication whose instance has not been renamed yet, is reported once,
	// as a service-instance collision: renaming the host would move
	// <name>.local, the leaf SANs and the WebAuthn RP ID.
	script, _ = fakeDNSSD(t, "echo 'Name conflict'\necho 'Name conflict'\nexit 1\n")
	b.cmd = script
	if err := b.publish(context.Background(), 2, testPublication()); err != nil {
		t.Fatal(err)
	}
	if ev := recvEvent(t, events); ev.gen != 2 || ev.state != stateInstanceCollision {
		t.Fatalf("%+v", ev)
	}
	select {
	case ev := <-events:
		t.Fatalf("extra event after collision: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}

	// dns-sd's real host-record conflict (it auto-renames the service
	// instance itself) renames the host on the first attempt, with no error
	// for the exit status 255 that follows.
	script, _ = fakeDNSSD(t, "echo 'Registering Service FileParcel on mac._https._tcp.local. host fileparcel.local port 8443'\n"+
		"echo ' 9:44:21.123  Got a reply for record fileparcel.local: Name in use, please choose another'\nexit 255\n")
	b.cmd = script
	if err := b.publish(context.Background(), 5, testPublication()); err != nil {
		t.Fatal(err)
	}
	if ev := recvEvent(t, events); ev.gen != 5 || ev.state != core.MDNSCollision {
		t.Fatalf("host record conflict: %+v", ev)
	}
	select {
	case ev := <-events:
		t.Fatalf("extra event after host collision: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}

	// An unexpected exit is an error (the supervisor retries).
	script, _ = fakeDNSSD(t, "echo 'Registering Service'\nexit 3\n")
	b.cmd = script
	if err := b.publish(context.Background(), 3, testPublication()); err != nil {
		t.Fatal(err)
	}
	if ev := recvEvent(t, events); ev.gen != 3 || ev.state != core.MDNSError || ev.err == nil {
		t.Fatalf("%+v", ev)
	}

	// Once the instance carries a " (n)" suffix, a further conflict is the host
	// label after all, and the supervisor may rename it.
	script, _ = fakeDNSSD(t, "echo 'Name conflict'\nexit 255\n")
	b.cmd = script
	renamed := testPublication()
	renamed.Instance = instanceName("FileParcel on mac", 2)
	if err := b.publish(context.Background(), 4, renamed); err != nil {
		t.Fatal(err)
	}
	if ev := recvEvent(t, events); ev.gen != 4 || ev.state != core.MDNSCollision {
		t.Fatalf("renamed instance: %+v", ev)
	}
	if err := b.close(); err != nil {
		t.Fatal(err)
	}

	// Missing binary.
	b.cmd = filepath.Join(t.TempDir(), "no-such-dns-sd")
	if err := b.publish(context.Background(), 4, testPublication()); err == nil {
		t.Fatal("missing dns-sd accepted")
	}
}
