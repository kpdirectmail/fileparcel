//go:build unix

package mdns

import (
	"context"
	"log/slog"
	"syscall"
	"testing"

	"fileparcel/internal/core"
)

// The dns-sd child shares FileParcel's process group, so launchd's cleanup
// of the job's group reaps it when FileParcel dies without stopping it.
func TestDNSSDChildInOurProcessGroup(t *testing.T) {
	events := make(chan backendEvent, 8)
	b := newDNSSDBackend(slog.Default(), func(ev backendEvent) { events <- ev })
	script, _ := fakeDNSSD(t, "echo 'Got a reply: Name now registered and active'\nexec sleep 60\n")
	b.cmd = script
	if err := b.publish(context.Background(), 1, testPublication()); err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if ev := recvEvent(t, events); ev.state != core.MDNSPublished {
		t.Fatalf("%+v", ev)
	}
	b.mu.Lock()
	pid := b.cur.cmd.Process.Pid
	b.mu.Unlock()
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != syscall.Getpgrp() {
		t.Fatalf("dns-sd in process group %d, want ours (%d)", pgid, syscall.Getpgrp())
	}
}
