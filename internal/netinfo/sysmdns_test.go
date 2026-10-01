package netinfo

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// A failed or cancelled lookup used to be cached like an answer: refresh runs
// on the caller's context, so a client aborting GET /network/urls or
// /admin/network — or a momentary avahi restart — removed <hostname>.local
// from the certificate SANs, the strict-Host allowlist and the access URLs for
// a full five minutes, reissuing the leaf twice in the process.
func TestSysHostCacheKeepsThePreviousName(t *testing.T) {
	var (
		mu    sync.Mutex
		now   = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
		reply = "fileshare.local"
	)
	r := &sysHostResolver{
		now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
		lookup: func(ctx context.Context) string {
			mu.Lock()
			defer mu.Unlock()
			if ctx.Err() != nil {
				return "" // a D-Bus dial on a cancelled context
			}
			return reply
		},
	}
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	set := func(v string) { mu.Lock(); reply = v; mu.Unlock() }

	if got := r.get(context.Background()); got != "fileshare.local" {
		t.Fatalf("first lookup: %q", got)
	}

	// A request the client aborted must not become the cached answer.
	advance(sysHostTTL)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := r.get(cancelled); got != "fileshare.local" {
		t.Fatalf("after a cancelled request: %q, want the previous name", got)
	}
	if got := r.get(context.Background()); got != "fileshare.local" {
		t.Fatalf("the cancelled lookup was cached: %q", got)
	}

	// avahi restarting: the previous name is served and retried soon.
	set("")
	advance(sysHostTTL)
	if got := r.get(context.Background()); got != "fileshare.local" {
		t.Fatalf("during a failing lookup: %q, want the previous name", got)
	}
	advance(sysHostRetry)
	set("fileshare.local")
	if got := r.get(context.Background()); got != "fileshare.local" {
		t.Fatalf("after the responder came back: %q", got)
	}

	// A responder that really stops publishing is believed in the end.
	set("")
	deadline := 2*(sysHostTTL+sysHostGrace)/sysHostRetry + 2
	for i := range int(deadline) {
		advance(sysHostRetry)
		if r.get(context.Background()) == "" {
			break
		}
		if i == int(deadline)-1 {
			t.Fatalf("a responder that stopped publishing is still reported as %q after %v",
				r.name, time.Duration(deadline)*sysHostRetry)
		}
	}
	// …and back to the normal TTL once the empty answer is accepted.
	if got := r.ttl(); got != sysHostTTL {
		t.Fatalf("ttl after giving up: %v, want %v", got, sysHostTTL)
	}
}

// The same, through the service: one aborted request must not drop the system
// responder's name from Hostnames() (which feeds certs.desiredSANs).
func TestCancelledRequestKeepsTheSystemName(t *testing.T) {
	env, _ := testEnv(t)
	s := newTestService(t, env, &fakeSource{list: hostList()}, "")
	s.sysHost.lookup = func(ctx context.Context) string {
		if ctx.Err() != nil {
			return ""
		}
		return "FileShare.local."
	}
	if !slices.Contains(s.Hostnames(), "fileshare.local") {
		t.Fatalf("names: %v", s.Hostnames())
	}
	s.sysHost.at = s.sysHost.at.Add(-2 * sysHostTTL) // expire the cache

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = s.Interfaces(cancelled)
	if got := s.Hostnames(); !slices.Contains(got, "fileshare.local") {
		t.Fatalf("one aborted request dropped the system .local name: %v", got)
	}
}
