package netinfo

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Caching of the system responder's host name: sysHostTTL is the lifetime of
// an answer, sysHostRetry the shorter one while lookups fail and the previous
// name is served, and sysHostGrace how long that name survives failing
// lookups before the responder counts as gone.
const (
	sysHostTTL   = 5 * time.Minute
	sysHostRetry = 15 * time.Second
	sysHostGrace = 10 * time.Minute
)

// sysHostResolver caches the ".local" name the operating system's own mDNS
// responder publishes for this machine (Avahi's host name on Linux, the
// LocalHostName on macOS) — the "<hostname>.local" URL of DESIGN §10.2.
type sysHostResolver struct {
	lookup func(ctx context.Context) string
	now    func() time.Time

	mu       sync.Mutex
	name     string
	at       time.Time
	ok       bool
	failedAt time.Time // first of the current run of empty lookups (zero = none)
}

func newSysHostResolver() *sysHostResolver {
	return &sysHostResolver{lookup: systemResponderHost, now: time.Now}
}

// get returns the cached FQDN ("fileshare.local"; "" when no system
// responder publishes one), refreshing it after sysHostTTL.
//
// An empty answer is not simply cached: refresh runs on the caller's context,
// so an aborted GET /network/urls or /admin/network — or a momentary avahi
// restart — used to store "" for the full TTL. That drops <hostname>.local
// from the certificate SANs, from the strict-Host allowlist and from the
// access URLs, so the leaf is reissued without the name and again five
// minutes later when it returns. A caller's cancellation is therefore never
// recorded (like the Tailscale client in this package), and a lookup that
// fails on its own keeps the previous name for sysHostGrace while retrying
// every sysHostRetry.
func (r *sysHostResolver) get(ctx context.Context) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ok && r.now().Sub(r.at) < r.ttl() {
		return r.name
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	n := normalizeLocalName(r.lookup(lctx))
	if n == "" && ctx.Err() != nil {
		return r.name // cancelled by the caller: keep serving the previous value
	}
	now := r.now()
	r.at, r.ok = now, true
	if n != "" {
		r.name, r.failedAt = n, time.Time{}
		return n
	}
	if r.failedAt.IsZero() {
		r.failedAt = now
	}
	if r.name != "" && now.Sub(r.failedAt) < sysHostGrace {
		return r.name
	}
	// No responder for sysHostGrace (or none ever): accept the empty answer
	// and go back to the normal TTL.
	r.name, r.failedAt = "", time.Time{}
	return ""
}

// ttl is the lifetime of the cached answer: shorter while lookups are failing
// and the previous name is being served.
func (r *sysHostResolver) ttl() time.Duration {
	if !r.failedAt.IsZero() {
		return sysHostRetry
	}
	return sysHostTTL
}

// normalizeLocalName lowercases a responder host name and makes it a
// ".local" FQDN without the trailing dot ("" stays "").
func normalizeLocalName(n string) string {
	n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
	if n == "" || strings.ContainsAny(n, " /\\") {
		return ""
	}
	if !strings.HasSuffix(n, ".local") {
		n += ".local"
	}
	return n
}
