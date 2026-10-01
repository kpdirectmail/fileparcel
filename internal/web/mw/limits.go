package mw

import (
	"io"
	"math"
	"net/http"
	"net/netip"
	"strconv"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// limitedBody lets an inner MaxBody replace an outer limit (both before the
// body is read), so upload/import routes can raise the 1 MiB API default.
type limitedBody struct {
	io.ReadCloser               // http.MaxBytesReader over orig
	orig          io.ReadCloser // the original request body
	limit         int64
	declared      int64 // Content-Length (-1 = unknown)
	started       bool
}

// Read fails fast when the declared Content-Length exceeds the limit, before
// any byte is consumed; otherwise it reads through the MaxBytesReader.
func (b *limitedBody) Read(p []byte) (int, error) {
	if !b.started {
		b.started = true
		if b.declared > b.limit {
			return 0, &http.MaxBytesError{Limit: b.limit}
		}
	}
	return b.ReadCloser.Read(p)
}

// MaxBody limits the request body to n bytes (n < 0 = unlimited). A MaxBody
// applied later in the chain replaces an earlier one (it may raise or lower
// the limit). Reads beyond the limit fail with *http.MaxBytesError, which
// httpx.Error maps to 413 too_large. A declared Content-Length above the
// effective (innermost) limit fails on the first Read, before any body byte
// is consumed.
func MaxBody(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.Body != http.NoBody {
				orig := r.Body
				if lb, ok := r.Body.(*limitedBody); ok {
					orig = lb.orig
				}
				if n < 0 {
					r.Body = orig
				} else {
					r.Body = &limitedBody{ReadCloser: http.MaxBytesReader(w, orig, n), orig: orig,
						limit: n, declared: r.ContentLength}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NoStore sets Cache-Control: no-store.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", CacheNoStore)
		next.ServeHTTP(w, r)
	})
}

// RateLimit consumes a token from bucket (Bucket* constants) for key(r) via
// d.Limiter.Allow; when denied it responds 429 rate_limited with
// Retry-After (whole seconds, at least 1). Trusted in-process callers (admin
// socket, offline CLI) are never limited — they all come from ::1 and would
// otherwise share one per-IP bucket. Without a limiter (tests) every request
// passes.
//
// A per-address (PerIP) limit on login, share or unlock also consumes a
// token of the bucket's per-/64 aggregate (netBuckets; ratelimit.NetFactor
// times the allowance) when the client is a remote IPv6 address (netKey):
// every address of a /64 is one host's to choose, so without it each new
// address would bring a fresh bucket.
func RateLimit(bucket string, key func(*http.Request) string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if trusted(r) {
				next.ServeHTTP(w, r)
				return
			}
			if d := Deps(r); d != nil && d.Limiter != nil {
				k := key(r)
				ok, retry := d.Limiter.Allow(bucket, k)
				if nb := netBuckets[bucket]; ok && nb != "" && k == PerIP(r) {
					if nk, agg := netKey(d, ClientIP(r)); agg {
						ok, retry = d.Limiter.Allow(nb, nk)
					}
				}
				if !ok {
					w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retry.Seconds())))
					httpx.Error(w, r, core.ErrRateLimited)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// netBuckets maps the per-IP buckets that guard guessing (passwords, codes,
// share links, the unlock passphrase) to their per-/64 aggregate.
var netBuckets = map[string]string{
	BucketLogin: BucketLoginNet, BucketLoginStart: BucketLoginStartNet, BucketShare: BucketShareNet, BucketUnlock: BucketUnlockNet,
}

// netKey returns the /64 of ip ("2001:db8:1:2::/64") and true when ip is a
// remote IPv6 client: a global unicast address that is not a ULA (fc00::/7,
// which covers tailnets) and not in the /64 of one of the server's own
// addresses (the LAN, where devices share the router's /64). IPv4, loopback,
// link-local, ULA and on-link clients keep per-address limits only.
func netKey(d *app.Deps, ip netip.Addr) (string, bool) {
	ip = ip.Unmap().WithZone("")
	if !ip.Is6() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", false
	}
	p := netip.PrefixFrom(ip, 64).Masked()
	if hasEnv(d) && d.Network != nil {
		for _, a := range d.Network.IPs() {
			if p.Contains(a.Unmap().WithZone("")) {
				return "", false
			}
		}
	}
	return p.String(), true
}

// retryAfterSeconds rounds up to whole seconds, at least 1, at most one day.
func retryAfterSeconds(s float64) int {
	switch {
	case math.IsNaN(s) || s < 1:
		return 1
	case s > 86400:
		return 86400
	}
	return int(math.Ceil(s))
}
