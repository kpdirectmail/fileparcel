// Package ratelimit provides keyed token-bucket rate limiting (x/time/rate)
// with LRU/TTL eviction (DESIGN §2, §9.1, §9.3; owned by unit B).
//
// Buckets are named ("api", "login", "share", "unlock", …) and configured with
// Configure; keys within a bucket are usually a client IP or a user id. The
// four well-known buckets are configured from the ratelimit.* settings when
// the registry is created and re-configured live on settings.changed:
//
//	api     ratelimit.api_rps per second, burst ratelimit.api_burst
//	login   ratelimit.login_per_min per minute (burst = one minute's allowance)
//	share   ratelimit.share_per_min per minute (burst = one minute's allowance)
//	unlock  ratelimit.unlock_per_min per minute (burst = one minute's allowance)
//
// login_start gets LoginStartFactor times the login allowance: the requests
// of the sign-in pages that check no credential (starting a passkey
// ceremony, which the sign-in page does on every load for passkey autofill,
// and reading an invitation) must not use up the allowance of real attempts,
// yet stay bounded (pending passkey ceremonies are a bounded table).
//
// login, login_start, share and unlock each have an aggregate twin (BucketLoginNet, …) at
// NetFactor times their allowance, keyed by a global IPv6 /64 (mw.RateLimit):
// one host cannot take a fresh per-address bucket for every address of its
// /64, while every client keeps its own per-address allowance.
//
// Requests over Tailscale Funnel (the internet, DESIGN §10.6) have buckets
// of their own, on top of the others:
//
//	funnel            ratelimit.funnel_per_min per client (core.IPLimitKey: IPv6 per /64)
//	funnel_global     ratelimit.funnel_global_per_min for all Funnel requests (key "*")
//	auth_funnel_user  wrong passwords/codes over Funnel per account: burst 10, 2 per hour
//	funnel_share_pw   wrong share passwords over Funnel per share: burst 20, 20 per hour
//
// Memory is bounded: at most MaxKeys (bucket, key) limiters are kept across
// all buckets. The least recently used limiter is evicted when the cap is
// reached, and limiters idle for longer than their bucket's refill time (at
// least MinIdleTTL) are dropped lazily — an idle limiter is full again, so
// forgetting it never grants more than a fresh key would get.
package ratelimit

import (
	"container/list"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// Well-known bucket names.
const (
	BucketAPI    = "api"    // per IP, ratelimit.api_rps / api_burst
	BucketLogin  = "login"  // per IP, ratelimit.login_per_min
	BucketShare  = "share"  // per IP, ratelimit.share_per_min
	BucketUnlock = "unlock" // per IP, ratelimit.unlock_per_min

	// BucketLoginStart: per IP, LoginStartFactor × ratelimit.login_per_min
	// (passkey/begin and invitation look-ups, see the package comment).
	BucketLoginStart = "login_start"

	// Aggregates of login, login_start, share and unlock per global IPv6
	// /64, at NetFactor times the per-address allowance.
	BucketLoginNet      = "login_net"
	BucketLoginStartNet = "login_start_net"
	BucketShareNet      = "share_net"
	BucketUnlockNet     = "unlock_net"

	// Tailscale Funnel (requests from the internet).
	BucketFunnel         = "funnel"           // per client, ratelimit.funnel_per_min
	BucketFunnelGlobal   = "funnel_global"    // key "*", ratelimit.funnel_global_per_min
	BucketAuthFunnelUser = "auth_funnel_user" // per user id: failed sign-ins over Funnel
	BucketFunnelSharePW  = "funnel_share_pw"  // per share id: wrong passwords over Funnel
)

// Fixed allowances of the Funnel sign-in and share-password buckets: an
// internet attacker gets a few guesses per account or share and hour
// without locking the account out of the LAN (DESIGN §10.6).
const (
	AuthFunnelUserBurst  = 10
	AuthFunnelUserPerMin = 2.0 / 60 // 2 per hour
	FunnelSharePWBurst   = 20
	FunnelSharePWPerMin  = 20.0 / 60 // 20 per hour
)

// NetFactor is how many clients' allowance one IPv6 /64 gets in the
// aggregate buckets.
const NetFactor = 8

// LoginStartFactor is how many sign-in allowances (ratelimit.login_per_min)
// the login_start bucket gets.
const LoginStartFactor = 4

// MaxKeys bounds the number of (bucket, key) limiters kept in memory.
const MaxKeys = 100_000

// MinIdleTTL is the minimum time an idle limiter is kept.
const MinIdleTTL = 5 * time.Minute

// maxIdleTTL caps the idle TTL of very slow buckets.
const maxIdleTTL = 24 * time.Hour

// evictPerCall bounds the lazy TTL sweep done by each Allow call.
const evictPerCall = 8

// Registry holds the buckets. It is safe for concurrent use.
type Registry struct {
	env *core.Env
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucketConfig
	entries map[entryKey]*list.Element // → *entry
	lru     *list.List                 // front = most recently used
	maxKeys int

	unsub func()
	done  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

type bucketConfig struct {
	perMinute float64
	burst     int
	limit     rate.Limit
	ttl       time.Duration
}

type entryKey struct{ bucket, key string }

type entry struct {
	k    entryKey
	lim  *rate.Limiter
	last time.Time
}

// New creates the registry, configures the well-known buckets from the
// ratelimit.* settings (their registered defaults when env.Settings is nil)
// and, when env.Bus is set, re-applies them on every settings.changed event.
// Close stops the subscription.
func New(env *core.Env) (*Registry, error) {
	r := &Registry{
		env:     env,
		buckets: map[string]*bucketConfig{},
		entries: map[entryKey]*list.Element{},
		lru:     list.New(),
		maxKeys: MaxKeys,
		done:    make(chan struct{}),
	}
	r.now = func() time.Time { return env.Now() }
	r.ApplySettings()
	if env != nil && env.Bus != nil {
		ch, unsub := env.Bus.Subscribe(events.TopicSettingsChanged)
		r.unsub = unsub
		r.wg.Add(1)
		go r.watch(ch)
	}
	return r, nil
}

func (r *Registry) watch(ch <-chan events.Event) {
	defer r.wg.Done()
	for {
		select {
		case <-r.done:
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if ev, ok := e.Data.(core.SettingsChangedEvent); ok && !touchesRateLimit(ev.Keys) {
				continue
			}
			r.ApplySettings()
		}
	}
}

func touchesRateLimit(keys []string) bool {
	for _, k := range keys {
		if len(k) >= len("ratelimit.") && k[:len("ratelimit.")] == "ratelimit." {
			return true
		}
	}
	return len(keys) == 0
}

// Close stops the settings subscription. It is safe to call more than once.
func (r *Registry) Close() error {
	r.once.Do(func() {
		close(r.done)
		if r.unsub != nil {
			r.unsub()
		}
		r.wg.Wait()
	})
	return nil
}

// ApplySettings (re)configures the well-known buckets from the current
// ratelimit.* settings (and the fixed Funnel sign-in and share-password
// buckets). Invalid or missing values fall back to the defaults.
func (r *Registry) ApplySettings() {
	get := func(key string) int64 {
		if r.env == nil || r.env.Settings == nil {
			return 0
		}
		return r.env.Settings.Int(key)
	}
	pick := func(v, def int64) float64 {
		if v <= 0 {
			v = def
		}
		return float64(v)
	}
	loginPM := pick(get("ratelimit.login_per_min"), DefaultLoginPerMin)
	sharePM := pick(get("ratelimit.share_per_min"), DefaultSharePerMin)
	unlockPM := pick(get("ratelimit.unlock_per_min"), DefaultUnlockPerMin)
	apiRPS := pick(get("ratelimit.api_rps"), DefaultAPIRPS)
	apiBurst := pick(get("ratelimit.api_burst"), DefaultAPIBurst)

	r.Configure(BucketLogin, loginPM, int(loginPM))
	r.Configure(BucketShare, sharePM, int(sharePM))
	r.Configure(BucketUnlock, unlockPM, int(unlockPM))
	r.Configure(BucketAPI, apiRPS*60, int(apiBurst))
	r.Configure(BucketLoginNet, loginPM*NetFactor, int(loginPM*NetFactor))
	r.Configure(BucketLoginStart, loginPM*LoginStartFactor, int(loginPM*LoginStartFactor))
	r.Configure(BucketLoginStartNet, loginPM*LoginStartFactor*NetFactor, int(loginPM*LoginStartFactor*NetFactor))
	r.Configure(BucketShareNet, sharePM*NetFactor, int(sharePM*NetFactor))
	r.Configure(BucketUnlockNet, unlockPM*NetFactor, int(unlockPM*NetFactor))

	funnelPM := pick(get("ratelimit.funnel_per_min"), DefaultFunnelPerMin)
	funnelGlobalPM := pick(get("ratelimit.funnel_global_per_min"), DefaultFunnelGlobalPerMin)
	r.Configure(BucketFunnel, funnelPM, int(funnelPM))
	r.Configure(BucketFunnelGlobal, funnelGlobalPM, int(funnelGlobalPM))
	r.Configure(BucketAuthFunnelUser, AuthFunnelUserPerMin, AuthFunnelUserBurst)
	r.Configure(BucketFunnelSharePW, FunnelSharePWPerMin, FunnelSharePWBurst)
}

// Configure sets (or replaces) a bucket's rate (events per minute) and burst.
// perMinute <= 0 disables limiting for the bucket; burst < 1 is raised to 1.
// Existing limiters of the bucket are updated in place (their current token
// count is kept, capped at the new burst).
func (r *Registry) Configure(bucket string, perMinute float64, burst int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if perMinute <= 0 || math.IsNaN(perMinute) || math.IsInf(perMinute, 0) {
		delete(r.buckets, bucket)
		r.dropBucketLocked(bucket)
		return
	}
	if burst < 1 {
		burst = 1
	}
	limit := rate.Limit(perMinute / 60)
	// An idle limiter refills completely after burst/limit seconds; keeping it
	// longer than that is pointless.
	ttl := time.Duration(float64(burst) / float64(limit) * float64(time.Second))
	ttl = min(max(ttl, MinIdleTTL), maxIdleTTL)
	cfg := &bucketConfig{perMinute: perMinute, burst: burst, limit: limit, ttl: ttl}
	old := r.buckets[bucket]
	r.buckets[bucket] = cfg
	if old != nil && (old.limit != limit || old.burst != burst) {
		now := r.now()
		for el := r.lru.Front(); el != nil; el = el.Next() {
			e := el.Value.(*entry)
			if e.k.bucket == bucket {
				e.lim.SetLimitAt(now, limit)
				e.lim.SetBurstAt(now, burst)
			}
		}
	}
}

// dropBucketLocked forgets every limiter of bucket. r.mu must be held.
func (r *Registry) dropBucketLocked(bucket string) {
	for el := r.lru.Front(); el != nil; {
		next := el.Next()
		if e := el.Value.(*entry); e.k.bucket == bucket {
			r.lru.Remove(el)
			delete(r.entries, e.k)
		}
		el = next
	}
}

// Allow consumes one token for key in bucket. When denied it returns the
// time until a token is available (for Retry-After). Unknown or disabled
// buckets always allow.
func (r *Registry) Allow(bucket, key string) (ok bool, retryAfter time.Duration) {
	if r == nil {
		return true, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := r.buckets[bucket]
	if cfg == nil {
		return true, 0
	}
	now := r.now()
	r.sweepLocked(now)
	e := r.getLocked(entryKey{bucket, key}, cfg, now)
	res := e.lim.ReserveN(now, 1)
	if !res.OK() {
		return false, time.Minute
	}
	if d := res.DelayFrom(now); d > 0 {
		res.CancelAt(now)
		return false, d
	}
	return true, 0
}

// Tokens reports the tokens currently available to key in bucket (burst for
// keys that have not been seen; +Inf for unknown or disabled buckets). It
// does not consume anything.
func (r *Registry) Tokens(bucket, key string) float64 {
	if r == nil {
		return math.Inf(1)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := r.buckets[bucket]
	if cfg == nil {
		return math.Inf(1)
	}
	el, ok := r.entries[entryKey{bucket, key}]
	if !ok {
		return float64(cfg.burst)
	}
	return el.Value.(*entry).lim.TokensAt(r.now())
}

// Reset forgets the limiter of key in bucket (it starts full again).
func (r *Registry) Reset(bucket, key string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := entryKey{bucket, key}
	if el, ok := r.entries[k]; ok {
		r.lru.Remove(el)
		delete(r.entries, k)
	}
}

// Len returns the number of limiters currently held.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lru.Len()
}

// getLocked returns (creating if needed) the limiter entry of k and marks it
// most recently used. r.mu must be held.
func (r *Registry) getLocked(k entryKey, cfg *bucketConfig, now time.Time) *entry {
	if el, ok := r.entries[k]; ok {
		r.lru.MoveToFront(el)
		e := el.Value.(*entry)
		e.last = now
		return e
	}
	for r.lru.Len() >= r.maxKeys {
		oldest := r.lru.Back()
		r.lru.Remove(oldest)
		delete(r.entries, oldest.Value.(*entry).k)
	}
	lim := rate.NewLimiter(cfg.limit, cfg.burst)
	// rate.NewLimiter starts full, but only relative to its first use: pin the
	// time base to now so the fake clocks of tests behave like the real one.
	lim.SetBurstAt(now, cfg.burst)
	e := &entry{k: k, lim: lim, last: now}
	r.entries[k] = r.lru.PushFront(e)
	return e
}

// sweepLocked examines a few entries at the LRU tail (the least recently
// used ones) and drops those idle for longer than their bucket's TTL. r.mu
// must be held.
func (r *Registry) sweepLocked(now time.Time) {
	el := r.lru.Back()
	for i := 0; i < evictPerCall && el != nil; i++ {
		prev := el.Prev()
		e := el.Value.(*entry)
		ttl := MinIdleTTL
		if cfg := r.buckets[e.k.bucket]; cfg != nil {
			ttl = cfg.ttl
		}
		if now.Sub(e.last) >= ttl {
			r.lru.Remove(el)
			delete(r.entries, e.k)
		}
		el = prev
	}
}
