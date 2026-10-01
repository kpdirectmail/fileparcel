package netinfo

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
)

// Tailscale status (DESIGN §10.1), read through package tslocal.
const (
	tsCacheTTL = 30 * time.Second
	// tsFetchTimeout bounds one fetch (status and prefs).
	tsFetchTimeout = 2 * tslocal.DefaultReadTimeout
	// While tailscaled fails to answer, the node's identity from its last
	// answer is kept for tsGrace, and tailscaled is asked again every
	// tsRetry (like sysHostRetry/sysHostGrace for the system .local name).
	tsRetry = 15 * time.Second
	tsGrace = 10 * time.Minute
)

// tailscaleClient reads the local node's status from tailscaled (LocalAPI
// over its Unix socket, falling back to the CLI; see tslocal) and caches it
// for 30 s.
type tailscaleClient struct {
	tl   *tslocal.Client
	ttl  time.Duration
	now  func() time.Time
	goos string
	// mayConfigure reports whether this process may use write-level
	// LocalAPI calls such as `tailscale cert` (nil: tl.MayConfigure).
	mayConfigure func(p *tslocal.Prefs) bool

	mu     sync.Mutex
	cached *core.TailscaleInfo
	at     time.Time
	// good is the last answer tailscaled gave; failedAt is the first of the
	// current run of failed fetches while good is being carried over (zero =
	// none).
	good     *core.TailscaleInfo
	failedAt time.Time
}

func newTailscaleClient() *tailscaleClient {
	return &tailscaleClient{tl: tslocal.Default(), ttl: tsCacheTTL, now: time.Now, goos: runtime.GOOS}
}

// get returns the cached info, refreshing it when older than the TTL (or
// always when force). The result is a copy and never nil.
//
// A failed fetch (tailscaled restarting for an update, the timeout under
// load) is reported as it is — Running=false with the error — but keeps the
// node's identity (MagicDNS name, kind, IPs, tailnet, control URL, node ID)
// from the last answer for tsGrace, retrying every tsRetry. Otherwise the
// MagicDNS name drops out of Hostnames for a TTL: network.changed fires, the
// leaf is reissued without the name and again when it returns, and
// strict_host refuses it meanwhile (the same failure sysHostResolver.get
// guards against).
func (c *tailscaleClient) get(ctx context.Context, force bool) *core.TailscaleInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.cached != nil && c.now().Sub(c.at) < c.cacheTTL() {
		return cloneTS(c.cached)
	}
	info, ok := c.fetch(ctx)
	if ctx.Err() != nil && c.cached != nil {
		// Cancelled by the caller: keep serving the previous value.
		return cloneTS(c.cached)
	}
	now := c.now()
	switch {
	case ok:
		c.good, c.failedAt = info, time.Time{}
	case c.good != nil:
		if c.failedAt.IsZero() {
			c.failedAt = now
		}
		if now.Sub(c.failedAt) < tsGrace {
			g := c.good
			info.DNSName, info.Kind, info.IPs = g.DNSName, g.Kind, slices.Clone(g.IPs)
			info.Tailnet, info.ControlURL, info.NodeID = g.Tailnet, g.ControlURL, g.NodeID
		} else {
			// Gone for tsGrace: accept the bare failure, normal TTL again.
			c.good, c.failedAt = nil, time.Time{}
		}
	}
	c.cached, c.at = info, now
	return cloneTS(info)
}

// cacheTTL is the lifetime of the cached info: shorter while fetches fail
// and the last answer's identity is being carried over.
func (c *tailscaleClient) cacheTTL() time.Duration {
	if !c.failedAt.IsZero() && tsRetry < c.ttl {
		return tsRetry
	}
	return c.ttl
}

// peek returns the cached info without fetching (nil when never fetched).
func (c *tailscaleClient) peek() *core.TailscaleInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached == nil {
		return nil
	}
	return cloneTS(c.cached)
}

func cloneTS(t *core.TailscaleInfo) *core.TailscaleInfo {
	if t == nil {
		return nil
	}
	c := *t
	c.IPs = slices.Clone(t.IPs)
	c.FunnelPorts = slices.Clone(t.FunnelPorts)
	if t.KeyExpiry != nil {
		e := *t.KeyExpiry
		c.KeyExpiry = &e
	}
	return &c
}

// fetch queries tailscaled (status, then the optional prefs). ok reports
// whether tailscaled answered (info then comes from build).
func (c *tailscaleClient) fetch(ctx context.Context) (info *core.TailscaleInfo, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, tsFetchTimeout)
	defer cancel()
	st, err := c.tl.Status(ctx)
	if err != nil {
		info = &core.TailscaleInfo{Running: false}
		if errors.Is(err, tslocal.ErrNotInstalled) {
			// No socket and no CLI: not installed (Installed stays false).
			info.Error = "Tailscale is not installed or tailscaled is not running"
		} else {
			// A socket or CLI exists but failed: a real problem to report.
			info.Installed = true
			info.Error = "could not read the Tailscale status: " + err.Error()
		}
		return info, false
	}
	prefs, err := c.tl.Prefs(ctx)
	if err != nil {
		prefs = nil // optional (control URL, operator, shields-up)
	}
	return c.build(st, prefs), true
}

// build converts the tailscaled answers to TailscaleInfo.
func (c *tailscaleClient) build(st *tslocal.Status, prefs *tslocal.Prefs) *core.TailscaleInfo {
	info := &core.TailscaleInfo{
		Running:      st.Running(),
		BackendState: st.BackendState,
		Kind:         core.IfTailscale,
		Installed:    true,
		Version:      st.Version,
		NodeID:       st.NodeID(),
		IPs:          st.IPs(),
		// A connected daemon without TUN device dials tailnet connections
		// to 127.0.0.1 (userspace networking).
		Userspace:     st.Running() && !st.TUN,
		FunnelCapable: st.HasCap("https") && st.HasCap("funnel"),
	}
	if ports := st.FunnelPorts(); len(ports) > 0 {
		info.FunnelPorts = ports
	}
	if st.Self != nil {
		info.DNSName = strings.TrimSuffix(strings.ToLower(st.Self.DNSName), ".")
		if st.Self.KeyExpiry != nil {
			e := st.Self.KeyExpiry.UTC()
			info.KeyExpiry = &e
		}
	}
	if st.CurrentTailnet != nil {
		info.Tailnet = st.CurrentTailnet.Name
		if !st.CurrentTailnet.MagicDNSEnabled {
			info.DNSName = "" // the name does not resolve for peers
		}
	}
	if prefs != nil {
		info.ControlURL = prefs.ControlURL
		info.ShieldsUp = prefs.ShieldsUp
		if tslocal.SelfHosted(prefs.ControlURL) {
			info.Kind = core.IfHeadscale
		}
	} else if guessHeadscale(st) {
		// Prefs unreadable: a MagicDNS name outside Tailscale's domains
		// means a self-hosted control server (DESIGN §10.1).
		info.Kind, info.KindGuessed = core.IfHeadscale, true
	}
	operator := c.operator(prefs)
	info.CertCapable = info.Running && info.Kind == core.IfTailscale && len(st.CertDomains) > 0 && operator
	// macOS: tailscaled's admin-group rule is not visible from here; the
	// write itself decides.
	info.CanConfigure = info.Running && (operator || c.goos == "darwin")
	if !info.Running && st.BackendState != "" {
		info.Error = "Tailscale is " + st.BackendState
	}
	return info
}

// operator reports whether this process may use write-level LocalAPI calls.
func (c *tailscaleClient) operator(prefs *tslocal.Prefs) bool {
	if c.mayConfigure != nil {
		return c.mayConfigure(prefs)
	}
	return c.tl.MayConfigure(prefs)
}

// guessHeadscale reports whether the node's MagicDNS name or suffix lies
// outside Tailscale's own domains (.ts.net, .tailscale.net). Unknown names
// guess nothing.
func guessHeadscale(st *tslocal.Status) bool {
	name := st.MagicDNSSuffix
	if st.Self != nil && st.Self.DNSName != "" {
		name = st.Self.DNSName
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return false
	}
	return !strings.HasSuffix(name, ".ts.net") && !strings.HasSuffix(name, ".tailscale.net") &&
		name != "ts.net" && name != "tailscale.net"
}
