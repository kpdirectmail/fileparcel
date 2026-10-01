package httpx

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fileparcel/internal/core"
)

// ProxySignals counts requests that reached FileParcel through a proxy it
// was not told about (DESIGN §10.6 "Hand-made Tailscale proxies"). Such a
// proxy makes every visitor look like one address, so the access policy,
// the rate limits and the audit trail no longer see the real clients:
//
//   - FunnelToMain: a request on the main HTTPS listener carried
//     Tailscale-Funnel-Request, i.e. a hand-made `tailscale funnel` (on this
//     machine or another tailnet node) points at FileParcel's own port. The
//     server refuses these requests (internal/server).
//   - LocalProxy: a request forwarded (X-Forwarded-For) by a peer on this
//     machine, or carrying Tailscale's identity header, while that peer is
//     not in server.trusted_proxies (mw.ResolveClientIP): `tailscale serve
//     localhost:8443`, cloudflared, nginx, … Detected only; the request is
//     served as before.
//
// The settings API (exposures) and the doctor read them. They are process
// wide and lock-free (package server and the middleware both write them).
var ProxySignals struct {
	FunnelToMain ProxySignal
	LocalProxy   ProxySignal
}

// ProxySignal is one counter of ProxySignals: how often, when last, and the
// host name the last request named (sanitised, for the hint).
type ProxySignal struct {
	count atomic.Int64
	last  atomic.Int64 // unix nanoseconds
	host  atomic.Pointer[string]
}

// ProxySignalSnapshot is a consistent-enough copy of a ProxySignal.
type ProxySignalSnapshot struct {
	Count int64
	Last  time.Time // zero when never seen
	Host  string
}

// Note records one request at now; host is the host name it named (the
// Host or X-Forwarded-Host header, client-controlled: it is sanitised). An
// empty host keeps the last one recorded.
func (s *ProxySignal) Note(host string, now time.Time) {
	if h := SanitizeHost(host); h != "" {
		s.host.Store(&h)
	}
	s.last.Store(now.UnixNano())
	s.count.Add(1)
}

// Snapshot returns the current values.
func (s *ProxySignal) Snapshot() ProxySignalSnapshot {
	out := ProxySignalSnapshot{Count: s.count.Load()}
	if n := s.last.Load(); n != 0 {
		out.Last = time.Unix(0, n).UTC()
	}
	if h := s.host.Load(); h != nil {
		out.Host = *h
	}
	return out
}

// Since reports whether the signal was seen at or after t.
func (s *ProxySignal) Since(t time.Time) bool {
	n := s.last.Load()
	return n != 0 && !time.Unix(0, n).Before(t)
}

// maxSignalHost bounds a recorded host name (a DNS name is at most 253
// characters, plus ":port").
const maxSignalHost = 260

// SanitizeHost reduces a client-supplied host[:port] to the characters a
// host name, an IP literal and a port can contain (letters, digits, '.',
// '-', '_', ':', '[', ']'), lowercased and bounded, so it can be shown in
// the UI and logged. Anything else is dropped.
func SanitizeHost(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if b.Len() >= maxSignalHost {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune(".-_:[]", r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Exposure IDs of the hand-made proxies (core.Exposure.ID on the Network
// page; the doctor reports them as network.funnel_bypass and
// network.proxy_unconfigured).
const (
	ExposureBypass     = "tailscale.bypass"
	ExposureLocalProxy = "proxy.local_unconfigured"
)

// ProxySignalWindow is how far back a proxy signal is reported.
const ProxySignalWindow = 24 * time.Hour

// maxBypassExposures bounds the foreign serve entries reported one by one.
const maxBypassExposures = 5

// ProxyExposures reports how hand-made proxies bypass the access policy
// (DESIGN §10.6): foreign Tailscale serve entries that target FileParcel's
// main port or admin socket (st.Foreign with Bypass; st may be nil), a
// Tailscale Funnel request that reached the main listener, and an
// unconfigured local proxy, the signals seen within ProxySignalWindow
// before now. Never nil.
func ProxyExposures(st *core.IngressStatus, now time.Time) []core.Exposure {
	out := []core.Exposure{}
	if st != nil {
		n := 0
		for _, f := range st.Foreign {
			if !f.Bypass {
				continue
			}
			if n++; n > maxBypassExposures {
				break
			}
			out = append(out, bypassExposure(f))
		}
	}
	since := now.Add(-ProxySignalWindow)
	if ProxySignals.FunnelToMain.Since(since) {
		s := ProxySignals.FunnelToMain.Snapshot()
		out = append(out, core.Exposure{ID: ExposureBypass, Severity: "fail",
			Message: "A Tailscale Funnel on this or another tailnet device forwards " + orUnknown(s.Host) +
				" to FileParcel's own port (last request " + s.Last.Format("2006-01-02 15:04 UTC") + "): every visitor " +
				"would look like one address, so FileParcel refuses these requests",
			// Only that entry: `tailscale funnel status` on that machine
			// lists its path (a bare off would remove every handler of
			// the port, FileParcel's own Funnel or Serve included).
			Hint: "On the machine that runs it, find that entry with `tailscale funnel status` and remove just it " +
				"(`tailscale serve --yes --https=" + strconv.Itoa(portOf(s.Host, 443)) + " --set-path=<its path> off`), " +
				"then use `fileparcel network funnel enable`."})
	}
	if ProxySignals.LocalProxy.Since(since) {
		s := ProxySignals.LocalProxy.Snapshot()
		out = append(out, core.Exposure{ID: ExposureLocalProxy, Severity: "warn",
			Message: "A proxy (" + orUnknown(s.Host) + ") forwards to FileParcel, and its visitors appear as the proxy's " +
				"address (last request " + s.Last.Format("2006-01-02 15:04 UTC") + ")",
			Hint: "Add the proxy's address to server.trusted_proxies so FileParcel sees the real clients, or publish " +
				"FileParcel with Tailscale Serve or Funnel instead."})
	}
	return out
}

// bypassExposure describes one foreign serve entry that reaches FileParcel's
// main listener or admin socket.
func bypassExposure(f core.ForeignServe) core.Exposure {
	where := f.HostPort + f.Mount
	e := core.Exposure{ID: ExposureBypass, Severity: "fail"}
	switch {
	case f.Funnel:
		e.Message = "Tailscale Funnel forwards " + where + " straight to FileParcel (" + f.Target + "): every visitor " +
			"would look like one address, so FileParcel refuses these requests"
	case strings.HasPrefix(f.Target, "unix:"):
		e.Message = "Tailscale Serve forwards " + where + " to FileParcel's admin socket (" + f.Target + "), which " +
			"refuses proxied requests"
	default:
		e.Message = "Tailscale Serve forwards " + where + " straight to FileParcel (" + f.Target + "): every tailnet " +
			"visitor looks like this machine, which the access policy always admits"
	}
	next := "use `fileparcel network funnel enable` or `fileparcel network tailscale-serve enable` instead."
	switch {
	case f.Foreground:
		e.Hint = "Stop the `tailscale serve` or `tailscale funnel` command that runs in the foreground, then " + next
	case f.Service != "":
		e.Hint = "Remove that handler from the Tailscale service " + f.Service + " (`tailscale serve status` lists it), then " + next
	default:
		e.Hint = "Remove it (" + serveOff(portOf(f.HostPort, 443)) + " on this machine), then " + next
	}
	return e
}

// serveOff is the command that removes every handler of an HTTPS port.
func serveOff(port int) string {
	return "`tailscale serve --yes --https=" + strconv.Itoa(port) + " off`"
}

// portOf returns the port of host:port (def without a valid one).
func portOf(hostPort string, def int) int {
	if i := strings.LastIndexByte(hostPort, ':'); i >= 0 && !strings.HasSuffix(hostPort, "]") {
		if n, err := strconv.Atoi(hostPort[i+1:]); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return def
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown host"
	}
	return s
}
