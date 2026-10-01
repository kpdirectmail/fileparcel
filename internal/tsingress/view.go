package tsingress

import (
	"context"
	"errors"
	"strings"
	"time"

	"fileparcel/internal/tslocal"
)

// tsView is one read of tailscaled: node status, preferences and the serve
// configuration.
type tsView struct {
	at    time.Time
	st    *tslocal.Status
	prefs *tslocal.Prefs       // nil when unreadable (optional)
	sc    *tslocal.ServeConfig // nil when unreadable
	err   error                // the status could not be read (not installed, not running, timeout)
	scErr error
}

// running reports whether tailscaled answered and is connected.
func (v *tsView) running() bool { return v != nil && v.err == nil && v.st.Running() }

// name returns the HostPort name of the node ("" when unknown).
func (v *tsView) name() string {
	if v == nil || v.st == nil {
		return ""
	}
	return v.st.HostPortName()
}

// dnsName returns the lowercase MagicDNS name (the Host tailscaled's clients
// use; "" when unknown).
func (v *tsView) dnsName() string { return strings.ToLower(v.name()) }

// selfHosted reports whether the node uses a control server other than
// Tailscale's (Headscale, …).
func (v *tsView) selfHosted() bool {
	return v != nil && v.prefs != nil && tslocal.SelfHosted(v.prefs.ControlURL)
}

// readView returns a read of tailscaled not older than maxAge (0 = read
// now). It is cached for Status and invalidated after every write.
func (s *Service) readView(ctx context.Context, maxAge time.Duration) *tsView {
	s.stMu.Lock()
	v := s.view
	s.stMu.Unlock()
	if v != nil && maxAge > 0 && s.now().Sub(v.at) < maxAge {
		return v
	}
	nv := &tsView{at: s.now()}
	nv.st, nv.err = s.ts.Status(ctx)
	if nv.err == nil {
		if p, err := s.ts.Prefs(ctx); err == nil {
			nv.prefs = p
		}
		nv.sc, nv.scErr = s.ts.ServeConfig(ctx)
	}
	s.stMu.Lock()
	s.view = nv
	s.stMu.Unlock()
	return nv
}

// invalidateView forgets the cached read (after a write to tailscaled).
func (s *Service) invalidateView() {
	s.stMu.Lock()
	s.view = nil
	s.stMu.Unlock()
}

// unavailableMessage describes why tailscaled cannot be used.
func unavailableMessage(v *tsView) string {
	switch {
	case v == nil:
		return "Tailscale has not been checked yet"
	case errors.Is(v.err, tslocal.ErrNotInstalled):
		return "Tailscale is not installed on this machine"
	case v.err != nil:
		return "tailscaled does not answer: " + v.err.Error()
	case !v.st.Running():
		return errNotRunning(v.st).Error()
	}
	return ""
}

// fixURL is a cached query-feature answer for Funnel.
type fixURL struct {
	at       time.Time
	complete bool
	url      string
}

// maxFixURL bounds a fix_url from tailscaled (shown as a link, never fetched).
const maxFixURL = 512

// refreshFix asks tailscaled where Funnel can be enabled for this node
// (query-feature; on ?refresh=1 and after a failed enable), cached.
func (s *Service) refreshFix(ctx context.Context) {
	s.stMu.Lock()
	f := s.fix
	s.stMu.Unlock()
	if f != nil && s.now().Sub(f.at) < s.t.fixTTL {
		return
	}
	q, err := s.ts.QueryFeature(ctx, "funnel")
	if err != nil {
		return
	}
	nf := &fixURL{at: s.now(), complete: q.Complete}
	if u := q.URL; strings.HasPrefix(u, "https://") && len(u) <= maxFixURL && !strings.ContainsAny(u, " \t\r\n\"'<>") {
		nf.url = u
	}
	s.stMu.Lock()
	s.fix = nf
	s.stMu.Unlock()
}
