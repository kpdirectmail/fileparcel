package tsingress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
)

// How tailscaled reaches FileParcel (funnel.backend, DESIGN §10.6
// "Backend choice") and the ingress listeners behind it.

// backendSpec is how tailscaled reaches one ingress listener.
type backendSpec struct {
	backend  string // BackendUnix | BackendTCP
	network  string // "unix" | "tcp4" (core.IngressListeners.Open)
	address  string // socket path | 127.0.0.1:port
	proxy    string // the serve-config target: unix:<path> | http://127.0.0.1:<port>
	fallback bool   // auto chose TCP because tailscaled refused the socket
}

func tcpProxy(port int) string { return "http://127.0.0.1:" + strconv.Itoa(port) }

// maxSocketPath is the longest Unix socket path tailscaled can dial (the
// admin socket's short-alias trick does not apply to a foreign dialer).
func maxSocketPath(goos string) int {
	if goos == "linux" {
		return 107
	}
	return 103
}

// backendMode resolves funnel.backend (auto: the Unix socket on Linux and
// the BSDs unless tailscaled refused it; TCP on macOS, whose sandboxed
// Tailscale builds cannot reach a socket in a home, and Windows).
func (s *Service) backendMode(d desired) (mode string, fallback bool) {
	switch d.Backend {
	case BackendUnix:
		return BackendUnix, false
	case BackendTCP:
		return BackendTCP, false
	}
	if s.goos == "darwin" || s.goos == "windows" {
		return BackendTCP, false
	}
	s.stMu.Lock()
	refused := s.unixRefused
	s.stMu.Unlock()
	if refused {
		return BackendTCP, true
	}
	return BackendUnix, false
}

// backends returns the listener of each kind for the wanted backend. A
// TCP backend without a port gets one now (stored in funnel.backend_port).
func (s *Service) backends(ctx context.Context, d desired, active [2]bool) (map[string]backendSpec, error) {
	out := map[string]backendSpec{}
	if !active[0] && !active[1] {
		return out, nil
	}
	mode, fallback := s.backendMode(d)
	if mode == BackendUnix {
		for _, k := range kinds {
			if p := s.sockPath(k); p == "" || len(p) > maxSocketPath(s.goos) {
				if d.Backend == BackendUnix {
					return nil, fmt.Errorf("the socket path %s is longer than %d bytes, which tailscaled cannot dial; "+
						"set funnel.backend to tcp", p, maxSocketPath(s.goos))
				}
				mode = BackendTCP
				break
			}
		}
	}
	if mode == BackendUnix {
		for _, k := range kinds {
			p := s.sockPath(k)
			out[k] = backendSpec{backend: BackendUnix, network: "unix", address: p, proxy: "unix:" + p}
		}
		return out, nil
	}
	port := d.BackendPort
	if port == 0 {
		var err error
		if port, err = s.chooseBackendPort(ctx); err != nil {
			return nil, err
		}
	}
	for i, k := range kinds {
		p := port + i
		out[k] = backendSpec{backend: BackendTCP, network: "tcp4", address: "127.0.0.1:" + strconv.Itoa(p),
			proxy: tcpProxy(p), fallback: fallback}
	}
	return out, nil
}

// plannedBackends is backends without side effects (the offline CLI): a
// TCP backend without a port yet has no proxy.
func (s *Service) plannedBackends(d desired) map[string]backendSpec {
	out := map[string]backendSpec{}
	mode, _ := s.backendMode(d)
	for i, k := range kinds {
		switch p := s.sockPath(k); {
		case mode == BackendUnix && p != "" && len(p) <= maxSocketPath(s.goos):
			out[k] = backendSpec{backend: BackendUnix, network: "unix", address: p, proxy: "unix:" + p}
		case d.BackendPort > 0:
			port := d.BackendPort + i
			out[k] = backendSpec{backend: BackendTCP, network: "tcp4", address: "127.0.0.1:" + strconv.Itoa(port), proxy: tcpProxy(port)}
		default:
			out[k] = backendSpec{backend: BackendTCP}
		}
	}
	return out
}

// chooseBackendPort picks the TCP backend's port pair: 18443/18444 when
// both are free, else a random free pair in 20000–60000, never FileParcel's
// own ports. It is stored in funnel.backend_port.
func (s *Service) chooseBackendPort(ctx context.Context) (int, error) {
	own := s.ownPorts()
	usable := func(p int) bool {
		return !slices.Contains(own, p) && !slices.Contains(own, p+1) && s.portFree(p) && s.portFree(p+1)
	}
	port := 0
	if usable(18443) {
		port = 18443
	}
	for i := 0; i < 64 && port == 0; i++ {
		if p := 20000 + rand.IntN(40000); usable(p) {
			port = p
		}
	}
	if port == 0 {
		return 0, errors.New("no free pair of local ports for the TCP connection from Tailscale; set funnel.backend_port")
	}
	if st := s.env.Settings; st != nil {
		sys := core.SystemPrincipal(core.ViaOffline)
		change := map[string]json.RawMessage{KeyBackendPort: json.RawMessage(strconv.Itoa(port))}
		if _, err := st.Set(core.WithPrincipal(ctx, sys), sys, change); err != nil {
			return 0, fmt.Errorf("storing funnel.backend_port: %w", err)
		}
	}
	return port, nil
}

// switchToTCP moves the ingress listeners to the TCP backend after
// tailscaled refused a Unix-socket target (auto backend only, once).
func (s *Service) switchToTCP(ctx context.Context, d desired, active, hold *[2]bool, be *map[string]backendSpec, v *tsView,
	own ownership, out *outcome) bool {
	if d.Backend != BackendAuto {
		return false
	}
	usesUnix := false
	for _, spec := range *be {
		usesUnix = usesUnix || spec.backend == BackendUnix
	}
	s.stMu.Lock()
	refused := s.unixRefused
	s.unixRefused = true
	s.stMu.Unlock()
	if !usesUnix || refused {
		return false
	}
	nbe, err := s.backends(ctx, d, *active)
	if err != nil {
		return false
	}
	*be = nbe
	for i, k := range kinds {
		if !active[i] {
			continue
		}
		if err := s.openKind(k, nbe[k], d, v, own); err != nil {
			out.k[i] = kindOutcome{state: core.IngressStateError, message: "the ingress listener could not be opened: " + err.Error(),
				err: err, backend: true}
			active[i], hold[i] = false, true
		}
	}
	return true
}

// policyFor is the policy of kind's open listener under d.
func policyFor(kind string, d desired, dnsName string) *core.IngressPolicy {
	p := &core.IngressPolicy{Mode: d.mode(kind), DNSName: dnsName, Port: d.port(kind)}
	if kind == core.IngressFunnel {
		p.AllowAdmin, p.Require2FA = d.AllowAdmin, d.Require2FA
	}
	return p
}

// addrListeners is implemented by listener managers that can hold a
// kind's listener at more than one address (server's ingressManager):
// with the TCP backend, the old 127.0.0.1 port stays bound next to the new
// listener while tailscaled may still route to it.
type addrListeners interface {
	// OpenAt opens kind's listener at address and keeps its other ones.
	OpenAt(kind, network, address string, peerUIDs []int) error
	// CloseAt closes kind's listener at address.
	CloseAt(kind, network, address string)
}

// routed reports whether tailscaled may still send requests to proxy, a
// target FileParcel wrote: own lists it, and sc (the configuration
// tailscaled has, nil when unknown) still has an entry of FileParcel's
// with it.
func routed(sc *tslocal.ServeConfig, proxy string, own ownership) bool {
	if proxy == "" || !own.owned(proxy) {
		return false
	}
	if sc == nil {
		return true
	}
	return slices.ContainsFunc(own.entries(sc), func(e ownedEntry) bool { return e.proxy == proxy })
}

// keepsPort reports whether the listener spec must stay bound while
// tailscaled may route to it: a 127.0.0.1 port any local program could
// take (a Unix socket cannot be taken: nobody else can create one in the
// 0700 run directory).
func keepsPort(spec backendSpec, sc *tslocal.ServeConfig, own ownership) bool {
	return spec.backend == BackendTCP && routed(sc, spec.proxy, own)
}

// openKind opens (or keeps) kind's ingress listener and publishes its
// policy first: tailscaled may connect as soon as the listener exists. A
// TCP listener at another address that tailscaled may still route to (v's
// configuration) stays bound as the kind's previous listener until a
// write no longer references it (settleKind).
func (s *Service) openKind(kind string, spec backendSpec, d desired, v *tsView, own ownership) error {
	i := kindIndex(kind)
	s.stMu.Lock()
	lis := s.lis
	cur, isOpen := s.open[kind]
	prev, hasPrev := s.prev[kind]
	s.stMu.Unlock()
	if lis == nil {
		return errors.New("the server is not running")
	}
	s.policy[i].Store(policyFor(kind, d, v.dnsName()))
	if isOpen && cur.network == spec.network && cur.address == spec.address {
		return nil
	}
	al, multi := lis.(addrListeners)
	if !multi {
		if err := lis.Open(kind, spec.network, spec.address, s.peerUIDs()); err != nil {
			s.policy[i].Store(&core.IngressPolicy{Mode: core.FunnelOff})
			s.stMu.Lock()
			delete(s.open, kind)
			s.stMu.Unlock()
			return err
		}
		s.stMu.Lock()
		s.open[kind] = spec
		s.stMu.Unlock()
		return nil
	}
	keepCur := isOpen && keepsPort(cur, v.sc, own)
	var closing []backendSpec
	next, hasNext := prev, hasPrev
	switch {
	case hasPrev && prev.network == spec.network && prev.address == spec.address:
		// The listener tailscaled still routes to is wanted again.
		hasNext = false
		if isOpen {
			if keepCur {
				next, hasNext = cur, true
			} else {
				closing = append(closing, cur)
			}
		}
	default:
		if err := al.OpenAt(kind, spec.network, spec.address, s.peerUIDs()); err != nil {
			// The current listener stays as it is (bound, answering 404).
			s.policy[i].Store(&core.IngressPolicy{Mode: core.FunnelOff})
			return err
		}
		if isOpen {
			if keepCur {
				if hasPrev {
					closing = append(closing, prev) // one previous listener per kind
				}
				next, hasNext = cur, true
			} else {
				closing = append(closing, cur)
			}
		}
	}
	s.stMu.Lock()
	s.open[kind] = spec
	if hasNext {
		s.prev[kind] = next
	} else {
		delete(s.prev, kind)
	}
	s.stMu.Unlock()
	for _, c := range closing {
		al.CloseAt(kind, c.network, c.address)
	}
	return nil
}

// openFromMarker opens kind's listener as the marker describes it while
// tailscaled cannot be asked (start before tailscaled): the listener of a
// wanted kind, so that it works as soon as tailscaled is back with its
// saved configuration, and the 127.0.0.1 port of an entry that is no
// longer wanted (policy off), so that no other local program can take it
// before the entry is removed.
func (s *Service) openFromMarker(kind string, d desired, m *marker, own ownership) {
	e := m.entry(kind)
	if e == nil || e.Proxy == "" || !own.owned(e.Proxy) {
		return
	}
	var spec backendSpec
	switch addr, ok := strings.CutPrefix(e.Proxy, "http://"); {
	case e.Proxy == "unix:"+s.sockPath(kind) && d.wants(kind):
		spec = backendSpec{backend: BackendUnix, network: "unix", address: s.sockPath(kind), proxy: e.Proxy}
	case ok && strings.HasPrefix(addr, "127.0.0.1:"):
		spec = backendSpec{backend: BackendTCP, network: "tcp4", address: addr, proxy: e.Proxy}
	default:
		return
	}
	dd := d
	if kind == core.IngressFunnel {
		dd.Port = e.Port
	} else {
		dd.ServePort = e.Port
	}
	v := &tsView{st: &tslocal.Status{Self: &tslocal.SelfStatus{DNSName: m.DNSName}}}
	if err := s.openKind(kind, spec, dd, v, own); err != nil {
		s.log.Warn("tsingress: could not open the ingress listener", "kind", kind, "err", err)
	}
}

// releaseKind switches kind's policy off (fail closed: the uniform 404)
// and closes its listeners tailscaled no longer routes to per sc (the
// configuration tailscaled has; nil when unknown): a Unix socket at once,
// a TCP port only once sc no longer has FileParcel's entry for it. It
// reports whether a TCP listener stays bound.
func (s *Service) releaseKind(kind string, sc *tslocal.ServeConfig, own ownership) (kept bool) {
	s.policy[kindIndex(kind)].Store(&core.IngressPolicy{Mode: core.FunnelOff})
	return s.settleKind(kind, sc, own, true)
}

// settleKind closes kind's previous listener (and with current, its
// current one) once tailscaled no longer routes to it per sc; it reports
// whether one of them stays bound.
func (s *Service) settleKind(kind string, sc *tslocal.ServeConfig, own ownership, current bool) (kept bool) {
	s.stMu.Lock()
	lis := s.lis
	cur, isOpen := s.open[kind]
	prev, hasPrev := s.prev[kind]
	isOpen = isOpen && current
	closeCur := isOpen && !keepsPort(cur, sc, own)
	closePrev := hasPrev && !keepsPort(prev, sc, own)
	if closeCur {
		delete(s.open, kind)
	}
	if closePrev {
		delete(s.prev, kind)
	}
	_, stillOpen := s.open[kind]
	_, stillPrev := s.prev[kind]
	s.stMu.Unlock()
	kept = isOpen && !closeCur || hasPrev && !closePrev
	if lis == nil || !closeCur && !closePrev {
		return kept
	}
	al, multi := lis.(addrListeners)
	switch {
	case !stillOpen && !stillPrev:
		lis.Close(kind)
	case multi && closeCur:
		al.CloseAt(kind, cur.network, cur.address)
	case multi && closePrev:
		al.CloseAt(kind, prev.network, prev.address)
	}
	return kept
}

// closeKind switches kind's policy off (fail closed), then closes all its
// listeners.
func (s *Service) closeKind(kind string) {
	s.policy[kindIndex(kind)].Store(&core.IngressPolicy{Mode: core.FunnelOff})
	s.stMu.Lock()
	lis := s.lis
	_, isOpen := s.open[kind]
	_, hasPrev := s.prev[kind]
	delete(s.open, kind)
	delete(s.prev, kind)
	s.stMu.Unlock()
	if lis != nil && (isOpen || hasPrev) {
		lis.Close(kind)
	}
}

// foreignOnBackend returns where a serve entry FileParcel does not own
// forwards to proxy, a 127.0.0.1 port FileParcel is about to use for kind
// (a program published there by hand), other than FileParcel's own
// HostPort hp for it; "" when there is none. FileParcel neither takes
// such an entry over nor removes it.
func foreignOnBackend(sc *tslocal.ServeConfig, proxy, hp string, own ownership) string {
	if sc == nil || backendOf(proxy) != BackendTCP || own.owned(proxy) {
		return ""
	}
	for _, e := range sc.Entries() {
		if e.Proxy != proxy || e.HostPort == hp && !e.Foreground && e.Service == "" && e.Mount == "/" {
			continue
		}
		if e.HostPort != "" {
			return e.HostPort
		}
		return "port " + strconv.Itoa(e.Port)
	}
	return ""
}

// backendOf derives the backend from a serve-config target.
func backendOf(proxy string) string {
	switch {
	case strings.HasPrefix(proxy, "unix:"):
		return BackendUnix
	case proxy != "":
		return BackendTCP
	}
	return ""
}
