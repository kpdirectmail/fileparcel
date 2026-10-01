package tsingress

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
)

// buildStatus assembles the status from a read of tailscaled, the
// settings, the marker and what the last reconcile and probe found.
func (s *Service) buildStatus(ctx context.Context, v *tsView, d desired) *core.IngressStatus {
	m, err := s.loadMarker()
	if err != nil {
		m = nil
	}
	own := s.ownership(m)
	ports := s.ownPorts()
	transport := s.ts.Transport()
	if transport == "" {
		transport = "none"
	}
	st := &core.IngressStatus{Transport: transport, AllowAdmin: d.AllowAdmin, Require2FA: d.Require2FA,
		FunnelPorts: []int{}, Foreign: []core.ForeignServe{}}
	if s.net != nil {
		if ti, err := s.net.Tailscale(ctx); err == nil {
			st.Tailscale = ti
		}
	}
	s.stMu.Lock()
	kst := s.kst
	attached := s.lis != nil
	open := map[string]bool{}
	for k := range s.open {
		open[k] = true
	}
	s.stMu.Unlock()

	st.Funnel = s.entryStatus(core.IngressFunnel, d, v, m, own, ports, kst[0], attached, open[core.IngressFunnel])
	st.Serve = s.entryStatus(core.IngressServe, d, v, m, own, ports, kst[1], attached, open[core.IngressServe])

	st.Available = true
	for _, c := range st.Serve.Checks { // Funnel's own capability checks decide its entry only
		if c.Status == statusFail && slices.Contains([]string{checkContainer, checkRunning, checkMagicDNS, checkHTTPS}, c.ID) {
			st.Available = false
			st.Reason = strings.TrimSuffix(c.Message, ".") + "."
			if c.Hint != "" {
				st.Reason += " " + c.Hint
			}
			break
		}
	}
	if v.running() {
		for _, p := range v.st.FunnelPorts() {
			if !slices.Contains(ports, p) {
				st.FunnelPorts = append(st.FunnelPorts, p)
			}
		}
	}
	if v.sc != nil {
		st.Foreign = s.foreign(v, own)
	}
	return st
}

// entryStatus is the IngressEntry of kind.
func (s *Service) entryStatus(kind string, d desired, v *tsView, m *marker, own ownership, ports []int,
	ks kindState, attached, listening bool) core.IngressEntry {
	i := kindIndex(kind)
	port := d.port(kind)
	e := core.IngressEntry{Kind: kind, Mode: d.mode(kind), Port: port, Checks: []core.IngressCheck{}}
	name := v.name()
	if name == "" && m != nil {
		name = m.DNSName
	}
	if name != "" {
		e.HostPort = name + ":" + strconv.Itoa(port)
		e.URL = hostURL(strings.ToLower(name), port) + "/"
	}
	applied := false
	if v.sc != nil && e.HostPort != "" {
		cur, _ := v.sc.Proxy(e.HostPort, port)
		applied = cur != "" && own.kinds[cur] == kind && v.sc.FunnelOn(e.HostPort) == (kind == core.IngressFunnel)
	}
	wanted := d.wants(kind)
	e.Checks = append(e.Checks, s.prerequisites(kind, d, v, ports)...)
	e.Checks = append(e.Checks, s.portChecks(kind, d, v, own, applied)...)
	if wanted {
		e.Checks = append(e.Checks, nodeCheck(d, v))
	}
	e.Checks = append(e.Checks, runtimeChecks(ks, wanted)...)
	if c := s.passkeyCheck(kind, d, v); c != nil {
		e.Checks = append(e.Checks, *c)
	}

	e.Backend = ks.proxy
	if e.Backend == "" && wanted {
		if me := m.entry(kind); me != nil {
			e.Backend = me.Proxy
		}
	}
	e.AppliedAt = ks.appliedAt
	if e.AppliedAt == nil && applied && m != nil {
		e.AppliedAt = m.AppliedAt
	}
	e.LastRequestAt = unixTime(s.lastReq[i].Load())
	e.LastPublicRequestAt = unixTime(s.lastPublic[i].Load())
	e.ProbedAt = ks.probedAt
	e.State, e.Message = s.entryState(kind, d, v, m, e.Checks, ks, attached, listening, applied)
	if e.State == core.IngressStateActive && kind == core.IngressFunnel && e.AppliedAt != nil &&
		s.now().Sub(*e.AppliedAt) < dnsDelay && e.LastPublicRequestAt == nil {
		e.Message = "Public DNS can take up to 10 minutes to know the new address."
	}
	return e
}

// entryState decides the state of an entry (DESIGN §10.6 "Entry states").
func (s *Service) entryState(kind string, d desired, v *tsView, m *marker, checks []core.IngressCheck, ks kindState,
	attached, listening, applied bool) (string, string) {
	if !d.wants(kind) {
		if ks.state == core.IngressStateError {
			return ks.state, ks.message // the removal failed
		}
		return core.IngressStateOff, ""
	}
	if !v.running() {
		return core.IngressStateUnavailable, unavailableMessage(v)
	}
	if c := nodeCheck(d, v); c.Status == statusFail {
		return core.IngressStatePaused, c.Message
	}
	for _, c := range checks {
		if c.Status != statusFail {
			continue
		}
		switch c.ID {
		case checkPortFree:
			return core.IngressStateConflict, c.Message
		case checkBackend, checkNode:
		default:
			return core.IngressStateUnavailable, c.Message
		}
	}
	if !attached {
		switch {
		case m.entry(kind) == nil:
			return core.IngressStateDrift, driftMessage(kind, nil)
		case m.waiting():
			return core.IngressStateStopped, "FileParcel publishes it on Tailscale when the server starts."
		}
		return core.IngressStateStopped, "The server is not running."
	}
	if kind == core.IngressServe && s.serveFunnel.Load() {
		return core.IngressStateConflict, "A Funnel request reached FileParcel's tailnet-only Serve port: " +
			"Funnel was turned on for it outside FileParcel, and FileParcel switches it off."
	}
	switch ks.state {
	case core.IngressStateConflict, core.IngressStateError:
		return ks.state, ks.message
	case "":
		return core.IngressStateUnavailable, "FileParcel has not checked Tailscale yet."
	}
	switch {
	case applied && listening:
		return core.IngressStateActive, ""
	case v.sc == nil && ks.state == core.IngressStateActive:
		return core.IngressStateActive, ""
	case ks.state == core.IngressStateDrift:
		return ks.state, ks.message
	}
	return core.IngressStateDrift, driftMessage(kind, m)
}

func unixTime(n int64) *time.Time {
	if n == 0 {
		return nil
	}
	t := time.Unix(0, n).UTC()
	return &t
}

// foreign lists the serve-config entries FileParcel did not create, and
// marks those that reach FileParcel's main listener or admin socket
// directly (every visitor would appear as one local address).
func (s *Service) foreign(v *tsView, own ownership) []core.ForeignServe {
	out := []core.ForeignServe{}
	local := s.localHost(v)
	mains := s.mainPorts()
	admin := s.adminSocket()
	for _, e := range v.sc.Entries() {
		if !e.Foreground && e.Service == "" && e.Mount == "/" && e.HostPort != "" && own.owned(e.Proxy) {
			continue
		}
		hp := e.HostPort
		if hp == "" {
			hp = v.name() + ":" + strconv.Itoa(e.Port)
		}
		out = append(out, core.ForeignServe{HostPort: hp, Mount: e.Mount, Target: e.Target(), Funnel: e.Funnel,
			Foreground: e.Foreground, Service: e.Service, Bypass: entryBypass(e, mains, admin, local)})
	}
	return out
}

// entryBypass reports whether a serve entry targets FileParcel's main port
// or admin socket.
func entryBypass(e tslocal.ServeEntry, mains []int, adminSock string, local func(string) bool) bool {
	return bypassTarget(e.Proxy, mains, adminSock, local) || bypassTarget(e.TCPForward, mains, adminSock, local)
}

// bypassTarget reports whether a Serve/Funnel target reaches FileParcel's
// main listener (a bare port, host:port, http://, https://,
// https+insecure:// or tcp:// on a local host) or its admin socket
// (unix:<HOME>/run/admin.sock, also through a symlink).
func bypassTarget(target string, mains []int, adminSock string, local func(string) bool) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if p, ok := strings.CutPrefix(target, "unix:"); ok {
		return adminSock != "" && sameFile(p, adminSock)
	}
	var host string
	var port int
	switch {
	case strings.Contains(target, "://"):
		u, err := url.Parse(target)
		if err != nil {
			return false
		}
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = 80
		case "https", "https+insecure":
			port = 443
		case "tcp":
		default:
			return false
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
	default:
		if n, err := strconv.Atoi(target); err == nil {
			host, port = "localhost", n // tailscale expands a bare port to http://127.0.0.1:<port>
			break
		}
		h, p, err := net.SplitHostPort(target)
		if err != nil {
			return false
		}
		host = h
		port, _ = strconv.Atoi(p)
	}
	return slices.Contains(mains, port) && local(host)
}

// sameFile reports whether path names the file want (directly or through
// a symlink).
func sameFile(path, want string) bool {
	if filepath.Clean(path) == filepath.Clean(want) {
		return true
	}
	a, err1 := os.Stat(path)
	b, err2 := os.Stat(want)
	return err1 == nil && err2 == nil && os.SameFile(a, b)
}

// localHost returns whether a target host is this machine: localhost,
// loopback, unspecified, any local address, or the node's own names.
func (s *Service) localHost(v *tsView) func(string) bool {
	names := []string{"localhost"}
	if n := v.dnsName(); n != "" {
		names = append(names, n)
	}
	if v != nil && v.st != nil && v.st.Self != nil && v.st.Self.HostName != "" {
		names = append(names, strings.ToLower(v.st.Self.HostName))
	}
	var tsIPs []netip.Addr
	if v != nil && v.st != nil {
		tsIPs = v.st.IPs()
	}
	return func(host string) bool {
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		if h == "" || slices.Contains(names, h) || strings.HasSuffix(h, ".localhost") {
			return true
		}
		ip, err := netip.ParseAddr(h)
		if err != nil {
			return false
		}
		ip = ip.Unmap().WithZone("")
		return ip.IsLoopback() || ip.IsUnspecified() || slices.Contains(tsIPs, ip) || (s.net != nil && s.net.IsLocal(ip))
	}
}
