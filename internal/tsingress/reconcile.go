package tsingress

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/tslocal"
)

// recOpts parameterizes a reconcile.
type recOpts struct {
	// reason names the trigger: start, retry, settings, network,
	// funnel_flag (automatic) or user, reapply, revert.
	reason string
	// add marks the kinds a person asked for (SetFunnel, SetServe: that
	// kind; Reapply: both): a wanted entry of such a kind that tailscaled
	// lacks is written. Otherwise a missing entry is written only when the
	// marker is pending or suspended, and is reported as drift else.
	add [2]bool
}

// user reports whether a person asked for the change.
func (o recOpts) user() bool { return o.add[0] || o.add[1] }

// kindOutcome is what one reconcile found or did for one kind.
type kindOutcome struct {
	state    string // core.IngressState*
	message  string
	check    *core.IngressCheck // the failing check (unavailable, paused)
	conflict string             // the foreign target (conflict)
	err      error              // the tailscaled or listener error (error)
	backend  bool               // the error is the backend's (listener, socket path, TCP port)
}

// outcome is the result of one reconcile.
type outcome struct {
	k           [2]kindOutcome
	unreachable bool  // tailscaled could not be read or is not connected
	wrote       bool  // the serve configuration was written
	err         error // the error of reading or writing the serve configuration
}

// ownership tells FileParcel's serve-config targets apart (DESIGN §10.6):
// the two ingress sockets of this home and the targets this home's marker
// lists (loadMarkerOf drops a copied home's marker). A listed socket of
// another home counts only while that home is gone (a moved home), so a
// home never claims a live installation's entry. The TCP backend's targets
// are owned once written (the marker), and while a reconcile publishes a
// kind with them (added there) — never just because of funnel.backend_port.
type ownership struct{ kinds map[string]string } // proxy → kind

func (s *Service) ownership(m *marker) ownership { return ownershipFor(s.home(), m) }

// ownershipFor is the ownership of home h (nil: none) whose marker is m.
func ownershipFor(h *home.Home, m *marker) ownership {
	o := ownership{kinds: map[string]string{}}
	if h == nil {
		return o
	}
	for _, k := range kinds {
		o.kinds["unix:"+filepath.Join(h.RunDir(), "ts-"+k+".sock")] = k
	}
	for _, e := range m.entries() {
		if e.Proxy == "" || kindIndex(e.Kind) < 0 {
			continue
		}
		if p, ok := strings.CutPrefix(e.Proxy, "unix:"); ok {
			if dir := filepath.Dir(filepath.Dir(p)); !sameDir(dir, h.Dir()) && !homeGone(dir) {
				continue // the socket of another installation that still exists
			}
		}
		o.kinds[e.Proxy] = e.Kind
	}
	return o
}

// loadMarker reads this home's marker (loadMarkerOf).
func (s *Service) loadMarker() (*marker, error) {
	m, err := readMarker(s.home())
	if err == nil && m != nil && foreignMarker(s.home(), m) {
		s.stMu.Lock()
		logged := s.foreignLogged
		s.foreignLogged = true
		s.stMu.Unlock()
		if !logged {
			s.log.Info("tsingress: ignoring the Tailscale marker of the installation in " + m.Home +
				" (this home is a copy of it); nothing is published from here until you turn Funnel or Serve on or Re-apply")
		}
		return nil, nil
	}
	return m, err
}

func (o ownership) owned(proxy string) bool { _, ok := o.kinds[proxy]; return ok }

// ownedEntry is one of FileParcel's entries in a serve configuration.
type ownedEntry struct {
	kind     string
	hostPort string
	port     int
	proxy    string
	funnel   bool
}

// entries returns FileParcel's entries of sc: top-level mounts "/" whose
// target is owned (foreground sessions and services are never FileParcel's).
func (o ownership) entries(sc *tslocal.ServeConfig) []ownedEntry {
	var out []ownedEntry
	for _, e := range sc.Entries() {
		if e.Foreground || e.Service != "" || e.Mount != "/" || e.HostPort == "" {
			continue
		}
		if k, ok := o.kinds[e.Proxy]; ok {
			out = append(out, ownedEntry{kind: k, hostPort: e.HostPort, port: e.Port, proxy: e.Proxy, funnel: e.Funnel})
		}
	}
	return out
}

// reconcileLocked brings tailscaled's serve configuration, the ingress
// listeners, the marker and the policy snapshot in line with d (DESIGN
// §10.6 "Reconcile"). The caller holds s.mu.
//
// A kind that is no longer published has its policy switched off first
// (the uniform 404). Its Unix socket closes at once (tailscaled answers
// 502; nobody else can create a socket in the 0700 run directory), but a
// 127.0.0.1 port stays bound until tailscaled no longer routes to it: any
// local program could take a free port and serve its own pages at the
// public address. A removal that fails is retried.
func (s *Service) reconcileLocked(ctx context.Context, d desired, o recOpts) *outcome {
	out := &outcome{}
	m, err := s.loadMarker()
	if err != nil {
		s.log.Warn("tsingress: ignoring an unreadable marker", "err", err)
		m = nil
	}
	own := s.ownership(m)
	v := s.readView(ctx, s.t.reconcileTTL)
	attached := s.attached()

	if !v.running() {
		// Leave tailscaled as it is. Wanted listeners stay (or, at start,
		// are opened from the marker): tailscaled keeps its serve
		// configuration across its own restarts, so they work again as
		// soon as it is back. So does the TCP port of an entry that is no
		// longer wanted and cannot be removed now (policy off).
		msg := unavailableMessage(v)
		removals := false
		for i, k := range kinds {
			switch {
			case d.wants(k):
				out.k[i] = kindOutcome{state: core.IngressStateUnavailable, message: msg}
				if attached {
					s.openFromMarker(k, d, m, own)
				}
			case m.entry(k) != nil:
				s.releaseKind(k, nil, own)
				if attached {
					s.openFromMarker(k, d, m, own)
				}
				removals = true
				out.k[i] = kindOutcome{state: core.IngressStateError, message: removalFailed(m.entry(k).Port, nil, msg)}
			default:
				s.releaseKind(k, nil, own)
				out.k[i].state = core.IngressStateOff
			}
		}
		out.unreachable = true
		if attached && (d.anyWanted() || removals) {
			s.scheduleRetry()
		}
		s.finish(d, v, m, nil, out, [2]bool{})
		return out
	}
	s.stopRetry()
	st := v.st
	name := st.HostPortName()

	if d.Node != "" && d.Node != st.NodeID() {
		c := nodeCheck(d, v)
		for i, k := range kinds {
			s.releaseKind(k, v.sc, own)
			if d.wants(k) {
				out.k[i] = kindOutcome{state: core.IngressStatePaused, message: c.Message, check: &c}
			} else {
				out.k[i].state = core.IngressStateOff
			}
		}
		s.resetRetry()
		s.finish(d, v, m, nil, out, [2]bool{})
		return out
	}

	// A wanted kind whose prerequisites fail is not applied. Its entry
	// stays as it is (tailscaled enforces its own capabilities), except
	// that an entry that would take FileParcel's own port is removed.
	ports := s.ownPorts()
	var active, hold [2]bool
	for i, k := range kinds {
		if !d.wants(k) {
			continue
		}
		if f := firstFailure(s.prerequisites(k, d, v, ports)); f != nil {
			out.k[i] = kindOutcome{state: core.IngressStateUnavailable, message: f.Message, check: f}
			hold[i] = f.ID != checkPortFileParcel
			continue
		}
		active[i] = true
	}
	if active[0] && active[1] && d.Port == d.ServePort {
		out.k[1] = kindOutcome{state: core.IngressStateConflict, conflict: "FileParcel's Funnel entry",
			message: "Tailscale Funnel uses port " + strconv.Itoa(d.Port) + "; choose another port for Serve"}
		active[1] = false
	}

	if !attached {
		s.resetRetry()
		s.reconcileOffline(ctx, d, v, m, own, active, hold, out)
		return out
	}

	be, err := s.backends(ctx, d, active)
	if err != nil {
		for i := range kinds {
			if active[i] {
				out.k[i] = kindOutcome{state: core.IngressStateError, message: err.Error(), err: err, backend: true}
				active[i], hold[i] = false, true
			}
		}
	}
	s.claimBackends(be, name, d, v, own, &active, &hold, out)
	for i, k := range kinds {
		if !active[i] && !hold[i] {
			s.releaseKind(k, v.sc, own)
		}
	}
	for i, k := range kinds {
		if !active[i] {
			continue
		}
		if err := s.openKind(k, be[k], d, v, own); err != nil {
			msg := "the ingress listener could not be opened: " + err.Error()
			out.k[i] = kindOutcome{state: core.IngressStateError, message: msg, err: err, backend: true}
			active[i], hold[i] = false, true
		}
	}

	allowAdd := [2]bool{o.add[0] || m.waiting(), o.add[1] || m.waiting()}
	var pr planResult
	final := (*tslocal.ServeConfig)(nil)
	for attempt := 0; attempt < 3; attempt++ {
		sc, err := s.ts.ServeConfig(ctx)
		if err != nil {
			out.err = err
			break
		}
		work := sc.Clone()
		pr = s.plan(work, name, d, active, hold, be, own, allowAdd, m)
		if !pr.any() {
			final, out.err = sc, nil
			break
		}
		err = s.write(ctx, sc, work, name, own)
		if err == nil {
			final, out.err, out.wrote = work, nil, true
			break
		}
		out.err = err
		if errors.Is(err, tslocal.ErrETagMismatch) {
			continue
		}
		if errors.Is(err, tslocal.ErrUnixForbidden) && s.switchToTCP(ctx, d, &active, &hold, &be, v, own, out) {
			s.claimBackends(be, name, d, v, own, &active, &hold, out)
			attempt-- // the retry with TCP does not count; switchToTCP succeeds once
			continue
		}
		if errors.Is(err, tslocal.ErrConfigLocked) {
			s.stMu.Lock()
			s.configLocked = true
			s.stMu.Unlock()
		}
		break
	}
	if out.wrote {
		s.invalidateView()
		s.stMu.Lock()
		s.configLocked = false
		s.stMu.Unlock()
	}

	for i, k := range kinds {
		switch {
		case !d.wants(k):
			if out.err != nil && (pr.changed[i] || final == nil && m.entry(k) != nil) {
				port := d.port(k)
				if len(pr.removed[i]) > 0 {
					port = pr.removed[i][0]
				} else if e := m.entry(k); e != nil {
					port = e.Port
				}
				out.k[i] = kindOutcome{state: core.IngressStateError, message: removalFailed(port, out.err, ""), err: out.err}
			} else {
				out.k[i] = kindOutcome{state: core.IngressStateOff}
			}
		case !active[i]:
			// unavailable, error or conflict: set above
		case pr.conflict[i] != "":
			c := core.IngressCheck{ID: checkPortFree, Label: "Port free in Tailscale", Status: statusFail,
				Message: pr.conflict[i] + " already uses port " + strconv.Itoa(d.port(k)) + " on this device"}
			out.k[i] = kindOutcome{state: core.IngressStateConflict, message: c.Message, check: &c, conflict: pr.conflict[i]}
		case out.err != nil && (pr.changed[i] || final == nil):
			out.k[i] = kindOutcome{state: core.IngressStateError, message: tailscaleErrorMessage(out.err), err: out.err}
		case pr.drift[i] != "":
			out.k[i] = kindOutcome{state: core.IngressStateDrift, message: pr.drift[i]}
		default:
			out.k[i] = kindOutcome{state: core.IngressStateActive}
		}
	}
	// Release what tailscaled no longer routes to (final: what it has now;
	// nil when the write failed, so every port it may still use stays
	// bound).
	retry := false
	for i, k := range kinds {
		if !active[i] && !hold[i] || pr.conflict[i] != "" {
			s.releaseKind(k, final, own)
		} else {
			s.settleKind(k, final, own, false)
		}
		retry = retry || !d.wants(k) && out.k[i].state == core.IngressStateError
	}
	if retry {
		s.scheduleRetry()
	} else {
		s.resetRetry()
	}

	if final != nil {
		m = s.updateMarker(m, final, own, name, st.NodeID(), pr, out.wrote)
	}
	s.finish(d, v, m, be, out, pr.changed)
	s.auditAutomatic(ctx, d, o, pr, out)
	return out
}

// claimBackends adds the targets of the active kinds' listeners to own. A
// kind whose 127.0.0.1 port a serve entry FileParcel does not own already
// forwards to (a program published there by hand) is not applied: its
// state is error and the entry stays as it is.
func (s *Service) claimBackends(be map[string]backendSpec, name string, d desired, v *tsView, own ownership,
	active, hold *[2]bool, out *outcome) {
	for i, k := range kinds {
		spec, ok := be[k]
		if !active[i] || !ok || spec.proxy == "" {
			continue
		}
		hp := name + ":" + strconv.Itoa(d.port(k))
		if where := foreignOnBackend(v.sc, spec.proxy, hp, own); where != "" {
			addr := strings.TrimPrefix(spec.proxy, "http://")
			err := fmt.Errorf("a Tailscale entry made outside FileParcel (%s) forwards to %s, the local port FileParcel "+
				"would use for %s; remove that entry, or set funnel.backend_port to a free pair of ports", where, addr, kindLabel(k))
			out.k[i] = kindOutcome{state: core.IngressStateError, message: err.Error(), err: err, backend: true}
			active[i], hold[i] = false, true
			continue
		}
		own.kinds[spec.proxy] = k
	}
}

// planResult is what plan changed in a serve configuration.
type planResult struct {
	changed     [2]bool   // FileParcel's entry of the kind was added, moved, changed or removed
	removed     [2][]int  // ports of the kind's removed entries
	drift       [2]string // a wanted entry is missing and may not be added now
	conflict    [2]string // a foreign target holds the wanted HostPort
	clash       [2]bool   // the entry of a wanted kind was removed because it would take FileParcel's own port
	renamed     bool      // entries moved to the node's new name
	flagRemoved bool      // Funnel was switched off on FileParcel's Serve entry
}

func (r planResult) any() bool { return r.changed[0] || r.changed[1] }

// plan edits work (a copy of tailscaled's configuration): FileParcel's
// entries that are not wanted (any more, or not there) are removed; wanted
// entries are added where allowed and conflict-free; Funnel is switched
// off on FileParcel's Serve entry.
func (s *Service) plan(work *tslocal.ServeConfig, name string, d desired, active, hold [2]bool,
	be map[string]backendSpec, own ownership, allowAdd [2]bool, m *marker) planResult {
	var r planResult
	existing := own.entries(work)
	var present [2]bool
	for _, e := range existing {
		if i := kindIndex(e.kind); i >= 0 {
			present[i] = true
		}
	}
	want := func(i int) (hp string, port int, proxy string) {
		k := kinds[i]
		port = d.port(k)
		return name + ":" + strconv.Itoa(port), port, be[k].proxy
	}
	for _, e := range existing {
		i := kindIndex(e.kind)
		if i < 0 || hold[i] {
			continue
		}
		if active[i] {
			if hp, port, proxy := want(i); e.hostPort == hp && e.port == port && e.proxy == proxy {
				continue
			}
		}
		if work.RemoveEntry(e.hostPort, e.port, own.owned) {
			r.changed[i] = true
			r.removed[i] = append(r.removed[i], e.port)
			if d.wants(kinds[i]) && !active[i] {
				r.clash[i] = true
			}
			if active[i] && m != nil && m.DNSName != "" && m.DNSName != name && strings.HasPrefix(e.hostPort, m.DNSName+":") {
				r.renamed = true
			}
		}
	}
	for i, k := range kinds {
		if !active[i] {
			continue
		}
		hp, port, proxy := want(i)
		isFunnel := k == core.IngressFunnel
		cur, _ := work.Proxy(hp, port)
		if cur == proxy {
			switch on := work.FunnelOn(hp); {
			case on == isFunnel:
				continue
			case !isFunnel:
				// Serve hardening: Funnel was turned on for the
				// tailnet-only port outside FileParcel.
				work.SetEntry(hp, port, proxy, false)
				r.changed[i], r.flagRemoved = true, true
				continue
			case !allowAdd[i]:
				r.drift[i] = "Funnel was turned off for FileParcel's entry outside FileParcel: Re-apply to publish it again."
				continue
			}
		} else if !present[i] && !allowAdd[i] {
			r.drift[i] = driftMessage(k, m)
			continue
		}
		if target, c := work.Conflict(hp, port, own.owned); c {
			r.conflict[i] = target
			continue
		}
		work.SetEntry(hp, port, proxy, isFunnel)
		r.changed[i] = true
	}
	return r
}

// driftMessage explains a wanted entry tailscaled does not have.
func driftMessage(kind string, m *marker) string {
	label := kindLabel(kind)
	if m.entry(kind) == nil {
		return label + " is configured but was not published from this install: Re-apply to publish."
	}
	return "Tailscale no longer has FileParcel's " + label + " entry (it was changed outside FileParcel): " +
		"Re-apply to publish it again."
}

func kindLabel(kind string) string {
	if kind == core.IngressFunnel {
		return "Funnel"
	}
	return "Serve"
}

// removalFailed is the message of an entry FileParcel could not remove.
func removalFailed(port int, err error, why string) string {
	msg := "FileParcel stopped serving, but could not remove its entry from tailscaled: run " +
		tslocal.OffCommand(port, errors.Is(err, tslocal.ErrUnixForbidden))
	switch {
	case why != "":
		msg += " (" + why + ")"
	case err != nil:
		msg += " (" + err.Error() + ")"
	}
	return msg
}

// tailscaleErrorMessage explains a failed write to tailscaled.
func tailscaleErrorMessage(err error) string {
	switch {
	case errors.Is(err, tslocal.ErrUnixForbidden):
		// FileParcel's server always writes as its own user (a sudo CLI
		// goes through the running server, and the offline CLI never
		// adds entries), so only changing that entry helps.
		return "Another serve entry uses a Unix socket or a path, so tailscaled accepts changes only from root or an " +
			"operator with sudo rights, which FileParcel's server is not: remove that entry (tailscale serve status " +
			"lists it; tailscale serve --https=<port> --set-path=<path> off) or point it at a TCP target " +
			"(http://127.0.0.1:<port>), then Re-apply."
	case errors.Is(err, tslocal.ErrPermission):
		return "FileParcel's user may not change tailscaled's configuration: sudo tailscale set --operator=<user>"
	case errors.Is(err, tslocal.ErrETagMismatch):
		return "tailscaled's serve configuration kept changing while FileParcel wrote it: Re-apply."
	}
	return "tailscaled refused the change: " + err.Error()
}

// write stores after (derived from before) in tailscaled: one LocalAPI POST
// with If-Match, or the equivalent tailscale commands.
func (s *Service) write(ctx context.Context, before, after *tslocal.ServeConfig, name string, own ownership) error {
	if s.ts.Transport() == "cli" {
		return s.writeCLI(ctx, before, after, name, own)
	}
	after.ETag = before.ETag
	return s.ts.SetServeConfig(ctx, after)
}

// writeCLI applies the difference of FileParcel's entries with the
// tailscale command (no LocalAPI socket, e.g. macOS GUI builds) and reads
// the result back.
func (s *Service) writeCLI(ctx context.Context, before, after *tslocal.ServeConfig, name string, own ownership) error {
	b, a := own.entries(before), own.entries(after)
	for _, e := range b {
		if slices.Contains(a, e) || slices.ContainsFunc(a, func(x ownedEntry) bool { return x.hostPort == e.hostPort }) {
			continue // unchanged, or rewritten below on the same HostPort
		}
		if e.hostPort != name+":"+strconv.Itoa(e.port) {
			return fmt.Errorf("the tailscale command cannot remove %s (made for another device name); "+
				"run tailscale serve reset if nothing else is served", e.hostPort)
		}
		if err := s.ts.ServeOffCLI(ctx, e.port); err != nil {
			return err
		}
	}
	for _, e := range a {
		if slices.Contains(b, e) {
			continue
		}
		if err := s.ts.ServeCLI(ctx, e.funnel, e.port, e.proxy); err != nil {
			return err
		}
	}
	now, err := s.ts.ServeConfig(ctx)
	if err != nil {
		return err
	}
	got := own.entries(now)
	cmp := func(x, y ownedEntry) int { return strings.Compare(x.hostPort+x.proxy, y.hostPort+y.proxy) }
	slices.SortFunc(got, cmp)
	slices.SortFunc(a, cmp)
	if !slices.Equal(got, a) {
		return fmt.Errorf("the tailscale command did not apply the change (tailscaled has %d FileParcel entries, %d expected)",
			len(got), len(a))
	}
	return nil
}

// ---------- outcome, snapshots, marker ----------

// finish records the outcome (state per kind, backend, applied time),
// refreshes the lock-free snapshots, announces the change and schedules
// the self-probes of newly applied entries.
func (s *Service) finish(d desired, v *tsView, m *marker, be map[string]backendSpec, out *outcome, changed [2]bool) {
	now := s.now()
	var probe [2]bool
	s.stMu.Lock()
	for i, k := range kinds {
		ks := &s.kst[i]
		wasActive := ks.state == core.IngressStateActive
		ks.state, ks.message, ks.backendErr = out.k[i].state, out.k[i].message, out.k[i].backend
		ks.port = d.port(k)
		if name := v.name(); name != "" {
			ks.hostPort = name + ":" + strconv.Itoa(ks.port)
		}
		// The backend of the entry tailscaled has (the marker), else the
		// one a wanted kind is being set up with.
		switch spec, ok := be[k]; {
		case m.entry(k) != nil:
			e := m.entry(k)
			ks.proxy, ks.backend = e.Proxy, backendOf(e.Proxy)
			ks.tcpWarn = ok && spec.proxy == e.Proxy && spec.fallback
		case d.wants(k) && ok:
			ks.proxy, ks.backend, ks.tcpWarn = spec.proxy, spec.backend, spec.fallback
		case !d.wants(k):
			ks.proxy, ks.backend, ks.tcpWarn = "", "", false
		}
		if ks.state != core.IngressStateActive {
			continue
		}
		switch {
		case changed[i]:
			t := now
			ks.appliedAt, ks.reachable, ks.probedAt = &t, nil, nil
			probe[i] = true
		case !wasActive:
			if m != nil && m.AppliedAt != nil {
				t := *m.AppliedAt
				ks.appliedAt = &t
			}
			probe[i] = ks.reachable == nil
		}
	}
	if v.st != nil {
		s.lastName, s.lastNode = v.name(), v.st.NodeID()
	}
	if out.k[1].state != core.IngressStateActive || changed[1] {
		s.serveFunnel.Store(false)
	}
	s.stMu.Unlock()
	s.updateSnapshots(d, v)
	for i, k := range kinds {
		if probe[i] {
			s.scheduleProbe(k, s.t.probeDelay)
		}
	}
	s.publish()
}

// updateSnapshots refreshes the public base URL and the access URLs.
func (s *Service) updateSnapshots(d desired, v *tsView) {
	s.stMu.Lock()
	funnelActive := s.kst[0].state == core.IngressStateActive
	serveActive := s.kst[1].state == core.IngressStateActive
	s.stMu.Unlock()
	dns := v.dnsName()
	if dns == "" {
		dns = s.Policy(core.IngressFunnel).DNSName
	}
	base := ""
	urls := []core.AccessURL{}
	if dns != "" && funnelActive && (d.Mode == core.FunnelShares || d.Mode == core.FunnelApp) {
		base = hostURL(dns, d.Port)
		if d.Mode == core.FunnelApp {
			urls = append(urls, core.AccessURL{URL: base + "/", Kind: core.URLKindFunnel,
				Label: "Internet (Tailscale Funnel)", Trusted: true})
		}
	}
	if dns != "" && serveActive {
		urls = append(urls, core.AccessURL{URL: hostURL(dns, d.ServePort) + "/", Kind: core.URLKindTailscaleServe,
			Label: "Tailscale Serve (tailnet, no port)", Trusted: true, Recommended: true})
	}
	s.base.Store(&base)
	s.urls.Store(&urls)
}

// clearSnapshots switches every policy off and forgets the URLs (the
// server stopped).
func (s *Service) clearSnapshots() {
	for i := range kinds {
		s.policy[i].Store(&core.IngressPolicy{Mode: core.FunnelOff})
	}
	empty := ""
	s.base.Store(&empty)
	s.urls.Store(&[]core.AccessURL{})
}

// updateMarker records FileParcel's entries of the configuration tailscaled
// now has (final). A wanted entry reported as drift keeps its old record,
// so the next status still tells "removed outside FileParcel" apart from
// "never published from this install".
func (s *Service) updateMarker(m *marker, final *tslocal.ServeConfig, own ownership, name, node string, pr planResult, wrote bool) *marker {
	nm := &marker{NodeID: node, DNSName: name, State: markerApplied}
	for _, e := range own.entries(final) {
		nm.Entries = append(nm.Entries, markerEntry{Kind: e.kind, HostPort: e.hostPort, Port: e.port, Proxy: e.proxy, Funnel: e.funnel})
	}
	for i, k := range kinds {
		if old := m.entry(k); pr.drift[i] != "" && old != nil && nm.entry(k) == nil {
			nm.Entries = append(nm.Entries, *old)
		}
	}
	for _, e := range nm.Entries {
		if b := backendOf(e.Proxy); b != "" {
			nm.Backend = b
		}
	}
	switch {
	case wrote:
		t := s.now()
		nm.AppliedAt = &t
	case m != nil:
		nm.AppliedAt = m.AppliedAt
	}
	if nm.AppliedAt == nil && len(nm.Entries) > 0 {
		t := s.now()
		nm.AppliedAt = &t
	}
	if err := writeMarker(s.home(), nm); err != nil {
		s.log.Warn("tsingress: could not write the marker", "err", err)
	}
	return nm
}

// reconcileOffline is the reconcile of the offline CLI (server stopped):
// removals are written to tailscaled at once; wanted entries are recorded
// in the marker (pending when tailscaled lacks them) and written when the
// server starts, so tailscaled never points at a listener that is not
// there.
func (s *Service) reconcileOffline(ctx context.Context, d desired, v *tsView, m *marker, own ownership,
	active, hold [2]bool, out *outcome) {
	name := v.name()
	be := s.plannedBackends(d)
	sc, err := s.ts.ServeConfig(ctx)
	if err != nil {
		out.err = err
		for i, k := range kinds {
			switch {
			case active[i]:
				out.k[i] = kindOutcome{state: core.IngressStateError, message: tailscaleErrorMessage(err), err: err}
			case !d.wants(k) && m.entry(k) != nil:
				out.k[i] = kindOutcome{state: core.IngressStateError, message: removalFailed(m.entry(k).Port, err, ""), err: err}
			case !d.wants(k):
				out.k[i].state = core.IngressStateOff
			}
		}
		s.finish(d, v, m, nil, out, [2]bool{})
		return
	}
	work := sc.Clone()
	var changed [2]bool
	for _, e := range own.entries(work) {
		i := kindIndex(e.kind)
		if i < 0 || hold[i] {
			continue
		}
		k := kinds[i]
		if active[i] && e.hostPort == name+":"+strconv.Itoa(d.port(k)) && (be[k].proxy == "" || e.proxy == be[k].proxy) {
			continue
		}
		if work.RemoveEntry(e.hostPort, e.port, own.owned) {
			changed[i] = true
		}
	}
	final := sc
	if changed[0] || changed[1] {
		if err := s.write(ctx, sc, work, name, own); err != nil {
			out.err = err
		} else {
			final, out.wrote = work, true
			s.invalidateView()
		}
	}

	nm := &marker{NodeID: v.st.NodeID(), DNSName: name, State: markerApplied}
	if m != nil {
		nm.AppliedAt = m.AppliedAt
	}
	present := own.entries(final)
	pending := false
	for i, k := range kinds {
		switch {
		case active[i]:
			hp, port := name+":"+strconv.Itoa(d.port(k)), d.port(k)
			idx := slices.IndexFunc(present, func(e ownedEntry) bool {
				return e.kind == k && e.hostPort == hp && e.funnel == (k == core.IngressFunnel)
			})
			if idx >= 0 {
				e := present[idx]
				nm.Entries = append(nm.Entries, markerEntry{Kind: k, HostPort: e.hostPort, Port: e.port, Proxy: e.proxy, Funnel: e.funnel})
			} else {
				pending = true
				nm.Entries = append(nm.Entries, markerEntry{Kind: k, HostPort: hp, Port: port, Proxy: be[k].proxy,
					Funnel: k == core.IngressFunnel})
			}
		case hold[i] || out.err != nil && changed[i]:
			if old := m.entry(k); old != nil {
				nm.Entries = append(nm.Entries, *old)
			}
		}
	}
	for _, e := range nm.Entries {
		if b := backendOf(e.Proxy); b != "" {
			nm.Backend = b
		}
	}
	if pending {
		nm.State = markerPending
	} else if m.waiting() {
		nm.State = m.State
	}
	if err := writeMarker(s.home(), nm); err != nil {
		s.log.Warn("tsingress: could not write the marker", "err", err)
	}
	for i, k := range kinds {
		switch {
		case active[i]:
			msg := "The server is not running."
			if nm.State != markerApplied {
				msg = "FileParcel publishes it on Tailscale when the server starts."
			}
			out.k[i] = kindOutcome{state: core.IngressStateStopped, message: msg}
		case !d.wants(k) && out.err != nil && changed[i]:
			out.k[i] = kindOutcome{state: core.IngressStateError, message: removalFailed(d.port(k), out.err, ""), err: out.err}
		case !d.wants(k):
			out.k[i].state = core.IngressStateOff
		}
	}
	s.finish(d, v, nm, nil, out, [2]bool{})
}

// auditAutomatic records the changes a reconcile made on its own: entries
// moved to a new node name, the Funnel flag removed from FileParcel's
// Serve entry, and entries removed because they would take FileParcel's
// own port.
func (s *Service) auditAutomatic(ctx context.Context, d desired, o recOpts, pr planResult, out *outcome) {
	if !out.wrote {
		return
	}
	if core.PrincipalFrom(ctx) == nil {
		ctx = core.WithPrincipal(ctx, core.SystemPrincipal(core.ViaOffline))
	}
	for i, k := range kinds {
		switch {
		case pr.clash[i]:
			s.audit(ctx, k, core.OutcomeSuccess, map[string]any{"reason": "port_clash_removed", "port": d.port(k)})
		case pr.renamed && pr.changed[i] && !o.user():
			s.audit(ctx, k, core.OutcomeSuccess, map[string]any{"reason": "renamed", "port": d.port(k)})
		}
	}
	if pr.flagRemoved {
		s.audit(ctx, core.IngressServe, core.OutcomeSuccess, map[string]any{"reason": "funnel_flag_removed", "port": d.ServePort})
	}
}

// ---------- start retries ----------

// scheduleRetry reconciles again later while tailscaled is not up (after
// a boot, FileParcel may start before tailscaled) or an entry that is no
// longer wanted could not be removed. Backoff retryMin … retryMax.
func (s *Service) scheduleRetry() {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	if s.retryTimer != nil || s.lis == nil {
		return
	}
	delay := s.retryDelay * 2
	if delay < s.t.retryMin {
		delay = s.t.retryMin
	}
	if delay > s.t.retryMax {
		delay = s.t.retryMax
	}
	s.retryDelay = delay
	ctx := s.attachCtx
	s.retryTimer = time.AfterFunc(delay, func() {
		s.stMu.Lock()
		s.retryTimer = nil
		s.stMu.Unlock()
		s.startReconcile(ctx, "retry")
	})
}

// stopRetry stops a pending retry and keeps the backoff (the reconcile
// that runs now schedules the next one if it is still needed).
func (s *Service) stopRetry() {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	if s.retryTimer != nil {
		s.retryTimer.Stop()
		s.retryTimer = nil
	}
}

// resetRetry stops pending retries and the backoff (nothing to retry).
func (s *Service) resetRetry() {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	s.retryDelay = 0
	if s.retryTimer != nil {
		s.retryTimer.Stop()
		s.retryTimer = nil
	}
}
