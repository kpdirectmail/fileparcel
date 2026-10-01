// Package netinfo enumerates and classifies network interfaces (LAN, Wi-Fi,
// Tailscale/Headscale, WireGuard, ZeroTier, exit and corporate VPNs, …) and
// gives each a role (mesh, unknown, access, egress, overlay, local, none;
// network.iface_roles overrides it), builds access URLs, lists the VPNs and
// the ways around the access policy, compiles and enforces the access
// policy and reads Tailscale status (DESIGN §10.1–10.3). Owned by unit G.
//
// Hot paths never block: Allowed evaluates an immutable compiled matcher
// behind an atomic.Pointer, and Hostnames/IPs read an immutable snapshot of
// the last interface enumeration. The snapshot is refreshed every 30 s by
// the poller started with Start (and on demand by Interfaces/URLs);
// network.changed is published whenever the offered address set or an
// interface role, the MagicDNS name, the system .local name or
// network.extra_hosts change.
package netinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// PollInterval is how often interfaces are re-enumerated (DESIGN §10.1).
const PollInterval = 30 * time.Second

// Service implements core.Network.
type Service struct {
	env  *core.Env
	log  *slog.Logger
	goos string
	port int // HTTPS port the server listens on (read once: changes need a restart)
	// cfgName is server.name read at construction (fallback when settings
	// are unavailable; env.Config is not safe for concurrent reads later).
	cfgName string

	source   func() ([]rawIface, error)
	ts       *tailscaleClient
	sysHost  *sysHostResolver
	hostname func() (string, error)
	poll     time.Duration
	// probe supplies the classification signals beyond the interface list
	// (default route, binaries, processes, tinc/innernet); routes caches
	// its default-route answer.
	probe  *hostProbe
	routes routeCache
	// cloudflared scans for a Cloudflare Tunnel to FileParcel (Exposures;
	// nil: none); expo caches the scan.
	cloudflared func(ctx context.Context, port int, local func(host string) bool) *core.Exposure
	expo        exposureCache

	matcher atomic.Pointer[matcher]
	snap    atomic.Pointer[snapshot]
	mdns    atomic.Pointer[core.MDNSStatus] // last mdns.changed (fallback when mdnsSvc is unbound)
	mdnsSvc atomic.Pointer[mdnsRef]
	certs   atomic.Pointer[certsRef]
	ingress atomic.Pointer[ingressRef]

	refreshMu sync.Mutex // serialises refreshes (and network.changed decisions)
	policyMu  sync.Mutex // serialises SetPolicy

	started   atomic.Bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// certsRef wraps the late-bound certificate service (Bind).
type certsRef struct{ c core.Certs }

// ingressRef wraps the late-bound Tailscale Funnel/Serve service (Bind): its
// addresses join the access URLs while they are published.
type ingressRef struct{ i core.Ingress }

// mdnsRef wraps the late-bound mDNS service (Bind). Reading its status
// directly beats the mdns.changed copy: the event reaches this service's
// goroutine a scheduling tick later, and the startup banner asks for the
// URLs the moment publishing settles.
type mdnsRef struct{ m core.MDNS }

// snapshot is an immutable view of the last enumeration. Never modify one.
type snapshot struct {
	ifaces   []core.NetInterface
	ts       *core.TailscaleInfo // nil until fetched
	sysHost  string              // system responder FQDN ("" = none)
	hostname string              // os.Hostname, lowercased
	fp       string              // fingerprint for network.changed
	// err is the enumeration failure of a snapshot taken without an earlier
	// one to fall back on (ifaces is then empty); Interfaces reports it.
	err error
}

var (
	_ core.Network = (*Service)(nil)
	_ core.Binder  = (*Service)(nil)
)

// New creates the service (constructor signature fixed by DESIGN §5.2). It
// compiles the access policy from the settings but does not touch the
// network; enumeration happens lazily and in Start.
func New(env *core.Env) (*Service, error) {
	s := newService(env)
	s.reloadPolicy()
	return s, nil
}

// newService builds a Service with the system collaborators (tests replace
// source, ts, sysHost, hostname and poll before use).
func newService(env *core.Env) *Service {
	s := &Service{
		env:         env,
		log:         slog.Default(),
		goos:        runtime.GOOS,
		port:        8443,
		source:      systemInterfaces,
		ts:          newTailscaleClient(),
		sysHost:     newSysHostResolver(),
		hostname:    os.Hostname,
		poll:        PollInterval,
		probe:       newHostProbe(),
		cloudflared: systemCloudflared,
		stopCh:      make(chan struct{}),
	}
	if env != nil {
		if env.Log != nil {
			s.log = env.Log
		}
		if env.Config != nil {
			if env.Config.Server.HTTPSPort > 0 {
				s.port = env.Config.Server.HTTPSPort
			}
			s.cfgName = env.Config.Server.Name
		}
	}
	s.matcher.Store(defaultMatcher())
	return s
}

// Bind picks up the certificate service (for AccessURL.Trusted), the mDNS
// service (for the effective .local name) and the Tailscale Funnel/Serve
// service (its addresses, DESIGN §10.6).
func (s *Service) Bind(reg *core.Services) error {
	if reg == nil {
		return nil
	}
	if reg.Certs != nil {
		s.certs.Store(&certsRef{c: reg.Certs})
	}
	if reg.MDNS != nil {
		s.mdnsSvc.Store(&mdnsRef{m: reg.MDNS})
	}
	if reg.Ingress != nil {
		s.ingress.Store(&ingressRef{i: reg.Ingress})
	}
	return nil
}

// Start takes the first snapshot and starts the 30 s poller and the event
// watchers (settings.changed → policy/extra hosts, mdns.changed → effective
// .local name). Background work stops when ctx is cancelled or on Close.
// Calling Start again is a no-op.
func (s *Service) Start(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return nil
	}
	s.refresh(ctx, false, false)
	var ch <-chan events.Event
	cancel := func() {}
	if s.env != nil && s.env.Bus != nil {
		ch, cancel = s.env.Bus.Subscribe(events.TopicSettingsChanged, events.TopicMDNSChanged)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		s.loop(ctx, ch)
	}()
	return nil
}

// Close stops the background goroutines (io.Closer; idempotent).
func (s *Service) Close() error {
	s.closeOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
	return nil
}

func (s *Service) loop(ctx context.Context, ch <-chan events.Event) {
	t := time.NewTicker(s.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-t.C:
			s.refresh(ctx, false, true)
		case e, ok := <-ch:
			if !ok {
				ch = nil
				continue
			}
			s.handleEvent(ctx, e)
		}
	}
}

func (s *Service) handleEvent(ctx context.Context, e events.Event) {
	switch e.Topic {
	case events.TopicMDNSChanged:
		var st core.MDNSStatus
		switch v := e.Data.(type) {
		case core.MDNSStatus:
			st = v
		case *core.MDNSStatus:
			if v == nil {
				return
			}
			st = *v
		default:
			return
		}
		st.Interfaces = slices.Clone(st.Interfaces)
		s.mdns.Store(&st)
		// No network.changed here: mdns republishes on network.changed,
		// and certs watches mdns.changed itself.
	case events.TopicSettingsChanged:
		var keys []string
		switch v := e.Data.(type) {
		case core.SettingsChangedEvent:
			keys = v.Keys
		case *core.SettingsChangedEvent:
			if v != nil {
				keys = v.Keys
			}
		}
		if len(keys) == 0 || slices.ContainsFunc(keys, func(k string) bool { return slices.Contains(policyKeys, k) }) {
			s.reloadPolicy()
		}
		if len(keys) == 0 || slices.Contains(keys, KeyExtraHosts) || slices.Contains(keys, KeyIfaceRoles) {
			s.refresh(ctx, false, true)
		}
	}
}

// ---------- snapshot ----------

// current returns the latest snapshot, taking one synchronously the first
// time (used by Hostnames/IPs before Start, e.g. `fileparcel init`).
func (s *Service) current() *snapshot {
	if sn := s.snap.Load(); sn != nil {
		return sn
	}
	ctx, cancel := context.WithTimeout(context.Background(), tsFetchTimeout)
	defer cancel()
	return s.refresh(ctx, false, false)
}

// refresh re-enumerates the interfaces (Tailscale and system-responder data
// honour their caches unless forceTS) and stores a new snapshot. With
// publish, network.changed is published when the fingerprint changed.
func (s *Service) refresh(ctx context.Context, forceTS, publish bool) *snapshot {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	old := s.snap.Load()
	raw, err := s.source()
	if err != nil {
		s.log.Warn("netinfo: cannot enumerate interfaces", "err", err)
		if old != nil {
			return old
		}
		raw = nil
	}
	ts := s.ts.get(ctx, forceTS)
	sn := &snapshot{ts: ts, sysHost: s.sysHost.get(ctx), err: err}
	if h, err := s.hostname(); err == nil {
		sn.hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	}
	sn.ifaces = s.classifyAll(ctx, raw, ts)
	sn.fp = s.fingerprint(sn)
	if ctx.Err() != nil && old != nil {
		// A cancelled caller may have got partial answers: keep the last
		// snapshot (the next refresh reads everything again).
		return old
	}
	s.snap.Store(sn)
	if publish && old != nil && old.fp != sn.fp && s.env != nil && s.env.Bus != nil {
		s.log.Info("network configuration changed")
		s.env.Bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	}
	return sn
}

// classifyAll classifies the enumerated interfaces (DESIGN §10.1): kind
// and role from the interface itself and the host probes, the default-route
// rule (the routing tables are read only while a VPN interface is up), then
// the administrator's overrides (network.iface_roles).
func (s *Service) classifyAll(ctx context.Context, raw []rawIface, ts *core.TailscaleInfo) []core.NetInterface {
	env := &classEnv{goos: s.goos, probe: s.probe}
	if ts != nil {
		env.tsIPs = ts.IPs
		env.tsInstalled = ts.Installed
		env.headscale = ts.Kind == core.IfHeadscale
	}
	classes := make([]ifaceClass, len(raw))
	var key strings.Builder
	candidate := false
	for i, r := range raw {
		classes[i] = classify(r, env)
		up := r.Flags&net.FlagUp != 0
		candidate = candidate || (up && vpnKinds[classes[i].kind])
		fmt.Fprintf(&key, "%d:%s:%t;", r.Index, r.Name, up)
	}
	var defRoutes map[int]bool
	if candidate && s.probe != nil && s.probe.defaultRouteIfaces != nil {
		defRoutes = s.routes.get(ctx, key.String(), time.Now(), s.probe.defaultRouteIfaces)
	}
	ifaces := make([]core.NetInterface, 0, len(raw))
	for i, r := range raw {
		ifaces = append(ifaces, toNetInterface(r, classes[i], defRoutes[r.Index]))
	}
	roles, err := parseIfaceRoles(s.settingStrings(KeyIfaceRoles))
	if err != nil {
		s.log.Warn("netinfo: ignoring invalid network.iface_roles", "err", err)
	}
	applyRoleOverrides(ifaces, roles)
	return ifaces
}

// fingerprint summarises what network.changed consumers care about: the
// offered addresses per interface, kind and role (mDNS follows the local
// role), and the SAN names.
func (s *Service) fingerprint(sn *snapshot) string {
	var b strings.Builder
	for _, ni := range sn.ifaces {
		if !offered(ni) {
			continue
		}
		fmt.Fprintf(&b, "%s|%s|%s|", ni.Name, ni.Kind, RoleOf(ni))
		addrs := make([]string, 0, len(ni.Addrs))
		for _, p := range ni.Addrs {
			if offeredAddr(ni, p.Addr()) {
				addrs = append(addrs, p.String())
			}
		}
		slices.Sort(addrs)
		b.WriteString(strings.Join(addrs, ","))
		b.WriteByte(';')
	}
	b.WriteString("#")
	b.WriteString(strings.Join(s.hostnamesFrom(sn, false), ","))
	return b.String()
}

// magicDNSOffered reports whether the MagicDNS name is offered: the
// Tailscale interface is (or there is none — userspace networking); an
// administrator who set it to egress or none (network.iface_roles) takes
// the name out of the URLs and the certificate too.
func magicDNSOffered(ifaces []core.NetInterface) bool {
	found := false
	for _, ni := range ifaces {
		if ni.Kind != core.IfTailscale && ni.Kind != core.IfHeadscale {
			continue
		}
		if offered(ni) || (!ni.Up && incoming(RoleOf(ni))) {
			return true
		}
		found = true
	}
	return !found
}

// ---------- core.Network: interfaces, URLs, names ----------

// Interfaces re-enumerates and returns every interface, classified
// (DESIGN §10.1). Tailscale interfaces become "headscale" when the control
// server is self-hosted. When enumeration fails and no earlier one succeeded,
// the error is returned (so `fileparcel init` and mDNS can report it rather
// than acting on an empty list); after a success, a failing enumeration
// keeps serving the last good list.
func (s *Service) Interfaces(ctx context.Context) ([]core.NetInterface, error) {
	sn := s.refresh(ctx, false, s.started.Load())
	if sn.err != nil {
		return nil, sn.err
	}
	return cloneIfaces(sn.ifaces), nil
}

func cloneIfaces(in []core.NetInterface) []core.NetInterface {
	out := make([]core.NetInterface, len(in))
	for i, ni := range in {
		ni.Addrs = slices.Clone(ni.Addrs)
		if ni.Addrs == nil {
			ni.Addrs = []netip.Prefix{}
		}
		out[i] = ni
	}
	return out
}

// URLs returns the access URLs (DESIGN §10.2).
func (s *Service) URLs(ctx context.Context) ([]core.AccessURL, error) {
	sn := s.refresh(ctx, false, s.started.Load())
	in := urlInput{
		port:    s.port,
		ifaces:  sn.ifaces,
		sysHost: sn.sysHost,
		extra:   append(s.settingStrings("tls.extra_sans"), s.settingStrings(KeyExtraHosts)...),
	}
	in.mdnsName, in.mdnsPublished = s.mdnsName()
	if ts := sn.ts; ts != nil && ts.Running && ts.DNSName != "" && magicDNSOffered(sn.ifaces) {
		in.magicDNS, in.magicKind = ts.DNSName, ts.Kind
		for _, ni := range sn.ifaces {
			if ni.Kind == core.IfTailscale || ni.Kind == core.IfHeadscale {
				in.magicIface = ni.Name
				break
			}
		}
	}
	in.publicURL = s.settingString("server.public_url")
	if ref := s.ingress.Load(); ref != nil && ref.i != nil {
		in.ingress = ref.i.AccessURLs()
	}
	if ref := s.certs.Load(); ref != nil && ref.c != nil {
		c := ref.c
		in.trusted = func(host string) bool { return c.PubliclyTrusted(host) }
	}
	return buildURLs(in), nil
}

// mdnsName returns the effective mDNS FQDN and whether it is published: the
// status of the bound mDNS service (or the last mdns.changed when none is
// bound), else the configured name (mdns.name, falling back to server.name)
// + ".local", unpublished.
func (s *Service) mdnsName() (string, bool) {
	st := s.mdns.Load()
	if ref := s.mdnsSvc.Load(); ref != nil && ref.m != nil {
		live := ref.m.Status()
		st = &live
	}
	if st != nil && st.Name != "" && st.State != core.MDNSOff {
		return strings.ToLower(st.Name), st.State == core.MDNSPublished
	}
	return s.configuredMDNSName(), false
}

// configuredMDNSName returns the configured .local name (mdns.name, falling
// back to server.name and to the bootstrap config), lowercased. It is what
// the operator typed, independent of any collision rename.
func (s *Service) configuredMDNSName() string {
	name := s.settingString("mdns.name")
	if name == "" {
		name = s.settingString("server.name")
	}
	if name == "" {
		name = s.cfgName
	}
	if name == "" {
		name = "fileparcel"
	}
	return strings.ToLower(name) + ".local"
}

// Hostnames returns the DNS names for certificate SANs and the Host check:
// the published mDNS name and the configured <name>.local (they differ after
// a collision rename), the system responder's .local name, the OS host name (and
// its first label + ".local"), the MagicDNS FQDN and network.extra_hosts.
// It never blocks on the network after the first snapshot.
func (s *Service) Hostnames() []string {
	return s.hostnamesFrom(s.current(), true)
}

func (s *Service) hostnamesFrom(sn *snapshot, withMDNS bool) []string {
	var out []string
	add := func(n string) {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" || !validDNSName(n, true) || slices.Contains(out, n) {
			return
		}
		out = append(out, n)
	}
	if withMDNS {
		name, _ := s.mdnsName()
		add(name)
		// Also the configured <name>.local, even while the responder
		// publishes a renamed one: the leaf must keep covering the name the
		// operator configured (it is the WebAuthn RP ID base too), so that a
		// transient rename cannot lock devices out.
		add(s.configuredMDNSName())
	}
	add(sn.sysHost)
	if h := sn.hostname; h != "" && h != "localhost" {
		add(h)
		first, _, _ := strings.Cut(h, ".")
		add(first + ".local")
	}
	if ts := sn.ts; ts != nil && ts.DNSName != "" && magicDNSOffered(sn.ifaces) {
		add(ts.DNSName)
	}
	for _, h := range s.settingStrings(KeyExtraHosts) {
		add(h)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// IPs returns the SAN addresses: every offered address of the offered
// interfaces (roles local, mesh and unknown; DESIGN §10.1) — never an exit,
// corporate or overlay VPN's, loopback, a container bridge's or link-local.
func (s *Service) IPs() []netip.Addr {
	sn := s.current()
	out := []netip.Addr{}
	for _, ni := range sn.ifaces {
		if !offered(ni) {
			continue
		}
		for _, p := range ni.Addrs {
			a := p.Addr().Unmap().WithZone("")
			if offeredAddr(ni, a) && !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// VPNs implements the optional VPN listing of the network service
// (GET /admin/network, the doctor): BuildVPNs over the last snapshot and the
// current policy.
func (s *Service) VPNs(context.Context) []core.VPNInfo {
	sn := s.current()
	return BuildVPNs(sn.ifaces, sn.ts, s.Policy())
}

// Tailscale returns the local Tailscale/Headscale node status (LocalAPI or
// CLI, cached 30 s). It never fails for a missing Tailscale: Running is
// false and Error explains.
func (s *Service) Tailscale(ctx context.Context) (*core.TailscaleInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ts.get(ctx, false), nil
}

// ---------- core.Network: access policy ----------

// Allowed reports whether a connection from ip may proceed (DESIGN §10.3).
// Lock-free; called at Accept() for every connection.
func (s *Service) Allowed(ip netip.Addr) bool {
	return s.matcher.Load().allowed(ip)
}

// Denied reports whether ip is covered by the deny list
// (network.deny_cidrs). Tailscale Funnel requests are checked against the
// deny list only (mw.IngressGate): the internet reaches Funnel by design,
// so the allow list and the mode do not apply there. Lock-free.
func (s *Service) Denied(ip netip.Addr) bool {
	return s.matcher.Load().denied(ip)
}

// Policy returns the current (normalised) access policy.
func (s *Service) Policy() core.AccessPolicy {
	return clonePolicy(s.matcher.Load().policy)
}

// CheckPolicy validates p and reports whether ip would be allowed under it,
// without applying anything. The settings API uses it (through a local
// interface) to apply the lockout guard to PATCH /admin/settings.
func (s *Service) CheckPolicy(p core.AccessPolicy, ip netip.Addr) (bool, error) {
	m, err := compilePolicy(p)
	if err != nil {
		return false, err
	}
	return m.allowed(ip), nil
}

// SetPolicy validates and applies a new access policy (DESIGN §10.3). The
// lockout guard refuses (409 conflict) a policy that would no longer admit
// current — the requesting client's address — unless force is set. The
// policy is stored through Settings.Set (network.access_mode, allow_cidrs,
// deny_cidrs: one transaction, settings.change audit entries,
// settings.changed event), applied to the matcher immediately and audited as
// network.policy. It returns user-facing warnings (e.g. mode "any").
func (s *Service) SetPolicy(ctx context.Context, by *core.Principal, p core.AccessPolicy, current netip.Addr, force bool) ([]string, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	m, err := compilePolicy(p)
	if err != nil {
		return nil, err
	}
	actx := withActor(ctx, by)
	if current.IsValid() && !m.allowed(current) && !force {
		s.audit(actx, core.OutcomeDenied, m.policy, force, "lockout_guard")
		return nil, core.Errorf(core.ErrConflict,
			"this policy would refuse your current address %s; include it in the allow list or confirm with force", current.Unmap().WithZone(""))
	}
	warnings := policyWarnings(m, current, force)
	if s.env == nil || s.env.Settings == nil {
		return nil, core.Wrap(core.ErrUnavailable, "settings are not available", nil)
	}
	changes := map[string]json.RawMessage{
		KeyAccessMode: mustJSON(m.policy.Mode),
		KeyAllowCIDRs: mustJSON(m.policy.Allow),
		KeyDenyCIDRs:  mustJSON(m.policy.Deny),
	}
	if _, err := s.env.Settings.Set(ctx, by, changes); err != nil {
		if ce := core.AsError(err); ce != nil && ce.Field != "" {
			// Report the policy field rather than the settings key.
			field := map[string]string{KeyAccessMode: "mode", KeyAllowCIDRs: "allow", KeyDenyCIDRs: "deny"}[ce.Field]
			if field != "" {
				return nil, &core.Error{Code: ce.Code, Status: ce.Status, Message: ce.Message, Field: field, Err: ce.Err}
			}
		}
		return nil, err
	}
	s.matcher.Store(m)
	s.audit(actx, core.OutcomeSuccess, m.policy, force, "")
	s.log.Info("access policy changed", "mode", m.policy.Mode, "allow", len(m.policy.Allow), "deny", len(m.policy.Deny))
	return warnings, nil
}

func (s *Service) audit(ctx context.Context, outcome string, p core.AccessPolicy, force bool, reason string) {
	if s.env == nil || s.env.Audit == nil {
		return
	}
	details := map[string]any{"mode": p.Mode, "allow": p.Allow, "deny": p.Deny, "force": force}
	if reason != "" {
		details["reason"] = reason
	}
	s.env.Audit.Record(ctx, core.AuditEntry{Action: core.ActNetworkPolicy, Outcome: outcome,
		TargetType: "network", TargetID: "access_policy", TargetName: "Access policy", Details: details})
}

// reloadPolicy compiles the policy from the settings (network.access_mode,
// allow_cidrs, deny_cidrs). An invalid stored policy keeps the previous one.
func (s *Service) reloadPolicy() {
	if s.env == nil || s.env.Settings == nil {
		return
	}
	p := core.AccessPolicy{
		Mode:  s.settingString(KeyAccessMode),
		Allow: s.settingStrings(KeyAllowCIDRs),
		Deny:  s.settingStrings(KeyDenyCIDRs),
	}
	m, err := compilePolicy(p)
	if err != nil {
		s.log.Error("netinfo: invalid stored access policy; keeping the previous one", "err", err)
		return
	}
	s.matcher.Store(m)
}

// ---------- helpers ----------

func (s *Service) settingString(key string) string {
	if s.env == nil || s.env.Settings == nil {
		return ""
	}
	return s.env.Settings.String(key)
}

func (s *Service) settingStrings(key string) []string {
	if s.env == nil || s.env.Settings == nil {
		return nil
	}
	return s.env.Settings.Strings(key)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// withActor makes by the context principal (for audit) unless one is set.
func withActor(ctx context.Context, by *core.Principal) context.Context {
	if by != nil && core.PrincipalFrom(ctx) == nil {
		return core.WithPrincipal(ctx, by)
	}
	return ctx
}
