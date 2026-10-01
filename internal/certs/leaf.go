package certs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// sanSet is the normalized, sorted SAN list of a leaf.
type sanSet struct {
	DNS []string
	IPs []netip.Addr
}

func (s sanSet) strings() []string {
	out := slices.Clone(s.DNS)
	for _, ip := range s.IPs {
		out = append(out, ip.String())
	}
	return out
}

func (s sanSet) equal(o sanSet) bool {
	return slices.Equal(s.DNS, o.DNS) && slices.Equal(s.IPs, o.IPs)
}

// sansOf returns the SANs of an existing certificate.
func sansOf(c *x509.Certificate) sanSet {
	var s sanSet
	for _, n := range c.DNSNames {
		s.DNS = append(s.DNS, strings.ToLower(n))
	}
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			s.IPs = append(s.IPs, a.Unmap())
		}
	}
	slices.Sort(s.DNS)
	s.DNS = slices.Compact(s.DNS)
	slices.SortFunc(s.IPs, func(a, b netip.Addr) int { return a.Compare(b) })
	s.IPs = slices.Compact(s.IPs)
	return s
}

// maxLeafDNS and maxLeafIPs bound the SAN set of the leaf. A TLS handshake
// carries the whole certificate, so an unbounded SAN list produces a
// certificate no client can read ("excessive message size") and takes HTTPS
// down completely. tls.extra_sans and acme.domains are capped when they are
// set; these are the last line of defence for the names that arrive from
// elsewhere (network.extra_hosts, the interface addresses).
const (
	maxLeafDNS = 128
	maxLeafIPs = 128
)

// renamedFrom returns the server name the server runs with while a new
// server.name waits for the restart it is flagged for ("" otherwise, and
// when mdns.name decides the .local name). mDNS and the host names follow
// the setting at once; the leaf keeps the running name's <name>.local until
// the restart, so the address an admin uses right now keeps validating and
// the certificate agrees with the reported restart state.
func (svc *Service) renamedFrom() string {
	c := svc.env.Config
	if c == nil || svc.settingString("mdns.name") != "" {
		return ""
	}
	running := strings.ToLower(c.Server.Name)
	if running == "" || !validDNSName(running+".local", true) || strings.EqualFold(svc.settingString("server.name"), running) {
		return ""
	}
	return running
}

// desiredSANs computes the leaf SANs (DESIGN §10.4): Network.Hostnames() +
// Network.IPs() + tls.extra_sans + localhost, 127.0.0.1 and ::1, limited to
// the names the CA's name constraints permit and to maxLeafDNS/maxLeafIPs
// entries. dropped lists the rest.
func (svc *Service) desiredSANs(ca *x509.Certificate) (s sanSet, dropped []string) {
	dns := []string{"localhost"}
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}
	addName := func(n string) {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" {
			return
		}
		if ip, err := netip.ParseAddr(n); err == nil {
			ips = append(ips, ip)
			return
		}
		if validDNSName(n, true) {
			dns = append(dns, n)
		}
	}
	if svc.net != nil {
		for _, n := range svc.net.Hostnames() {
			addName(n)
		}
		ips = append(ips, svc.net.IPs()...)
	}
	if old := svc.renamedFrom(); old != "" {
		addName(old + ".local")
	}
	for _, n := range svc.settingStrings(KeyExtraSANs) {
		addName(n)
	}
	// Cap before filtering and sorting: the collection order is the priority
	// order (localhost, this machine's own names, then tls.extra_sans), so an
	// overlong extra_sans list can never push the server's own names out.
	dns, ips, dropped = capNames(dns, ips, dropped)
	for _, n := range dns {
		if dnsPermitted(ca, n) {
			s.DNS = append(s.DNS, n)
		} else {
			dropped = append(dropped, n)
		}
	}
	for _, ip := range ips {
		ip = ip.Unmap().WithZone("")
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if ipPermitted(ca, ip) {
			s.IPs = append(s.IPs, ip)
		} else {
			dropped = append(dropped, ip.String())
		}
	}
	slices.Sort(s.DNS)
	s.DNS = slices.Compact(s.DNS)
	slices.SortFunc(s.IPs, func(a, b netip.Addr) int { return a.Compare(b) })
	s.IPs = slices.Compact(s.IPs)
	slices.Sort(dropped)
	return s, slices.Compact(dropped)
}

// capNames trims the collected SAN candidates to maxLeafDNS/maxLeafIPs,
// keeping the first (highest priority) entries and reporting the rest as
// dropped. Duplicates are removed first so they do not eat the budget.
func capNames(dns []string, ips []netip.Addr, dropped []string) ([]string, []netip.Addr, []string) {
	dns = dedupeBy(dns, func(n string) string { return n })
	ips = dedupeBy(ips, func(a netip.Addr) string { return a.Unmap().WithZone("").String() })
	if len(dns) > maxLeafDNS {
		dropped = append(dropped, dns[maxLeafDNS:]...)
		dns = dns[:maxLeafDNS]
	}
	if len(ips) > maxLeafIPs {
		for _, ip := range ips[maxLeafIPs:] {
			dropped = append(dropped, ip.String())
		}
		ips = ips[:maxLeafIPs]
	}
	return dns, ips, dropped
}

// dedupeBy removes repeated entries, keeping the first occurrence and the order.
func dedupeBy[T any](in []T, key func(T) string) []T {
	seen := make(map[string]struct{}, len(in))
	out := make([]T, 0, len(in))
	for _, v := range in {
		k := key(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	return out
}

// leafDays returns the configured validity of the local leaf in days, clamped
// to the range issueLeaf accepts.
func (svc *Service) leafDays() int64 {
	days := svc.settingInt(KeyLeafDays, 397)
	if days < 1 || days > 825 {
		days = 397
	}
	return days
}

// renewBefore returns how long before expiry a leaf is reissued. The fixed
// 30-day window (DESIGN §10.4) only makes sense for a certificate that lives
// considerably longer than that: with tls.leaf_days ≤ 30 every leaf would be
// "expiring" the moment it is signed, and the twice-daily certs.renew_check
// would rotate the key and certificate for ever. Short-lived leaves therefore
// renew after two thirds of their own lifetime.
func renewBefore(span time.Duration) time.Duration {
	if span <= 0 {
		return leafRenewBefore
	}
	return min(leafRenewBefore, span/3)
}

// leafNeedsRenewal reports whether the leaf must be (re)issued and why.
func (svc *Service) leafNeedsRenewal(st *state, force bool) (bool, string) {
	switch {
	case st.ca == nil:
		return false, ""
	case force:
		return true, "forced"
	case st.leaf == nil || st.leaf.Leaf == nil:
		return true, "missing"
	}
	leaf := st.leaf.Leaf
	if leaf.CheckSignatureFrom(st.ca) != nil {
		return true, "ca_changed"
	}
	now := svc.env.Now()
	span := leaf.NotAfter.Sub(leaf.NotBefore)
	if leaf.NotAfter.Sub(now) < renewBefore(span) || now.Before(leaf.NotBefore) {
		return true, "expiring"
	}
	// tls.leaf_days only ever reached the certificate through issueLeaf, so a
	// change sat unapplied until something else reissued the leaf — up to 13
	// months with the default validity. Compare the span instead, unless it
	// was clamped to the CA's own expiry (then a shorter span is correct).
	if want := time.Duration(svc.leafDays()) * 24 * time.Hour; span != want &&
		leaf.NotAfter.Before(st.ca.NotAfter) && (span-want).Abs() > time.Hour {
		return true, "validity_changed"
	}
	want, _ := svc.desiredSANs(st.ca)
	if !want.equal(sansOf(leaf)) {
		return true, "sans_changed"
	}
	return false, ""
}

// UncoveredNames returns the wanted SAN entries the local CA may not sign
// (its name constraints) or that exceed the SAN limit — the names that are
// advertised as access URLs and accepted by the strict Host check but are
// missing from the local certificate. It is what GET /admin/certs reports as
// "uncovered_names" and what the settings API warns about.
func (svc *Service) UncoveredNames() []string {
	st := svc.snapshot()
	if st.ca == nil {
		return nil
	}
	_, dropped := svc.desiredSANs(st.ca)
	return dropped
}

// UnsignableNames returns those of names the local CA's name constraints do
// not permit. It answers for names that are not configured yet, so the
// settings API can warn while tls.extra_sans / network.extra_hosts is being
// changed instead of letting the name disappear silently.
func (svc *Service) UnsignableNames(names []string) []string {
	ca := svc.snapshot().ca
	if ca == nil {
		return nil
	}
	var out []string
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" {
			continue
		}
		if ip, err := netip.ParseAddr(n); err == nil {
			if !ipPermitted(ca, ip) {
				out = append(out, n)
			}
			continue
		}
		if !dnsPermitted(ca, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// warnUncovered logs the names left out of the local certificate once per
// distinct set: the warning used to live in issueLeaf, where the common case
// (only a non-permitted name was added, so nothing is reissued) never reached
// it and the drop was completely silent.
func (svc *Service) warnUncovered(dropped []string) {
	key := strings.Join(dropped, ",")
	if prev := svc.uncovered.Swap(&key); prev != nil && *prev == key {
		return
	}
	if len(dropped) == 0 {
		return
	}
	svc.log.Warn("names left out of the local certificate: not permitted by the local CA's name constraints "+
		"(regenerate the CA to include them)", "names", dropped)
}

// issueLeaf signs a new server certificate with the CA key and stores it
// (server/leaf.crt, server/leaf.key 0600, unsealed).
func (svc *Service) issueLeaf(ctx context.Context, ca *x509.Certificate) (*tls.Certificate, error) {
	if svc.env.Keys == nil || svc.env.Keys.State() != core.KeyStateUnlocked {
		return nil, core.ErrKeysLocked
	}
	caKey, err := svc.openSealedKey(fileCAKey, aadCAKey)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(ca.PublicKey, caKey.Public()) {
		return nil, errKeyMismatch("local CA")
	}
	sans, dropped := svc.desiredSANs(ca)
	svc.warnUncovered(dropped)
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := svc.env.Now()
	days := svc.leafDays()
	// The validity span is measured from NotBefore, which is backdated against
	// clock skew: anchoring NotAfter on it keeps the span exactly days*24h, so
	// the documented maximum (825 days) stays within the Apple limit.
	notBefore := now.Add(-backdate)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	cn := "localhost"
	for _, n := range sans.DNS {
		if n != "localhost" && !strings.HasPrefix(n, "*.") {
			cn = n
			break
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"FileParcel"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     sans.DNS,
	}
	for _, ip := range sans.IPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, fmt.Errorf("certs: sign leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := keyPKCS8(key)
	if err != nil {
		return nil, err
	}
	defer crypt.Zero(keyDER)
	keyPEM := pemBlock("PRIVATE KEY", keyDER)
	defer crypt.Zero(keyPEM)
	// Two renames can never replace a pair atomically, and a crash between
	// them left a key next to a certificate it does not belong to: no leaf at
	// the next start, so a sealed server could not even serve /unlock. The
	// new key is therefore staged as leaf.key.next, the certificate rename is
	// the commit point, and only then does the staged key replace leaf.key.
	// A crash before the commit leaves the old pair; after it, leaf.crt
	// matches leaf.key.next, which loadLeafPair falls back to and
	// settleLeafKey moves into place before the next swap.
	if err := svc.settleLeafKey(); err != nil {
		return nil, err
	}
	next := svc.path(fileLeafKeyNext)
	if err := writeFileAtomic(next, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(svc.path(fileLeafCert), certPEM(der), 0o644); err != nil {
		_ = removeOptional(next)
		return nil, err
	}
	if err := renameSync(next, svc.path(fileLeafKey)); err != nil {
		// Committed: the pair on disk is leaf.crt + leaf.key.next.
		svc.log.Warn("cannot move the new server key into place; it is kept as "+fileLeafKeyNext, "err", err)
	}
	svc.pendingRenew.Store(false)
	svc.log.Info("local server certificate issued", "names", sans.strings(), "not_after", notAfter.Format(time.RFC3339))
	// The CA is sent with the leaf so a client that pins it (--fingerprint)
	// receives the certificate it pinned; verifyPinned then uses it as the
	// trust anchor. Clients that verify against a trust store ignore the
	// extra self-signed root (RFC 8446 §4.4.2).
	return tlsCert([]*x509.Certificate{leaf, ca}, key), nil
}

// settleLeafKey finishes or discards a leaf swap interrupted by a crash
// (issueLeaf) so that leaf.crt matches leaf.key again: a staged
// leaf.key.next that matches leaf.crt was committed and replaces leaf.key;
// one that does not was never committed and is removed.
func (svc *Service) settleLeafKey() error {
	next := svc.path(fileLeafKeyNext)
	kb, err := readOptional(next)
	if err != nil || kb == nil {
		return err
	}
	defer crypt.Zero(kb)
	cb, err := readOptional(svc.path(fileLeafCert))
	if err != nil {
		return err
	}
	if cb != nil {
		if _, err := tls.X509KeyPair(cb, kb); err == nil {
			return renameSync(next, svc.path(fileLeafKey))
		}
	}
	return removeOptional(next)
}

// RenewLocal implements core.Certs: reissues the local leaf when forced,
// missing, signed by another CA, within 30 days of expiry or when the SAN set
// changed. Needs unlocked keys (core.ErrKeysLocked otherwise).
func (svc *Service) RenewLocal(ctx context.Context, force bool) error {
	svc.opMu.Lock()
	defer svc.opMu.Unlock()
	st := svc.snapshot()
	if st.ca == nil {
		return core.Errorf(core.ErrPrecondition, `the local CA does not exist yet; run "fileparcel init"`)
	}
	need, reason := svc.leafNeedsRenewal(st, force)
	if !need {
		// Adding a name the CA may not sign changes nothing about the leaf, so
		// without this the drop was invisible: leafNeedsRenewal compares the
		// already-filtered desired set and issueLeaf is never reached.
		_, dropped := svc.desiredSANs(st.ca)
		svc.warnUncovered(dropped)
		return nil
	}
	leaf, err := svc.issueLeaf(ctx, st.ca)
	if err != nil {
		if core.AsError(err) != nil && core.AsError(err).Code == core.ErrKeysLocked.Code {
			svc.pendingRenew.Store(true)
		}
		svc.audit(ctx, core.AuditEntry{Action: core.ActCertRenew, Outcome: core.OutcomeFailure, TargetType: "certificate",
			TargetName: "local", Details: map[string]any{"reason": reason, "error": err.Error()}})
		return err
	}
	next := st.clone()
	next.leaf = leaf
	svc.state.Store(next)
	svc.publishChanged()
	svc.audit(ctx, core.AuditEntry{Action: core.ActCertRenew, TargetType: "certificate", TargetName: "local",
		Details: map[string]any{"reason": reason, "names": sansOf(leaf.Leaf).strings(),
			"not_after": leaf.Leaf.NotAfter.UTC().Format(time.RFC3339)}})
	return nil
}
