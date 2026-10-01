package netinfo

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"fileparcel/internal/core"
)

// maxPolicyEntries bounds the allow and deny lists.
const maxPolicyEntries = 1024

// privateRanges are the networks admitted by access mode "private"
// (DESIGN §10.3). Loopback is always allowed separately.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

// PrivateRanges returns the CIDRs of access mode "private" (for the UI and docs).
func PrivateRanges() []string {
	out := make([]string, len(privateRanges))
	for i, p := range privateRanges {
		out[i] = p.String()
	}
	return out
}

// matcher is a compiled, immutable access policy. Allowed is lock-free: the
// Service swaps whole matchers through an atomic.Pointer.
type matcher struct {
	policy core.AccessPolicy // normalised (canonical CIDR strings)
	any    bool
	allow  []netip.Prefix
	deny   []netip.Prefix
}

// allowed evaluates the policy for ip (DESIGN §10.3): IPv4-mapped IPv6
// addresses are unmapped and zones dropped; loopback is always allowed;
// otherwise the deny list wins over the mode and allow list.
func (m *matcher) allowed(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() {
		return true
	}
	if m == nil {
		return false
	}
	for _, p := range m.deny {
		if p.Contains(ip) {
			return false
		}
	}
	if m.any {
		return true
	}
	for _, p := range m.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// denied reports whether the deny list covers ip (loopback never: it is
// always allowed, see allowed).
func (m *matcher) denied(ip netip.Addr) bool {
	if !ip.IsValid() || m == nil {
		return false
	}
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() {
		return false
	}
	for _, p := range m.deny {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// parseEntry parses a CIDR or a single IP address into a canonical prefix
// (host bits masked, IPv4-mapped prefixes converted to IPv4, zones dropped).
func parseEntry(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty entry")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR", s)
		}
		a, bits := p.Addr(), p.Bits()
		if a.Is4In6() {
			if bits < 96 {
				return netip.Prefix{}, fmt.Errorf("%q: IPv4-mapped prefixes must be /96 or longer", s)
			}
			a, bits = a.Unmap(), bits-96
		}
		return netip.PrefixFrom(a, bits).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// entryString renders a canonical prefix: single addresses without the
// /32 or /128 suffix.
func entryString(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// parseList parses and de-duplicates a list of CIDRs/IPs, returning the
// prefixes and their canonical strings (input order kept).
func parseList(field string, in []string) ([]netip.Prefix, []string, error) {
	if len(in) > maxPolicyEntries {
		return nil, nil, core.Invalid(field, fmt.Sprintf("at most %d entries", maxPolicyEntries))
	}
	prefixes := make([]netip.Prefix, 0, len(in))
	strs := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		p, err := parseEntry(s)
		if err != nil {
			return nil, nil, core.Invalid(field, err.Error())
		}
		if slices.Contains(prefixes, p) {
			continue
		}
		prefixes = append(prefixes, p)
		strs = append(strs, entryString(p))
	}
	return prefixes, strs, nil
}

// compilePolicy validates and compiles p. An empty mode means allowlist
// (the install default). Mode "private" admits the private ranges plus the
// allow list (so a LAN's global IPv6 prefix can be added).
func compilePolicy(p core.AccessPolicy) (*matcher, error) {
	mode := strings.TrimSpace(strings.ToLower(p.Mode))
	if mode == "" {
		mode = core.AccessAllowlist
	}
	switch mode {
	case core.AccessPrivate, core.AccessAllowlist, core.AccessAny:
	default:
		return nil, core.Invalid("mode", "must be one of: private, allowlist, any")
	}
	allow, allowStr, err := parseList("allow", p.Allow)
	if err != nil {
		return nil, err
	}
	deny, denyStr, err := parseList("deny", p.Deny)
	if err != nil {
		return nil, err
	}
	m := &matcher{
		policy: core.AccessPolicy{Mode: mode, Allow: allowStr, Deny: denyStr},
		any:    mode == core.AccessAny,
		deny:   deny,
	}
	if mode == core.AccessPrivate {
		m.allow = append(slices.Clone(privateRanges), allow...)
	} else {
		m.allow = allow
	}
	return m, nil
}

// defaultMatcher is the fail-safe policy: allowlist with no entries
// (loopback only).
func defaultMatcher() *matcher {
	m, _ := compilePolicy(core.AccessPolicy{Mode: core.AccessAllowlist})
	return m
}

// clonePolicy deep-copies p (never nil slices).
func clonePolicy(p core.AccessPolicy) core.AccessPolicy {
	c := core.AccessPolicy{Mode: p.Mode, Allow: slices.Clone(p.Allow), Deny: slices.Clone(p.Deny)}
	if c.Allow == nil {
		c.Allow = []string{}
	}
	if c.Deny == nil {
		c.Deny = []string{}
	}
	return c
}

// policyWarnings lists the user-facing warnings about m (DESIGN §10.3). ip
// is the requesting client's address (may be invalid for in-process callers).
func policyWarnings(m *matcher, ip netip.Addr, force bool) []string {
	w := []string{}
	switch m.policy.Mode {
	case core.AccessAny:
		w = append(w, `Access mode "any" accepts connections from every address, including the internet if this machine is reachable from it.`)
	case core.AccessAllowlist:
		if len(m.allow) == 0 {
			w = append(w, "The allow list is empty: only this machine (loopback) can connect.")
		}
	}
	if m.policy.Mode != core.AccessAny {
		for _, p := range m.allow {
			if p.Bits() == 0 {
				w = append(w, fmt.Sprintf("%s admits every %s address.", p, family(p.Addr())))
			}
		}
	}
	for _, p := range m.deny {
		if p.Contains(netip.MustParseAddr("127.0.0.1")) || p.Contains(netip.IPv6Loopback()) {
			w = append(w, fmt.Sprintf("Deny entry %s covers loopback addresses, which are always allowed.", entryString(p)))
		}
	}
	if ip.IsValid() && !m.allowed(ip) {
		if force {
			w = append(w, fmt.Sprintf("Your current address %s is not allowed by this policy: new connections from it will be refused.", ip.Unmap().WithZone("")))
		}
	}
	return w
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}
