package tslocal

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Status is the subset of tailscale's ipnstate.Status that FileParcel reads
// (GET /localapi/v0/status?peers=false, `tailscale status --json`).
type Status struct {
	BackendState   string         `json:"BackendState"`
	TUN            bool           `json:"TUN"`
	Version        string         `json:"Version"`
	TailscaleIPs   []netip.Addr   `json:"TailscaleIPs"`
	MagicDNSSuffix string         `json:"MagicDNSSuffix"`
	CertDomains    []string       `json:"CertDomains"`
	Self           *SelfStatus    `json:"Self"`
	CurrentTailnet *TailnetStatus `json:"CurrentTailnet"`
}

// SelfStatus describes this node.
type SelfStatus struct {
	ID           string       `json:"ID"` // StableNodeID
	HostName     string       `json:"HostName"`
	DNSName      string       `json:"DNSName"` // MagicDNS FQDN with a trailing dot
	TailscaleIPs []netip.Addr `json:"TailscaleIPs"`
	KeyExpiry    *time.Time   `json:"KeyExpiry"` // nil: key expiry disabled
	// CapMap holds the node capabilities ("https", "funnel",
	// "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000", …).
	CapMap map[string]json.RawMessage `json:"CapMap"`
	// Capabilities is the deprecated list form of CapMap (older daemons).
	Capabilities []string `json:"Capabilities"`
	Tags         []string `json:"Tags"`
}

// TailnetStatus describes the tailnet.
type TailnetStatus struct {
	Name            string `json:"Name"`
	MagicDNSSuffix  string `json:"MagicDNSSuffix"`
	MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
}

// Running reports whether the node is connected (BackendState "Running").
func (s *Status) Running() bool { return s != nil && s.BackendState == "Running" }

// NodeID returns Self.ID ("" when unknown).
func (s *Status) NodeID() string {
	if s == nil || s.Self == nil {
		return ""
	}
	return s.Self.ID
}

// IPs returns the node's Tailscale addresses (unmapped; Self's list when the
// top-level one is empty).
func (s *Status) IPs() []netip.Addr {
	if s == nil {
		return nil
	}
	ips := s.TailscaleIPs
	if len(ips) == 0 && s.Self != nil {
		ips = s.Self.TailscaleIPs
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, a := range ips {
		if a.IsValid() {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// HasCap reports whether the node has capability name (a CapMap key or a
// Capabilities entry).
func (s *Status) HasCap(name string) bool {
	if s == nil || s.Self == nil {
		return false
	}
	if _, ok := s.Self.CapMap[name]; ok {
		return true
	}
	return slices.Contains(s.Self.Capabilities, name)
}

// capFunnelPorts is tailcfg.CapabilityFunnelPorts.
const capFunnelPorts = "https://tailscale.com/cap/funnel-ports"

// FunnelCandidatePorts are the only ports Tailscale Funnel supports.
var FunnelCandidatePorts = []int{443, 8443, 10000}

// FunnelPorts returns the Funnel ports the node's funnel-ports capability
// allows, parsed like ipn.CheckFunnelPort (comma list, "a-b" ranges) and
// limited to FunnelCandidatePorts. A missing or malformed capability allows
// none.
func (s *Status) FunnelPorts() []int {
	if s == nil || s.Self == nil {
		return []int{}
	}
	var ports string
	found := false
	check := func(c string) {
		if found || !strings.HasPrefix(c, capFunnelPorts) {
			return
		}
		found = true
		u, err := url.Parse(c)
		if err != nil {
			return
		}
		ports = u.Query().Get("ports")
		u.RawQuery = ""
		if u.String() != capFunnelPorts {
			ports = ""
		}
	}
	keys := make([]string, 0, len(s.Self.CapMap))
	for k := range s.Self.CapMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		check(k)
	}
	for _, c := range s.Self.Capabilities {
		check(c)
	}
	out := []int{}
	if ports == "" {
		return out
	}
	for _, want := range FunnelCandidatePorts {
		ok, malformed := portAllowed(ports, want)
		if malformed {
			return []int{}
		}
		if ok {
			out = append(out, want)
		}
	}
	return out
}

// portAllowed evaluates one funnel-ports value for port the way tailscale
// does: a malformed range denies every port.
func portAllowed(list string, port int) (ok, malformed bool) {
	want := strconv.Itoa(port)
	for ps := range strings.SplitSeq(list, ",") {
		if ps == "" {
			continue
		}
		first, last, isRange := strings.Cut(ps, "-")
		if !isRange {
			if first == want {
				return true, false
			}
			continue
		}
		fp, err1 := strconv.ParseUint(first, 10, 16)
		lp, err2 := strconv.ParseUint(last, 10, 16)
		if err1 != nil || err2 != nil {
			return false, true
		}
		if uint64(port) >= fp && uint64(port) <= lp {
			return true, false
		}
	}
	return false, false
}

// HostPortName returns the name the HostPort keys of the serve config use:
// Self.DNSName without its trailing dot, exactly as the tailscale CLI builds
// it (no lowercasing). "" when unknown.
func (s *Status) HostPortName() string {
	if s == nil || s.Self == nil {
		return ""
	}
	return strings.TrimSuffix(s.Self.DNSName, ".")
}

// DNSName returns the MagicDNS name lowercased without its trailing dot
// ("" when unknown or when MagicDNS is off for the tailnet).
func (s *Status) DNSName() string {
	if s == nil || s.Self == nil {
		return ""
	}
	if s.CurrentTailnet != nil && !s.CurrentTailnet.MagicDNSEnabled {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(s.Self.DNSName, "."))
}

// Prefs is the subset of tailscale's ipn.Prefs that FileParcel reads
// (GET /localapi/v0/prefs, `tailscale debug prefs`).
type Prefs struct {
	ControlURL   string `json:"ControlURL"`
	OperatorUser string `json:"OperatorUser"`
	ShieldsUp    bool   `json:"ShieldsUp"`
	WantRunning  bool   `json:"WantRunning"`
}

// officialControlHosts are the Tailscale-operated control servers.
var officialControlHosts = []string{"controlplane.tailscale.com", "login.tailscale.com"}

// SelfHosted reports whether controlURL names a self-hosted control server
// (Headscale or another one) rather than Tailscale's. An empty or
// unparsable URL is not self-hosted.
func SelfHosted(controlURL string) bool {
	if strings.TrimSpace(controlURL) == "" {
		return false
	}
	u, err := url.Parse(controlURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return !slices.Contains(officialControlHosts, strings.ToLower(u.Hostname()))
}

// QueryFeature is tailcfg.QueryFeatureResponse (POST
// /localapi/v0/query-feature): whether a feature (funnel, serve) is enabled
// for this node and, if not, where an admin can enable it.
type QueryFeature struct {
	Complete   bool   `json:"Complete"`
	Text       string `json:"Text"`
	URL        string `json:"URL"`
	ShouldWait bool   `json:"ShouldWait"`
}
