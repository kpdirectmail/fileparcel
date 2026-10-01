package netinfo

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/core"
)

// Exposures (DESIGN §10.3): ways the access policy can be bypassed on this
// machine that netinfo can see. The Funnel/Serve bypass entries and the
// unconfigured-proxy signal come from the request path
// (httpx.ProxyExposures); the settings API and the doctor merge both.

// Exposure IDs reported by netinfo.
const (
	ExposureUserspace   = "tailscale.userspace"
	ExposureShieldsUp   = "tailscale.shields_up"
	ExposureCloudflared = "cloudflared"
)

// Exposure scan limits.
const (
	exposureTTL      = 60 * time.Second
	exposureTimeout  = 2 * time.Second
	maxCloudflaredCf = 256 << 10 // one cloudflared config file
)

// cloudflaredConfigs are where cloudflared looks for its configuration
// ("~" is the home of the account FileParcel runs as).
var cloudflaredConfigs = []string{"~/.cloudflared/config.yml", "~/.cloudflared/config.yaml",
	"/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml", "/usr/local/etc/cloudflared/config.yml"}

// cloudflaredUnits are the service registrations of cloudflared.
var cloudflaredUnits = []string{"/etc/systemd/system/cloudflared.service", "/lib/systemd/system/cloudflared.service",
	"/usr/lib/systemd/system/cloudflared.service", "/Library/LaunchDaemons/com.cloudflare.cloudflared.plist",
	"~/Library/LaunchAgents/com.cloudflare.cloudflared.plist"}

// exposureCache keeps the last exposure scan for exposureTTL.
type exposureCache struct {
	mu  sync.Mutex
	at  time.Time
	key string
	val []core.Exposure
}

// Exposures implements the optional exposure listing of the network
// service (GET /admin/network, doctor): Tailscale in userspace mode or
// with shields up, and a Cloudflare Tunnel forwarding to FileParcel.
// Cached for a minute; each probe is bounded.
func (s *Service) Exposures(ctx context.Context) []core.Exposure {
	sn := s.current()
	trusted := s.settingStrings("server.trusted_proxies")
	key := fmt.Sprint(s.port, trusted)
	s.expo.mu.Lock()
	defer s.expo.mu.Unlock()
	now := time.Now()
	if s.expo.val != nil && s.expo.key == key && now.Sub(s.expo.at) < exposureTTL {
		return append(tailscaleExposures(sn.ts), s.expo.val...)
	}
	ctx, cancel := context.WithTimeout(ctx, exposureTimeout)
	defer cancel()
	var cf []core.Exposure
	if s.cloudflared != nil && !loopbackTrusted(trusted) {
		if e := s.cloudflared(ctx, s.port, s.ownHost); e != nil {
			cf = append(cf, *e)
		}
	}
	if ctx.Err() == nil || cf != nil {
		s.expo.val, s.expo.at, s.expo.key = append([]core.Exposure{}, cf...), now, key
	}
	return append(tailscaleExposures(sn.ts), cf...)
}

// tailscaleExposures reports tailscaled in userspace-networking mode
// (tailnet connections reach FileParcel from 127.0.0.1, which is always
// allowed) and shields-up (tailnet devices cannot connect).
func tailscaleExposures(ts *core.TailscaleInfo) []core.Exposure {
	out := []core.Exposure{}
	if ts == nil || !ts.Running {
		return out
	}
	if ts.Userspace {
		out = append(out, core.Exposure{ID: ExposureUserspace, Severity: "warn",
			Message: "Tailscale runs without a TUN device: tailnet connections reach FileParcel from 127.0.0.1 and bypass the access policy.",
			Hint:    "Run tailscaled with a TUN device, or use Tailscale Serve (fileparcel network tailscale-serve enable), which keeps the real tailnet address."})
	}
	if ts.ShieldsUp {
		out = append(out, core.Exposure{ID: ExposureShieldsUp, Severity: "info",
			Message: "Tailscale shields-up is on: tailnet devices cannot connect to this machine.",
			Hint:    "sudo tailscale set --shields-up=false"})
	}
	return out
}

// loopbackTrusted reports whether server.trusted_proxies covers loopback:
// a local tunnel's X-Forwarded-For is then honoured and the access policy
// applies to its visitors.
func loopbackTrusted(entries []string) bool {
	for _, e := range entries {
		p, err := parseEntry(e)
		if err == nil && (p.Contains(netip.MustParseAddr("127.0.0.1")) || p.Contains(netip.IPv6Loopback())) {
			return true
		}
	}
	return false
}

// ownHost reports whether host (a name or an IP literal) is this machine:
// localhost, one of its addresses or one of its names (.local, host name).
func (s *Service) ownHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return s.IsLocal(ip)
	}
	return h != "" && slices.Contains(s.Hostnames(), h)
}

// systemCloudflared scans for a Cloudflare Tunnel that forwards to
// FileParcel's HTTPS port (DESIGN §10.3): only while a cloudflared process
// runs or its service is registered. local tells this machine's hosts
// (nil: loopback only). Besides the default configuration files it reads
// the --config file of every running cloudflared.
func systemCloudflared(ctx context.Context, port int, local func(host string) bool) *core.Exposure {
	in := cloudflaredInput{port: port, local: local}
	in.running = runningProcesses()["cloudflared"]
	home, _ := os.UserHomeDir()
	expand := func(p string) string {
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			if home == "" {
				return ""
			}
			return filepath.Join(home, rest)
		}
		return p
	}
	for _, u := range cloudflaredUnits {
		if p := expand(u); p != "" {
			if _, err := os.Stat(p); err == nil {
				in.running = true
			}
		}
	}
	if !in.running || ctx.Err() != nil {
		return nil
	}
	in.cmdlines = processArgs("cloudflared")
	paths := slices.Clone(cloudflaredConfigs)
	for _, args := range in.cmdlines {
		for _, p := range configArgs(args) {
			if (filepath.IsAbs(p) || strings.HasPrefix(p, "~/")) && !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
	}
	for _, c := range paths {
		if p := expand(c); p != "" {
			if b, ok := readSmall(p, maxCloudflaredCf); ok {
				in.configs = append(in.configs, b)
			}
		}
	}
	return cloudflaredExposure(in)
}

// configArgs returns the --config values of a cloudflared command line.
func configArgs(args []string) []string {
	var out []string
	for i, a := range args {
		switch {
		case (a == "--config" || a == "-config") && i+1 < len(args):
			out = append(out, args[i+1])
		case strings.HasPrefix(a, "--config="):
			out = append(out, strings.TrimPrefix(a, "--config="))
		}
	}
	return out
}

// cloudflaredInput is what cloudflaredExposure decides on.
type cloudflaredInput struct {
	running  bool                   // a cloudflared process or service exists
	configs  [][]byte               // readable configuration files (default paths and --config)
	cmdlines [][]string             // arguments of the running cloudflared processes
	port     int                    // FileParcel's HTTPS port
	local    func(host string) bool // this machine's addresses and names (nil: loopback only)
}

// toFileParcel reports whether a tunnel origin (http:// or https://)
// reaches FileParcel's HTTPS port on this machine: localhost, loopback, one
// of its addresses (a LAN URL copied into the config) or its names (.local).
// cloudflared then connects from this machine, which the access policy
// admits for every visitor alike.
func (in cloudflaredInput) toFileParcel(service string) bool {
	u, err := url.Parse(strings.TrimSpace(service))
	if err != nil || u.Host == "" {
		return false
	}
	port := u.Port()
	switch strings.ToLower(u.Scheme) {
	case "http":
		port = cmp.Or(port, "80")
	case "https":
		port = cmp.Or(port, "443")
	default:
		return false
	}
	if port != strconv.Itoa(in.port) {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Unmap().IsLoopback() {
		return true
	}
	return in.local != nil && in.local(host)
}

// cloudflaredExposure finds tunnel origins pointing at this server's HTTPS
// port on this machine — `service:` of an ingress rule or the legacy
// top-level `url:` in a configuration, `--url` on a command line — and
// names their public hostnames. A cloudflared without a configuration that
// could be read here (a remotely managed tunnel started with a token, or a
// --config file this account cannot read) is reported as info: its origins
// are not visible here.
func cloudflaredExposure(in cloudflaredInput) *core.Exposure {
	if !in.running || in.port <= 0 {
		return nil
	}
	var hosts []string
	matched, configured := false, len(in.configs) > 0
	found := func(host string) {
		matched = true
		if host != "" && !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	for _, cfg := range in.configs {
		for _, r := range yamlRules(cfg) {
			if in.toFileParcel(r.service) {
				found(r.hostname)
			}
		}
	}
	for _, args := range in.cmdlines {
		for i, a := range args {
			var v string
			switch {
			case a == "--url" && i+1 < len(args):
				v = args[i+1]
			case strings.HasPrefix(a, "--url="):
				v = strings.TrimPrefix(a, "--url=")
			default:
				continue
			}
			configured = true
			if in.toFileParcel(v) {
				found("")
			}
		}
	}
	const hint = "Protect it with Cloudflare Access and set server.trusted_proxies to the address cloudflared connects " +
		"from (127.0.0.1 and ::1 for a localhost origin), so the access policy and the logs see the visitors' addresses."
	switch {
	case matched:
		what := "a public hostname"
		if len(hosts) > 0 {
			what = strings.Join(hosts, ", ")
		}
		return &core.Exposure{ID: ExposureCloudflared, Severity: "warn",
			Message: "Cloudflare Tunnel forwards " + what + " to FileParcel: visitors appear as this machine (127.0.0.1 or " +
				"its own address).", Hint: hint}
	case !configured:
		return &core.Exposure{ID: ExposureCloudflared, Severity: "info",
			Message: "cloudflared runs without a local configuration FileParcel can read (a remotely managed tunnel, or a " +
				"--config file it may not open): if it forwards to FileParcel, visitors appear as this machine.",
			Hint: hint}
	}
	return nil
}

// tunnelRule is one origin of a cloudflared configuration.
type tunnelRule struct{ hostname, service string }

// yamlRules line-scans a cloudflared config.yml: every `service:` of an
// ingress rule with the rule's `hostname:`, and the legacy top-level
// `url:` with the top-level `hostname:`. It is no YAML parser — enough for
// the flat files cloudflared documents.
func yamlRules(b []byte) []tunnelRule {
	var out []tunnelRule
	var topHost, topURL string
	var cur *tunnelRule
	flush := func() {
		if cur != nil && cur.service != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indented := raw[0] == ' ' || raw[0] == '\t'
		if item, ok := strings.CutPrefix(line, "- "); ok {
			flush()
			cur = &tunnelRule{}
			line = strings.TrimSpace(item)
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), yamlScalar(v)
		switch {
		case !indented && cur == nil && k == "hostname":
			topHost = v
		case !indented && cur == nil && k == "url":
			topURL = v
		case !indented && !strings.HasPrefix(raw, "-"):
			flush() // a new top-level key ends the ingress list
		case cur != nil && k == "hostname":
			cur.hostname = v
		case cur != nil && k == "service":
			cur.service = v
		}
	}
	flush()
	if topURL != "" {
		out = append(out, tunnelRule{hostname: topHost, service: topURL})
	}
	return out
}

// yamlScalar strips quotes and a trailing comment from a YAML value.
func yamlScalar(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if i := strings.IndexByte(v[1:], v[0]); i >= 0 {
			return v[1 : i+1]
		}
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
