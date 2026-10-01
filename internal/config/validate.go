package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ValidationError describes one invalid key.
type ValidationError struct {
	Key string
	Msg string
}

// Error implements error.
func (e *ValidationError) Error() string { return "config: " + e.Key + ": " + e.Msg }

// Validate checks every value; the returned error joins one *ValidationError
// per problem (use errors.As to inspect).
func (c *Config) Validate() error {
	var errs []error
	bad := func(key, format string, a ...any) {
		errs = append(errs, &ValidationError{Key: key, Msg: fmt.Sprintf(format, a...)})
	}

	if b, err := hex.DecodeString(c.InstallID); err != nil || len(b) != 16 {
		bad("install_id", "must be 32 hex characters")
	}
	if !ValidDNSLabel(c.Server.Name) {
		bad("server.name", "must be a DNS label (1-63 chars: a-z, 0-9, '-'; not starting or ending with '-')")
	}
	if c.Server.HTTPSPort < 1 || c.Server.HTTPSPort > 65535 {
		bad("server.https_port", "must be 1-65535")
	}
	if c.Server.HTTPPort < 0 || c.Server.HTTPPort > 65535 {
		bad("server.http_port", "must be 0-65535 (0 disables)")
	} else if c.Server.HTTPPort != 0 && c.Server.HTTPPort == c.Server.HTTPSPort {
		bad("server.http_port", "must differ from https_port")
	}
	// Only each entry on its own: a list that repeats an address or adds one
	// next to a wildcard is refused when set through the catalog
	// (CheckBindList) but tolerated here, so the CLI keeps working on such a
	// file and the server starts on it (it skips the covered entries).
	if len(c.Server.Bind) == 0 {
		bad("server.bind", "must list at least one address (e.g. \"::\")")
	}
	for _, b := range c.Server.Bind {
		if _, err := netip.ParseAddr(b); err != nil {
			bad("server.bind", "%q is not an IP address", b)
		}
	}
	if err := CheckPublicURL(c.Server.PublicURL); err != nil {
		bad("server.public_url", "%s", err)
	}
	for _, p := range c.Server.TrustedProxies {
		if _, err := ParsePrefixOrAddr(p); err != nil {
			bad("server.trusted_proxies", "%q is not an IP address or CIDR", p)
		}
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		bad("log.level", "must be debug, info, warn or error")
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		bad("log.format", "must be text or json")
	}
	if c.Log.MaxSizeMB < 1 || c.Log.MaxSizeMB > 10240 {
		bad("log.max_size_mb", "must be 1-10240")
	}
	if c.Log.MaxFiles < 1 || c.Log.MaxFiles > 100 {
		bad("log.max_files", "must be 1-100")
	}
	if c.Runtime.GOMemLimitMB < 0 {
		bad("runtime.gomemlimit_mb", "must be >= 0 (0 = auto)")
	}
	return errors.Join(errs...)
}

// CheckBindList checks a new server.bind list (the settings catalog's
// validator). Every entry is bound separately on the same port, so the list
// must be one that can actually be bound: no entry twice (::ffff:10.0.0.1 is
// 10.0.0.1), and a wildcard ("::" or "0.0.0.0", both dual-stack listeners in
// Go) only on its own, since it already covers every other address and a
// second bind fails with "address already in use".
func CheckBindList(l []string) error {
	if len(l) == 0 {
		return errors.New("must list at least one address (e.g. \"::\")")
	}
	seen := make(map[netip.Addr]string, len(l))
	for _, s := range l {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("%q is not an IP address", s)
		}
		a = a.Unmap()
		if a.IsUnspecified() && len(l) > 1 {
			return fmt.Errorf("%q listens on every interface (IPv4 and IPv6); list it alone", s)
		}
		if prev, dup := seen[a]; dup {
			if prev == s {
				return fmt.Errorf("%q is listed twice", s)
			}
			return fmt.Errorf("%q and %q are the same address", prev, s)
		}
		seen[a] = s
	}
	return nil
}

// CheckPublicURL checks a server.public_url value (config.Validate and the
// settings catalog's validator): empty, or an absolute http(s) origin —
// scheme, host and an optional port 1-65535, with at most a trailing "/".
// The value is the base of every share and invitation link handed to other
// people, so a user name or password in it would travel with each link, and
// the web app is served from the root of its host: a path, query or fragment
// would only make those links useless.
func CheckPublicURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Opaque != "" {
		return errors.New("must be an absolute http(s) URL or empty")
	}
	switch {
	case u.User != nil:
		return errors.New("must not contain a user name or password (it would appear in every share and invitation link)")
	case u.Path != "" && u.Path != "/" || u.RawPath != "":
		return errors.New("must not have a path: FileParcel is served from the root of its host (e.g. https://files.example.com)")
	case strings.ContainsAny(s, "?#"):
		return errors.New("must not have a query or fragment")
	case u.Hostname() == "":
		return errors.New("must name a host")
	}
	if p := u.Port(); p != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("port must be 1-65535")
		}
	}
	return nil
}

// ValidDNSLabel reports whether s is a lowercase DNS label (RFC 1123).
func ValidDNSLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// ParsePrefixOrAddr parses "10.0.0.0/8" or a single IP ("10.0.0.1" -> /32,
// "::1" -> /128). IPv4-mapped IPv6 addresses are unmapped.
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			bits := p.Bits() - 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("invalid IPv4-mapped prefix %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), bits)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
