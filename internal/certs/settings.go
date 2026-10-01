package certs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"fileparcel/internal/settings"
)

// Setting keys owned by this package (DESIGN §11.2, sections tls, acme,
// tailscale and mtls). All of them apply live: the TLS configuration is
// computed per handshake and the service watches settings.changed.
const (
	KeyExtraSANs       = "tls.extra_sans"
	KeyHSTS            = "tls.hsts"
	KeyMinVersion      = "tls.min_version"
	KeyLeafDays        = "tls.leaf_days"
	KeyACMEEnabled     = "acme.enabled"
	KeyACMEEmail       = "acme.email"
	KeyACMEDomains     = "acme.domains"
	KeyACMECA          = "acme.ca"
	KeyACMEChallenge   = "acme.challenge"
	KeyACMEProvider    = "acme.dns_provider"
	KeyACMECreds       = "acme.dns_credentials"
	KeyTailscaleCert   = "tailscale.cert_enabled"
	KeyTailscaleName   = "tailscale.domain"
	KeyMTLSMode        = "mtls.mode"
	KeyMTLSExempt      = "mtls.exempt_shares"
	KeyMTLSSelfService = "mtls.self_service"
)

// mTLS modes (mtls.mode).
const (
	MTLSOff      = "off"
	MTLSOptional = "optional"
	MTLSRequired = "required"
)

// maxExtraSANs and maxACMEDomains bound the name lists that end up in one
// certificate. Without a cap a perfectly valid PATCH /admin/settings locks the
// server out of HTTPS: 12 000 names in tls.extra_sans produced a 228 KB leaf
// and every client failed the handshake with "excessive message size", leaving
// shell access to the host as the only way back. desiredSANs enforces a second
// bound on the assembled SAN set (maxLeafDNS/maxLeafIPs).
const (
	maxExtraSANs   = 64
	maxACMEDomains = 64
)

// ACME challenge types (acme.challenge) and DNS providers (acme.dns_provider).
const (
	ChallengeDNS     = "dns"
	ChallengeHTTP    = "http"
	ChallengeTLSALPN = "tls-alpn"

	ProviderCloudflare = "cloudflare"
	ProviderRFC2136    = "rfc2136"
)

func init() {
	settings.Register(settings.Def{Key: KeyExtraSANs, Section: "tls", Order: 10, Type: settings.TypeStrings,
		Default: []string{}, Label: "Extra certificate names",
		Description: "Additional DNS names or IP addresses for the local certificate (e.g. a DNS name pointing at this server). " +
			"Names outside the local CA's name constraints require regenerating the CA.",
		Validate: func(v any) error {
			l := v.([]string)
			if len(l) > maxExtraSANs {
				return fmt.Errorf("at most %d names (they all go into one certificate, "+
					"and an oversized certificate breaks every TLS handshake)", maxExtraSANs)
			}
			for _, s := range l {
				if _, err := netip.ParseAddr(s); err == nil {
					continue
				}
				if !validDNSName(strings.TrimSuffix(strings.ToLower(s), "."), true) {
					return fmt.Errorf("%q is neither a DNS name nor an IP address", s)
				}
			}
			return nil
		}})
	settings.Register(settings.Def{Key: KeyHSTS, Section: "tls", Order: 20, Type: settings.TypeEnum,
		Default: "auto", Enum: []string{"auto", "on", "off"}, Label: "HSTS",
		Description: "Strict-Transport-Security: auto sends it only while the served certificate is publicly trusted."})
	settings.Register(settings.Def{Key: KeyMinVersion, Section: "tls", Order: 30, Type: settings.TypeEnum,
		Default: "1.2", Enum: []string{"1.2", "1.3"}, Label: "Minimum TLS version",
		Description: "Oldest TLS version accepted: 1.2 (default) or 1.3."})
	settings.Register(settings.Def{Key: KeyLeafDays, Section: "tls", Order: 40, Type: settings.TypeInt,
		Default: 397, Min: 7, Max: 825, Label: "Local certificate validity (days)",
		Description: "Validity of the server certificate issued by the local CA (Apple devices accept at most 825 days)."})

	settings.Register(settings.Def{Key: KeyACMEEnabled, Section: "acme", Order: 10, Type: settings.TypeBool,
		Default: false, Label: "Use ACME (Let's Encrypt)",
		Description: "Obtain publicly trusted certificates for the ACME domains."})
	settings.Register(settings.Def{Key: KeyACMEEmail, Section: "acme", Order: 20, Type: settings.TypeEmail,
		Default: "", Label: "ACME account e-mail", Validate: validACMEEmail,
		Description: "Account e-mail for the ACME CA (expiry notices)."})
	settings.Register(settings.Def{Key: KeyACMEDomains, Section: "acme", Order: 30, Type: settings.TypeStrings,
		Default: []string{}, Label: "ACME domains",
		Description: "Public DNS names to obtain certificates for (wildcards need the dns challenge).",
		Validate: func(v any) error {
			l := v.([]string)
			if len(l) > maxACMEDomains {
				return fmt.Errorf("at most %d domains", maxACMEDomains)
			}
			for _, s := range l {
				if err := validACMEDomain(s); err != nil {
					return err
				}
			}
			return nil
		}})
	settings.Register(settings.Def{Key: KeyACMECA, Section: "acme", Order: 40, Type: settings.TypeString,
		Default: "staging", Label: "ACME CA",
		Description: `"staging" (Let's Encrypt staging, not trusted), "production" (Let's Encrypt) or an ACME directory URL.`,
		Validate: func(v any) error {
			s := v.(string)
			if s == "staging" || s == "production" {
				return nil
			}
			u, err := url.Parse(s)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return errors.New(`must be "staging", "production" or an https:// ACME directory URL`)
			}
			return nil
		}})
	settings.Register(settings.Def{Key: KeyACMEChallenge, Section: "acme", Order: 50, Type: settings.TypeEnum,
		Default: ChallengeDNS, Enum: []string{ChallengeDNS, ChallengeHTTP, ChallengeTLSALPN}, Label: "ACME challenge",
		Description: "dns works without public reachability; http needs port 80 forwarded to the HTTP port, " +
			"tls-alpn needs port 443 forwarded to the HTTPS port. The validation requests are admitted even from " +
			"addresses outside the access policy (they reach nothing but the challenge)."})
	settings.Register(settings.Def{Key: KeyACMEProvider, Section: "acme", Order: 60, Type: settings.TypeEnum,
		Default: ProviderCloudflare, Enum: []string{ProviderCloudflare, ProviderRFC2136}, Label: "DNS provider",
		Description: "DNS provider for the dns challenge: cloudflare or rfc2136."})
	settings.Register(settings.Def{Key: KeyACMECreds, Section: "acme", Order: 70, Type: settings.TypeSecret,
		Default: "", Label: "DNS provider credentials",
		Description: `JSON object. Cloudflare: {"api_token":"…"} (optionally "zone_token"); ` +
			`RFC 2136: {"server":"ns.example.com:53","key_name":"…","key_alg":"hmac-sha256.","key":"<base64>"}.`,
		Validate: validACMECreds})

	settings.Register(settings.Def{Key: KeyTailscaleCert, Section: "tailscale", Order: 10, Type: settings.TypeBool,
		Default: false, Label: "Use Tailscale HTTPS certificate",
		Description: "Fetch a certificate for the MagicDNS name from tailscaled (needs HTTPS enabled for the tailnet and operator permission)."})
	settings.Register(settings.Def{Key: KeyTailscaleName, Section: "tailscale", Order: 20, Type: settings.TypeString,
		Default: "", Label: "Tailscale certificate name",
		Description: "MagicDNS name to fetch a certificate for (empty = this machine's MagicDNS name).",
		Validate: func(v any) error {
			s := strings.TrimSuffix(strings.ToLower(v.(string)), ".")
			if s != "" && (!validDNSName(s, false) || !strings.Contains(s, ".")) {
				return errors.New("must be a fully qualified DNS name")
			}
			return nil
		}})

	settings.Register(settings.Def{Key: KeyMTLSMode, Section: "mtls", Order: 10, Type: settings.TypeEnum,
		Default: MTLSOff, Enum: []string{MTLSOff, MTLSOptional, MTLSRequired}, Label: "Client certificates (mTLS)",
		Description: "required: only devices with a client certificate issued by this server can use it."})
	settings.Register(settings.Def{Key: KeyMTLSExempt, Section: "mtls", Order: 20, Type: settings.TypeBool,
		Default: true, Label: "Exempt public share links",
		Description: "In required mode, share links, the trust page and health checks work without a client certificate."})
	settings.Register(settings.Def{Key: KeyMTLSSelfService, Section: "mtls", Order: 30, Type: settings.TypeBool,
		Default: false, Label: "Users may issue their own client certificates",
		Description: "Users may issue client certificates for their own devices (Settings → Devices)."})
}

// validACMEDomain accepts a public DNS name an ACME CA can issue for: at
// least two labels, the last one not all digits (so no IP address), and not
// a name that only exists locally (.local, .localhost).
func validACMEDomain(s string) error {
	n := strings.TrimSuffix(strings.ToLower(s), ".")
	if _, err := netip.ParseAddr(strings.Trim(n, "[]")); err == nil {
		return fmt.Errorf("%q is an IP address; ACME certificates are for public DNS names", s)
	}
	if !validDNSName(n, true) || !strings.Contains(n, ".") {
		return fmt.Errorf("%q is not a valid public DNS name", s)
	}
	tld := n[strings.LastIndexByte(n, '.')+1:]
	if strings.Trim(tld, "0123456789") == "" || tld == "local" || tld == "localhost" {
		return fmt.Errorf("%q is not a valid public DNS name", s)
	}
	return nil
}

// validACMEEmail bounds the account e-mail (the syntax is checked by the
// e-mail type): 254 bytes, a local part of at most 64 (RFC 5321).
func validACMEEmail(v any) error {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	at := strings.LastIndexByte(s, '@')
	if len(s) > 254 || at > 64 {
		return errors.New("the e-mail address is too long (at most 64 characters before the @, 254 in all)")
	}
	return nil
}

// acmeCredFields are the fields of the DNS providers' credentials.
var acmeCredFields = map[string]string{"api_token": ProviderCloudflare, "zone_token": ProviderCloudflare,
	"server": ProviderRFC2136, "key_name": ProviderRFC2136, "key_alg": ProviderRFC2136, "key": ProviderRFC2136}

// validACMECreds checks the credentials JSON against the providers'
// shapes: Cloudflare {"api_token", optional "zone_token"}, RFC 2136
// {"server", "key_name", "key", optional "key_alg"}, non-empty strings
// only. Which provider is used is acme.dns_provider (checked with the
// credentials when ACME is applied).
func validACMECreds(v any) error {
	s, _ := v.(string)
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil || m == nil {
		return errors.New("must be a JSON object")
	}
	seen := map[string]bool{}
	for k, x := range m {
		p, known := acmeCredFields[k]
		if !known {
			return fmt.Errorf(`unknown field %q (Cloudflare: "api_token", "zone_token"; RFC 2136: "server", "key_name", "key_alg", "key")`, k)
		}
		if str, ok := x.(string); !ok || strings.TrimSpace(str) == "" {
			return fmt.Errorf("%q must be a non-empty string", k)
		}
		seen[p] = true
	}
	_, token := m["api_token"]
	_, server := m["server"]
	_, name := m["key_name"]
	_, key := m["key"]
	switch {
	case seen[ProviderCloudflare] && seen[ProviderRFC2136]:
		return errors.New("mixes Cloudflare and RFC 2136 fields")
	case seen[ProviderCloudflare] && !token:
		return errors.New(`the Cloudflare credentials need "api_token"`)
	case seen[ProviderRFC2136] && !(server && name && key):
		return errors.New(`RFC 2136 credentials need "server", "key_name" and "key"`)
	case len(seen) == 0:
		return errors.New(`needs "api_token" (Cloudflare) or "server", "key_name" and "key" (RFC 2136)`)
	}
	return nil
}

// validDNSName reports whether s is a syntactically valid (lower-case) DNS
// name: 1–253 bytes, labels of 1–63 letters, digits, '-' and '_' not starting
// or ending with '-'. A leading "*." label is accepted when wildcard is set.
func validDNSName(s string, wildcard bool) bool {
	if wildcard && strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
