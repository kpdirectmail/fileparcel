package settings

import (
	"fmt"

	"fileparcel/internal/config"
)

// The "server" section: the bootstrap bridge (DESIGN §11.2). These keys live
// in fileparcel.toml (Bootstrap) so the server can start before the database
// is open; the Store reads and writes them through config.Config.
func init() {
	Register(Def{Key: "server.name", Section: "server", Order: 10, Type: TypeString, Default: "fileparcel",
		Bootstrap: true, Restart: true, Validate: validDNSLabel,
		Label: "Server name",
		Description: "DNS label used for <name>.local (mDNS, applied live), the local CA name and the default WebAuthn RP ID. " +
			"Lowercase letters, digits and '-'. Changing it orphans passkeys registered for the old name."})
	Register(Def{Key: "server.https_port", Section: "server", Order: 20, Type: TypeInt, Default: 8443, Min: 1, Max: 65535,
		Bootstrap: true, Restart: true,
		Label:       "HTTPS port",
		Description: "TCP port of the HTTPS listener. Ports below 1024 need root or CAP_NET_BIND_SERVICE."})
	Register(Def{Key: "server.http_port", Section: "server", Order: 30, Type: TypeInt, Default: 8080, Min: 0, Max: 65535,
		Bootstrap: true, Restart: true,
		Label:       "HTTP redirect port",
		Description: "Plain-HTTP port that redirects to HTTPS and answers ACME HTTP-01 challenges; 0 disables it."})
	Register(Def{Key: "server.bind", Section: "server", Order: 40, Type: TypeStrings, Default: []string{"::"},
		Bootstrap: true, Restart: true, Validate: validBindList,
		Label:       "Listen addresses",
		Description: "IP addresses to listen on. \"::\" listens on every interface (IPv4 and IPv6), so list it alone; the access policy does the filtering."})
	Register(Def{Key: "server.public_url", Section: "server", Order: 50, Type: TypeURL, Default: "",
		Bootstrap: true, Restart: true, Validate: validPublicURL,
		Label: "Public URL",
		Description: "Optional canonical URL (e.g. behind a reverse proxy) used in links, invitations and for WebAuthn: " +
			"scheme, host and port only, such as https://files.example.com."})
	Register(Def{Key: "server.trusted_proxies", Section: "server", Order: 60, Type: TypeCIDRs, Default: []string{},
		Bootstrap:   true,
		Label:       "Trusted reverse proxies",
		Description: "Addresses or CIDRs whose X-Forwarded-For header is trusted for the client IP (access policy, rate limits, audit)."})
	Register(Def{Key: "log.level", Section: "server", Order: 70, Type: TypeEnum, Default: "info",
		Enum: []string{"debug", "info", "warn", "error"}, Bootstrap: true,
		Label:       "Log level",
		Description: "Minimum level written to the log (applied immediately)."})
	Register(Def{Key: "runtime.gomemlimit_mb", Section: "server", Order: 80, Type: TypeInt, Default: 0,
		Min: 0, Max: 1 << 20, Bootstrap: true, Restart: true,
		Label: "Go memory limit (MiB)",
		Description: "Soft limit for the Go heap, applied at start. 0 = automatic " +
			"(the smaller of 1 GiB and a quarter of the memory available to the process). " +
			"An explicit $GOMEMLIMIT wins."})
}

func validDNSLabel(v any) error {
	if s, _ := v.(string); !config.ValidDNSLabel(s) {
		return fmt.Errorf("must be a DNS label: 1-63 characters a-z, 0-9 and '-', not starting or ending with '-'")
	}
	return nil
}

// validPublicURL applies config.CheckPublicURL: the value is the base of the
// links handed to other people, so it carries no user name, password, path,
// query or fragment, and a port only in range.
func validPublicURL(v any) error {
	s, _ := v.(string)
	return config.CheckPublicURL(s)
}

// validBindList applies config.CheckBindList, so the field reports what would
// otherwise only fail at the next start ("address already in use").
func validBindList(v any) error {
	l, _ := v.([]string)
	return config.CheckBindList(l)
}
