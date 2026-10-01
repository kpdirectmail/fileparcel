package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/rfc2136"

	"fileparcel/internal/core"
)

// acmeState is one active certmagic configuration (DESIGN §10.4 ACME). It is
// replaced as a whole whenever the acme.* settings change.
type acmeState struct {
	magic   *certmagic.Config
	cache   *certmagic.Cache
	issuer  *certmagic.ACMEIssuer
	domains []string // normalized (lower case, no trailing dot)
	alpn    bool     // tls-alpn challenge: advertise acme-tls/1
	key     string   // configuration fingerprint (detects changes)
	cancel  context.CancelFunc
	once    sync.Once
}

// covers reports whether name is one of the ACME domains (exact, or matched
// by a "*.example.com" wildcard domain).
func (a *acmeState) covers(name string) bool {
	if a == nil {
		return false
	}
	for _, d := range a.domains {
		if d == name {
			return true
		}
		if rest, ok := strings.CutPrefix(d, "*."); ok {
			if i := strings.IndexByte(name, '.'); i > 0 && name[i+1:] == rest {
				return true
			}
		}
	}
	return false
}

// stop cancels certificate management and stops certmagic's maintenance
// goroutine (safe to call more than once).
func (a *acmeState) stop() {
	if a == nil {
		return
	}
	a.once.Do(func() {
		if a.cancel != nil {
			a.cancel()
		}
		if a.cache != nil {
			a.cache.Stop()
		}
	})
}

// certificates returns the managed certificates currently in memory.
func (a *acmeState) certificates() []*x509.Certificate {
	if a == nil || a.cache == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []*x509.Certificate
	for _, d := range a.domains {
		// The domain as configured: certmagic indexes a wildcard certificate
		// under its literal SAN "*.example.com", which a lookup of
		// "example.com" never tries (it only tries "*.com").
		for _, c := range a.cache.AllMatchingCertificates(d) {
			leaf := c.Leaf
			if leaf == nil && len(c.Certificate.Certificate) > 0 {
				leaf, _ = x509.ParseCertificate(c.Certificate.Certificate[0])
			}
			if leaf == nil || seen[string(leaf.Raw)] {
				continue
			}
			seen[string(leaf.Raw)] = true
			out = append(out, leaf)
		}
	}
	return out
}

// acmeConfig is the validated acme.* configuration.
type acmeConfig struct {
	Email     string
	Domains   []string
	CA        string
	Challenge string
	Provider  string
	Creds     string // secret JSON (never logged)
}

// key fingerprints the configuration so that ApplyACME can tell whether it
// changed. It contains the credentials and therefore never leaves memory.
func (c acmeConfig) key() string {
	return strings.Join([]string{c.Email, strings.Join(c.Domains, ","), c.CA, c.Challenge, c.Provider, c.Creds}, "\x00")
}

// acmeDirectory maps acme.ca to a directory URL.
func acmeDirectory(ca string) string {
	switch ca {
	case "", "staging":
		return certmagic.LetsEncryptStagingCA
	case "production":
		return certmagic.LetsEncryptProductionCA
	}
	return ca
}

// readACMEConfig reads and validates the acme.* settings. enabled is false
// when ACME is switched off or has no domains.
func (svc *Service) readACMEConfig() (cfg acmeConfig, enabled bool, err error) {
	if !svc.settingBool(KeyACMEEnabled) {
		return cfg, false, nil
	}
	cfg.Email = strings.TrimSpace(svc.settingString(KeyACMEEmail))
	for _, d := range svc.settingStrings(KeyACMEDomains) {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !slices.Contains(cfg.Domains, d) {
			cfg.Domains = append(cfg.Domains, d)
		}
	}
	slices.Sort(cfg.Domains)
	if len(cfg.Domains) == 0 {
		return cfg, false, core.Invalid(KeyACMEDomains, "ACME is enabled but no domains are configured")
	}
	cfg.CA = acmeDirectory(svc.settingString(KeyACMECA))
	cfg.Challenge = svc.settingString(KeyACMEChallenge)
	if cfg.Challenge == "" {
		cfg.Challenge = ChallengeDNS
	}
	for _, d := range cfg.Domains {
		if strings.HasPrefix(d, "*.") && cfg.Challenge != ChallengeDNS {
			return cfg, false, core.Invalid(KeyACMEChallenge, "wildcard domains need the dns challenge")
		}
	}
	if cfg.Challenge == ChallengeDNS {
		cfg.Provider = svc.settingString(KeyACMEProvider)
		if cfg.Provider == "" {
			cfg.Provider = ProviderCloudflare
		}
		if svc.env.Settings == nil {
			return cfg, false, core.Invalid(KeyACMECreds, "DNS provider credentials are not available")
		}
		creds, err := svc.env.Settings.Secret(KeyACMECreds)
		if err != nil {
			return cfg, false, err
		}
		if strings.TrimSpace(creds) == "" {
			return cfg, false, core.Invalid(KeyACMECreds, "the dns challenge needs DNS provider credentials")
		}
		cfg.Creds = creds
		if _, err := dnsProvider(cfg.Provider, creds); err != nil {
			return cfg, false, err
		}
	}
	return cfg, true, nil
}

// dnsProvider builds the libdns provider for DNS-01 from the credentials JSON.
func dnsProvider(provider, creds string) (certmagic.DNSProvider, error) {
	switch provider {
	case ProviderCloudflare:
		var p struct {
			APIToken  string `json:"api_token"`
			ZoneToken string `json:"zone_token"`
		}
		if err := json.Unmarshal([]byte(creds), &p); err != nil {
			return nil, core.Invalid(KeyACMECreds, "credentials must be a JSON object")
		}
		if p.APIToken == "" {
			return nil, core.Invalid(KeyACMECreds, `Cloudflare credentials need "api_token"`)
		}
		return &cloudflare.Provider{APIToken: p.APIToken, ZoneToken: p.ZoneToken}, nil
	case ProviderRFC2136:
		var p struct {
			Server  string `json:"server"`
			KeyName string `json:"key_name"`
			KeyAlg  string `json:"key_alg"`
			Key     string `json:"key"`
		}
		if err := json.Unmarshal([]byte(creds), &p); err != nil {
			return nil, core.Invalid(KeyACMECreds, "credentials must be a JSON object")
		}
		if p.Server == "" || p.KeyName == "" || p.Key == "" {
			return nil, core.Invalid(KeyACMECreds, `RFC 2136 credentials need "server", "key_name" and "key"`)
		}
		if p.KeyAlg == "" {
			p.KeyAlg = "hmac-sha256."
		}
		return &rfc2136.Provider{Server: p.Server, KeyName: p.KeyName, KeyAlg: p.KeyAlg, Key: p.Key}, nil
	}
	return nil, core.Invalid(KeyACMEProvider, "unknown DNS provider "+provider)
}

// ports returns the configured HTTPS and HTTP ports (for the challenge
// listeners certmagic would otherwise try to open on 443/80).
func (svc *Service) ports() (https, http int) {
	https, http = 8443, 8080
	if c := svc.env.Config; c != nil {
		if c.Server.HTTPSPort > 0 {
			https = c.Server.HTTPSPort
		}
		http = c.Server.HTTPPort
	}
	return https, http
}

// newACMEState builds (but does not start) a certmagic configuration.
func (svc *Service) newACMEState(cfg acmeConfig) (*acmeState, error) {
	httpsPort, httpPort := svc.ports()
	if cfg.Challenge == ChallengeHTTP && httpPort == 0 {
		return nil, core.Invalid(KeyACMEChallenge, "the http challenge needs the HTTP port (server.http_port) to be enabled")
	}
	var provider certmagic.DNSProvider
	if cfg.Challenge == ChallengeDNS {
		p, err := dnsProvider(cfg.Provider, cfg.Creds)
		if err != nil {
			return nil, err
		}
		provider = p
	}
	storage := &certmagic.FileStorage{Path: svc.path(dirACME)}
	// certmagic logs through zap; without a logger it writes to stderr in
	// its own format. zapLogger routes those records into the FileParcel log.
	logger := zapLogger(svc.log.With("subsystem", "acme"))
	a := &acmeState{domains: slices.Clone(cfg.Domains), key: cfg.key(), alpn: cfg.Challenge == ChallengeTLSALPN}
	var magicPtr atomic.Pointer[certmagic.Config] // the cache's goroutine may ask before New returns
	a.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			if m := magicPtr.Load(); m != nil {
				return m, nil
			}
			return nil, errors.New("certs: ACME configuration not ready")
		},
		Logger: logger,
	})
	magic := certmagic.New(a.cache, certmagic.Config{
		Storage: storage,
		OnEvent: svc.onACMEEvent,
		Logger:  logger,
	})
	tmpl := certmagic.ACMEIssuer{
		CA:                      cfg.CA,
		Email:                   cfg.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    cfg.Challenge != ChallengeHTTP,
		DisableTLSALPNChallenge: cfg.Challenge != ChallengeTLSALPN,
		// Our own listeners answer the challenges (HTTPChallenge wrapper on
		// the HTTP port, GetConfigForClient for acme-tls/1 on the HTTPS
		// port); certmagic finds the ports busy and relies on them.
		AltHTTPPort:    httpPort,
		AltTLSALPNPort: httpsPort,
		Logger:         logger,
	}
	if provider != nil {
		tmpl.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: provider, Logger: logger}}
	}
	a.issuer = certmagic.NewACMEIssuer(magic, tmpl)
	magic.Issuers = []certmagic.Issuer{a.issuer}
	a.magic = magic
	magicPtr.Store(magic)
	return a, nil
}

// onACMEEvent records certmagic results (status, audit, certs.changed).
func (svc *Service) onACMEEvent(ctx context.Context, event string, data map[string]any) error {
	switch event {
	case "cert_obtained":
		svc.acmeErr.Store(nil)
		svc.trust.reset()
		svc.publishChanged()
		svc.audit(context.WithoutCancel(ctx), core.AuditEntry{Action: core.ActCertACME, TargetType: "certificate",
			TargetName: fmt.Sprint(data["identifier"]), Details: map[string]any{"renewal": data["renewal"], "issuer": data["issuer"]}})
	case "cert_failed":
		msg := fmt.Sprintf("%v: %v", data["identifier"], data["error"])
		svc.acmeErr.Store(&msg)
		svc.audit(context.WithoutCancel(ctx), core.AuditEntry{Action: core.ActCertACME, Outcome: core.OutcomeFailure,
			TargetType: "certificate", TargetName: fmt.Sprint(data["identifier"]),
			Details: map[string]any{"renewal": data["renewal"], "error": fmt.Sprint(data["error"])}})
	case "cached_managed_cert":
		svc.trust.reset()
	}
	return nil
}

// started reports whether Start ran (background work is allowed).
func (svc *Service) started() bool {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.cancel != nil
}

// ApplyACME implements core.Certs: (re)configures ACME from the acme.*
// settings. With ACME disabled it stops certificate management (stored
// certificates stay in certs/acme for a later re-enable). Otherwise it starts
// certmagic management of the domains in the background — obtaining or
// renewing as needed; failures are reported by Status (acme_error) and
// audited as cert.acme failures. In offline mode (Start never ran) the
// configuration is only validated and takes effect at the next server start.
func (svc *Service) ApplyACME(ctx context.Context) error {
	cfg, enabled, err := svc.readACMEConfig()
	if err != nil {
		svc.acmeErr.Store(errString(err))
		// A configuration that no longer describes anything must not leave the
		// previous certmagic state managing (and answering SNI for) domains
		// that were removed or whose credentials were cleared. A merely
		// unavailable configuration (locked keys) is transient: keep managing
		// what is already running and retry on unlock.
		if !errors.Is(err, core.ErrKeysLocked) {
			svc.acmeMu.Lock()
			defer svc.acmeMu.Unlock()
			if old := svc.acme.Swap(nil); old != nil {
				old.stop()
				svc.publishChanged()
				svc.log.Warn("ACME certificate management stopped: the configuration is no longer valid", "err", err)
			}
		}
		return err
	}
	svc.acmeMu.Lock()
	defer svc.acmeMu.Unlock()
	if !enabled {
		if old := svc.acme.Swap(nil); old != nil {
			old.stop()
			svc.publishChanged()
			svc.log.Info("ACME certificate management stopped")
		}
		svc.acmeErr.Store(nil)
		return nil
	}
	if !svc.started() {
		svc.log.Info("ACME configuration is valid; it takes effect when the server starts", "domains", cfg.Domains)
		return nil
	}
	if cur := svc.acme.Load(); cur != nil && cur.key == cfg.key() {
		// Unchanged configuration: just make sure everything is managed
		// (e.g. retry after a failure).
		return svc.manageACME(cur)
	}
	next, err := svc.newACMEState(cfg)
	if err != nil {
		svc.acmeErr.Store(errString(err))
		return err
	}
	if old := svc.acme.Swap(next); old != nil {
		old.stop()
	}
	svc.acmeErr.Store(nil)
	svc.log.Info("ACME certificate management configured", "domains", cfg.Domains, "ca", cfg.CA, "challenge", cfg.Challenge)
	return svc.manageACME(next)
}

// manageACME starts asynchronous management of a's domains, bound to the
// service's background context.
func (svc *Service) manageACME(a *acmeState) error {
	svc.mu.Lock()
	base := svc.bgCtx
	svc.mu.Unlock()
	ctx, cancel := context.WithCancel(base)
	prev := a.cancel
	a.cancel = func() {
		cancel()
		if prev != nil {
			prev()
		}
	}
	if err := a.magic.ManageAsync(ctx, a.domains); err != nil {
		svc.acmeErr.Store(errString(err))
		return core.Wrap(core.ErrUnavailable, "ACME: "+err.Error(), err)
	}
	return nil
}

// certFor returns the certmagic certificate for hello when one is available
// (the caller checked that the name is an ACME domain). Synthetic hellos
// without a connection (PubliclyTrusted) only consult the in-memory cache.
func (a *acmeState) certFor(hello *tls.ClientHelloInfo) *tls.Certificate {
	if a == nil || a.magic == nil {
		return nil
	}
	if hello.Conn == nil {
		name := strings.ToLower(hello.ServerName)
		for _, c := range a.cache.AllMatchingCertificates(name) {
			if !c.Empty() && (c.Leaf == nil || c.Leaf.VerifyHostname(name) == nil) {
				tc := c.Certificate
				return &tc
			}
		}
		return nil
	}
	c, err := a.magic.GetCertificate(hello)
	if err != nil || c == nil || len(c.Certificate) == 0 {
		return nil
	}
	return c
}
