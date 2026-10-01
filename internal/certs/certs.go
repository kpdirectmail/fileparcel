// Package certs manages the local CA (+ client CA), the server leaf, SNI
// dispatch, ACME (certmagic), Tailscale and custom certificates, PKCS#12 and
// mobileconfig exports (DESIGN §10.4). Owned by unit F.
//
// Lifecycle (see core.Certs): New loads every certificate that exists on disk
// (CA, client CA, leaf, custom, cached ACME/Tailscale) without network access
// or goroutines and works while the keys are locked; in offline CLI mode
// wire.Start does NOT call Start, so all read paths work right after New.
// Start only launches renewal, the SAN-change watcher, ACME and Tailscale.
//
// Files (under <HOME>/certs, DESIGN §3):
//
//	ca/ca.crt, ca/ca.key.enc               local CA (key sealed, AAD "file|certs/ca/ca.key")
//	ca/client-ca.crt, ca/client-ca.key.enc client CA (key sealed, AAD "file|certs/ca/client-ca.key")
//	server/leaf.crt, server/leaf.key       local leaf (key NOT sealed: needed to serve /unlock while locked;
//	server/leaf.key.next                   the new key while the pair is being replaced, see issueLeaf)
//	custom/cert.pem, custom/key.pem.enc    uploaded certificate (key sealed, AAD "file|certs/custom/key.pem")
//	tailscale/cert.pem, tailscale/key.pem  certificate fetched from tailscaled
//	acme/                                  certmagic FileStorage
//
// Private keys of the CAs are unsealed only for the duration of an issuing
// operation and are never retained by the service; the marshalled copies it
// makes (PKCS#8 DER, PEM) are zeroed on all paths, and the PKCS#12 blob of a
// client certificate is zeroed by its caller. The wiping is best
// effort — the ephemeral *ecdsa.PrivateKey and the intermediate buffers of
// the standard marshaller cannot be zeroed — so package keys, whose vault is
// mlock'ed and MADV_DONTDUMP, remains the only place with a hard guarantee.
package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// File names relative to the certs directory and field-encryption AADs (DESIGN §7.5).
const (
	fileCACert       = "ca/ca.crt"
	fileCAKey        = "ca/ca.key.enc"
	fileClientCACert = "ca/client-ca.crt"
	fileClientCAKey  = "ca/client-ca.key.enc"
	fileLeafCert     = "server/leaf.crt"
	fileLeafKey      = "server/leaf.key"
	fileLeafKeyNext  = "server/leaf.key.next" // staged key of a leaf swap (issueLeaf)
	fileCustomCert   = "custom/cert.pem"
	fileCustomKey    = "custom/key.pem.enc"
	fileTSCert       = "tailscale/cert.pem"
	fileTSKey        = "tailscale/key.pem"
	dirACME          = "acme"

	aadCAKey       = "file|certs/ca/ca.key"
	aadClientCAKey = "file|certs/ca/client-ca.key"
	aadCustomKey   = "file|certs/custom/key.pem"
)

// state is an immutable snapshot of the loaded certificates. Handshakes read
// it lock-free; changes build a new snapshot under Service.opMu.
type state struct {
	ca         *x509.Certificate
	clientCA   *x509.Certificate
	clientPool *x509.CertPool
	leaf       *tls.Certificate // Leaf set; nil when missing

	customCert *x509.Certificate // parsed custom leaf (also while its key is sealed)
	custom     *tls.Certificate  // nil until the key could be unsealed
	tailscale  *tls.Certificate
}

func (s *state) clone() *state {
	c := *s
	return &c
}

// Service implements core.Certs.
type Service struct {
	env *core.Env
	net core.Network
	log *slog.Logger
	dir string

	opMu  sync.Mutex // serializes every change of certificate files and state
	state atomic.Pointer[state]

	tlsConf *tls.Config

	acmeMu  sync.Mutex // serializes ACME (re)configuration
	acme    atomic.Pointer[acmeState]
	acmeErr atomic.Pointer[string]
	tsErr   atomic.Pointer[string]

	pendingRenew atomic.Bool            // a leaf renewal waits for the keys to be unlocked
	uncovered    atomic.Pointer[string] // last logged "names left out of the leaf" set

	trust   trustCache
	clients clientCache

	jobsScheduled atomic.Bool
	startOnce     sync.Once
	closeOnce     sync.Once
	mu            sync.Mutex // guards cancel and bgCtx
	cancel        context.CancelFunc
	bgCtx         context.Context
	wg            sync.WaitGroup
}

var (
	_ core.Certs        = (*Service)(nil)
	_ core.JobRegistrar = (*Service)(nil)
)

// New creates the service (constructor signature fixed by DESIGN §5.2) and
// loads the certificates present on disk (no network, no goroutines).
// Missing files are not an error; unreadable or corrupt ones are logged and
// treated as missing (Init replaces them).
func New(env *core.Env, net core.Network) (*Service, error) {
	if env == nil || env.Home == nil {
		return nil, errors.New("certs: env with a home is required")
	}
	log := env.Log
	if log == nil {
		log = slog.Default()
	}
	svc := &Service{
		env: env,
		net: net,
		log: log.With("component", "certs"),
		dir: env.Home.CertsDir(),
	}
	svc.bgCtx = context.Background()
	svc.tlsConf = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		GetCertificate:     svc.getCertificate,
		GetConfigForClient: svc.getConfigForClient,
	}
	svc.state.Store(svc.loadState())
	return svc, nil
}

func (svc *Service) path(rel string) string { return filepath.Join(svc.dir, filepath.FromSlash(rel)) }

// snapshot returns the current state (never nil).
func (svc *Service) snapshot() *state { return svc.state.Load() }

// publishChanged announces a certificate change (events.TopicCertsChanged).
func (svc *Service) publishChanged() {
	svc.trust.reset()
	if svc.env.Bus != nil {
		svc.env.Bus.Publish(events.Event{Topic: events.TopicCertsChanged})
	}
}

// audit records e when an audit log is available. Background actions without
// a principal in ctx are attributed to "system".
func (svc *Service) audit(ctx context.Context, e core.AuditEntry) {
	if svc.env.Audit == nil {
		return
	}
	if core.PrincipalFrom(ctx) == nil && e.ActorName == "" {
		e.ActorName = "system"
	}
	svc.env.Audit.Record(ctx, e)
}

// keysUnlocked reports whether sealed files can be opened now.
func (svc *Service) keysUnlocked() bool {
	return svc.env.Keys != nil && svc.env.Keys.State() == core.KeyStateUnlocked
}

// TLSConfig implements core.Certs: the server configuration. Everything is
// decided per handshake (GetConfigForClient): minimum version, cipher
// suites, ALPN, client-certificate request and the SNI certificate dispatch.
func (svc *Service) TLSConfig() *tls.Config { return svc.tlsConf }

// Fingerprint implements core.Certs: SHA-256 of the local CA certificate DER
// as colon-separated upper-case hex ("" when there is no CA yet).
func (svc *Service) Fingerprint() string {
	if st := svc.snapshot(); st.ca != nil {
		return fingerprint(st.ca.Raw)
	}
	return ""
}

// HTTPChallenge implements core.Certs: answers ACME HTTP-01 challenges for
// the active ACME configuration and passes every other request to next.
func (svc *Service) HTTPChallenge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := svc.acme.Load(); a != nil && a.issuer != nil && a.issuer.HandleHTTPChallenge(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Init implements core.Certs: creates the local CA, the client CA and the
// leaf when they are missing (idempotent; used by `init`, `install` and
// `serve --init-if-missing` right after Keys.Init). The keys must be unlocked.
func (svc *Service) Init(ctx context.Context) error {
	svc.opMu.Lock()
	defer svc.opMu.Unlock()
	st := svc.snapshot().clone()
	changed := false
	if st.ca == nil {
		ca, err := svc.createCA(ctx, true)
		if err != nil {
			return err
		}
		st.ca = ca
		changed = true
	}
	if st.clientCA == nil {
		cca, err := svc.createClientCA(ctx)
		if err != nil {
			return err
		}
		st.clientCA = cca
		st.clientPool = poolOf(cca)
		changed = true
	}
	if need, _ := svc.leafNeedsRenewal(st, false); need {
		leaf, err := svc.issueLeaf(ctx, st.ca)
		if err != nil {
			return err
		}
		st.leaf = leaf
		changed = true
	}
	if changed {
		svc.state.Store(st)
		svc.publishChanged()
		svc.log.Info("local certificates initialised", "ca_fingerprint", fingerprint(st.ca.Raw))
	}
	return nil
}

// Close stops the background work (watcher, renewal ticker, certmagic).
func (svc *Service) Close() error {
	svc.closeOnce.Do(func() {
		svc.mu.Lock()
		if svc.cancel != nil {
			svc.cancel()
		}
		svc.mu.Unlock()
		svc.wg.Wait()
		svc.acmeMu.Lock()
		if old := svc.acme.Swap(nil); old != nil {
			old.stop()
		}
		svc.acmeMu.Unlock()
	})
	return nil
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		if c != nil {
			p.AddCert(c)
		}
	}
	return p
}

// errString renders err for a status field (acme_error, tailscale_error) and
// for an audit detail. A *core.Error whose Message already quotes its cause —
// as the Tailscale and ACME failures do, because the message is what the API
// returns — must not have the cause appended a second time by Error().
func errString(err error) *string {
	if err == nil {
		return nil
	}
	s := err.Error()
	if ce := core.AsError(err); ce != nil && ce.Message != "" {
		s = ce.Message
		if ce.Field != "" {
			s = ce.Field + ": " + s
		}
	}
	return &s
}

// errText is errString for callers that want a plain string.
func errText(err error) string {
	if s := errString(err); s != nil {
		return *s
	}
	return ""
}

func loadString(p *atomic.Pointer[string]) string {
	if s := p.Load(); s != nil {
		return *s
	}
	return ""
}
