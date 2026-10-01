package securityapi_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"fileparcel/internal/app"
	"fileparcel/internal/certs"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/ratelimit"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/securityapi"
)

// These tests run the handlers against the real certificate service, a real
// database and the real rate limiter (the other services are small fakes).

// sealingKeys is a minimal core.Keys with working field encryption.
type sealingKeys struct {
	core.Keys // other methods are not used (nil → panic = test failure)
	mu        sync.Mutex
	state     core.KeyState
	aead      cipher.AEAD
	unlocks   int
}

func newSealingKeys(t *testing.T) *sealingKeys {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return &sealingKeys{state: core.KeyStateUnlocked, aead: g}
}

func (k *sealingKeys) State() core.KeyState {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.state
}
func (k *sealingKeys) Unlock(context.Context, []byte) error {
	k.mu.Lock()
	k.unlocks++
	k.mu.Unlock()
	return core.Errorf(core.ErrUnauthorized, "wrong passphrase or recovery key")
}
func (k *sealingKeys) SealField(aad string, pt []byte) (string, error) {
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return "v1:t:" + base64.RawURLEncoding.EncodeToString(k.aead.Seal(nonce, nonce, pt, []byte(aad))), nil
}
func (k *sealingKeys) OpenField(aad, sealed string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:t:"))
	if err != nil || len(b) < k.aead.NonceSize() {
		return nil, core.ErrCorrupt
	}
	pt, err := k.aead.Open(nil, b[:k.aead.NonceSize()], b[k.aead.NonceSize():], []byte(aad))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	return pt, nil
}

type recAudit struct {
	core.Audit
	mu      sync.Mutex
	actions []string
}

func (a *recAudit) Record(_ context.Context, e core.AuditEntry) {
	a.mu.Lock()
	a.actions = append(a.actions, e.Action+"/"+e.Outcome)
	a.mu.Unlock()
}
func (a *recAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}

type staticNet struct{ core.Network }

func (staticNet) Hostnames() []string { return []string{"fileparcel.local"} }
func (staticNet) IPs() []netip.Addr   { return []netip.Addr{netip.MustParseAddr("192.168.1.10")} }

type realEnv struct {
	d      *app.Deps
	certs  *certs.Service
	keys   *sealingKeys
	audit  *recAudit
	h      http.Handler
	userID string
}

func newRealEnv(t *testing.T) *realEnv {
	t.Helper()
	h, err := home.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	t.Cleanup(func() {
		bus.Close()
		database.Close()
	})
	re := &realEnv{keys: newSealingKeys(t), audit: &recAudit{}}
	env := &core.Env{Home: h, Config: config.Default("0123456789abcdef0123456789abcdef"), DB: database,
		Log: slog.New(slog.DiscardHandler), Clock: core.SystemClock{}, Bus: bus, Keys: re.keys, Audit: re.audit}
	cs, err := certs.New(env, staticNet{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	if err := cs.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	limiter, err := ratelimit.New(&core.Env{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = limiter.Close() })
	re.certs = cs
	re.d = &app.Deps{Env: env, Mode: app.ModeNetwork, Certs: cs, Limiter: limiter}

	re.userID = ids.New(ids.PrefixUser)
	now := db.Ms(time.Now())
	err = database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO users (id, username, role, status, webauthn_handle, created_at, updated_at)
			VALUES (?, 'alice', 'member', 'active', ?, ?, ?)`, re.userID, []byte(re.userID), now, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Use(mw.Inject(re.d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP,
		func(next http.Handler) http.Handler { // requests marked X-Socket act like the admin socket
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Socket") == "1" {
					r = r.WithContext(core.WithPrincipal(r.Context(), core.SystemPrincipal(core.ViaSocket)))
				}
				next.ServeHTTP(w, r)
			})
		})
	api := chi.NewRouter()
	securityapi.Mount(api, re.d)
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.Authenticate, mw.CSRF).Mount("/api/v1", api)
	securityapi.MountRoot(r, re.d)
	re.h = r
	return re
}

func (re *realEnv) do(t *testing.T, method, path string, body any, socket bool, remote string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if socket {
		req.Header.Set("X-Socket", "1")
	}
	if remote != "" {
		req.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	re.h.ServeHTTP(rec, req)
	return rec
}

func TestIntegrationClientCertLifecycle(t *testing.T) {
	re := newRealEnv(t)
	rec := re.do(t, "POST", "/api/v1/admin/client-certs",
		core.ClientCertInput{UserID: re.userID, Name: "Alice's phone", Days: 90}, true, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	var res securityapi.ClientCertIssued
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	p12, err := base64.StdEncoding.DecodeString(res.P12)
	if err != nil {
		t.Fatal(err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(p12, res.Password)
	if err != nil {
		t.Fatalf("PKCS#12 does not open with the generated password: %v", err)
	}
	if leaf.Subject.CommonName != "alice" || len(leaf.URIs) != 1 || leaf.URIs[0].String() != certs.ClientURIPrefix+re.userID {
		t.Fatalf("certificate subject %v uris %v", leaf.Subject, leaf.URIs)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU %v", leaf.ExtKeyUsage)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("validity %v", d)
	}
	// No CA: Android and Windows install one found in a .p12 as a trusted root.
	if len(chain) != 0 {
		t.Fatal("the client CA must not be in the PKCS#12 file")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("private key %T", key)
	}
	if pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(leaf.PublicKey) {
		t.Fatal("the private key does not match the certificate")
	}
	if res.ClientCert == nil || res.ClientCert.Serial != strings.ToUpper(leaf.SerialNumber.Text(16)) {
		t.Fatalf("metadata %+v", res.ClientCert)
	}

	// The one-time download returns the same bytes.
	rec = re.do(t, "GET", res.DownloadURL, nil, true, "")
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), p12) {
		t.Fatalf("download: %d", rec.Code)
	}

	// The certificate authenticates a TLS peer until it is revoked.
	cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if _, err := re.certs.CheckClient(context.Background(), cs); err != nil {
		t.Fatalf("CheckClient: %v", err)
	}
	rec = re.do(t, "GET", "/api/v1/admin/client-certs?user_id="+re.userID, nil, true, "")
	var page core.Page[core.ClientCert]
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].ID != res.ClientCert.ID {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	rec = re.do(t, "DELETE", "/api/v1/admin/client-certs/"+res.ClientCert.ID+"?reason=lost", nil, true, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := re.certs.CheckClient(context.Background(), cs); err == nil {
		t.Fatal("revoked certificate still accepted")
	}
	re.audit.mu.Lock()
	got := strings.Join(re.audit.actions, " ")
	re.audit.mu.Unlock()
	if !strings.Contains(got, core.ActClientCertIssue) || !strings.Contains(got, core.ActClientCertRevoke) {
		t.Fatalf("audit %q", got)
	}
}

func TestIntegrationTrustDownloads(t *testing.T) {
	re := newRealEnv(t)
	fp := re.certs.Fingerprint()

	rec := re.do(t, "GET", "/trust/ca.pem", nil, false, "")
	block, _ := pem.Decode(rec.Body.Bytes())
	if rec.Code != 200 || block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("pem: %d %q", rec.Code, rec.Body.String())
	}
	if got := fingerprintOf(block.Bytes); got != fp {
		t.Fatalf("pem fingerprint %s, want %s", got, fp)
	}
	rec = re.do(t, "GET", "/trust/ca.crt", nil, false, "")
	ca, err := x509.ParseCertificate(rec.Body.Bytes())
	if err != nil || !bytes.Equal(ca.Raw, block.Bytes) || !ca.IsCA {
		t.Fatalf("der: %v", err)
	}
	rec = re.do(t, "GET", "/trust/ca.mobileconfig", nil, false, "")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "com.apple.security.root") ||
		!strings.Contains(strings.Join(strings.Fields(body), ""), base64.StdEncoding.EncodeToString(ca.Raw)) {
		t.Fatalf("mobileconfig: %d", rec.Code)
	}
	// The admin status reports the same CA.
	rec = re.do(t, "GET", "/api/v1/admin/certs", nil, true, "")
	var st core.CertStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.CA == nil || st.CA.Fingerprint != fp || st.Leaf == nil {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	// Forced renewal issues a new leaf.
	old := st.Leaf.Serial
	rec = re.do(t, "POST", "/api/v1/admin/certs/renew?force=1", nil, true, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != 200 || st.Leaf.Serial == old {
		t.Fatalf("renew: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationUnlockRateLimit(t *testing.T) {
	re := newRealEnv(t)
	re.keys.state = core.KeyStateLocked
	attempt := func(remote string) *httptest.ResponseRecorder {
		return re.do(t, "POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "guess"}, false, remote)
	}
	for i := range ratelimit.DefaultUnlockPerMin {
		if rec := attempt("192.168.1.50:1000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := attempt("192.168.1.50:1001")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d %v", rec.Code, rec.Header())
	}
	if re.keys.unlocks != ratelimit.DefaultUnlockPerMin {
		t.Fatalf("the key service saw %d attempts", re.keys.unlocks)
	}
	// Per client address.
	if rec := attempt("192.168.1.51:1000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other client: %d", rec.Code)
	}
	// The admin socket is never limited.
	if rec := re.do(t, "POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "guess"}, true, "@"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("socket: %d", rec.Code)
	}
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hexByte(b))
	}
	return strings.Join(parts, ":")
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}
