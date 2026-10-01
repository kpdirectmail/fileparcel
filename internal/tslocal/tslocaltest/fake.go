// Package tslocaltest is a fake tailscaled for tests: the LocalAPI endpoints
// FileParcel uses (status, prefs, serve-config with Etag/If-Match,
// query-feature, cert) on a Unix socket in a short temporary directory.
// Point a tslocal.Client at it with Client, or a server under test with
// FILEPARCEL_TAILSCALE_SOCKET=Fake.Path. It never touches a real tailscaled.
package tslocaltest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/tslocal"
)

// Node describes the fake node (StatusJSON).
type Node struct {
	BackendState string   // "Running"
	TUN          bool     // false = userspace networking
	Version      string   // "1.102.4"
	DNSName      string   // MagicDNS name with trailing dot
	NodeID       string   // StableNodeID
	IPs          []string // Tailscale addresses
	Caps         []string // CapMap keys
	CertDomains  []string
	MagicDNS     bool
	Tailnet      string
	KeyExpiry    *time.Time
}

// FunnelPortsCap is the funnel-ports capability of a node allowed every
// Funnel port.
const FunnelPortsCap = "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000"

// DefaultNode is a connected node with HTTPS, Funnel on every port and
// MagicDNS: node.tail.ts.net, 100.101.102.103.
func DefaultNode() Node {
	return Node{
		BackendState: "Running", TUN: true, Version: "1.102.4",
		DNSName: "node.tail.ts.net.", NodeID: "nTESTNODE1CNTRL",
		IPs:         []string{"100.101.102.103", "fd7a:115c:a1e0::1"},
		Caps:        []string{"https", "funnel", FunnelPortsCap},
		CertDomains: []string{"node.tail.ts.net"}, MagicDNS: true, Tailnet: "example.org",
	}
}

// StatusJSON renders n like GET /localapi/v0/status?peers=false.
func StatusJSON(n Node) string {
	capMap := map[string]any{}
	for _, c := range n.Caps {
		capMap[c] = nil
	}
	self := map[string]any{
		"ID": n.NodeID, "HostName": strings.SplitN(n.DNSName, ".", 2)[0], "DNSName": n.DNSName,
		"TailscaleIPs": n.IPs, "CapMap": capMap,
	}
	if n.KeyExpiry != nil {
		self["KeyExpiry"] = n.KeyExpiry.UTC().Format(time.RFC3339)
	}
	suffix := strings.TrimSuffix(strings.SplitN(n.DNSName+".", ".", 2)[1], ".")
	st := map[string]any{
		"Version": n.Version, "TUN": n.TUN, "BackendState": n.BackendState,
		"TailscaleIPs": n.IPs, "Self": self, "MagicDNSSuffix": suffix, "CertDomains": n.CertDomains,
		"CurrentTailnet": map[string]any{"Name": n.Tailnet, "MagicDNSSuffix": suffix, "MagicDNSEnabled": n.MagicDNS},
	}
	b, _ := json.Marshal(st)
	return string(b)
}

// Request is one request the fake received.
type Request struct {
	Method, Path, Query, Host, Origin, Referer, IfMatch string
	Body                                                []byte
}

type failure struct {
	status int
	body   string
}

// Fake is a fake tailscaled. Its methods are safe for concurrent use.
type Fake struct {
	// Path is the Unix socket.
	Path string

	mu            sync.Mutex
	status        string
	prefs         string
	config        string // "" = none ("null")
	query         string
	cert          func(name string) (int, []byte)
	postFailures  []failure
	unixForbidden bool
	beforePost    func(f *Fake)
	requests      []Request
}

// New starts a fake tailscaled for DefaultNode with an empty serve
// configuration and prefs of Tailscale's control server; it stops with the
// test.
func New(t testing.TB) *Fake {
	t.Helper()
	dir, err := os.MkdirTemp("", "fpts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &Fake{
		Path:   filepath.Join(dir, "tailscaled.sock"),
		status: StatusJSON(DefaultNode()),
		prefs:  `{"ControlURL":"https://controlplane.tailscale.com","OperatorUser":"","ShieldsUp":false,"WantRunning":true}`,
		query:  `{"Complete":true}`,
	}
	ln, err := net.Listen("unix", f.Path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

// Client returns a tslocal client that reaches only this fake.
func (f *Fake) Client() *tslocal.Client {
	return &tslocal.Client{Sockets: []string{f.Path}, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
}

// SetNode replaces the status with StatusJSON(n).
func (f *Fake) SetNode(n Node) { f.SetStatus(StatusJSON(n)) }

// SetStatus replaces the raw status document.
func (f *Fake) SetStatus(raw string) { f.mu.Lock(); f.status = raw; f.mu.Unlock() }

// SetPrefs replaces the raw prefs document.
func (f *Fake) SetPrefs(raw string) { f.mu.Lock(); f.prefs = raw; f.mu.Unlock() }

// SetQueryFeature replaces the query-feature answer.
func (f *Fake) SetQueryFeature(raw string) { f.mu.Lock(); f.query = raw; f.mu.Unlock() }

// SetCert sets the cert endpoint handler (status and body for a name).
func (f *Fake) SetCert(h func(name string) (int, []byte)) { f.mu.Lock(); f.cert = h; f.mu.Unlock() }

// SetConfig replaces the serve configuration ("" or "null" = none).
func (f *Fake) SetConfig(raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if raw == "null" {
		raw = ""
	}
	f.config = raw
}

// Config returns the stored serve configuration ("null" when none).
func (f *Fake) Config() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.config == "" {
		return "null"
	}
	return f.config
}

// ETag is the current Etag (hex SHA-256 of the stored configuration).
func (f *Fake) ETag() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return etag(f.config)
}

func etag(config string) string {
	if config == "" {
		config = "null"
	}
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}

// FailNextPost makes the next serve-config POST answer status with body
// (queued: one call per failing POST).
func (f *Fake) FailNextPost(status int, body string) {
	f.mu.Lock()
	f.postFailures = append(f.postFailures, failure{status, body})
	f.mu.Unlock()
}

// SetUnixForbidden makes every POST whose configuration contains a Unix
// socket or path handler anywhere answer 401, like tailscaled for a user
// that is neither root nor a sudo-capable operator.
func (f *Fake) SetUnixForbidden(on bool) { f.mu.Lock(); f.unixForbidden = on; f.mu.Unlock() }

// BeforePost runs fn (without the fake's lock) before each POST is judged,
// e.g. to change the configuration concurrently (ETag mismatch).
func (f *Fake) BeforePost(fn func(f *Fake)) { f.mu.Lock(); f.beforePost = fn; f.mu.Unlock() }

// Requests returns every request received so far.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// Posts returns the serve-config POSTs received so far.
func (f *Fake) Posts() []Request {
	var out []Request
	for _, r := range f.Requests() {
		if r.Method == http.MethodPost && r.Path == "/localapi/v0/serve-config" {
			out = append(out, r)
		}
	}
	return out
}

// ResetRequests forgets the recorded requests.
func (f *Fake) ResetRequests() { f.mu.Lock(); f.requests = nil; f.mu.Unlock() }

const unixRefusal = "must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket"

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := readAll(r)
	req := Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Host: r.Host,
		Origin: r.Header.Get("Origin"), Referer: r.Header.Get("Referer"), IfMatch: r.Header.Get("If-Match"), Body: body}
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	if r.Host != "local-tailscaled.sock" || req.Origin != "" || req.Referer != "" {
		http.Error(w, "invalid localapi request", http.StatusForbidden)
		return
	}
	switch {
	case r.URL.Path == "/localapi/v0/status":
		f.mu.Lock()
		s := f.status
		f.mu.Unlock()
		writeJSON(w, s)
	case r.URL.Path == "/localapi/v0/prefs":
		f.mu.Lock()
		s := f.prefs
		f.mu.Unlock()
		writeJSON(w, s)
	case r.URL.Path == "/localapi/v0/query-feature" && r.Method == http.MethodPost:
		f.mu.Lock()
		s := f.query
		f.mu.Unlock()
		writeJSON(w, s)
	case r.URL.Path == "/localapi/v0/serve-config" && r.Method == http.MethodGet:
		f.mu.Lock()
		cfg := f.config
		f.mu.Unlock()
		w.Header().Set("Etag", etag(cfg))
		if cfg == "" {
			cfg = "null"
		}
		writeJSON(w, cfg)
	case r.URL.Path == "/localapi/v0/serve-config" && r.Method == http.MethodPost:
		f.post(w, req)
	case strings.HasPrefix(r.URL.Path, "/localapi/v0/cert/"):
		f.mu.Lock()
		h := f.cert
		f.mu.Unlock()
		if h == nil {
			http.Error(w, "no cert", http.StatusInternalServerError)
			return
		}
		st, b := h(strings.TrimPrefix(r.URL.Path, "/localapi/v0/cert/"))
		w.WriteHeader(st)
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) post(w http.ResponseWriter, req Request) {
	f.mu.Lock()
	hook := f.beforePost
	f.mu.Unlock()
	if hook != nil {
		hook(f)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.postFailures) > 0 {
		fl := f.postFailures[0]
		f.postFailures = f.postFailures[1:]
		w.WriteHeader(fl.status)
		_, _ = w.Write([]byte(fl.body))
		return
	}
	if req.IfMatch != "" && req.IfMatch != etag(f.config) {
		http.Error(w, "etag mismatch", http.StatusPreconditionFailed)
		return
	}
	var sc tslocal.ServeConfig
	if err := sc.UnmarshalJSON(req.Body); err != nil {
		http.Error(w, `{"error":"decoding config: `+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if f.unixForbidden {
		for _, e := range sc.Entries() {
			if e.UsesLocalPath() {
				http.Error(w, unixRefusal, http.StatusUnauthorized)
				return
			}
		}
	}
	if sc.Empty() {
		f.config = ""
	} else {
		f.config = string(req.Body)
	}
	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, s)
}

func readAll(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	return io.ReadAll(io.LimitReader(r.Body, 16<<20))
}
