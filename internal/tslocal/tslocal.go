// Package tslocal is FileParcel's single client of the local Tailscale
// daemon (DESIGN §10.6): the LocalAPI over tailscaled's Unix socket, with
// the tailscale CLI as a fallback where no socket exists (macOS GUI builds,
// or an unusual socket path). netinfo (status), certs (certificate pair),
// tsingress (Serve/Funnel configuration) and the CLI use it.
//
// It is a leaf utility importable by anyone (DESIGN §2). It keeps no state:
// callers cache what they read.
//
// LocalAPI requests use the Host "local-tailscaled.sock" and never carry
// Origin or Referer (tailscaled refuses them with 403 "invalid localapi
// request"). A serve-config write always sends the ETag of the read it
// modifies as If-Match: an empty If-Match would overwrite unconditionally.
//
// Test safety: inside `go test`, Default returns a client without sockets
// and without CLI unless FILEPARCEL_TAILSCALE_SOCKET names a fake daemon, so
// no test can reach (and reconfigure) the real tailscaled of the machine.
package tslocal

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// EnvSocket names the tailscaled LocalAPI socket to use instead of the
// platform defaults (a non-default `tailscaled --socket`, and tests). It
// also disables the CLI fallback, which could reach a different daemon.
const EnvSocket = "FILEPARCEL_TAILSCALE_SOCKET"

// Timeouts.
const (
	DefaultReadTimeout  = 3 * time.Second  // status, prefs, serve-config GET
	DefaultWriteTimeout = 15 * time.Second // serve-config POST, query-feature
	CertTimeout         = 3 * time.Minute  // a certificate may need a Let's Encrypt issuance first
	CLITimeout          = 20 * time.Second // one `tailscale serve|funnel` call
)

const (
	localAPIHost = "local-tailscaled.sock"
	maxBody      = 8 << 20 // LocalAPI answers and CLI stdout
	maxStderr    = 4 << 10
	maxErrBody   = 300 // error texts kept from tailscaled
)

// Client talks to tailscaled. The zero value reaches nothing; use Default.
// A Client is a plain value: copy it to change a field.
type Client struct {
	// Sockets are the LocalAPI socket paths, tried in order ("@name" is a
	// Linux abstract socket).
	Sockets []string
	// CLIs are the tailscale commands tried when no socket exists.
	CLIs []string
	// ReadTimeout and WriteTimeout bound one LocalAPI call (0 = defaults).
	ReadTimeout, WriteTimeout time.Duration
	// TempDir receives the private directory the CLI fallback of CertPair
	// writes the pair into ("" = os.TempDir()).
	TempDir string
}

// Default returns the client for this process:
//   - $FILEPARCEL_TAILSCALE_SOCKET set: that socket only, no CLI;
//   - otherwise inside `go test`: no socket and no CLI;
//   - otherwise the platform defaults (core.TailscaleSockets,
//     core.TailscaleCLIs).
func Default() *Client {
	return defaultClient(os.Getenv(EnvSocket), testing.Testing())
}

func defaultClient(envSocket string, inTest bool) *Client {
	c := &Client{ReadTimeout: DefaultReadTimeout, WriteTimeout: DefaultWriteTimeout}
	switch {
	case envSocket != "":
		c.Sockets = []string{envSocket}
	case inTest:
	default:
		c.Sockets, c.CLIs = core.TailscaleSockets(), core.TailscaleCLIs()
	}
	return c
}

func (c *Client) readTimeout() time.Duration {
	if c.ReadTimeout > 0 {
		return c.ReadTimeout
	}
	return DefaultReadTimeout
}

func (c *Client) writeTimeout() time.Duration {
	if c.WriteTimeout > 0 {
		return c.WriteTimeout
	}
	return DefaultWriteTimeout
}

// socketExists reports whether a LocalAPI socket exists at p.
func socketExists(p string) bool {
	if strings.HasPrefix(p, "@") {
		return runtime.GOOS == "linux" // abstract socket: no file to look at
	}
	st, err := os.Stat(p)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// sockets returns the configured sockets that exist.
func (c *Client) sockets() []string {
	var out []string
	for _, s := range c.Sockets {
		if socketExists(s) {
			out = append(out, s)
		}
	}
	return out
}

// cli returns the first configured tailscale command found ("" = none).
func (c *Client) cli() string {
	for _, name := range c.CLIs {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// Transport reports how the serve configuration is read and written:
// "localapi" when a socket exists, "cli" when only the tailscale command
// does, "" when neither.
func (c *Client) Transport() string {
	if len(c.sockets()) > 0 {
		return "localapi"
	}
	if c.cli() != "" {
		return "cli"
	}
	return ""
}

// Installed reports whether a LocalAPI socket or a tailscale command exists.
func (c *Client) Installed() bool { return c.Transport() != "" }

// SocketOwnerUID returns the owner of the first existing socket file (-1
// when unknown: no socket, an abstract socket, or not a Unix system).
func (c *Client) SocketOwnerUID() int {
	socks := c.sockets()
	if len(socks) == 0 || strings.HasPrefix(socks[0], "@") {
		return -1
	}
	return fileOwner(socks[0])
}

// MayConfigure reports whether this process may change tailscaled's
// configuration (serve config, certificates) — tailscaled's PermitWrite:
// root, the user tailscaled runs as (the socket owner), or the operator of
// prefs (a user name or uid). It cannot know macOS's admin-group rule; use
// the result on Linux and the BSDs only.
func (c *Client) MayConfigure(p *Prefs) bool {
	uid := os.Geteuid()
	if uid == 0 || (uid >= 0 && uid == c.SocketOwnerUID()) {
		return true
	}
	return p != nil && IsCurrentUser(p.OperatorUser)
}

// IsCurrentUser reports whether name is the user name or uid of this
// process ("" never is).
func IsCurrentUser(name string) bool {
	if name == "" {
		return false
	}
	if name == strconv.Itoa(os.Geteuid()) {
		return true
	}
	u, err := user.Current()
	return err == nil && (u.Username == name || u.Uid == name)
}

// ---------- LocalAPI plumbing ----------

// errNoSocket: no configured socket exists (the CLI may still).
var errNoSocket = errors.New("tailscale: no tailscaled socket")

// dialError marks a failure to connect to the socket (as opposed to an
// answer or a failure after connecting).
type dialError struct{ err error }

func (e *dialError) Error() string { return e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

type response struct {
	status int
	header http.Header
	body   []byte
}

// localAPI sends one request to the first existing socket that accepts the
// connection. Only connection failures move on to the next socket. It
// returns errNoSocket when no socket exists and ErrNoDaemon when none
// accepts.
func (c *Client) localAPI(ctx context.Context, method, path string, hdr http.Header, body []byte, timeout time.Duration) (*response, error) {
	socks := c.sockets()
	if len(socks) == 0 {
		return nil, errNoSocket
	}
	var dialErr error
	for _, sock := range socks {
		resp, err := doLocalAPI(ctx, sock, method, path, hdr, body, timeout)
		var de *dialError
		if errors.As(err, &de) {
			if dialErr == nil {
				dialErr = de
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		return resp, err
	}
	return nil, fmt.Errorf("%w: %v", ErrNoDaemon, dialErr)
}

func doLocalAPI(ctx context.Context, sock, method, path string, hdr http.Header, body []byte, timeout time.Duration) (*response, error) {
	network, addr := "unix", sock
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, &dialError{err: err}
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// A redirect would add a Referer; tailscaled never redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+localAPIHost+path, rd)
	if err != nil {
		return nil, err
	}
	req.Host = localAPIHost
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	req.Header.Del("Origin")
	req.Header.Del("Referer")
	resp, err := hc.Do(req)
	if err != nil {
		var de *dialError
		if errors.As(err, &de) {
			return nil, de
		}
		return nil, fmt.Errorf("tailscaled LocalAPI %s: %w", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("tailscaled LocalAPI %s: %w", path, err)
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("tailscaled LocalAPI %s: answer larger than %d bytes", path, maxBody)
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// getJSON reads path from the LocalAPI into v (errNoSocket when none exists).
func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	resp, err := c.localAPI(ctx, http.MethodGet, path, nil, nil, c.readTimeout())
	if err != nil {
		return err
	}
	if resp.status != http.StatusOK {
		return httpError(resp.status, resp.body)
	}
	if err := json.Unmarshal(resp.body, v); err != nil {
		return fmt.Errorf("tailscaled LocalAPI %s: %w", path, err)
	}
	return nil
}

// read fetches a JSON document: from the LocalAPI when a socket answers,
// otherwise with the CLI (each argument list is tried in turn, e.g. without
// a flag older CLIs lack). ErrNotInstalled when neither exists.
func (c *Client) read(ctx context.Context, path string, argvs [][]string, v any) error {
	var errs []error
	err := c.getJSON(ctx, path, v)
	if err == nil {
		return nil
	}
	if !errors.Is(err, errNoSocket) {
		errs = append(errs, err)
	}
	if bin := c.cli(); bin != "" {
		for _, args := range argvs {
			out, cerr := c.runCLI(ctx, bin, c.readTimeout(), args...)
			if cerr == nil {
				if jerr := json.Unmarshal(out, v); jerr != nil {
					cerr = fmt.Errorf("tailscale %s: %w", strings.Join(args, " "), jerr)
				} else {
					return nil
				}
			}
			errs = append(errs, cerr)
			if ctx.Err() != nil {
				break
			}
		}
	}
	if len(errs) == 0 {
		return ErrNotInstalled
	}
	return errs[0]
}

// Status reads this node's status (GET /localapi/v0/status?peers=false, or
// `tailscale status --json --peers=false`, retried without --peers for
// older CLIs).
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var st Status
	if err := c.read(ctx, "/localapi/v0/status?peers=false",
		[][]string{{"status", "--json", "--peers=false"}, {"status", "--json"}}, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Prefs reads tailscaled's preferences (GET /localapi/v0/prefs, or
// `tailscale debug prefs`).
func (c *Client) Prefs(ctx context.Context) (*Prefs, error) {
	var p Prefs
	if err := c.read(ctx, "/localapi/v0/prefs", [][]string{{"debug", "prefs"}}, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ServeConfig reads the serve configuration: GET /localapi/v0/serve-config
// (keeps the Etag; "null" = empty) when a socket exists, otherwise `tailscale
// serve status --json` (no ETag: read-only). ErrNotInstalled when neither.
func (c *Client) ServeConfig(ctx context.Context) (*ServeConfig, error) {
	resp, err := c.localAPI(ctx, http.MethodGet, "/localapi/v0/serve-config", nil, nil, c.readTimeout())
	switch {
	case errors.Is(err, errNoSocket):
		bin := c.cli()
		if bin == "" {
			return nil, ErrNotInstalled
		}
		out, err := c.runCLI(ctx, bin, c.readTimeout(), "serve", "status", "--json")
		if err != nil {
			return nil, err
		}
		sc := &ServeConfig{}
		if err := sc.UnmarshalJSON(out); err != nil {
			return nil, err
		}
		return sc, nil
	case err != nil:
		return nil, err
	case resp.status != http.StatusOK:
		return nil, httpError(resp.status, resp.body)
	}
	sc := &ServeConfig{}
	if err := sc.UnmarshalJSON(resp.body); err != nil {
		return nil, err
	}
	sc.ETag = resp.header.Get("Etag")
	return sc, nil
}

// SetServeConfig writes sc (POST /localapi/v0/serve-config) with If-Match =
// sc.ETag. It refuses a configuration without ETag (one not read from the
// LocalAPI) without sending anything: an empty If-Match would overwrite
// changes made since. LocalAPI only; see ServeCLI for the CLI transport.
func (c *Client) SetServeConfig(ctx context.Context, sc *ServeConfig) error {
	if sc == nil || sc.ETag == "" {
		return errors.New("tailscale: refusing to write a serve config without the ETag of the read it modifies")
	}
	body, err := sc.MarshalJSON()
	if err != nil {
		return err
	}
	hdr := http.Header{"If-Match": {sc.ETag}, "Content-Type": {"application/json"}}
	resp, err := c.localAPI(ctx, http.MethodPost, "/localapi/v0/serve-config", hdr, body, c.writeTimeout())
	if errors.Is(err, errNoSocket) {
		return errCLIOnly
	}
	if err != nil {
		return err
	}
	if resp.status/100 != 2 {
		return httpError(resp.status, resp.body)
	}
	return nil
}

// QueryFeature asks whether feature ("funnel", "serve") is enabled for this
// node (POST /localapi/v0/query-feature). LocalAPI only.
func (c *Client) QueryFeature(ctx context.Context, feature string) (*QueryFeature, error) {
	resp, err := c.localAPI(ctx, http.MethodPost, "/localapi/v0/query-feature?feature="+url.QueryEscape(feature),
		nil, nil, c.writeTimeout())
	if errors.Is(err, errNoSocket) {
		return nil, errCLIOnly
	}
	if err != nil {
		return nil, err
	}
	if resp.status != http.StatusOK {
		return nil, httpError(resp.status, resp.body)
	}
	var q QueryFeature
	if err := json.Unmarshal(resp.body, &q); err != nil {
		return nil, fmt.Errorf("tailscaled LocalAPI query-feature: %w", err)
	}
	return &q, nil
}

// ---------- certificates ----------

// CertPair fetches the certificate chain and private key tailscaled holds
// for fqdn (GET /localapi/v0/cert/<fqdn>?type=pair on every existing socket,
// then `tailscale cert`), within CertTimeout. Distinct failures of the
// attempts are joined.
func (c *Client) CertPair(ctx context.Context, fqdn string) (certPEM, keyPEM []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, CertTimeout)
	defer cancel()
	var errs []error
	for _, sock := range c.sockets() {
		cp, kp, err := certLocalAPI(ctx, sock, fqdn)
		if err == nil {
			return cp, kp, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			return nil, nil, joinDistinct(errs)
		}
	}
	cp, kp, err := c.certCLI(ctx, fqdn)
	if err == nil {
		return cp, kp, nil
	}
	errs = append(errs, err)
	return nil, nil, joinDistinct(errs)
}

// certLocalAPI calls GET /localapi/v0/cert/<fqdn>?type=pair. The answer is
// the key PEM followed by the chain PEM.
func certLocalAPI(ctx context.Context, sock, fqdn string) (certPEM, keyPEM []byte, err error) {
	resp, err := doLocalAPI(ctx, sock, http.MethodGet, "/localapi/v0/cert/"+url.PathEscape(fqdn)+"?type=pair",
		nil, nil, CertTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("tailscaled LocalAPI: %w", err)
	}
	if resp.status != http.StatusOK {
		return nil, nil, &APIError{Status: resp.status, Body: clip(strings.TrimSpace(string(resp.body)), maxErrBody)}
	}
	return SplitPEMPair(resp.body)
}

// certCLI runs "tailscale cert --cert-file … --key-file … <fqdn>" into a
// private temporary directory below TempDir.
func (c *Client) certCLI(ctx context.Context, fqdn string) (certPEM, keyPEM []byte, err error) {
	bin := c.cli()
	if bin == "" {
		return nil, nil, fmt.Errorf("tailscale CLI not found: %w", exec.ErrNotFound)
	}
	base := c.TempDir
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, nil, err
	}
	tmp, err := os.MkdirTemp(base, ".fetch-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmp)
	certFile, keyFile := filepath.Join(tmp, "cert.pem"), filepath.Join(tmp, "key.pem")
	if _, err := c.runCLI(ctx, bin, CertTimeout, "cert", "--cert-file", certFile, "--key-file", keyFile, fqdn); err != nil {
		return nil, nil, err
	}
	if certPEM, err = os.ReadFile(certFile); err != nil {
		return nil, nil, err
	}
	if keyPEM, err = os.ReadFile(keyFile); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// SplitPEMPair separates the certificate blocks and the private key block
// of a combined PEM document (tailscaled's type=pair answer).
func SplitPEMPair(data []byte) (certPEM, keyPEM []byte, err error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch {
		case b.Type == "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(b)...)
		case strings.HasSuffix(b.Type, "PRIVATE KEY") && keyPEM == nil:
			keyPEM = pem.EncodeToMemory(b)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, errors.New("response does not contain a certificate and a private key")
	}
	return certPEM, keyPEM, nil
}
