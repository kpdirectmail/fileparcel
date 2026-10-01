package tslocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Errors of the LocalAPI and the CLI fallback. Every error a Client returns
// for one of these conditions matches the sentinel with errors.Is; the
// wrapped text carries tailscaled's own words for the log.
var (
	ErrNoDaemon      = errors.New("tailscale: tailscaled is not running or not reachable")
	ErrNotConnected  = errors.New("tailscale: this device is not connected to its tailnet")
	ErrPermission    = errors.New("tailscale: this user may not change tailscaled's configuration")
	ErrUnixForbidden = errors.New("tailscale: tailscaled refuses Unix socket targets for this user")
	ErrETagMismatch  = errors.New("tailscale: serve config changed concurrently")
	ErrShieldsUp     = errors.New("tailscale: Funnel cannot be enabled while shields-up is on")
	ErrConfigLocked  = errors.New("tailscale: tailscaled runs from a config file; its serve config is locked")
	ErrPortInUse     = errors.New("tailscale: the port is used by another serve/funnel listener")
)

// ErrNotInstalled means that neither a LocalAPI socket nor a tailscale CLI
// exists: Tailscale is simply not used on this machine. It also matches
// ErrNoDaemon.
var ErrNotInstalled = fmt.Errorf("%w (no tailscaled socket and no tailscale command found)", ErrNoDaemon)

// errCLIOnly is returned by the LocalAPI-only calls (SetServeConfig,
// QueryFeature) when the client can only use the CLI.
var errCLIOnly = errors.New("tailscale: this call needs the tailscaled LocalAPI socket, which does not exist here")

// APIError is a LocalAPI answer that none of the sentinel errors describes
// (any other non-2xx status, including 403 "invalid localapi request").
type APIError struct {
	Status int
	Body   string // at most maxErrBody bytes, trimmed
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("tailscaled LocalAPI: HTTP %d %s", e.Status, http.StatusText(e.Status))
	}
	return fmt.Sprintf("tailscaled LocalAPI: HTTP %d: %s", e.Status, e.Body)
}

// sentinelText maps tailscaled's error texts (LocalAPI JSON errors, CLI
// stderr) to the sentinel errors; nil when none applies. The texts were
// checked against tailscale v1.102.4 (ipn/localapi, ipn/ipnlocal).
func sentinelText(s string) error {
	switch {
	case strings.Contains(s, "etag mismatch"):
		return ErrETagMismatch
	case strings.Contains(s, "serve config denied"):
		return ErrPermission
	case strings.Contains(s, "Unix socket") && strings.Contains(s, "operator"):
		// "must be root, or be an operator and able to run 'sudo tailscale'
		// to serve a path or Unix socket"
		return ErrUnixForbidden
	case strings.Contains(s, "shields-up"):
		return ErrShieldsUp
	case strings.Contains(s, "config file is locked"):
		return ErrConfigLocked
	case strings.Contains(s, "listener already exists for port"), strings.Contains(s, "is already serving"):
		return ErrPortInUse
	case strings.Contains(s, "netMap is nil"), strings.Contains(s, "netMap SelfNode is nil"),
		strings.Contains(s, "no netmap"):
		return ErrNotConnected
	}
	return nil
}

// httpError converts a non-2xx LocalAPI answer to an error (POST
// serve-config mapping of DESIGN §10.6, used for every call).
func httpError(status int, body []byte) error {
	text := strings.TrimSpace(string(body))
	// 500 answers are JSON {"error": "..."}; keep the message only.
	var je struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &je) == nil && je.Error != "" {
		text = je.Error
	}
	text = clip(text, maxErrBody)
	switch {
	case status == http.StatusPreconditionFailed:
		return wrapText(ErrETagMismatch, text)
	case status == http.StatusUnauthorized || strings.Contains(text, "Unix socket"):
		return wrapText(ErrUnixForbidden, text)
	case status == http.StatusForbidden && strings.Contains(text, "denied"):
		return wrapText(ErrPermission, text)
	case status == http.StatusForbidden:
		return &APIError{Status: status, Body: text}
	}
	if s := sentinelText(text); s != nil {
		return wrapText(s, text)
	}
	return &APIError{Status: status, Body: text}
}

// wrapText returns base annotated with tailscaled's text (errors.Is(…, base)).
func wrapText(base error, text string) error {
	if text == "" {
		return base
	}
	return fmt.Errorf("%w: %s", base, text)
}

// clip shortens s to at most n bytes without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] >= 0xC0 {
		s = s[:len(s)-1]
	}
	return s
}

// joinDistinct joins errs, dropping repetitions of the same complaint. The
// tailscaled sockets are usually the same socket under two paths (/var/run
// is a symlink to /run) and the CLI fallback talks to that very daemon, so
// all of them may quote one sentence behind their own prefix, which a status
// line would otherwise show several times over. The first (most specific)
// wording of a repeated complaint is kept.
func joinDistinct(errs []error) error {
	out := errs[:0:0]
	for _, e := range errs {
		if e == nil {
			continue
		}
		msg := e.Error()
		dup := false
		for _, kept := range out {
			if k := kept.Error(); k == msg || commonSuffix(k, msg) >= sharedTail {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, e)
		}
	}
	return errors.Join(out...)
}

// sharedTail is how many trailing bytes two messages must have in common to
// count as the same complaint behind different prefixes.
const sharedTail = 40

// commonSuffix returns the length of the longest common suffix of a and b.
func commonSuffix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	return n
}
