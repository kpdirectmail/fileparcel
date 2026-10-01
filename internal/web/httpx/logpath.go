package httpx

import (
	"net/url"
	"strings"
)

// credentialPrefixes are path prefixes whose next segment is a credential.
var credentialPrefixes = []string{"/s/", "/invite/", "/api/v1/auth/invite/", "/api/v1/archives/"}

// sensitiveParams are query parameters that are never logged verbatim.
var sensitiveParams = map[string]bool{
	"token": true, "ticket": true, "t": true, "code": true, "password": true, "pass": true, "passphrase": true,
	"secret": true, "key": true, "data": true, "setup_token": true, "sig": true, "signature": true,
	"access_token": true, "state": true,
}

// LogPath returns the loggable form of u: credential path segments redacted
// (the token of /s/<token>, /invite/<token> and /api/v1/auth/invite/<token>,
// the ticket of /api/v1/archives/<ticket> and /s/<token>/zip/<ticket>, each
// replaced by "…"), the query dropped for non-API paths and sensitive
// parameters masked. Every log line that names a request path uses it — the
// access log (mw.AccessLog), Error and mw.Recover — so no credential carried
// in a URL reaches the log.
func LogPath(u *url.URL) string {
	p := redactPath(u.Path)
	if u.RawQuery == "" || !strings.HasPrefix(u.Path, "/api/") {
		return p
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return p + "?…"
	}
	for k, vs := range q {
		if sensitiveParams[strings.ToLower(k)] {
			for i := range vs {
				vs[i] = "…"
			}
		}
	}
	return p + "?" + q.Encode()
}

// redactPath replaces credential segments of p with "…".
func redactPath(p string) string {
	for _, pre := range credentialPrefixes {
		if !strings.HasPrefix(p, pre) {
			continue
		}
		rest := p[len(pre):]
		seg, tail, _ := strings.Cut(rest, "/")
		if seg == "" {
			return p
		}
		out := pre + "…"
		if tail != "" || strings.HasSuffix(rest, "/") {
			// /s/<token>/zip/<ticket>: redact the ticket too.
			if pre == "/s/" && strings.HasPrefix(tail, "zip/") {
				tail = "zip/…"
			}
			out += "/" + tail
		}
		return out
	}
	return p
}
