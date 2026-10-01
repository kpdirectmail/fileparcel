package mw

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// reqLog carries per-request facts that inner middleware (Authenticate)
// reports back to AccessLog.
type reqLog struct {
	user string
	via  string
}

type reqLogKey struct{}

func setLogUser(ctx context.Context, user, via string) {
	if rl, ok := ctx.Value(reqLogKey{}).(*reqLog); ok {
		rl.user, rl.via = user, via
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 && code >= 200 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// ReadFrom keeps the underlying writer's io.ReaderFrom fast path (net/http's
// *response implements it; internal/server/streams.go forwards it too), so a
// body served with io.Copy/http.ServeContent is not funnelled through an extra
// buffered copy just because this wrapper is in the chain.
func (s *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	var (
		n   int64
		err error
	)
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		// writerOnly hides the wrapper's own ReadFrom, so io.Copy cannot recurse.
		n, err = io.Copy(writerOnly{s.ResponseWriter}, r)
	}
	s.bytes += n
	return n, err
}

// Unwrap exposes the underlying writer to http.ResponseController (Flush, deadlines).
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush supports streaming responses (SSE).
func (s *statusWriter) Flush() {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// AccessLog logs one line per request: method, redacted path, status,
// bytes, duration, client IP, user and request id, plus ingress=funnel|serve
// for a request of a Tailscale ingress listener (and ts_user, the tailnet
// login tailscaled names, for Serve). Health checks and static assets log
// at debug level. Credentials never reach the log (the path is
// httpx.LogPath): the token segments of /s/<token>, /invite/<token>,
// /api/v1/auth/invite/<token>, /api/v1/archives/<ticket> and
// /s/<token>/zip/<ticket> are replaced by "…", query strings are dropped
// outside /api/, and sensitive query parameters (token, ticket, code,
// password, data, …) are masked everywhere.
//
// The line is emitted from a defer, so a panicking handler is logged too. It
// is reported as 500, because Recover sits outside this middleware and writes
// its error response past the status writer.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rl := &reqLog{}
		sw := &statusWriter{ResponseWriter: w}
		returned := false
		defer func() {
			level := slog.LevelInfo
			p := r.URL.Path
			if strings.HasPrefix(p, "/static/") || p == "/healthz" || p == "/readyz" || p == "/favicon.ico" {
				level = slog.LevelDebug
			}
			status := sw.status
			if status == 0 {
				// A handler that returned without writing sends 200; one that
				// panicked is turned into a 500 by Recover, further out.
				status = http.StatusOK
				if !returned {
					status = http.StatusInternalServerError
				}
			}
			args := []any{
				"method", r.Method, "path", httpx.LogPath(r.URL), "status", status, "bytes", sw.bytes,
				"dur_ms", time.Since(start).Milliseconds(), "ip", ClientIP(r).String(),
				"request_id", httpx.RequestID(r.Context()),
			}
			if rl.user != "" {
				args = append(args, "user", rl.user, "via", rl.via)
			}
			if in := core.IngressFrom(r.Context()); in != nil {
				args = append(args, "ingress", in.Kind)
				if in.Kind == core.IngressServe && in.TSUser != "" {
					args = append(args, "ts_user", sanitizeLog(in.TSUser))
				}
			}
			logger(r).Log(r.Context(), level, "http", args...)
		}()
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), reqLogKey{}, rl)))
		returned = true
	})
}
