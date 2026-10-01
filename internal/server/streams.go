package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
)

// streams tracks long-lived streaming responses (Server-Sent Events). A
// graceful shutdown waits for in-flight requests, but an event stream never
// ends by itself, so its request context is cancelled as soon as the
// shutdown starts; ordinary requests (uploads, downloads) keep draining.
type streams struct {
	mu      sync.Mutex
	active  map[*streamWriter]context.CancelFunc
	closing bool
}

// wrap installs the tracking on next.
func (s *streams) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		sw := &streamWriter{ResponseWriter: w, s: s, cancel: cancel}
		defer s.remove(sw)
		next.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func (s *streams) add(sw *streamWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		sw.cancel()
		return
	}
	if s.active == nil {
		s.active = map[*streamWriter]context.CancelFunc{}
	}
	s.active[sw] = sw.cancel
}

func (s *streams) remove(sw *streamWriter) {
	if !sw.streaming {
		return
	}
	s.mu.Lock()
	delete(s.active, sw)
	s.mu.Unlock()
}

// closeAll cancels every active stream and every stream started later.
func (s *streams) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	for sw, cancel := range s.active {
		cancel()
		delete(s.active, sw)
	}
}

// streamWriter detects text/event-stream responses.
type streamWriter struct {
	http.ResponseWriter
	s         *streams
	cancel    context.CancelFunc
	checked   bool
	streaming bool
}

func (w *streamWriter) check() {
	if w.checked {
		return
	}
	w.checked = true
	if strings.HasPrefix(strings.ToLower(w.Header().Get("Content-Type")), "text/event-stream") {
		w.streaming = true
		w.s.add(w)
	}
}

// WriteHeader implements http.ResponseWriter.
func (w *streamWriter) WriteHeader(code int) {
	if code >= 200 {
		w.check()
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter.
func (w *streamWriter) Write(b []byte) (int, error) {
	w.check()
	return w.ResponseWriter.Write(b)
}

// ReadFrom keeps the underlying writer's io.ReaderFrom fast path.
func (w *streamWriter) ReadFrom(r io.Reader) (int64, error) {
	w.check()
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(writerOnly{w.ResponseWriter}, r)
}

// Flush implements http.Flusher.
func (w *streamWriter) Flush() {
	w.check()
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (w *streamWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type writerOnly struct{ io.Writer }
