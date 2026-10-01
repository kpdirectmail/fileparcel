package opsapi

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// GET /events streams bus events as Server-Sent Events (DESIGN §5.3, §9.4):
//
//	event: <topic>
//	data: <JSON payload of the topic, e.g. core.JobEvent>
//
// Filtering (per principal, DESIGN §6a; Principal.Can applies the role and,
// for API tokens, the admin scope that server permissions need):
//   - job.* — the creator's own jobs; holders of system.view ("Server
//     status") receive every job (the job list is theirs to see anyway, and
//     system jobs have no user);
//   - upload.* and share.accessed — only the events of the user they concern
//     (administrators included: no content access by role);
//   - keys.state — everyone (the state is public through GET /system/status
//     and the app redirects to /unlock when the server locks);
//   - the server topics of topicCaps — holders of one of the listed
//     permissions: settings.changed for anyone who may change some settings,
//     network.changed, mdns.changed and ingress.changed (Tailscale
//     Funnel/Serve) for network.manage, certs.changed for certs.manage,
//     backup.finished for backups.run;
//   - authz.changed (a role was assigned, edited or deleted, or its group
//     memberships changed) — the accounts it concerns (listed in user_ids or
//     holding role_id) and holders of users.view, who may be looking at
//     them; without users.view, user_ids holds at most the recipient's own
//     id. An affected stream is closed right after the event, unless only
//     group memberships changed: its permissions are those of the request
//     that opened it, so EventSource reconnects and authenticates again
//     with the new ones (the web app reloads /me on the event);
//   - system.restart and every other topic — never.
//
// A comment line is sent every 25 s as a heartbeat. Streams end after
// sseMaxLifetime (± jitter) so that revoked sessions and every other change
// of the principal take effect; EventSource reconnects by itself and
// re-authenticates.

// Stream tunables (variables so tests can shorten them).
var (
	sseHeartbeat    = 25 * time.Second
	sseMaxLifetime  = 30 * time.Minute
	sseWriteTimeout = 30 * time.Second
)

// Concurrent stream limits.
const (
	sseMaxPerPrincipal = 8
	sseMaxTotal        = 1024
	sseRetryMillis     = 5000
)

// Topic groups: every stream subscribes to sseUserTopics, streams of
// principals with server access (Principal.ServerAccess) also to the
// topics of topicCaps; deliverable then decides per event.
var sseUserTopics = []string{"job.*", "upload.*", events.TopicShareAccessed, events.TopicKeysState,
	events.TopicAuthzChanged}

// topicCaps are the server topics and the permissions that receive them
// (any of them).
var topicCaps = map[string][]core.Capability{
	events.TopicSettingsChanged: {core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage, core.CapSystemManage},
	events.TopicNetworkChanged:  {core.CapNetworkManage},
	events.TopicMDNSChanged:     {core.CapNetworkManage},
	events.TopicIngressChanged:  {core.CapNetworkManage},
	events.TopicCertsChanged:    {core.CapCertsManage},
	events.TopicBackupFinished:  {core.CapBackupsRun},
}

// sseServerTopics are the keys of topicCaps, sorted.
var sseServerTopics = slices.Sorted(maps.Keys(topicCaps))

// sseLimiter bounds concurrent event streams per principal and in total.
type sseLimiter struct {
	mu        sync.Mutex
	perKey    map[string]int
	total     int
	maxPerKey int
	maxTotal  int
}

func newSSELimiter() *sseLimiter {
	return &sseLimiter{perKey: map[string]int{}, maxPerKey: sseMaxPerPrincipal, maxTotal: sseMaxTotal}
}

// acquire reserves a stream slot for key; release must be called once.
func (l *sseLimiter) acquire(key string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.perKey[key] >= l.maxPerKey {
		return nil, false
	}
	l.total++
	l.perKey[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.perKey[key]--; l.perKey[key] <= 0 {
				delete(l.perKey, key)
			}
		})
	}, true
}

// active returns the number of open streams (tests, diagnostics).
func (l *sseLimiter) active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// streamKey identifies the principal for the per-principal limit.
func streamKey(p *core.Principal) string {
	switch {
	case p.UserID != "":
		return "u:" + p.UserID
	case p.TokenID != "":
		return "t:" + p.TokenID
	}
	return "v:" + string(p.Via)
}

// deliverable decides whether event e may be sent to p.
func deliverable(p *core.Principal, e events.Event) bool {
	own := e.UserID != "" && e.UserID == p.UserID
	switch {
	case e.Topic == events.TopicSystemRestart:
		return false
	case e.Topic == events.TopicKeysState:
		return true
	case strings.HasPrefix(e.Topic, "job."):
		return own || p.Can(core.CapSystemView)
	case strings.HasPrefix(e.Topic, "upload."), e.Topic == events.TopicShareAccessed:
		return own
	case e.Topic == events.TopicAuthzChanged:
		ev, ok := authzEvent(e)
		return ok && (affected(p, ev) || p.Can(core.CapUsersView))
	}
	if caps, ok := topicCaps[e.Topic]; ok {
		return p.CanAny(caps...)
	}
	return false
}

// authzEvent returns the payload of an authz.changed event.
func authzEvent(e events.Event) (core.AuthzChangedEvent, bool) {
	switch ev := e.Data.(type) {
	case core.AuthzChangedEvent:
		return ev, true
	case *core.AuthzChangedEvent:
		if ev != nil {
			return *ev, true
		}
	}
	return core.AuthzChangedEvent{}, false
}

// affected reports whether an authz.changed event concerns p's own account:
// it is listed, or it held the role when the stream was opened.
func affected(p *core.Principal, ev core.AuthzChangedEvent) bool {
	if p.UserID != "" && slices.Contains(ev.UserIDs, p.UserID) {
		return true
	}
	return ev.RoleID != "" && ev.RoleID == p.RoleID
}

// redact trims what p may not see from e: an authz.changed event names
// other accounts only to holders of users.view; an affected account without
// it learns that its own permissions changed, nothing about the others.
func redact(p *core.Principal, e events.Event) events.Event {
	ev, ok := authzEvent(e)
	if !ok || e.Topic != events.TopicAuthzChanged || p.Can(core.CapUsersView) {
		return e
	}
	var own []string
	if p.UserID != "" && slices.Contains(ev.UserIDs, p.UserID) {
		own = []string{p.UserID}
	}
	ev.UserIDs = own
	e.Data = ev
	return e
}

// closesStream reports whether the stream of p must end after delivering e:
// an authz.changed event about p's own account that may have changed its
// permissions (everything but group memberships of its role, which change
// file access only and are read afresh on every request anyway, and a new
// name, description or delegable flag of its role, which change nothing the
// holders may do).
func closesStream(p *core.Principal, e events.Event) bool {
	if e.Topic != events.TopicAuthzChanged {
		return false
	}
	ev, ok := authzEvent(e)
	return ok && ev.Reason != core.AuthzRoleGroups && ev.Reason != core.AuthzRoleDetails && affected(p, ev)
}

// validTopic guards the "event:" line (topics are dotted lowercase names).
func validTopic(t string) bool {
	if t == "" || len(t) > 64 {
		return false
	}
	for _, c := range t {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// frame renders one SSE frame. JSON never contains raw newlines, so the
// payload fits one data line.
func frame(e events.Event) ([]byte, error) {
	data, err := json.Marshal(e.Data)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, len(e.Topic)+len(data)+16)
	b = append(b, "event: "...)
	b = append(b, e.Topic...)
	b = append(b, "\ndata: "...)
	b = append(b, data...)
	b = append(b, "\n\n"...)
	return b, nil
}

// sseCoalesce bounds how many queued events are written before one flush.
const sseCoalesce = 64

// events is GET /events (F): the per-user filtered SSE stream.
func (h *handlers) events(w http.ResponseWriter, r *http.Request) {
	d := h.deps(r)
	if d == nil || d.Env == nil || d.Bus == nil {
		httpx.Error(w, r, errUnavailable)
		return
	}
	p := mw.Principal(r)
	if p == nil {
		httpx.Error(w, r, core.ErrUnauthorized)
		return
	}
	release, ok := h.sse.acquire(streamKey(p))
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(sseRetryMillis/1000))
		httpx.Error(w, r, core.Errorf(core.ErrRateLimited, "too many open event streams; close other tabs"))
		return
	}
	defer release()

	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream; charset=utf-8")
	hd.Set("Cache-Control", mw.CacheNoStore)
	hd.Set("X-Accel-Buffering", "no") // reverse proxies: do not buffer
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	topics := sseUserTopics
	if p.ServerAccess() {
		topics = slices.Concat(sseUserTopics, sseServerTopics)
	}
	// Subscribe before the client sees the stream open, so nothing published
	// afterwards is missed.
	ch, unsubscribe := d.Bus.Subscribe(topics...)
	defer unsubscribe()

	rc := http.NewResponseController(w)
	deadline := func() { _ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)) }
	deadline()
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, "retry: %d\n: connected\n\n", sseRetryMillis); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		if d.Log != nil {
			d.Log.Warn("opsapi: event stream cannot be flushed", "err", err)
		}
		return
	}

	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()
	// Jitter spreads reconnects of many clients (±10 %).
	life := sseMaxLifetime + time.Duration((rand.Float64()*0.2-0.1)*float64(sseMaxLifetime))
	lifetime := time.NewTimer(life)
	defer lifetime.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-lifetime.C:
			return
		case e, ok := <-ch:
			if !ok { // bus closed (shutdown)
				return
			}
			// Write this event and whatever else is already queued (bounded),
			// then flush once. A change of this principal's permissions ends
			// the stream after the event that announces it.
			wrote, closing := false, false
			for i := 0; ; i++ {
				if validTopic(e.Topic) && deliverable(p, e) {
					b, err := frame(redact(p, e))
					if err != nil {
						if d.Log != nil {
							d.Log.Warn("opsapi: event not encodable", "topic", e.Topic, "err", err)
						}
					} else {
						deadline()
						if _, err := w.Write(b); err != nil {
							return
						}
						wrote = true
					}
					if closesStream(p, e) {
						closing = true
						break
					}
				}
				if i >= sseCoalesce {
					break
				}
				select {
				case e, ok = <-ch:
				default:
					ok = false
				}
				if !ok {
					break
				}
			}
			if wrote {
				if err := rc.Flush(); err != nil {
					return
				}
			}
			if closing {
				return
			}
		case <-heartbeat.C:
			deadline()
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}
