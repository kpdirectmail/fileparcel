// Package events is the in-process publish/subscribe bus (DESIGN §5.3).
//
// Publish never blocks: every subscriber has a bounded buffer of BufferSize
// events and, when it is full, the oldest buffered event is dropped to make
// room for the new one. Subscribers therefore must tolerate gaps (e.g. by
// re-fetching state) and should drain their channel promptly.
//
// Payload types for the standard topics are defined in package core
// (core.SettingsChangedEvent, core.JobEvent, …).
package events

import (
	"strings"
	"sync"
	"sync/atomic"
)

// Standard topics (DESIGN §5.3). The comment gives the payload type in core.
const (
	TopicSettingsChanged = "settings.changed"  // core.SettingsChangedEvent{Keys}
	TopicNetworkChanged  = "network.changed"   // nil
	TopicCertsChanged    = "certs.changed"     // nil
	TopicKeysState       = "keys.state"        // core.KeysStateEvent{State}
	TopicMDNSChanged     = "mdns.changed"      // core.MDNSStatus
	TopicJobProgress     = "job.progress"      // core.JobEvent{Job, User}
	TopicJobDone         = "job.done"          // core.JobEvent{Job, User}
	TopicUploadBatchDone = "upload.batch_done" // core.UploadBatchEvent{Batch, User}
	TopicShareAccessed   = "share.accessed"    // core.ShareAccessedEvent{Share, User}
	TopicBackupFinished  = "backup.finished"   // core.BackupEvent{Backup}
	// TopicAuthzChanged: the permissions of some accounts changed (a role
	// was given, edited or deleted, or its group memberships changed).
	TopicAuthzChanged = "authz.changed" // core.AuthzChangedEvent{UserIDs, RoleID, Reason}
	// TopicIngressChanged: the Tailscale Funnel/Serve status changed.
	TopicIngressChanged = "ingress.changed" // nil
	// TopicSystemRestart asks the running server to restart (nil payload).
	// Published by POST /admin/system/restart (opsapi, after auditing
	// system.restart) and by Backups.ScheduleRestore; package server
	// subscribes, shuts down gracefully and exits with server.ExitRestart (75)
	// — or re-execs itself in the foreground without a supervisor (DESIGN §11.3).
	// Not delivered to SSE clients.
	TopicSystemRestart = "system.restart"
)

// BufferSize is the per-subscriber buffer (events beyond it drop the oldest).
const BufferSize = 256

// Event is one message on the bus.
type Event struct {
	// Topic is a dotted topic name, e.g. "job.done".
	Topic string
	// UserID is the user the event concerns ("" = system/admin-level event).
	// The SSE endpoint uses it for per-user filtering.
	UserID string
	// Data is the topic-specific payload (see the Topic* constants).
	Data any
}

// Bus is a topic-filtered, non-blocking fan-out bus. The zero value is not
// usable; call New. A Bus is safe for concurrent use.
type Bus struct {
	mu     sync.RWMutex
	subs   map[*sub]struct{}
	closed bool
}

type sub struct {
	ch      chan Event
	topics  []string // empty = all
	mu      sync.Mutex
	dropped atomic.Uint64
}

// New returns an empty bus.
func New() *Bus { return &Bus{subs: map[*sub]struct{}{}} }

// Subscribe returns a channel receiving events whose topic matches one of
// topics, and a cancel func that unsubscribes and closes the channel (safe to
// call more than once). A topic pattern is an exact topic ("job.done"), a
// prefix wildcard ("job.*" matches "job.done" and "job.progress") or "*".
// No topics means all topics. After Close the channel is closed.
func (b *Bus) Subscribe(topics ...string) (<-chan Event, func()) {
	s := &sub{ch: make(chan Event, BufferSize), topics: topics}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		close(s.ch)
		return s.ch, func() {}
	}
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			b.mu.Lock()
			if _, ok := b.subs[s]; ok {
				delete(b.subs, s)
				close(s.ch)
			}
			b.mu.Unlock()
		})
	}
}

// Publish delivers e to every matching subscriber without blocking. It is a
// no-op after Close.
func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	for s := range b.subs {
		if s.matches(e.Topic) {
			s.deliver(e)
		}
	}
}

// Close unsubscribes everyone and closes all subscriber channels.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for s := range b.subs {
		close(s.ch)
		delete(b.subs, s)
	}
}

// Subscribers returns the current number of subscribers.
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

func (s *sub) matches(topic string) bool {
	if len(s.topics) == 0 {
		return true
	}
	for _, t := range s.topics {
		if Match(t, topic) {
			return true
		}
	}
	return false
}

// Match reports whether pattern ("x.y", "x.*" or "*") matches topic.
func Match(pattern, topic string) bool {
	switch {
	case pattern == "*" || pattern == topic:
		return true
	case strings.HasSuffix(pattern, ".*"):
		return strings.HasPrefix(topic, pattern[:len(pattern)-1])
	}
	return false
}

// deliver sends without blocking, dropping the oldest buffered event when full.
// Called with the bus read lock held, so the channel cannot be closed meanwhile.
func (s *sub) deliver(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		select {
		case s.ch <- e:
			return
		default:
		}
		select {
		case <-s.ch:
			s.dropped.Add(1)
		default:
		}
	}
}
