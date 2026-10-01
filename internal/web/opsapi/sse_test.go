package opsapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// sseClient reads one event stream.
type sseClient struct {
	t      *testing.T
	resp   *http.Response
	lines  chan string
	cancel context.CancelFunc
}

type sseEvent struct {
	topic string
	data  string
}

func openStream(t *testing.T, srv *httptest.Server, who string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events", nil)
	req.Header.Set("X-Test-As", who)
	resp, err := srv.Client().Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	c := &sseClient{t: t, resp: resp, lines: make(chan string, 1024), cancel: cancel}
	go func() {
		defer close(c.lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
	}()
	t.Cleanup(c.close)
	return c
}

func (c *sseClient) close() {
	c.cancel()
	_ = c.resp.Body.Close()
}

// next returns the next event (skipping comments and directives) or false on timeout.
func (c *sseClient) next(timeout time.Duration) (sseEvent, bool) {
	var ev sseEvent
	deadline := time.After(timeout)
	for {
		select {
		case l, ok := <-c.lines:
			if !ok {
				return ev, false
			}
			switch {
			case strings.HasPrefix(l, "event: "):
				ev.topic = strings.TrimPrefix(l, "event: ")
			case strings.HasPrefix(l, "data: "):
				ev.data = strings.TrimPrefix(l, "data: ")
			case l == "" && ev.topic != "":
				return ev, true
			}
		case <-deadline:
			return ev, false
		}
	}
}

// collect returns the topics+users received until the marker event arrives.
func (c *sseClient) collect(marker string) []string {
	c.t.Helper()
	var got []string
	for {
		ev, ok := c.next(5 * time.Second)
		if !ok {
			c.t.Fatalf("stream ended or timed out; got %v", got)
		}
		var payload struct {
			Job  *core.Job `json:"job"`
			User string    `json:"user"`
		}
		_ = json.Unmarshal([]byte(ev.data), &payload)
		tag := ev.topic
		if payload.Job != nil {
			tag += ":" + payload.Job.ID
		}
		if ev.topic == events.TopicKeysState && strings.Contains(ev.data, marker) {
			return got
		}
		got = append(got, tag)
	}
}

func waitSubscribers(t *testing.T, bus *events.Bus, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for bus.Subscribers() < n {
		if time.Now().After(deadline) {
			t.Fatalf("subscribers %d, want %d", bus.Subscribers(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSSEFiltering(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	srv := httptest.NewServer(te.handler)
	defer srv.Close()

	alice := openStream(t, srv, "alice")
	admin := openStream(t, srv, "admin")
	tok := openStream(t, srv, "token") // admin role, no admin scope
	for _, c := range []*sseClient{alice, admin, tok} {
		if c.resp.StatusCode != 200 || !strings.HasPrefix(c.resp.Header.Get("Content-Type"), "text/event-stream") ||
			c.resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("stream response %d %v", c.resp.StatusCode, c.resp.Header)
		}
	}
	waitSubscribers(t, te.bus, 3)

	job := func(id, user string) events.Event {
		return events.Event{Topic: events.TopicJobDone, UserID: user, Data: core.JobEvent{Job: &core.Job{ID: id}, User: user}}
	}
	te.bus.Publish(job("job_alice", "usr_alice"))
	te.bus.Publish(job("job_bob", "usr_bob"))
	te.bus.Publish(job("job_system", ""))
	te.bus.Publish(events.Event{Topic: events.TopicJobProgress, UserID: "usr_admin",
		Data: core.JobEvent{Job: &core.Job{ID: "job_admin"}, User: "usr_admin"}})
	te.bus.Publish(events.Event{Topic: events.TopicUploadBatchDone, UserID: "usr_alice", Data: core.UploadBatchEvent{User: "usr_alice"}})
	te.bus.Publish(events.Event{Topic: events.TopicUploadBatchDone, UserID: "usr_bob", Data: core.UploadBatchEvent{User: "usr_bob"}})
	te.bus.Publish(events.Event{Topic: events.TopicShareAccessed, UserID: "usr_alice", Data: core.ShareAccessedEvent{User: "usr_alice"}})
	te.bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"backup.enabled"}}})
	te.bus.Publish(events.Event{Topic: events.TopicCertsChanged})
	te.bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	te.bus.Publish(events.Event{Topic: events.TopicMDNSChanged, Data: core.MDNSStatus{State: core.MDNSPublished}})
	te.bus.Publish(events.Event{Topic: events.TopicBackupFinished, Data: core.BackupEvent{Backup: &core.Backup{ID: "bak_1"}}})
	te.bus.Publish(events.Event{Topic: events.TopicSystemRestart})
	te.bus.Publish(events.Event{Topic: "custom.secret", UserID: "usr_alice"})
	te.bus.Publish(events.Event{Topic: events.TopicKeysState, Data: core.KeysStateEvent{State: "marker"}})

	want := map[string][]string{
		"alice": {"job.done:job_alice", "upload.batch_done", "share.accessed"},
		"admin": {"job.done:job_alice", "job.done:job_bob", "job.done:job_system", "job.progress:job_admin",
			"settings.changed", "certs.changed", "network.changed", "mdns.changed", "backup.finished"},
		"token": {"job.progress:job_admin"},
	}
	for name, c := range map[string]*sseClient{"alice": alice, "admin": admin, "token": tok} {
		got := c.collect("marker")
		if strings.Join(got, ",") != strings.Join(want[name], ",") {
			t.Errorf("%s received %v, want %v", name, got, want[name])
		}
	}

	// Closing the bus ends the streams.
	te.bus.Close()
	if _, ok := alice.next(5 * time.Second); ok {
		t.Fatal("event after bus close")
	}
}

func TestSSEHeartbeatHeadAndLimits(t *testing.T) {
	oldHB, oldLife := sseHeartbeat, sseMaxLifetime
	sseHeartbeat, sseMaxLifetime = 20*time.Millisecond, 400*time.Millisecond
	defer func() { sseHeartbeat, sseMaxLifetime = oldHB, oldLife }()

	te := newTestEnv(t, app.ModeNetwork)
	srv := httptest.NewServer(te.handler)
	defer srv.Close()

	// HEAD: headers only, no subscription.
	req, _ := http.NewRequest(http.MethodHead, srv.URL+"/api/v1/events", nil)
	req.Header.Set("X-Test-As", "alice")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("HEAD %d %v", resp.StatusCode, resp.Header)
	}
	if te.bus.Subscribers() != 0 {
		t.Fatal("HEAD subscribed")
	}

	// Heartbeats and the retry directive.
	c := openStream(t, srv, "alice")
	var sawRetry, pings int
	deadline := time.After(3 * time.Second)
loop:
	for pings < 3 {
		select {
		case l, ok := <-c.lines:
			if !ok {
				break loop
			}
			if strings.HasPrefix(l, "retry: ") {
				sawRetry++
			}
			if l == ": ping" {
				pings++
			}
		case <-deadline:
			break loop
		}
	}
	if sawRetry != 1 || pings < 3 {
		t.Fatalf("retry %d pings %d", sawRetry, pings)
	}
	// The stream ends after its maximum lifetime.
	ended := false
	timeout := time.After(3 * time.Second)
	for !ended {
		select {
		case _, ok := <-c.lines:
			ended = !ok
		case <-timeout:
			t.Fatal("stream did not end after its lifetime")
		}
	}
	waitSubscribers(t, te.bus, 0)

	// Per-principal limit; the slot of the ended stream was released, so
	// alice can open the full quota again.
	sseMaxLifetime = time.Minute
	var streams []*sseClient
	for i := 0; i < sseMaxPerPrincipal; i++ {
		s := openStream(t, srv, "alice")
		if s.resp.StatusCode != 200 {
			t.Fatalf("stream %d: %d", i, s.resp.StatusCode)
		}
		streams = append(streams, s)
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events", nil)
	req.Header.Set("X-Test-As", "alice")
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("over limit: %d", resp.StatusCode)
	}
	// Another user is not affected.
	bob := openStream(t, srv, "bob")
	if bob.resp.StatusCode != 200 {
		t.Fatalf("other user blocked: %d", bob.resp.StatusCode)
	}
	bob.close()
	for _, s := range streams {
		s.close()
	}
}

func TestSSELimiterAndHelpers(t *testing.T) {
	l := newSSELimiter()
	l.maxPerKey, l.maxTotal = 2, 3
	r1, ok1 := l.acquire("a")
	_, ok2 := l.acquire("a")
	_, ok3 := l.acquire("a")
	if !ok1 || !ok2 || ok3 {
		t.Fatal("per-key limit")
	}
	_, ok4 := l.acquire("b")
	_, ok5 := l.acquire("c")
	if !ok4 || ok5 {
		t.Fatal("total limit")
	}
	r1()
	r1() // idempotent
	if l.active() != 2 {
		t.Fatalf("active %d", l.active())
	}
	if _, ok := l.acquire("c"); !ok {
		t.Fatal("slot not released")
	}

	for topic, ok := range map[string]bool{"job.done": true, "a_b-c.9": true, "": false, "Job.done": false,
		"job done": false, "x\ny": false, strings.Repeat("a", 65): false} {
		if validTopic(topic) != ok {
			t.Errorf("validTopic(%q)", topic)
		}
	}
	b, err := frame(events.Event{Topic: "job.done", Data: map[string]string{"x": "line1\nline2"}})
	if err != nil || string(b) != "event: job.done\ndata: {\"x\":\"line1\\nline2\"}\n\n" {
		t.Fatalf("frame %q %v", b, err)
	}
	if _, err := frame(events.Event{Topic: "x", Data: make(chan int)}); err == nil {
		t.Fatal("unencodable payload")
	}
	for p, want := range map[*core.Principal]string{
		{UserID: "u1"}: "u:u1", {TokenID: "t1"}: "t:t1", core.SystemPrincipal(core.ViaSocket): "v:socket",
	} {
		if got := streamKey(p); got != want {
			t.Errorf("streamKey = %q, want %q", got, want)
		}
	}
}
