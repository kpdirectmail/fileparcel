package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/settings"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeSettings serves registered defaults overridden by vals.
type fakeSettings struct {
	mu   sync.Mutex
	vals map[string]int64
}

func (s *fakeSettings) Int(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.vals[key]; ok {
		return v
	}
	d, ok := settings.Lookup(key)
	if !ok {
		return 0
	}
	_, v, _ := d.Decode(d.DefaultJSON())
	n, _ := v.(int64)
	return n
}

func (s *fakeSettings) set(key string, v int64) {
	s.mu.Lock()
	s.vals[key] = v
	s.mu.Unlock()
}

func (s *fakeSettings) Raw(string) (json.RawMessage, error) { return nil, core.ErrNotFound }
func (s *fakeSettings) Bool(string) bool                    { return false }
func (s *fakeSettings) String(string) string                { return "" }
func (s *fakeSettings) Strings(string) []string             { return nil }
func (s *fakeSettings) Duration(string) time.Duration       { return 0 }
func (s *fakeSettings) Secret(string) (string, error)       { return "", nil }
func (s *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, errors.New("unsupported")
}
func (s *fakeSettings) Reset(context.Context, *core.Principal, string) error { return nil }
func (s *fakeSettings) Catalog(context.Context) ([]core.SettingView, error) {
	return nil, errors.New("unsupported")
}

func newTest(t *testing.T) (*Registry, *fakeClock, *fakeSettings, *events.Bus) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	st := &fakeSettings{vals: map[string]int64{}}
	bus := events.New()
	env := &core.Env{Clock: clk, Settings: st, Bus: bus}
	r, err := New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); bus.Close() })
	return r, clk, st, bus
}

func TestSettingsRegistered(t *testing.T) {
	for key, want := range map[string]int64{
		"ratelimit.login_per_min": 10, "ratelimit.api_rps": 50, "ratelimit.api_burst": 200,
		"ratelimit.share_per_min": 120, "ratelimit.unlock_per_min": 5,
	} {
		d, ok := settings.Lookup(key)
		if !ok {
			t.Fatalf("%s not registered", key)
		}
		if d.Section != "ratelimit" || string(d.DefaultJSON()) != fmt.Sprint(want) {
			t.Errorf("%s: section %q default %s", key, d.Section, d.DefaultJSON())
		}
		if _, _, err := d.Decode(json.RawMessage("0")); err == nil {
			t.Errorf("%s accepts 0", key)
		}
	}
}

func TestBurstRefillAndRetryAfter(t *testing.T) {
	r, clk, _, _ := newTest(t)
	// login: 10/min, burst 10.
	for i := 0; i < 10; i++ {
		if ok, _ := r.Allow(BucketLogin, "1.2.3.4"); !ok {
			t.Fatalf("attempt %d denied", i)
		}
	}
	ok, retry := r.Allow(BucketLogin, "1.2.3.4")
	if ok || retry <= 0 || retry > 6*time.Second+time.Millisecond {
		t.Fatalf("11th: ok=%v retry=%v", ok, retry)
	}
	// A denied attempt does not consume: the retry hint stays the same.
	if _, retry2 := r.Allow(BucketLogin, "1.2.3.4"); retry2 != retry {
		t.Fatalf("denied attempt consumed a token: %v then %v", retry, retry2)
	}
	// Other keys are independent.
	if ok, _ := r.Allow(BucketLogin, "5.6.7.8"); !ok {
		t.Fatal("other key denied")
	}
	clk.Add(retry)
	if ok, _ := r.Allow(BucketLogin, "1.2.3.4"); !ok {
		t.Fatal("not refilled after retryAfter")
	}
	if ok, _ := r.Allow(BucketLogin, "1.2.3.4"); ok {
		t.Fatal("refilled too much")
	}
	clk.Add(time.Minute)
	if got := r.Tokens(BucketLogin, "1.2.3.4"); got != 10 {
		t.Fatalf("tokens after a minute = %v", got)
	}
}

func TestUnknownAndDisabledBuckets(t *testing.T) {
	r, _, _, _ := newTest(t)
	for i := 0; i < 1000; i++ {
		if ok, _ := r.Allow("nope", "k"); !ok {
			t.Fatal("unknown bucket limited")
		}
	}
	if !math.IsInf(r.Tokens("nope", "k"), 1) {
		t.Fatal("unknown bucket tokens")
	}
	r.Configure("x", 60, 1)
	if ok, _ := r.Allow("x", "k"); !ok {
		t.Fatal("first denied")
	}
	if ok, _ := r.Allow("x", "k"); ok {
		t.Fatal("second allowed")
	}
	r.Configure("x", 0, 0) // disable
	if ok, _ := r.Allow("x", "k"); !ok {
		t.Fatal("disabled bucket limited")
	}
	var nilReg *Registry
	if ok, _ := nilReg.Allow("x", "k"); !ok {
		t.Fatal("nil registry limited")
	}
}

func TestReconfigureKeepsState(t *testing.T) {
	r, _, _, _ := newTest(t)
	r.Configure("b", 60, 5)
	for i := 0; i < 5; i++ {
		r.Allow("b", "k")
	}
	if ok, _ := r.Allow("b", "k"); ok {
		t.Fatal("burst not enforced")
	}
	// Raising the burst does not refill an exhausted limiter instantly.
	r.Configure("b", 60, 10)
	if ok, _ := r.Allow("b", "k"); ok {
		t.Fatal("reconfigure refilled")
	}
	r.Reset("b", "k")
	for i := 0; i < 10; i++ {
		if ok, _ := r.Allow("b", "k"); !ok {
			t.Fatalf("after reset %d denied", i)
		}
	}
}

func TestSettingsChangedReconfigures(t *testing.T) {
	r, _, st, bus := newTest(t)
	// unlock default 5/min.
	for i := 0; i < 5; i++ {
		r.Allow(BucketUnlock, "ip")
	}
	if ok, _ := r.Allow(BucketUnlock, "ip"); ok {
		t.Fatal("unlock default not applied")
	}
	st.set("ratelimit.unlock_per_min", 100)
	bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"ratelimit.unlock_per_min"}}})
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		burst := r.buckets[BucketUnlock].burst
		r.mu.Unlock()
		if burst == 100 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("settings.changed not applied")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Unrelated keys are ignored (no reconfiguration needed; must not panic).
	bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"ui.instance_name"}}})
	r.mu.Lock()
	api := r.buckets[BucketAPI]
	r.mu.Unlock()
	if api.burst != DefaultAPIBurst || api.perMinute != DefaultAPIRPS*60 {
		t.Fatalf("api bucket %+v", api)
	}
}

func TestLRUCapAndTTL(t *testing.T) {
	r, clk, _, _ := newTest(t)
	r.maxKeys = 3
	r.Configure("b", 60, 1)
	for _, k := range []string{"a", "b", "c"} {
		r.Allow("b", k)
	}
	r.Allow("b", "a") // a is now most recently used (denied, but touched)
	r.Allow("b", "d") // evicts b (the LRU)
	if r.Len() != 3 {
		t.Fatalf("len %d", r.Len())
	}
	if _, ok := r.entries[entryKey{"b", "b"}]; ok {
		t.Fatal("LRU entry not evicted")
	}
	if _, ok := r.entries[entryKey{"b", "a"}]; !ok {
		t.Fatal("recently used entry evicted")
	}
	// Idle entries expire after the TTL (MinIdleTTL for this fast bucket).
	clk.Add(MinIdleTTL + time.Second)
	r.Allow("b", "z")
	if r.Len() != 1 {
		t.Fatalf("idle entries not swept: %d", r.Len())
	}
}

func TestCloseIdempotentAndConcurrency(t *testing.T) {
	r, _, _, _ := newTest(t)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				r.Allow(BucketAPI, fmt.Sprintf("10.0.%d.%d", g, i%7))
				if i%50 == 0 {
					r.ApplySettings()
				}
			}
		}(g)
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Works without env/bus as well (mw tests construct it that way).
	r2, err := New(&core.Env{})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if ok, _ := r2.Allow(BucketLogin, "x"); !ok {
		t.Fatal("default login bucket denied first request")
	}
}
