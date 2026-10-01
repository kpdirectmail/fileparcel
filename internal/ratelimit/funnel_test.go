package ratelimit

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"fileparcel/internal/settings"
)

func TestFunnelSettingsRegistered(t *testing.T) {
	for key, want := range map[string]int64{"ratelimit.funnel_per_min": 1200, "ratelimit.funnel_global_per_min": 12000} {
		d, ok := settings.Lookup(key)
		if !ok {
			t.Fatalf("%s not registered", key)
		}
		if d.Section != "ratelimit" || string(d.DefaultJSON()) != fmt.Sprint(want) || d.Managed != "" {
			t.Errorf("%s: %+v", key, d)
		}
		if _, _, err := d.Decode(json.RawMessage("0")); err == nil {
			t.Errorf("%s accepts 0", key)
		}
	}
}

// The Funnel buckets: per client and global from the settings, and the
// fixed per-account and per-share buckets of failed guesses over Funnel.
func TestFunnelBuckets(t *testing.T) {
	r, clk, st, _ := newTest(t)
	r.mu.Lock()
	f, g := r.buckets[BucketFunnel], r.buckets[BucketFunnelGlobal]
	r.mu.Unlock()
	if f == nil || f.burst != DefaultFunnelPerMin || f.perMinute != DefaultFunnelPerMin ||
		g == nil || g.burst != DefaultFunnelGlobalPerMin || g.perMinute != DefaultFunnelGlobalPerMin {
		t.Fatalf("funnel %+v global %+v", f, g)
	}
	st.set("ratelimit.funnel_per_min", 3)
	r.ApplySettings()
	for i := 0; i < 3; i++ {
		if ok, _ := r.Allow(BucketFunnel, "2001:db8:1:2::/64"); !ok {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if ok, retry := r.Allow(BucketFunnel, "2001:db8:1:2::/64"); ok || retry <= 0 {
		t.Fatal("per-client Funnel limit not applied")
	}
	// Ten wrong sign-ins per account, then two per hour.
	for i := 0; i < AuthFunnelUserBurst; i++ {
		if ok, _ := r.Allow(BucketAuthFunnelUser, "usr_1"); !ok {
			t.Fatalf("guess %d refused", i+1)
		}
	}
	if ok, retry := r.Allow(BucketAuthFunnelUser, "usr_1"); ok || retry < 29*time.Minute {
		t.Fatalf("auth_funnel_user: ok=%v retry=%v", ok, retry)
	}
	clk.Add(30 * time.Minute)
	if ok, _ := r.Allow(BucketAuthFunnelUser, "usr_1"); !ok {
		t.Fatal("no token after 30 minutes")
	}
	// Twenty wrong share passwords per share, then twenty per hour.
	for i := 0; i < FunnelSharePWBurst; i++ {
		r.Allow(BucketFunnelSharePW, "shr_1")
	}
	if ok, retry := r.Allow(BucketFunnelSharePW, "shr_1"); ok || retry < 2*time.Minute {
		t.Fatalf("funnel_share_pw: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := r.Allow(BucketFunnelSharePW, "shr_2"); !ok {
		t.Fatal("another share is limited too")
	}
}
