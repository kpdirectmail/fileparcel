package ratelimit

import (
	"strings"
	"testing"

	"fileparcel/internal/settings"
)

// TestLoginStartFollowsTheLoginSetting: login_start (and its /64 aggregate)
// get LoginStartFactor times ratelimit.login_per_min, live, and the
// setting's description says how many that is.
func TestLoginStartFollowsTheLoginSetting(t *testing.T) {
	r, _, st, _ := newTest(t)
	if got := r.Tokens(BucketLoginStart, "ip"); got != DefaultLoginPerMin*LoginStartFactor {
		t.Fatalf("login_start burst %v, want %d", got, DefaultLoginPerMin*LoginStartFactor)
	}
	st.set("ratelimit.login_per_min", 3)
	r.ApplySettings()
	for range 3 * LoginStartFactor {
		if ok, _ := r.Allow(BucketLoginStart, "ip"); !ok {
			t.Fatal("login_start refused within its allowance")
		}
	}
	if ok, _ := r.Allow(BucketLoginStart, "ip"); ok {
		t.Fatal("login_start is not bounded")
	}
	if ok, _ := r.Allow(BucketLogin, "ip"); !ok {
		t.Fatal("login_start used the login allowance")
	}
	if got := r.Tokens(BucketLoginStartNet, "net"); got != 3*LoginStartFactor*NetFactor {
		t.Fatalf("login_start_net burst %v", got)
	}
	d, _ := settings.Lookup("ratelimit.login_per_min")
	if LoginStartFactor != 4 || !strings.Contains(d.Description, "four times as many") {
		t.Fatalf("the description of ratelimit.login_per_min does not state LoginStartFactor (%d): %q", LoginStartFactor, d.Description)
	}
}
