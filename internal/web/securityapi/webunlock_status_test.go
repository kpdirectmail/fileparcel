package securityapi

import (
	"fmt"
	"testing"

	"fileparcel/internal/core"
)

// TestSystemStatusSaysWhetherWebUnlockIsAllowed: while locked, GET
// /system/status tells the unlock page what POST /system/unlock would answer
// this client, so the page does not ask for the passphrase only to refuse
// it; unlocked, it says nothing.
func TestSystemStatusSaysWhetherWebUnlockIsAllowed(t *testing.T) {
	for _, tc := range []struct {
		state           core.KeyState
		mode, addr, who string
		want            string
	}{
		{core.KeyStateLocked, "", "192.168.1.5:40000", "", "allowed"}, // default lan
		{core.KeyStateLocked, "lan", "203.0.113.9:40000", "", "network"},
		{core.KeyStateLocked, "any", "203.0.113.9:40000", "", "allowed"},
		{core.KeyStateLocked, "off", "192.168.1.5:40000", "", "off"},
		{core.KeyStateLocked, "off", "@", "socket", "allowed"},
		{core.KeyStateUnlocked, "off", "192.168.1.5:40000", "", ""},
	} {
		t.Run(fmt.Sprintf("%s %s from %s as %q", tc.state, tc.mode, tc.addr, tc.who), func(t *testing.T) {
			hs := newHarness(t)
			hs.keys.state = tc.state
			if tc.mode != "" {
				hs.settings.set(keyWebUnlock, tc.mode)
			}
			rec := hs.do(t, "GET", "/api/v1/system/status", nil, from(tc.addr), as(tc.who))
			if st := decode[core.SystemStatus](t, rec); rec.Code != 200 || st.WebUnlock != tc.want {
				t.Fatalf("%d web_unlock %q, want %q", rec.Code, st.WebUnlock, tc.want)
			}
		})
	}
}
