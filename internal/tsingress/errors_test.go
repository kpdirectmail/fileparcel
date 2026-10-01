package tsingress

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/tslocal/tslocaltest"
)

// tailscaled's refusals of a write map to the API errors of DESIGN §9.4:
// LocalAPI 401/403 never surface as 403.
func TestWriteErrorsMapToAPIErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		base   *core.Error
		field  string
	}{
		{http.StatusForbidden, "serve config denied", core.ErrPrecondition, checkOperator},
		{http.StatusInternalServerError, `{"error":"updating config: Unable to turn on Funnel while shields-up is enabled"}`,
			core.ErrPrecondition, checkShieldsUp},
		{http.StatusInternalServerError, `{"error":"updating config: can't reconfigure tailscaled when using a config file; config file is locked"}`,
			core.ErrPrecondition, checkConfigLocked},
		{http.StatusInternalServerError, `{"error":"updating config: netMap is nil"}`, core.ErrPrecondition, checkRunning},
		{http.StatusInternalServerError, `{"error":"updating config: listener already exists for port 443"}`, core.ErrConflict, "port"},
		{http.StatusForbidden, "invalid localapi request", core.ErrUnavailable, ""},
	} {
		t.Run(tc.body, func(t *testing.T) {
			h := newHarness(t)
			h.attach()
			h.f.FailNextPost(tc.status, tc.body)
			_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
			mustCode(t, err, tc.base, tc.field)
			if h.env.Settings.String(KeyMode) != core.FunnelOff {
				t.Fatal("stored")
			}
		})
	}
}

// A config-locked tailscaled shows up as a failing check until Re-apply
// finds it writable again.
func TestConfigLockedCheck(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.f.FailNextPost(http.StatusInternalServerError, `{"error":"config file is locked"}`)
	_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrPrecondition, checkConfigLocked)
	found := false
	for _, c := range h.status().Funnel.Checks {
		found = found || c.ID == checkConfigLocked && c.Status == statusFail
	}
	if !found {
		t.Fatal("no config_locked check")
	}
	// Enabling is refused by the check itself now; Re-apply retries.
	_, err = h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrPrecondition, checkConfigLocked)
	if _, err := h.s.Reapply(context.Background(), admin()); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.status().Funnel.Checks {
		if c.ID == checkConfigLocked {
			t.Fatalf("still locked: %+v", c)
		}
	}
}

// The ingress listener cannot be opened: 412 backend, nothing written.
func TestListenerOpenFailure(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.lis.fail = errors.New("address already in use")
	_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrPrecondition, checkBackend)
	if !strings.Contains(err.Error(), "address already in use") || len(h.f.Posts()) != 0 {
		t.Fatalf("%v, %d posts", err, len(h.f.Posts()))
	}
	// A long home: the explicit Unix backend cannot be used.
	h = newHarness(t)
	h.setting(KeyBackend, `"unix"`)
	h.s.goos = "freebsd"
	long := strings.Repeat("x", 120)
	h.env.Home = mustHome(t, t.TempDir()+"/"+long)
	h.attach()
	_, err = h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrPrecondition, checkBackend)
	if !strings.Contains(err.Error(), "set funnel.backend to tcp") {
		t.Fatalf("%v", err)
	}
	// auto falls back to TCP for a long path.
	h.setting(KeyBackend, `"auto"`)
	st := h.enable(core.FunnelShares)
	if st.Funnel.Backend != "http://127.0.0.1:18443" {
		t.Fatalf("backend %q", st.Funnel.Backend)
	}
}

func TestUserErrorMapping(t *testing.T) {
	d := desired{Mode: core.FunnelShares, Port: 443}
	out := &outcome{}
	out.k[0] = kindOutcome{state: core.IngressStateDrift, message: "gone"}
	mustCode(t, userError(out, 0, d), core.ErrConflict, "")
	out.k[0] = kindOutcome{state: core.IngressStateUnavailable, message: "down"}
	out.unreachable = true
	mustCode(t, userError(out, 0, d), core.ErrUnavailable, "")
	for _, st := range []string{core.IngressStateActive, core.IngressStateStopped, core.IngressStateOff} {
		out.k[0] = kindOutcome{state: st}
		if err := userError(out, 0, d); err != nil {
			t.Fatalf("%s: %v", st, err)
		}
	}
	out.k[0] = kindOutcome{state: core.IngressStateError, err: context.DeadlineExceeded, message: "timeout"}
	mustCode(t, userError(out, 0, d), core.ErrUnavailable, "")
}

// The event loop reconciles after settings and network changes, and Attach
// runs the first reconcile in the background.
func TestEventLoop(t *testing.T) {
	h := newHarness(t)
	if err := h.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.enable(core.FunnelShares) // pending: the server is stopped
	h.s.Attach(h.lis)
	waitFor(t, func() bool { return h.status().Funnel.State == core.IngressStateActive })
	// A rename (network.changed) moves the entry.
	n := tslocaltest.DefaultNode()
	n.DNSName = "moved.tail.ts.net."
	h.f.SetNode(n)
	h.env.Bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	waitFor(t, func() bool { return strings.Contains(h.f.Config(), "moved.tail.ts.net:443") })
	// The server port moved onto the Funnel port (settings.changed).
	h.setting("server.https_port", `443`)
	waitFor(t, func() bool { return h.f.Config() == "null" })
	// A Funnel request on the serve listener triggers the hardening.
	h.setting("server.https_port", `8443`)
	if _, err := h.s.SetServe(context.Background(), admin(), core.ServeInput{Enabled: true, Port: 10000}); err != nil {
		t.Fatal(err)
	}
	h.f.SetConfig(funnelConfig("moved.tail.ts.net:10000", "10000", "unix:"+h.sock(core.IngressServe)))
	h.s.Note(core.IngressServe, true, true)
	waitFor(t, func() bool { return !strings.Contains(h.f.Config(), "AllowFunnel") })
	h.s.Detach(context.Background())
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("condition not reached")
}
