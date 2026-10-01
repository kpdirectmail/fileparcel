package tsingress

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/settings"
	"fileparcel/internal/tslocal/tslocaltest"
)

func init() {
	// The auth.webauthn_* settings belong to package auth, which this test
	// binary does not link; the passkey check reads them.
	if _, ok := settings.Lookup(keyWebAuthnRPID); !ok {
		settings.Register(settings.Def{Key: keyWebAuthnRPID, Section: "auth", Order: 1, Type: settings.TypeString, Default: ""})
		settings.Register(settings.Def{Key: keyWebAuthnOrigins, Section: "auth", Order: 2, Type: settings.TypeStrings,
			Default: []string{}})
	}
}

// retryPending reports whether a retry is scheduled.
func (h *harness) retryPending() bool {
	h.s.stMu.Lock()
	defer h.s.stMu.Unlock()
	return h.s.retryTimer != nil
}

// reconcile runs an automatic reconcile synchronously.
func (h *harness) reconcile(reason string) *outcome {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	return h.s.reconcileLocked(context.Background(), h.s.loadDesired(), recOpts{reason: reason})
}

// tcpFunnel sets up Funnel (shares) on the TCP backend at 127.0.0.1:18443.
func tcpFunnel(t *testing.T) *harness {
	h := newHarness(t)
	h.setting(KeyBackend, `"tcp"`)
	h.setting(KeyBackendPort, `18443`)
	h.attach()
	h.enable(core.FunnelShares)
	if h.f.Config() != funnelConfig(hp443, "443", "http://127.0.0.1:18443") || !h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") {
		t.Fatalf("setup: %s", h.f.Config())
	}
	return h
}

// While tailscaled may still route public traffic to 127.0.0.1:<port>,
// FileParcel keeps that port bound (policy off: the uniform 404) so that no
// other local program can take the Funnel address; a failed removal is
// retried and the port released once the entry is gone.
func TestTCPPortKeptUntilEntryRemoved(t *testing.T) {
	h := tcpFunnel(t)
	h.f.FailNextPost(http.StatusForbidden, "serve config denied")
	st, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelOff})
	if err != nil || st.Funnel.State != core.IngressStateError {
		t.Fatalf("disable: %v %+v", err, st)
	}
	if !h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") || !strings.Contains(h.f.Config(), "127.0.0.1:18443") {
		t.Fatalf("port released while tailscaled still routes to it: %v", h.log.all())
	}
	if p := h.s.Policy(core.IngressFunnel); p.Mode != core.FunnelOff {
		t.Fatalf("policy %+v", p)
	}
	if !h.retryPending() {
		t.Fatal("no retry of the removal")
	}
	var tcp bool
	for _, c := range st.Funnel.Checks {
		tcp = tcp || c.ID == checkBackendTCP && c.Status == statusWarn && strings.Contains(c.Message, "keeps that port bound")
	}
	if !tcp {
		t.Fatalf("no backend.tcp warning: %+v", st.Funnel.Checks)
	}
	// The retry succeeds: entry removed, port released, no further retry.
	if out := h.reconcile("retry"); out.k[0].state != core.IngressStateOff {
		t.Fatalf("retry: %+v", out.k[0])
	}
	if h.f.Config() != "null" || h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") || h.retryPending() {
		t.Fatalf("after the retry: %s %v", h.f.Config(), h.log.all())
	}
}

// Disabling while tailscaled is not running: tailscaled keeps its saved
// configuration, so the port stays bound and the removal is retried; a
// start before tailscaled binds the port of such an entry from the marker.
func TestTCPPortKeptWhileTailscaledDown(t *testing.T) {
	h := tcpFunnel(t)
	n := tslocaltest.DefaultNode()
	n.BackendState = "Stopped"
	h.f.SetNode(n)
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelOff}); err != nil {
		t.Fatal(err)
	}
	if !h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") || !h.retryPending() ||
		h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff {
		t.Fatalf("port released or no retry: %v", h.log.all())
	}
	// A restart while tailscaled is still down: the port is bound again
	// from the marker (policy off).
	h.restart()
	h.attach()
	if !h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") || h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff ||
		!h.retryPending() {
		t.Fatalf("not guarded after a restart: %v", h.log.all())
	}
	h.f.SetNode(tslocaltest.DefaultNode())
	h.reconcile("retry")
	if h.f.Config() != "null" || h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") || h.marker() != nil {
		t.Fatalf("after tailscaled is back: %s %v", h.f.Config(), h.log.all())
	}
}

// A backend or port move opens the new listener next to the old one and
// releases the old port only after tailscaled was told.
func TestBackendMoveKeepsOldPortUntilWritten(t *testing.T) {
	h := tcpFunnel(t)
	// The write fails: tailscaled keeps routing to the old port, which
	// stays bound (and keeps serving the Funnel policy).
	h.f.SetUnixForbidden(true)
	h.setting(KeyBackend, `"unix"`)
	if out := h.reconcile("settings"); out.k[0].state != core.IngressStateError {
		t.Fatalf("move: %+v", out.k[0])
	}
	if !strings.Contains(h.f.Config(), "http://127.0.0.1:18443") || !h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") ||
		!h.lis.bound(core.IngressFunnel, h.sock(core.IngressFunnel)) {
		t.Fatalf("old port released: %s %v", h.f.Config(), h.log.all())
	}
	if p := h.s.Policy(core.IngressFunnel); p.Mode != core.FunnelShares {
		t.Fatalf("policy %+v", p)
	}
	// Back to tcp: the kept listener is the current one again.
	h.setting(KeyBackend, `"tcp"`)
	if out := h.reconcile("settings"); out.k[0].state != core.IngressStateActive {
		t.Fatalf("back: %+v", out.k[0])
	}
	if h.lis.bound(core.IngressFunnel, h.sock(core.IngressFunnel)) || !h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") {
		t.Fatalf("listeners %v", h.log.all())
	}
	// A successful move releases the old port.
	h.f.SetUnixForbidden(false)
	h.setting(KeyBackendPort, `20000`)
	if out := h.reconcile("settings"); out.k[0].state != core.IngressStateActive {
		t.Fatalf("port move: %+v", out.k[0])
	}
	if h.f.Config() != funnelConfig(hp443, "443", "http://127.0.0.1:20000") || h.lis.bound(core.IngressFunnel, "127.0.0.1:18443") ||
		!h.lis.bound(core.IngressFunnel, "127.0.0.1:20000") {
		t.Fatalf("after the move: %s %v", h.f.Config(), h.log.all())
	}
}

// Detach cancels a change that is still talking to tailscaled and returns
// within its context.
func TestDetachCancelsRunningChange(t *testing.T) {
	h := newHarness(t)
	h.setting(KeyBackend, `"tcp"`)
	h.setting(KeyBackendPort, `18443`)
	h.attach()
	started := make(chan struct{}, 1)
	h.f.BeforePost(func(*tslocaltest.Fake) {
		select {
		case started <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Second)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	h.s.Detach(ctx)
	if d := time.Since(t0); d > 400*time.Millisecond {
		t.Fatalf("Detach took %v", d)
	}
	<-done
	if h.s.attached() {
		t.Fatal("still attached")
	}
}

// Detach gives up waiting for the change lock when its context ends.
func TestDetachBoundedByContext(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.s.mu.Lock() // a change that does not return
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	h.s.Detach(ctx)
	h.s.mu.Unlock()
	if d := time.Since(t0); d > time.Second || h.s.attached() {
		t.Fatalf("Detach took %v (attached %v)", d, h.s.attached())
	}
}

// copyMarker gives dst a copy of src's marker (cp -a of a home).
func copyMarker(t *testing.T, src, dst *harness) {
	t.Helper()
	b, err := os.ReadFile(markerPath(src.home))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(markerPath(dst.home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath(dst.home), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// markHome creates fileparcel.toml (an installed home).
func markHome(t *testing.T, h *harness) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.home.Dir(), "fileparcel.toml"), []byte("[server]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A copied home carries the marker of the live installation: it neither
// takes over nor removes that installation's entries.
func TestCopiedHomeLeavesOriginalEntries(t *testing.T) {
	h := newHarness(t)
	markHome(t, h)
	h.attach()
	h.enable(core.FunnelShares)
	orig := h.f.Config()
	if m := h.marker(); m.Home != h.home.Dir() {
		t.Fatalf("marker home %q", m.Home)
	}

	c := newHarness(t)
	markHome(t, c)
	c.s.ts = h.f.Client()
	c.setting(KeyMode, `"shares"`)
	c.setting(KeyNode, `"`+h.env.Settings.String(KeyNode)+`"`)
	copyMarker(t, h, c)
	if HasMarker(c.home) {
		t.Fatal("the copy lists the original's entries for removal")
	}
	c.attach()
	if h.f.Config() != orig {
		t.Fatalf("the copy changed the original's entry: %s", h.f.Config())
	}
	if st := c.status(); st.Funnel.State != core.IngressStateConflict || len(st.Foreign) != 1 {
		t.Fatalf("copy status %+v foreign %+v", st.Funnel, st.Foreign)
	}
	if out := h.reconcile("settings"); out.k[0].state != core.IngressStateActive {
		t.Fatalf("original: %+v", out.k[0])
	}
	// Re-apply on the copy: the original's entry holds the port.
	if _, err := c.s.Reapply(context.Background(), admin()); err == nil {
		t.Fatal("the copy took the port over")
	}
	if h.f.Config() != orig {
		t.Fatalf("re-apply changed the original's entry: %s", h.f.Config())
	}
	// Uninstalling the copy leaves the original alone.
	copyMarker(t, h, c)
	if err := RemoveMarked(context.Background(), c.home, h.f.Client()); err != nil {
		t.Fatal(err)
	}
	if h.f.Config() != orig {
		t.Fatalf("uninstalling the copy removed the original's entry: %s", h.f.Config())
	}
	if _, err := os.Stat(markerPath(c.home)); !os.IsNotExist(err) {
		t.Fatalf("the copy's marker file stayed: %v", err)
	}
}

// A moved home (the home named in the marker is gone) adopts its marker
// and moves the entries to its own socket.
func TestMovedHomeAdoptsMarker(t *testing.T) {
	h := newHarness(t)
	gone := filepath.Join(t.TempDir(), "old-home")
	oldSock := "unix:" + filepath.Join(gone, "run", "ts-funnel.sock")
	m := &marker{Version: markerVersion, Home: gone, NodeID: tslocaltest.DefaultNode().NodeID, DNSName: "node.tail.ts.net",
		Backend: BackendUnix, State: markerApplied,
		Entries: []markerEntry{{Kind: core.IngressFunnel, HostPort: hp443, Port: 443, Proxy: oldSock, Funnel: true}}}
	b, _ := json.Marshal(m)
	if err := os.MkdirAll(filepath.Dir(markerPath(h.home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath(h.home), b, 0o600); err != nil {
		t.Fatal(err)
	}
	h.f.SetConfig(funnelConfig(hp443, "443", oldSock))
	h.setting(KeyMode, `"shares"`)
	h.setting(KeyNode, `"`+tslocaltest.DefaultNode().NodeID+`"`)
	h.attach()
	if h.f.Config() != funnelConfig(hp443, "443", "unix:"+h.sock(core.IngressFunnel)) {
		t.Fatalf("not moved: %s", h.f.Config())
	}
	if nm := h.marker(); nm.Home != h.home.Dir() || nm.Entries[0].Proxy != "unix:"+h.sock(core.IngressFunnel) {
		t.Fatalf("marker %+v", nm)
	}
}

// A hand-made entry for another program on the TCP backend's Serve port
// (backend_port+1) is foreign: listed, never removed, and Serve does not
// take that port.
func TestForeignEntryOnBackendPortKept(t *testing.T) {
	h := tcpFunnel(t)
	foreign := `{"AllowFunnel":{"node.tail.ts.net:443":true},"TCP":{"443":{"HTTPS":true},"9000":{"HTTPS":true}},"Web":{` +
		`"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:18443"}}},` +
		`"node.tail.ts.net:9000":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:18444"}}}}}`
	h.f.SetConfig(foreign)
	if st := h.status(); len(st.Foreign) != 1 || st.Foreign[0].Target != "http://127.0.0.1:18444" {
		t.Fatalf("foreign %+v", st.Foreign)
	}
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Port: 10000}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.f.Config(), `"node.tail.ts.net:9000":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:18444"}}}`) {
		t.Fatalf("the hand-made entry was removed: %s", h.f.Config())
	}
	_, err := h.s.SetServe(context.Background(), admin(), core.ServeInput{Enabled: true})
	mustCode(t, err, core.ErrPrecondition, checkBackend)
	if !strings.Contains(err.Error(), "node.tail.ts.net:9000") || !strings.Contains(h.f.Config(), "127.0.0.1:18444") ||
		h.lis.bound(core.IngressServe, "127.0.0.1:18444") {
		t.Fatalf("serve: %v %s", err, h.f.Config())
	}
}

// allow_admin and require_2fa stay stored while Funnel is off or shares
// only; entering app mode with them weakens sign-in over Funnel, which
// needs an owner or administrator and the typed confirmation.
func TestStoredWeakFlagsNeedAdmin(t *testing.T) {
	h := newHarness(t)
	h.attach()
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelApp, AllowAdmin: ptr(true),
		Confirm: ConfirmPublic}); err != nil {
		t.Fatal(err)
	}
	h.enable2(core.FunnelShares, 0)
	if !h.env.Settings.Bool(KeyAllowAdmin) {
		t.Fatal("setup: allow_admin not stored")
	}
	_, err := h.s.SetFunnel(context.Background(), delegate(), core.FunnelInput{Mode: core.FunnelApp, Confirm: ConfirmPublic})
	if !strings.Contains(core.AsError(err).Message, "turn that off") {
		t.Fatalf("delegate: %v", err)
	}
	mustCode(t, err, core.ErrForbidden, "")
	if len(h.audit.withReason(core.ActNetworkFunnel, "rbac")) == 0 {
		t.Fatal("denial not audited")
	}
	// The delegate may switch it off on the way.
	if _, err := h.s.SetFunnel(context.Background(), delegate(), core.FunnelInput{Mode: core.FunnelApp, AllowAdmin: ptr(false),
		Confirm: ConfirmPublic}); err != nil {
		t.Fatal(err)
	}
	if p := h.s.Policy(core.IngressFunnel); p.Mode != core.FunnelApp || p.AllowAdmin {
		t.Fatalf("policy %+v", p)
	}
	// require_2fa off, stored while off: the same.
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelApp, Require2FA: ptr(false),
		Confirm: ConfirmPublic}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelOff}); err != nil {
		t.Fatal(err)
	}
	_, err = h.s.SetFunnel(context.Background(), delegate(), core.FunnelInput{Mode: core.FunnelApp, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrForbidden, "")
	// An administrator switching to app with the stored flag still confirms it.
	h.enable2(core.FunnelShares, 0)
	_, err = h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelApp})
	mustCode(t, err, core.ErrInvalid, "confirm")
}

// Passkeys work only on their RP ID and allowed origins: the check warns
// on the Funnel (app) and Serve addresses until both cover them.
func TestPasskeyCheck(t *testing.T) {
	h := newHarness(t)
	h.attach()
	find := func(e core.IngressEntry) *core.IngressCheck {
		for i := range e.Checks {
			if e.Checks[i].ID == checkPasskeys {
				return &e.Checks[i]
			}
		}
		return nil
	}
	if c := find(h.enable(core.FunnelShares).Funnel); c != nil {
		t.Fatalf("shares mode: %+v", c)
	}
	st := h.enable(core.FunnelApp)
	c := find(st.Funnel)
	if c == nil || c.Status != statusWarn || !strings.Contains(c.Message, ".local name") ||
		!strings.Contains(c.Hint, "auth.webauthn_rp_id to node.tail.ts.net") {
		t.Fatalf("default RP ID: %+v", c)
	}
	h.setting(keyWebAuthnRPID, `"node.tail.ts.net"`)
	if c := find(h.status().Funnel); c == nil || c.Status != statusOK {
		t.Fatalf("RP ID set: %+v", c)
	}
	st, err := h.s.SetServe(context.Background(), admin(), core.ServeInput{Enabled: true, Port: 4443})
	if err != nil {
		t.Fatal(err)
	}
	if c := find(st.Serve); c == nil || c.Status != statusWarn || !strings.Contains(c.Hint, "https://node.tail.ts.net:4443 to auth.webauthn_origins") {
		t.Fatalf("serve on 4443: %+v", c)
	}
	h.setting(keyWebAuthnOrigins, `["https://node.tail.ts.net:4443"]`)
	if c := find(h.status().Serve); c == nil || c.Status != statusOK {
		t.Fatalf("origin allowed: %+v", c)
	}
}
