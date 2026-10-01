package tsingress

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
	"fileparcel/internal/tslocal/tslocaltest"
)

// Start only subscribes: no request reaches tailscaled, no listener opens.
func TestStartDoesNotWrite(t *testing.T) {
	h := newHarness(t)
	h.setting(KeyMode, `"shares"`)
	h.f.ResetRequests()
	if err := h.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if reqs := h.f.Requests(); len(reqs) != 0 {
		t.Fatalf("requests %+v", reqs)
	}
	if h.marker() != nil || len(h.log.all()) != 0 {
		t.Fatal("wrote something")
	}
}

// While the server is stopped an enable stores the settings and a pending
// marker, and tailscaled is changed only when the server starts.
func TestOfflineEnableIsPending(t *testing.T) {
	h := newHarness(t)
	st := h.enable(core.FunnelShares)
	if len(h.f.Posts()) != 0 {
		t.Fatalf("posted while stopped: %s", h.f.Config())
	}
	if st.Funnel.State != core.IngressStateStopped || !strings.Contains(st.Funnel.Message, "when the server starts") {
		t.Fatalf("status %+v", st.Funnel)
	}
	m := h.marker()
	if m == nil || m.State != markerPending || m.entry(core.IngressFunnel) == nil ||
		m.entry(core.IngressFunnel).Proxy != "unix:"+h.sock(core.IngressFunnel) {
		t.Fatalf("marker %+v", m)
	}
	if h.env.Settings.String(KeyMode) != core.FunnelShares || h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff {
		t.Fatal("settings not stored, or a policy without listener")
	}
	h.attach()
	if got := h.f.Config(); got != funnelConfig(hp443, "443", "unix:"+h.sock(core.IngressFunnel)) {
		t.Fatalf("not applied at start: %s", got)
	}
	if m := h.marker(); m.State != markerApplied || h.status().Funnel.State != core.IngressStateActive {
		t.Fatalf("marker %+v", m)
	}
	// Offline disable removes the entry at once.
	h.restart()
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelOff}); err != nil {
		t.Fatal(err)
	}
	if h.f.Config() != "null" || h.marker() != nil {
		t.Fatalf("offline disable: %s", h.f.Config())
	}
}

// Entries removed outside FileParcel while it was stopped are drift, not
// re-added at start; Re-apply publishes them again.
func TestAttachDriftNotReadded(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	h.restart()
	h.f.SetConfig("null") // `tailscale serve reset`
	h.f.ResetRequests()
	h.attach()
	if len(h.f.Posts()) != 0 {
		t.Fatalf("re-added: %s", h.f.Config())
	}
	st := h.status()
	if st.Funnel.State != core.IngressStateDrift || !strings.Contains(st.Funnel.Message, "no longer has") {
		t.Fatalf("status %+v", st.Funnel)
	}
	if h.marker().entry(core.IngressFunnel) == nil {
		t.Fatal("marker lost the entry")
	}
	if st, err := h.s.Reapply(context.Background(), admin()); err != nil || st.Funnel.State != core.IngressStateActive {
		t.Fatalf("reapply %v %+v", err, st)
	}
	if len(h.audit.withReason(core.ActNetworkFunnel, "reapply")) != 1 {
		t.Fatal("reapply not audited")
	}
}

// A change of Serve does not republish a Funnel entry removed outside
// FileParcel (only Re-apply or enabling Funnel again does).
func TestServeChangeKeepsFunnelDrift(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	h.f.SetConfig("null")
	if _, err := h.s.SetServe(context.Background(), admin(), core.ServeInput{Enabled: true, Port: 10000}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.f.Config(), "AllowFunnel") {
		t.Fatalf("Funnel republished: %s", h.f.Config())
	}
	st := h.status()
	if st.Funnel.State != core.IngressStateDrift || st.Serve.State != core.IngressStateActive {
		t.Fatalf("funnel %s serve %s", st.Funnel.State, st.Serve.State)
	}
}

// Settings that want Funnel without a marker (a restored backup, a copied
// home) publish nothing by themselves.
func TestAttachWithoutMarkerIsDrift(t *testing.T) {
	h := newHarness(t)
	h.setting(KeyMode, `"shares"`)
	h.setting(KeyNode, `"nTESTNODE1CNTRL"`)
	h.attach()
	if len(h.f.Posts()) != 0 {
		t.Fatal("published without a marker")
	}
	st := h.status()
	if st.Funnel.State != core.IngressStateDrift || !strings.Contains(st.Funnel.Message, "not published from this install") {
		t.Fatalf("status %+v", st.Funnel)
	}
}

func TestDetachTCPSuspendsAndStartRestores(t *testing.T) {
	h := newHarness(t)
	h.setting(KeyBackend, `"tcp"`)
	h.attach()
	h.enable(core.FunnelShares)
	want := funnelConfig(hp443, "443", "http://127.0.0.1:18443")
	if h.f.Config() != want {
		t.Fatalf("config %s", h.f.Config())
	}
	h.restart() // Detach
	if h.f.Config() != "null" {
		t.Fatalf("TCP entry kept on stop: %s", h.f.Config())
	}
	if m := h.marker(); m == nil || m.State != markerSuspended || m.Backend != BackendTCP {
		t.Fatalf("marker %+v", m)
	}
	h.attach()
	if h.f.Config() != want || h.marker().State != markerApplied || h.status().Funnel.State != core.IngressStateActive {
		t.Fatalf("not restored: %s", h.f.Config())
	}
}

func TestDetachUnixKeepsEntries(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	n := len(h.f.Posts())
	h.s.Detach(context.Background())
	if len(h.f.Posts()) != n || h.marker().State != markerApplied {
		t.Fatal("the Unix backend changed tailscaled on stop")
	}
	if h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff || h.s.InternetLinks() {
		t.Fatal("snapshots kept after Detach")
	}
}

// A configuration bound to another node is paused; enabling again here
// re-binds it.
func TestNodeMismatchPaused(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	n := len(h.f.Posts())
	h.setting(KeyNode, `"nOTHERNODE"`)
	h.s.autoReconcile(context.Background(), []string{"settings"})
	st := h.status()
	if st.Funnel.State != core.IngressStatePaused || len(h.f.Posts()) != n {
		t.Fatalf("status %+v", st.Funnel)
	}
	if _, ok := h.lis.get(core.IngressFunnel); ok || h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff {
		t.Fatal("still serving")
	}
	h.enable(core.FunnelShares)
	if h.env.Settings.String(KeyNode) != "nTESTNODE1CNTRL" || h.status().Funnel.State != core.IngressStateActive {
		t.Fatal("not re-bound")
	}
	// Serve cannot re-bind silently while Funnel is bound elsewhere.
	h.setting(KeyNode, `"nOTHERNODE"`)
	_, err := h.s.SetServe(context.Background(), admin(), core.ServeInput{Enabled: true, Port: 10000})
	mustCode(t, err, core.ErrPrecondition, checkNode)
}

// A new MagicDNS name moves FileParcel's entries (network.changed).
func TestRenameMovesEntries(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	// An unrelated network change does nothing.
	h.s.autoReconcile(context.Background(), []string{"network"})
	if posts := len(h.f.Posts()); posts != 1 {
		t.Fatalf("%d posts", posts)
	}
	node := tslocaltest.DefaultNode()
	node.DNSName = "renamed.tail.ts.net."
	h.f.SetNode(node)
	h.s.autoReconcile(context.Background(), []string{"network"})
	want := funnelConfig("renamed.tail.ts.net:443", "443", "unix:"+h.sock(core.IngressFunnel))
	if got := h.f.Config(); got != want {
		t.Fatalf("not moved:\n%s", got)
	}
	if len(h.audit.withReason(core.ActNetworkFunnel, "renamed")) != 1 {
		t.Fatal("rename not audited")
	}
	if m := h.marker(); m.DNSName != "renamed.tail.ts.net" || h.s.Policy(core.IngressFunnel).DNSName != "renamed.tail.ts.net" ||
		h.s.PublicBaseURL() != "https://renamed.tail.ts.net" {
		t.Fatalf("marker %+v", m)
	}
}

// tailscaled not up at start (boot order): the listeners open from the
// marker so tailscaled's kept entries work, and a retry verifies later.
func TestTailscaledDownAtStart(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	h.restart()
	fake := h.s.ts
	h.s.ts = &tslocal.Client{Sockets: []string{filepath.Join(t.TempDir(), "gone.sock")}}
	ctx := h.s.attach(h.lis)
	h.s.startReconcile(ctx, "start")
	if v, ok := h.lis.get(core.IngressFunnel); !ok || v[1] != h.sock(core.IngressFunnel) {
		t.Fatalf("listener not opened from the marker: %v", h.log.all())
	}
	if p := h.s.Policy(core.IngressFunnel); p.Mode != core.FunnelShares || p.DNSName != "node.tail.ts.net" {
		t.Fatalf("policy %+v", p)
	}
	h.s.stMu.Lock()
	retry := h.s.retryTimer != nil
	h.s.stMu.Unlock()
	if !retry {
		t.Fatal("no retry scheduled")
	}
	if st := h.status(); st.Funnel.State != core.IngressStateUnavailable {
		t.Fatalf("status %+v", st.Funnel)
	}
	h.s.ts = fake
	h.s.startReconcile(ctx, "retry")
	if st := h.status(); st.Funnel.State != core.IngressStateActive {
		t.Fatalf("after retry %+v", st.Funnel)
	}
	h.s.stMu.Lock()
	retry = h.s.retryTimer != nil
	h.s.stMu.Unlock()
	if retry {
		t.Fatal("retry still scheduled")
	}
}

func TestRemoveAllAndRemoveMarked(t *testing.T) {
	h := newHarness(t)
	h.f.SetConfig(`{"TCP":{"22":{"TCPForward":"127.0.0.1:22"}}}`)
	h.attach()
	h.enable2(core.FunnelShares, 10000)
	if _, err := h.s.SetServe(context.Background(), admin(), core.ServeInput{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.RemoveAll(context.Background(), core.SystemPrincipal(core.ViaOffline), "uninstall"); err != nil {
		t.Fatal(err)
	}
	if got := h.f.Config(); got != `{"TCP":{"22":{"TCPForward":"127.0.0.1:22"}}}` {
		t.Fatalf("left %s", got)
	}
	if h.marker() != nil || HasMarker(h.home) || len(h.lis.open) != 0 {
		t.Fatal("marker or listeners left")
	}
	if len(h.audit.withReason(core.ActNetworkFunnel, "uninstall")) != 1 || len(h.audit.withReason(core.ActNetworkServe, "uninstall")) != 1 {
		t.Fatal("not audited")
	}

	// Uninstall with the server stopped.
	h.enable(core.FunnelShares)
	h.restart()
	if !HasMarker(h.home) {
		t.Fatal("no marker")
	}
	if err := RemoveMarked(context.Background(), h.home, h.f.Client()); err != nil {
		t.Fatal(err)
	}
	if h.f.Config() != `{"TCP":{"22":{"TCPForward":"127.0.0.1:22"}}}` || HasMarker(h.home) {
		t.Fatalf("left %s", h.f.Config())
	}
	// A failure names the commands.
	h.attach()
	h.enable(core.FunnelShares)
	h.f.FailNextPost(401, "must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket")
	err := RemoveMarked(context.Background(), h.home, h.f.Client())
	if err == nil || !strings.Contains(err.Error(), "sudo tailscale serve --yes --https=10000 --set-path=/ off") {
		t.Fatalf("error %v", err)
	}
}

// fakeCLIClient is a client whose only transport is a fake tailscale
// command keeping a one-entry serve configuration in a file.
func fakeCLIClient(t *testing.T, n tslocaltest.Node, cfg string) *tslocal.Client {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("status.json", tslocaltest.StatusJSON(n), 0o600)
	write("prefs.json", `{"ControlURL":"https://controlplane.tailscale.com"}`, 0o600)
	write("cfg.json", cfg, 0o600)
	write("tailscale", `#!/bin/sh
dir=`+dir+`
echo "$*" >> "$dir/args"
case "$1" in
status) cat "$dir/status.json" ;;
debug) cat "$dir/prefs.json" ;;
serve)
  if [ "$2" = status ]; then cat "$dir/cfg.json"; exit 0; fi
  if [ "$5" = off ]; then echo '{}' > "$dir/cfg.json"; exit 0; fi
  port=${4#--https=}
  printf '{"TCP":{"%s":{"HTTPS":true}},"Web":{"node.tail.ts.net:%s":{"Handlers":{"/":{"Proxy":"%s"}}}}}' "$port" "$port" "$6" > "$dir/cfg.json" ;;
funnel)
  port=${4#--https=}
  printf '{"AllowFunnel":{"node.tail.ts.net:%s":true},"TCP":{"%s":{"HTTPS":true}},"Web":{"node.tail.ts.net:%s":{"Handlers":{"/":{"Proxy":"%s"}}}}}' "$port" "$port" "$port" "$6" > "$dir/cfg.json" ;;
esac
`, 0o755)
	return &tslocal.Client{Sockets: []string{filepath.Join(dir, "none.sock")}, CLIs: []string{filepath.Join(dir, "tailscale")}}
}

func cliArgs(t *testing.T, c *tslocal.Client) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(c.CLIs[0]), "args"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// Without a LocalAPI socket the tailscale command publishes and removes the
// entry; removal always uses `tailscale serve … off`.
func TestCLITransport(t *testing.T) {
	h := newHarness(t)
	c := fakeCLIClient(t, tslocaltest.DefaultNode(), `{}`)
	h.s.ts = c
	h.attach()
	st := h.enable(core.FunnelShares)
	if st.Funnel.State != core.IngressStateActive || st.Transport != "cli" {
		t.Fatalf("status %+v", st.Funnel)
	}
	sock := h.sock(core.IngressFunnel)
	if !slices.Contains(cliArgs(t, c), "funnel --bg --yes --https=443 --set-path=/ unix:"+sock) {
		t.Fatalf("argv %v", cliArgs(t, c))
	}
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelOff}); err != nil {
		t.Fatal(err)
	}
	args := cliArgs(t, c)
	if !slices.Contains(args, "serve --yes --https=443 --set-path=/ off") || slices.ContainsFunc(args, func(a string) bool {
		return strings.HasPrefix(a, "funnel") && strings.HasSuffix(a, " off")
	}) {
		t.Fatalf("argv %v", args)
	}
	if h.status().Funnel.State != core.IngressStateOff {
		t.Fatal("not off")
	}
}
