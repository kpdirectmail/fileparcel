package cli

// Tests of "network vpn|funnel|tailscale-serve", the Remote access block of
// "network", the ROLE column of "network interfaces", the Funnel line of
// "status", the managed-setting hint of "config set" and the local doctor's
// Funnel seam, against fake routes built from the contract goldens.

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/home"
)

// fakeIngress is the Funnel/Serve and network state of addIngressRoutes.
type fakeIngress struct {
	mu     sync.Mutex
	st     core.IngressStatus
	ov     core.NetworkOverview
	put    func(in core.FunnelInput) error // optional refusal of PUT /admin/network/funnel
	policy []core.PolicyInput
}

// addIngressRoutes serves GET /admin/network (network_overview.json with the
// VPNs of vpn_info.json plus a Mullvad and a Yggdrasil VPN), GET
// /admin/network/tailscale (ingress_status.json with Funnel off), PUT
// /admin/network/funnel|serve, POST …/tailscale/reapply and PUT
// /admin/network/policy.
func addIngressRoutes(f *fakeAPI) *fakeIngress {
	fi := &fakeIngress{st: golden[core.IngressStatus](f.t, "ingress_status.json"), ov: golden[core.NetworkOverview](f.t, "network_overview.json")}
	fi.st.Funnel.Mode, fi.st.Funnel.State, fi.st.Funnel.URL = core.FunnelOff, core.IngressStateOff, ""
	fi.ov.Policy = core.AccessPolicy{Mode: core.AccessAllowlist, Allow: []string{"192.168.1.0/24"}, Deny: []string{}}
	fi.ov.VPNs = []core.VPNInfo{
		golden[core.VPNInfo](f.t, "vpn_info.json"),
		{ID: "wg0-mullvad", Kind: core.IfExitVPN, Label: "Mullvad VPN", Role: core.VPNRoleEgress, RoleSource: core.VPNRoleSourceAuto,
			Interfaces: []string{"wg0-mullvad"}, Ranges: []string{}, Allowed: "no"},
		{ID: "yggdrasil", Kind: core.IfYggdrasil, Label: "Yggdrasil", Role: core.VPNRoleOverlay, RoleSource: core.VPNRoleSourceAuto,
			Interfaces: []string{"ygg0"}, Ranges: []string{"200::/7"}, Allowed: "no", CanAllow: true, NeedsForce: true,
			Warning: "public overlay: anyone on the Yggdrasil network"},
		{ID: "headscale", Kind: core.IfHeadscale, Label: "Headscale", Role: core.VPNRoleMesh, Interfaces: []string{"tailscale1"},
			Ranges: []string{}, Allowed: "no", Note: "custom Headscale prefixes: add them with fileparcel network allow add <prefix>"},
	}
	f.handle("GET", "/api/v1/admin/network", func(w http.ResponseWriter, r *http.Request) {
		fi.mu.Lock()
		defer fi.mu.Unlock()
		ov := fi.ov
		st := fi.st
		ov.Ingress = &st
		writeJSON(w, 200, ov)
	})
	f.handle("GET", "/api/v1/admin/network/tailscale", func(w http.ResponseWriter, r *http.Request) {
		fi.mu.Lock()
		defer fi.mu.Unlock()
		writeJSON(w, 200, fi.st)
	})
	f.handle("PUT", "/api/v1/admin/network/funnel", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.FunnelInput](r)
		fi.mu.Lock()
		defer fi.mu.Unlock()
		if fi.put != nil {
			if err := fi.put(in); err != nil {
				writeErr(w, err)
				return
			}
		}
		widens := fi.st.Funnel.Mode == core.FunnelOff && in.Mode != core.FunnelOff ||
			fi.st.Funnel.Mode == core.FunnelShares && in.Mode == core.FunnelApp
		if widens && in.Confirm != "public" {
			writeErr(w, core.Invalid("confirm", `type-confirmation required: send confirm="public"`))
			return
		}
		fi.st.Funnel.Mode = in.Mode
		fi.st.Funnel.State, fi.st.Funnel.URL = core.IngressStateActive, "https://box.tail1234.ts.net/"
		if in.Mode == core.FunnelOff {
			fi.st.Funnel.State, fi.st.Funnel.URL = core.IngressStateOff, ""
		}
		if in.Port != 0 {
			fi.st.Funnel.Port = in.Port
		}
		now := time.Now().UTC()
		fi.st.Funnel.AppliedAt = &now
		writeJSON(w, 200, fi.st)
	})
	f.handle("PUT", "/api/v1/admin/network/serve", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.ServeInput](r)
		fi.mu.Lock()
		defer fi.mu.Unlock()
		if in.Enabled && in.Port == 443 && fi.st.Funnel.State != core.IngressStateOff && fi.st.Funnel.Port == 443 {
			writeErr(w, core.Invalid("port", "Funnel uses this port"))
			return
		}
		fi.st.Serve.Mode, fi.st.Serve.State = core.FunnelOff, core.IngressStateOff
		if in.Enabled {
			fi.st.Serve.Mode, fi.st.Serve.State, fi.st.Serve.URL = core.FunnelApp, core.IngressStateActive, "https://box.tail1234.ts.net/"
		}
		writeJSON(w, 200, fi.st)
	})
	f.handle("POST", "/api/v1/admin/network/tailscale/reapply", func(w http.ResponseWriter, r *http.Request) {
		fi.mu.Lock()
		defer fi.mu.Unlock()
		writeJSON(w, 200, fi.st)
	})
	f.handle("PUT", "/api/v1/admin/network/policy", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.PolicyInput](r)
		fi.mu.Lock()
		defer fi.mu.Unlock()
		fi.policy = append(fi.policy, in)
		fi.ov.Policy = core.AccessPolicy{Mode: in.Mode, Allow: in.Allow, Deny: in.Deny}
		writeJSON(w, 200, core.PolicyResult{Policy: fi.ov.Policy})
	})
	return fi
}

func TestFunnelEnablePrompts(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	body := func() core.FunnelInput {
		var in core.FunnelInput
		_ = json.Unmarshal(f.body("PUT /api/v1/admin/network/funnel"), &in)
		return in
	}
	// off → shares asks; no terminal and no -y is exit 1 and nothing is sent.
	res := f.run(t, "", "network", "funnel", "enable")
	if res.code != ExitFailure || f.requested("PUT /api/v1/admin/network/funnel") != 0 {
		t.Fatalf("no -y: %+v", res)
	}
	res = f.run(t, "n\n", "network", "funnel", "enable")
	if res.code != ExitFailure || !strings.Contains(res.stderr,
		"Share links and file requests will be reachable from the whole internet at https://box.tail1234.ts.net/s/…. Continue?") ||
		f.requested("PUT /api/v1/admin/network/funnel") != 0 {
		t.Fatalf("declined: %+v", res)
	}
	res = f.run(t, "y\n", "network", "funnel", "enable")
	if in := body(); res.code != 0 || in.Mode != core.FunnelShares || in.Confirm != "public" || in.AllowAdmin != nil || in.Require2FA != nil {
		t.Fatalf("off → shares: %+v %+v", res, in)
	}
	if !strings.Contains(res.stdout, "Funnel is on (share links): https://box.tail1234.ts.net/") ||
		!strings.Contains(res.stderr, "It can take up to 10 minutes") {
		t.Errorf("success output: %+v", res)
	}
	// A port change does not widen anything: no question.
	res = f.run(t, "", "network", "funnel", "enable", "--port", "8443")
	if in := body(); res.code != 0 || in.Mode != core.FunnelShares || in.Port != 8443 || in.Confirm != "" {
		t.Fatalf("port change: %+v %+v", res, in)
	}
	// shares → app asks about the sign-in page; -y answers.
	res = f.run(t, "", "-y", "network", "funnel", "enable", "--mode", "app")
	if in := body(); res.code != 0 || in.Mode != core.FunnelApp || in.Confirm != "public" {
		t.Fatalf("shares → app: %+v %+v", res, in)
	}
	res = f.run(t, "n\n", "network", "funnel", "enable", "--allow-admin")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "Admin pages will be reachable over Funnel. Continue?") {
		t.Errorf("--allow-admin asks: %+v", res)
	}
	res = f.run(t, "y\ny\n", "network", "funnel", "enable", "--allow-admin", "--no-require-2fa")
	in := body()
	if res.code != 0 || in.AllowAdmin == nil || !*in.AllowAdmin || in.Require2FA == nil || *in.Require2FA || in.Confirm != "public" ||
		!strings.Contains(res.stderr, "anyone who guesses a password can sign in over Funnel") ||
		!strings.Contains(res.stderr, "admin pages are reachable from the internet") {
		t.Fatalf("weakening: %+v %+v", res, in)
	}
	// Offline (the server is stopped): saved, published at the start.
	fi.put = func(core.FunnelInput) error { fi.st.Funnel.State = core.IngressStateStopped; return nil }
	f.handle("PUT", "/api/v1/admin/network/funnel", func(w http.ResponseWriter, r *http.Request) {
		fi.mu.Lock()
		defer fi.mu.Unlock()
		st := fi.st
		st.Funnel.State = core.IngressStateStopped
		writeJSON(w, 200, st)
	})
	if res := f.run(t, "", "network", "funnel", "enable"); res.code != 0 ||
		!strings.Contains(res.stdout, "Saved. FileParcel publishes it on Tailscale when the server starts.") {
		t.Errorf("stopped: %+v", res)
	}
	// JSON: the status object.
	res = f.run(t, "", "--json", "network", "funnel", "disable")
	var st core.IngressStatus
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &st) != nil || st.Funnel.Kind != core.IngressFunnel {
		t.Errorf("disable --json: %+v", res)
	}
}

func TestFunnelModeFlags(t *testing.T) {
	f := newFakeAPI(t)
	addIngressRoutes(f)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--mode", "shares", "--allow-admin"}, "--allow-admin only applies to --mode app"},
		{[]string{"--mode", "shares", "--no-require-2fa"}, "--no-require-2fa only applies to --mode app"},
		{[]string{"--allow-admin"}, "--allow-admin only applies to --mode app"}, // Funnel is off: shares
		{[]string{"--mode", "off"}, "--mode must be shares or app"},
		{[]string{"--port", "8080"}, "--port must be 443, 8443 or 10000"},
		{[]string{"--allow-admin", "--no-allow-admin", "--mode", "app"}, "use only one of"},
	} {
		res := f.run(t, "", append([]string{"-y", "network", "funnel", "enable"}, tc.args...)...)
		if res.code != ExitUsage || !strings.Contains(res.stderr, tc.want) || f.requested("PUT /api/v1/admin/network/funnel") != 0 {
			t.Errorf("%v: %+v", tc.args, res)
		}
	}
	// Flags not given are not sent.
	if res := f.run(t, "", "-y", "network", "funnel", "enable", "--mode", "app"); res.code != 0 ||
		strings.Contains(string(f.body("PUT /api/v1/admin/network/funnel")), "require_2fa") ||
		strings.Contains(string(f.body("PUT /api/v1/admin/network/funnel")), "allow_admin") {
		t.Errorf("unset flags: %+v %s", res, f.body("PUT /api/v1/admin/network/funnel"))
	}
}

func TestFunnel412PrintsChecks(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	fi.st.Funnel.Checks = []core.IngressCheck{
		{ID: "tailscale.https", Label: "HTTPS certificates", Status: "ok"},
		{ID: "tailscale.funnel_attr", Label: "Funnel permission", Status: "fail", Message: "Funnel is not allowed for this device",
			Hint: "add the funnel node attribute", FixURL: "https://login.tailscale.com/admin/acls"},
	}
	fi.put = func(core.FunnelInput) error {
		return &core.Error{Code: core.ErrPrecondition.Code, Status: 412, Field: "tailscale.funnel_attr",
			Message: "Funnel is not allowed for this device: add the funnel node attribute"}
	}
	res := f.run(t, "", "-y", "network", "funnel", "enable")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "Checks\n"+
		"✓ tailscale.https        HTTPS certificates\n"+
		"✗ tailscale.funnel_attr  Funnel is not allowed for this device\n"+
		"                         → add the funnel node attribute https://login.tailscale.com/admin/acls\n") ||
		!strings.Contains(res.stderr, "fileparcel: tailscale.funnel_attr: Funnel is not allowed") {
		t.Fatalf("412: %+v", res)
	}
	// A port held by a foreign entry.
	fi.put = func(core.FunnelInput) error {
		return &core.Error{Code: core.ErrConflict.Code, Status: 409, Field: "port", Message: "port 443 is used by localhost:3000"}
	}
	if res := f.run(t, "", "-y", "network", "funnel", "enable"); res.code != ExitFailure || !strings.Contains(res.stderr, `"tailscale serve status"`) {
		t.Errorf("409: %+v", res)
	}
	// A server from before Funnel.
	g := newFakeAPI(t)
	if res := g.run(t, "", "network", "funnel", "status"); res.code != ExitFailure ||
		!strings.Contains(res.stderr, "this server has no Tailscale Funnel or Serve support (upgrade it)") {
		t.Errorf("old server: %+v", res)
	}
}

func TestFunnelStatus(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	fi.st.Funnel = golden[core.IngressStatus](t, "ingress_status.json").Funnel
	fi.st.Funnel.Checks = append(fi.st.Funnel.Checks, core.IngressCheck{ID: "reachable", Label: "Reachable over the tailnet",
		Status: "ok", Message: "Tailscale reached FileParcel"})
	res := f.run(t, "", "network", "funnel")
	for _, want := range []string{"State:               on (share links): https://box.tail1234.ts.net/\n", "Mode:                share links\n",
		"Port:                443\n", "Backend:             unix:/srv/fileparcel/run/ts-funnel.sock\n",
		"Reachable:           ✓ Tailscale reached FileParcel\n", "Tailscale device:    box.tail1234.ts.net (tailscale)\n",
		"! tailscale.funnel_attr  the tailnet policy does not grant funnel\n" +
			"                         → add the funnel node attribute https://login.tailscale.com/admin/acls\n",
		"Tailscale forwards box.tail1234.ts.net:8443 to FileParcel directly", "tailscale serve --yes --https=8443 off"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("funnel status lacks %q:\n%s", want, res.stdout)
		}
	}
	res = f.run(t, "", "--json", "network", "funnel", "status", "--refresh")
	var st core.IngressStatus
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &st) != nil || st.Funnel.State != core.IngressStateActive ||
		!strings.Contains(f.query("GET /api/v1/admin/network/tailscale"), "refresh=1") {
		t.Errorf("status --refresh --json: %+v", res)
	}
	// Unavailable: why; still exit 0. What else works is shown on the
	// Funnel page while Funnel is off (as in the web UI), worded for the
	// reason, and never on the Serve page.
	fi.st.Available, fi.st.Reason = false, "this tailnet uses Headscale, which has no Funnel"
	res = f.run(t, "", "network", "funnel", "status")
	if res.code != 0 || !strings.Contains(res.stdout, "Unavailable:") || !strings.Contains(res.stdout, "Headscale") ||
		strings.Contains(res.stdout, "server.trusted_proxies") {
		t.Errorf("unavailable while on: %+v", res)
	}
	fi.st.Funnel.Mode, fi.st.Funnel.State = core.FunnelOff, core.IngressStateOff
	fi.st.Tailscale = &core.TailscaleInfo{Running: true, Installed: true, Kind: core.IfHeadscale, DNSName: "box.hs.example"}
	res = f.run(t, "", "network", "funnel", "status")
	if res.code != 0 || !strings.Contains(res.stdout, "Instead: sign this machine in to Tailscale's own control server (Headscale has\nno Funnel)") ||
		!strings.Contains(res.stdout, "server.trusted_proxies") {
		t.Errorf("Headscale: %+v", res)
	}
	fi.st.Tailscale = &core.TailscaleInfo{Error: "Tailscale is not installed"}
	fi.st.Reason = "Tailscale is not installed. Install Tailscale and sign in."
	res = f.run(t, "", "network", "funnel", "status")
	if res.code != 0 || strings.Contains(res.stdout, "Headscale has") ||
		!strings.Contains(res.stdout, "Without Tailscale Funnel: use a reverse proxy with a public certificate") {
		t.Errorf("not installed: %+v", res)
	}
	if res := f.run(t, "", "network", "tailscale-serve", "status"); res.code != 0 || strings.Contains(res.stdout, "trusted_proxies") {
		t.Errorf("serve status shows the Funnel alternatives: %+v", res)
	}
	if res := f.run(t, "", "network", "funnel", "reapply"); res.code != 0 || f.requested("POST /api/v1/admin/network/tailscale/reapply") != 1 {
		t.Errorf("reapply: %+v", res)
	}
}

func TestTailscaleServeNotServe(t *testing.T) {
	res := runArgs(t, "", "network", "serve")
	if res.code != ExitUsage || !strings.Contains(res.stderr, `unknown command "serve" for "fileparcel network"`) ||
		!strings.Contains(res.stderr, "\ttailscale-serve\n") {
		t.Fatalf("network serve: %+v", res)
	}
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	res = f.run(t, "", "network", "ts-serve", "enable")
	var in core.ServeInput
	if _ = json.Unmarshal(f.body("PUT /api/v1/admin/network/serve"), &in); res.code != 0 || !in.Enabled || in.Port != 0 ||
		!strings.Contains(res.stdout, "Tailscale Serve is on: https://box.tail1234.ts.net/") {
		t.Fatalf("serve enable: %+v %+v", res, in)
	}
	if res := f.run(t, "", "network", "tailscale-serve", "enable", "--port", "70000"); res.code != ExitUsage {
		t.Errorf("--port 70000: %+v", res)
	}
	// Funnel on 443: Serve cannot take it.
	fi.st.Funnel.State, fi.st.Funnel.Port = core.IngressStateActive, 443
	res = f.run(t, "", "network", "tailscale-serve", "enable", "--port", "443")
	if res.code == 0 || !strings.Contains(res.stderr, `Funnel uses port 443: run "fileparcel network funnel enable --port 10000" first, or pick --port`) {
		t.Errorf("port clash: %+v", res)
	}
	if res := f.run(t, "", "network", "tailscale-serve", "disable"); res.code != 0 || !strings.Contains(res.stdout, "Tailscale Serve is off") {
		t.Errorf("serve disable: %+v", res)
	}
	if res := f.run(t, "", "network", "tailscale-serve"); res.code != 0 || !strings.Contains(res.stdout, "State:") || strings.Contains(res.stdout, "Mode:") {
		t.Errorf("serve status: %+v", res)
	}
}

func TestVPNListAllowRemove(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	res := f.run(t, "", "network", "vpn")
	if res.code != 0 || !regexp.MustCompile(`Tailscale\s+tailscale0\s+100\.64\.0\.0/10, fd7a:115c:a1e0::/48\s+mesh\s+partly\s+warning: shared`).MatchString(res.stdout) ||
		!strings.Contains(res.stdout, "Mullvad VPN") {
		t.Fatalf("vpn list:\n%s", res.stdout)
	}
	res = f.run(t, "", "--json", "network", "vpn", "list")
	var vpns []core.VPNInfo
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &vpns) != nil || len(vpns) != 4 {
		t.Fatalf("vpn list --json: %+v", res)
	}
	res = f.run(t, "", "network", "vpn", "allow", "tailscale")
	if res.code != 0 || len(fi.policy) != 1 || strings.Join(fi.policy[0].Allow, ",") != "192.168.1.0/24,100.64.0.0/10,fd7a:115c:a1e0::/48" ||
		!strings.Contains(res.stderr, "shared with NetBird") {
		t.Fatalf("vpn allow tailscale: %+v %+v", res, fi.policy)
	}
	// Again: nothing to add, nothing sent.
	if res := f.run(t, "", "network", "vpn", "allow", "tailscale0"); res.code != 0 || len(fi.policy) != 1 {
		t.Errorf("allow again: %+v", res)
	}
	res = f.run(t, "", "network", "vpn", "rm", "Tailscale", "--force")
	if res.code != 0 || len(fi.policy) != 2 || strings.Join(fi.policy[1].Allow, ",") != "192.168.1.0/24" || !fi.policy[1].Force {
		t.Fatalf("vpn remove: %+v %+v", res, fi.policy)
	}
	if res := f.run(t, "", "network", "vpn", "allow", "nope"); res.code != ExitUsage || !strings.Contains(res.stderr, "known: tailscale, wg0-mullvad") {
		t.Errorf("unknown VPN: %+v", res)
	}
}

func TestVPNAllowRefusesEgress(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	res := f.run(t, "", "network", "vpn", "allow", "wg0-mullvad")
	if res.code != ExitUsage || !strings.Contains(res.stderr,
		"devices cannot reach this server through Mullvad VPN (it only carries this machine's outgoing traffic)") ||
		!strings.Contains(res.stderr, "if that is wrong: fileparcel network vpn role wg0-mullvad mesh") || len(fi.policy) != 0 {
		t.Fatalf("egress: %+v", res)
	}
	// Headscale with its own prefixes: the note says what to do.
	res = f.run(t, "", "network", "vpn", "allow", "headscale")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "custom Headscale prefixes") {
		t.Errorf("no ranges: %+v", res)
	}
}

func TestVPNAllowOverlayAsks(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	res := f.run(t, "n\n", "network", "vpn", "allow", "yggdrasil")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "Anyone on Yggdrasil could then connect to this server. Continue?") || len(fi.policy) != 0 {
		t.Fatalf("declined: %+v", res)
	}
	// -y answers the question; --force stays the lockout override only.
	res = f.run(t, "", "-y", "network", "vpn", "allow", "ygg0")
	if res.code != 0 || len(fi.policy) != 1 || fi.policy[0].Force || !strings.Contains(strings.Join(fi.policy[0].Allow, ","), "200::/7") {
		t.Fatalf("-y: %+v %+v", res, fi.policy)
	}
}

func TestVPNRole(t *testing.T) {
	f := newFakeAPI(t)
	addIngressRoutes(f)
	store := addSettingsRoutes(f, core.SettingView{Key: "network.iface_roles", Section: "network", Type: "strings",
		Value: json.RawMessage(`["wg0=egress","eth1=local"]`), Default: json.RawMessage(`[]`)})
	res := f.run(t, "", "network", "vpn", "role", "wg0", "mesh")
	if res.code != 0 || stored(store, "network.iface_roles") != `["eth1=local","wg0=mesh"]` || !strings.Contains(res.stdout, "wg0 is mesh now") ||
		!strings.Contains(res.stderr, `there is no interface "wg0" on this machine now`) {
		t.Fatalf("role wg0 mesh: %+v %s", res, stored(store, "network.iface_roles"))
	}
	if res := f.run(t, "", "network", "vpn", "role", "wg0", "auto"); res.code != 0 || stored(store, "network.iface_roles") != `["eth1=local"]` {
		t.Fatalf("role wg0 auto: %+v %s", res, stored(store, "network.iface_roles"))
	}
	for _, args := range [][]string{{"wg0", "friendly"}, {"a/b", "mesh"}, {"x=y", "mesh"}} {
		if res := f.run(t, "", append([]string{"network", "vpn", "role"}, args...)...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
}

func TestNetworkRemoteAccessAndRoles(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	fi.ov.Exposures = []core.Exposure{golden[core.Exposure](t, "exposure.json")}
	fi.ov.Interfaces = []core.NetInterface{golden[core.NetInterface](t, "net_interface.json"),
		{Name: "wg1", Label: "WireGuard", Up: true, Role: core.VPNRoleMesh, RoleSource: core.VPNRoleSourceOverride}}
	res := f.run(t, "", "network")
	for _, want := range []string{"Remote access\n", "Funnel: off (fileparcel network funnel enable)\n", "Serve:  off\n", "Mullvad VPN",
		"Needs attention\n", fi.ov.Exposures[0].Message} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("network lacks %q:\n%s", want, res.stdout)
		}
	}
	res = f.run(t, "", "network", "interfaces")
	if res.code != 0 || !regexp.MustCompile(`wg0-mullvad\s+Mullvad VPN\s+egress\s+yes`).MatchString(res.stdout) ||
		!strings.Contains(res.stdout, "mesh (override)") {
		t.Errorf("interfaces:\n%s", res.stdout)
	}
	// Servers from before VPN detection: no block.
	g := newFakeAPI(t)
	g.handle("GET", "/api/v1/admin/network", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"interfaces": []any{}, "urls": []any{}, "policy": core.AccessPolicy{Mode: "private"}})
	})
	if res := g.run(t, "", "network"); res.code != 0 || strings.Contains(res.stdout, "Remote access") {
		t.Errorf("old server:\n%s", res.stdout)
	}
}

func TestStatusFunnelLine(t *testing.T) {
	f := newFakeAPI(t)
	fi := addIngressRoutes(f)
	fi.st.Funnel = golden[core.IngressStatus](t, "ingress_status.json").Funnel
	f.handle("GET", "/api/v1/admin/system", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"version": "4.0.0", "mode": "network"})
	})
	res := f.run(t, "", "status")
	if res.code != 0 || !strings.Contains(res.stdout, "Funnel:") || !strings.Contains(res.stdout, "on (share links): https://box.tail1234.ts.net/") ||
		strings.Contains(res.stdout, "Tailscale Serve:") {
		t.Fatalf("status:\n%s%s", res.stdout, res.stderr)
	}
	res = f.run(t, "", "--json", "status")
	var rep struct{ Ingress *core.IngressStatus }
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &rep) != nil || rep.Ingress == nil {
		t.Errorf("status --json: %+v", res)
	}
	// Funnel off: no line; a server without the route: no line either.
	fi.st.Funnel.State = core.IngressStateOff
	if res := f.run(t, "", "status"); strings.Contains(res.stdout, "Funnel:") {
		t.Errorf("status with Funnel off:\n%s", res.stdout)
	}
}

func TestConfigSetManagedHint(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []core.SettingView{{Key: "funnel.mode", Section: "funnel", Type: "enum", Value: json.RawMessage(`"off"`),
			Default: json.RawMessage(`"off"`), Managed: "PUT /api/v1/admin/network/funnel"}})
	})
	msg := "Tailscale Funnel manages this setting: change it in Admin → Network & VPN or with \"fileparcel network funnel\""
	f.handle("PATCH", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, &core.Error{Code: core.ErrConflict.Code, Status: 409, Field: "funnel.mode", Message: msg})
	})
	// The server's message names the command: no hint repeats it.
	res := f.run(t, "", "config", "set", "funnel.mode", "shares", "--force")
	if res.code != ExitFailure || !strings.Contains(res.stderr, msg) || strings.Contains(res.stderr, "hint:") ||
		strings.Contains(res.stderr, "--force") {
		t.Fatalf("config set funnel.mode: %+v", res)
	}
	// A message without it: the command that owns the key.
	msg = "managed by the Network page"
	if res := f.run(t, "", "config", "set", "funnel.mode", "shares"); res.code != ExitFailure ||
		!strings.Contains(res.stderr, `hint: use "fileparcel network funnel"`) || strings.Contains(res.stderr, "tailscale-serve") {
		t.Errorf("config set funnel.mode, plain message: %+v", res)
	}
	if hint := managedHint("funnel.serve_port", "managed"); hint != `use "fileparcel network tailscale-serve"` {
		t.Errorf("funnel.serve_port hint: %q", hint)
	}
	if res := f.run(t, "", "config", "list", "--all"); !regexp.MustCompile(`funnel\.mode\s+"?off"?.*managed`).MatchString(res.stdout) {
		t.Errorf("config list --all:\n%s", res.stdout)
	}
}

func TestDoctorFunnelSeam(t *testing.T) {
	lcIsolateHost(t)
	h := lcBareHome(t)
	// No Funnel rows for a home without Funnel or Serve (the wired
	// tsingress.OfflineFindings; tailscaled is never reached in tests).
	rep, _ := lcDoctorJSON(t, h)
	if _, ok := lcStatuses(rep)["network.funnel"]; ok {
		t.Fatal("a Funnel row for a home without Funnel or Serve")
	}
	var gotHome string
	wired := offlineIngressFindings
	t.Cleanup(func() { offlineIngressFindings = wired })
	offlineIngressFindings = func(_ context.Context, hh *home.Home) []ingressFinding {
		gotHome = hh.Dir()
		return []ingressFinding{{ID: "network.funnel", Status: lcInfo, Message: "Funnel (share links) is published when the server starts"},
			{ID: "network.funnel_bypass", Status: lcFail, Message: "tailscale serve forwards to FileParcel's main port", Hint: "tailscale serve --yes --https=443 off"}}
	}
	rep, code := lcDoctorJSON(t, h)
	st := lcStatuses(rep)
	if gotHome != h.Dir() || st["network.funnel"] != lcInfo || st["network.funnel_bypass"] != lcFail || code != ExitFailure {
		t.Fatalf("seam rows: %v (home %q, exit %d)", st, gotHome, code)
	}
}
