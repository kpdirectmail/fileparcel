package opsapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// fakeIngressStatus is a core.Ingress that only reports a status.
type fakeIngressStatus struct {
	core.Ingress
	st *core.IngressStatus
}

func (f *fakeIngressStatus) Status(context.Context, bool) (*core.IngressStatus, error) {
	return f.st, nil
}

// ingressStatus builds a status with Funnel and Serve off.
func ingressStatus() *core.IngressStatus {
	off := func(kind string, port int) core.IngressEntry {
		return core.IngressEntry{Kind: kind, Mode: core.FunnelOff, Port: port, State: core.IngressStateOff, Checks: []core.IngressCheck{}}
	}
	return &core.IngressStatus{Available: true, Transport: "localapi", Funnel: off(core.IngressFunnel, 443),
		Serve: off(core.IngressServe, 10000), FunnelPorts: []int{443, 8443, 10000}, Require2FA: true, Foreign: []core.ForeignServe{}}
}

func active(e *core.IngressEntry, mode string) {
	e.Mode, e.State = mode, core.IngressStateActive
	e.URL = "https://node.tail.ts.net/"
	if e.Port != 443 {
		e.URL = "https://node.tail.ts.net:10000/"
	}
}

// ingressRows runs the Funnel/Serve rows of the doctor at now.
func ingressRows(te *testEnv, st *core.IngressStatus, now time.Time) map[string][]DoctorCheck {
	te.t.Helper()
	te.d.Ingress = &fakeIngressStatus{st: st}
	out := map[string][]DoctorCheck{}
	for _, c := range checkIngress(context.Background(), te.d, now) {
		if c.Name == "" || c.Message == "" || c.Link == "" {
			te.t.Errorf("row without name, message or link: %+v", c)
		}
		out[c.ID] = append(out[c.ID], c)
	}
	return out
}

// Proxy signals are process wide: the tests note them long ago and ask at
// that time, so they are stale for every other test.
var signalTime = time.Date(2019, 6, 1, 12, 0, 0, 0, time.UTC)

func TestDoctorIngressStates(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	now := te.now

	// Without the service, and with both kinds off: no row.
	if rows := checkIngress(context.Background(), te.d, now); len(rows) != 0 {
		t.Fatalf("no service: %+v", rows)
	}
	if rows := ingressRows(te, ingressStatus(), now); len(rows) != 0 {
		t.Fatalf("off: %+v", rows)
	}

	st := ingressStatus()
	active(&st.Funnel, core.FunnelShares)
	active(&st.Serve, core.FunnelApp)
	rows := ingressRows(te, st, now)
	if c := rows["network.funnel"]; len(c) != 1 || c[0].Status != CheckOK || c[0].Message != "Share links are public at https://node.tail.ts.net/" ||
		c[0].Link != "/admin/network#funnel" {
		t.Fatalf("funnel shares: %+v", c)
	}
	if c := rows["network.serve"]; len(c) != 1 || c[0].Status != CheckOK ||
		c[0].Message != "Tailnet devices reach FileParcel at https://node.tail.ts.net:10000/" || c[0].Link != "/admin/network#serve" {
		t.Fatalf("serve: %+v", c)
	}

	// The TCP backend is always worth a warning.
	st.Funnel.Checks = []core.IngressCheck{{ID: "backend.tcp", Status: "warn", Message: "FileParcel uses 127.0.0.1:18443.",
		Hint: "Allow FileParcel's user to run sudo tailscale, or keep the TCP connection."}}
	if c := ingressRows(te, st, now)["network.funnel"][0]; c.Status != CheckWarn || !strings.Contains(c.Hint, "127.0.0.1:18443") {
		t.Fatalf("tcp backend: %+v", c)
	}

	// The whole app over Funnel is a warning; without 2FA it says who can sign in.
	st.Funnel.Checks = []core.IngressCheck{}
	st.Funnel.Mode = core.FunnelApp
	c := ingressRows(te, st, now)["network.funnel"][0]
	if c.Status != CheckWarn || !strings.Contains(c.Message, "The whole app is public at https://node.tail.ts.net/") ||
		!strings.Contains(c.Message, "two-factor") {
		t.Fatalf("funnel app: %+v", c)
	}
	st.Require2FA = false
	if c := ingressRows(te, st, now)["network.funnel"][0]; !strings.Contains(c.Message, "accounts without two-factor authentication can sign in") ||
		c.Hint == "" {
		t.Fatalf("funnel app without 2fa: %+v", c)
	}
	st.Require2FA = true

	// Not running as wanted: stopped (info), drift/conflict/paused/error (warn), unavailable (warn with the hint).
	for _, tc := range []struct {
		state, status, hint string
		checks              []core.IngressCheck
	}{
		{core.IngressStateStopped, CheckInfo, "", nil},
		{core.IngressStateDrift, CheckWarn, "fileparcel network funnel reapply", nil},
		{core.IngressStateConflict, CheckWarn, "Remove it", []core.IngressCheck{{ID: "port.free", Status: "fail", Message: "x", Hint: "Remove it."}}},
		{core.IngressStatePaused, CheckWarn, "Turn them on again here", []core.IngressCheck{{ID: "node", Status: "fail", Message: "x", Hint: "Turn them on again here to publish from this device."}}},
		{core.IngressStateError, CheckWarn, "", nil},
		{core.IngressStateUnavailable, CheckWarn, "sudo tailscale up", []core.IngressCheck{{ID: "tailscale.running", Status: "fail", Message: "Tailscale is Stopped", Hint: "Start Tailscale: sudo tailscale up"}}},
	} {
		st := ingressStatus()
		st.Funnel.Mode, st.Funnel.State, st.Funnel.Message = core.FunnelShares, tc.state, "what happened"
		if tc.checks != nil {
			st.Funnel.Checks = tc.checks
		}
		c := ingressRows(te, st, now)["network.funnel"]
		if len(c) != 1 || c[0].Status != tc.status || !strings.Contains(c[0].Message, "what happened") || !strings.Contains(c[0].Hint, tc.hint) {
			t.Errorf("%s: %+v", tc.state, c)
		}
	}
	// A removal that failed is reported although the kind is off.
	st = ingressStatus()
	st.Serve.State, st.Serve.Message = core.IngressStateError, "run tailscale serve --yes --https=10000 --set-path=/ off"
	if c := ingressRows(te, st, now)["network.serve"]; len(c) != 1 || c[0].Status != CheckWarn || !strings.Contains(c[0].Message, "--https=10000") {
		t.Fatalf("removal failure: %+v", c)
	}

	// An expiring key while Funnel or Serve is wanted.
	st = ingressStatus()
	active(&st.Funnel, core.FunnelShares)
	st.Funnel.Checks = []core.IngressCheck{{ID: "tailscale.key_expiry", Status: "warn", Message: "The key of this device expires on 2026-10-01",
		Hint: "Disable key expiry for this machine in the admin console"}}
	if c := ingressRows(te, st, now)["tailscale.key_expiry"]; len(c) != 1 || c[0].Status != CheckWarn || !strings.Contains(c[0].Message, "2026-10-01") {
		t.Fatalf("key expiry: %+v", c)
	}
	st.Funnel.Mode, st.Funnel.State = core.FunnelOff, core.IngressStateOff
	if c := ingressRows(te, st, now)["tailscale.key_expiry"]; len(c) != 0 {
		t.Fatalf("key expiry while off: %+v", c)
	}
}

// With administration allowed over Funnel, the warning names the staff
// accounts (built-in administrators and custom roles with a server
// permission) that have no second factor.
func TestDoctorFunnelAdminsWithout2FA(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.users.users = []core.User{
		{ID: "usr_owner", Username: "owner", Role: core.RoleOwner, Status: "active"},
		{ID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Status: "active"},
		{ID: "usr_netops", Username: "netops", Role: core.RoleMember, Status: "active", Permissions: core.NewCapSet(core.CapNetworkManage)},
		{ID: "usr_member", Username: "member", Role: core.RoleMember, Status: "active", Permissions: core.MemberCaps},
		{ID: "usr_gone", Username: "gone", Role: core.RoleAdmin, Status: "active"},
	}
	te.auth.mfa["usr_owner"] = &core.MFAStatus{TOTPEnabled: true}
	te.auth.errs = map[string]error{"usr_gone": core.ErrNotFound}
	st := ingressStatus()
	active(&st.Funnel, core.FunnelApp)
	st.AllowAdmin = true
	c := ingressRows(te, st, te.now)["network.funnel"][0]
	if c.Status != CheckWarn || !strings.HasSuffix(c.Message, "administration is allowed over Funnel, and these administrators "+
		"have no two-factor authentication: admin, netops") || !strings.Contains(c.Hint, "Settings → Security") {
		t.Fatalf("staff without 2fa: %+v", c)
	}
	// Unreadable 2FA status: said so, nobody is vouched for.
	te.auth.errs["usr_admin"] = context.DeadlineExceeded
	if c := ingressRows(te, st, te.now)["network.funnel"][0]; !strings.Contains(c.Message, "could not be read") {
		t.Fatalf("unreadable: %+v", c)
	}
	delete(te.auth.errs, "usr_admin")
	te.auth.mfa["usr_admin"] = &core.MFAStatus{PasskeyCount: 1}
	te.auth.mfa["usr_netops"] = &core.MFAStatus{TOTPEnabled: true}
	if c := ingressRows(te, st, te.now)["network.funnel"][0]; !strings.HasSuffix(c.Message, "administration is allowed over Funnel") {
		t.Fatalf("everyone with 2fa: %+v", c)
	}
}

// Hand-made proxies: a foreign serve entry targeting FileParcel fails the
// doctor, as does a Funnel request on the main listener within 24 hours; an
// unconfigured local proxy warns.
func TestDoctorProxyRows(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	st := ingressStatus()
	st.Foreign = []core.ForeignServe{
		{HostPort: "node.tail.ts.net:8443", Mount: "/", Target: "http://127.0.0.1:8443", Foreground: true, Bypass: true},
		{HostPort: "node.tail.ts.net:10000", Mount: "/", Target: "http://127.0.0.1:3000"},
	}
	rows := ingressRows(te, st, signalTime)
	if c := rows["network.funnel_bypass"]; len(c) != 1 || c[0].Status != CheckFail || !strings.Contains(c[0].Message, "http://127.0.0.1:8443") ||
		!strings.Contains(c[0].Hint, "foreground") {
		t.Fatalf("bypass: %+v", rows)
	}
	httpx.ProxySignals.FunnelToMain.Note("box.tail.ts.net", signalTime.Add(-time.Hour))
	httpx.ProxySignals.LocalProxy.Note("files.example.org", signalTime.Add(-time.Hour))
	rows = ingressRows(te, ingressStatus(), signalTime)
	if c := rows["network.funnel_bypass"]; len(c) != 1 || c[0].Status != CheckFail || !strings.Contains(c[0].Hint, "--https=443 --set-path=") {
		t.Fatalf("funnel to main: %+v", rows)
	}
	if c := rows["network.proxy_unconfigured"]; len(c) != 1 || c[0].Status != CheckWarn || !strings.Contains(c[0].Message, "files.example.org") ||
		!strings.Contains(c[0].Hint, "server.trusted_proxies") {
		t.Fatalf("local proxy: %+v", rows)
	}
	if rows := ingressRows(te, ingressStatus(), signalTime.Add(25*time.Hour)); len(rows) != 0 {
		t.Fatalf("a day later: %+v", rows)
	}
}

// The rows are part of GET /admin/system/doctor (and count as warnings and
// failures there).
func TestDoctorReportsIngress(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	st := ingressStatus()
	active(&st.Funnel, core.FunnelApp)
	te.d.Ingress = &fakeIngressStatus{st: st}
	rep := te.doctor("")
	if c := rep.find("network.funnel"); c == nil || c.Status != CheckWarn {
		t.Fatalf("report %+v", rep.Checks)
	}
	if rep.Warnings == 0 {
		t.Fatal("the Funnel warning is not counted")
	}
}
