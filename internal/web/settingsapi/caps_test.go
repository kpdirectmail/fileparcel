package settingsapi

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func TestSettingCap(t *testing.T) {
	for _, c := range []struct {
		key, section string
		want         core.Capability
		ok           bool
	}{
		{"ui.instance_name", "general", core.CapSettingsManage, true},
		{"maintenance.enabled", "general", core.CapSystemManage, true},
		{"maintenance.message", "general", core.CapSystemManage, true},
		{"storage.trash_days", "storage", core.CapSettingsManage, true},
		{"sharing.links_enabled", "sharing", core.CapSettingsManage, true},
		{"network.access_mode", "network", core.CapNetworkManage, true},
		{"mdns.mode", "mdns", core.CapNetworkManage, true},
		{"funnel.mode", "funnel", core.CapNetworkManage, true},
		{"tls.hsts", "tls", core.CapCertsManage, true},
		{"acme.enabled", "acme", core.CapCertsManage, true},
		{"tailscale.cert_enabled", "tailscale", core.CapCertsManage, true},
		{"mtls.mode", "mtls", core.CapCertsManage, true},
		{"log.level", "server", core.CapSystemManage, true},
		{"runtime.gomemlimit_mb", "server", core.CapSystemManage, true},
		{"server.public_url", "server", "", false},
		{"server.trusted_proxies", "server", "", false},
		{"auth.require_2fa", "auth", "", false},
		{"auth.admin_can_access_files", "auth", "", false},
		{"ratelimit.login_per_min", "ratelimit", "", false},
		{"audit.retention_days", "audit", "", false},
		{"smtp.host", "email", "", false},
		{"backup.copy_to", "backup", "", false},
		{"keys.web_unlock", "keys", "", false},
		{"future.key", "future", "", false}, // unknown sections fail closed
	} {
		got, ok := settingCap(c.key, c.section)
		if got != c.want || ok != c.ok {
			t.Errorf("%s (%s): %q %v", c.key, c.section, got, ok)
		}
	}
	for _, s := range adminOnlySections {
		if _, ok := sectionCaps[s]; ok {
			t.Errorf("section %s is both admin-only and delegable", s)
		}
	}
}

// delegate is a member-based custom role holding caps (session, elevated
// unless noted).
func (te *testEnv) delegate(caps ...core.Capability) *core.Principal {
	p := te.principal(core.RoleMember, true)
	p.Username, p.RoleID, p.RoleName = "delegate", "rol_01k5z8r3m9d4q7w2x6c1v0b5na", "Delegates"
	p.SetCaps(core.MemberCaps.With(caps...).Closure())
	return p
}

// Delegates see and change only the settings of their permissions; the rest
// are refused with 403 naming the key, before anything is applied.
func TestSettingsPerPermission(t *testing.T) {
	te := newTestEnv(t)
	listed := func(p *core.Principal) []string {
		t.Helper()
		var list []core.SettingView
		if r := te.do(t, p, http.MethodGet, "/api/v1/admin/settings", nil, &list); r.status != http.StatusOK {
			t.Fatalf("list as %v: %d %s", p.RoleCaps(), r.status, r.body)
		}
		var keys []string
		for _, v := range list {
			keys = append(keys, v.Key)
		}
		return keys
	}
	all := listed(te.admin(false))
	for _, c := range []core.Capability{core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage, core.CapSystemManage} {
		p := te.delegate(c)
		keys := listed(p)
		if len(keys) >= len(all) {
			t.Errorf("%s: lists %d of %d", c, len(keys), len(all))
		}
		cat := te.catalog(t)
		for _, k := range all {
			v := cat[k]
			want, ok := settingCap(k, v.Section)
			if shown := slices.Contains(keys, k); shown != (ok && want == c) {
				t.Errorf("%s: %s (%s) shown %v", c, k, v.Section, shown)
			}
		}
	}
	// Without any of the four permissions the settings routes are closed.
	if r := te.do(t, te.delegate(core.CapAuditView), http.MethodGet, "/api/v1/admin/settings", nil, nil); r.status != http.StatusForbidden ||
		r.msg != "this needs the “General settings” permission" {
		t.Errorf("audit.view: %d %s", r.status, r.msg)
	}

	settingsDelegate := te.delegate(core.CapSettingsManage)
	for _, c := range []struct {
		p     *core.Principal
		body  map[string]any
		field string
		msg   string
	}{
		{settingsDelegate, map[string]any{keyTestCount: 4, "maintenance.enabled": true}, "maintenance.enabled",
			"changing maintenance.enabled needs the “Operate the server” permission"},
		{settingsDelegate, map[string]any{keyTestFlag: true}, keyTestFlag, "only administrators can change " + keyTestFlag},
		{settingsDelegate, map[string]any{"mdns.mode": "off"}, "mdns.mode", "changing mdns.mode needs the “Network & VPN” permission"},
		{settingsDelegate, map[string]any{"log.level": "debug"}, "log.level",
			"changing log.level needs the “Operate the server” permission"},
		{te.delegate(core.CapSystemManage), map[string]any{"server.public_url": "https://files.example.org"}, "server.public_url",
			"only administrators can change server.public_url"},
		{te.delegate(core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage, core.CapSystemManage),
			map[string]any{"smtp.host": "mail.example.org"}, "smtp.host", "only administrators can change smtp.host"},
	} {
		r := te.do(t, c.p, http.MethodPatch, "/api/v1/admin/settings", c.body, nil)
		if r.status != http.StatusForbidden || r.code != "forbidden" || r.field != c.field || r.msg != c.msg {
			t.Errorf("PATCH %v: %d %s %s %q", c.body, r.status, r.code, r.field, r.msg)
		}
		r = te.do(t, c.p, http.MethodDelete, "/api/v1/admin/settings/"+c.field, nil, nil)
		if r.status != http.StatusForbidden || r.field != c.field || r.msg != c.msg {
			t.Errorf("DELETE %s: %d %s %q", c.field, r.status, r.field, r.msg)
		}
	}
	if v := te.catalog(t)[keyTestCount].Value; strings.TrimSpace(string(v)) != "3" {
		t.Errorf("a refused PATCH applied %s = %s", keyTestCount, v)
	}

	// Allowed keys go through, with the usual step-up for sensitive sections.
	if r := te.do(t, settingsDelegate, http.MethodPatch, "/api/v1/admin/settings", map[string]any{keyTestCount: 4}, nil); r.status != http.StatusOK {
		t.Errorf("settings.manage PATCH %s: %d %s", keyTestCount, r.status, r.body)
	}
	if r := te.do(t, settingsDelegate, http.MethodDelete, "/api/v1/admin/settings/"+keyTestCount, nil, nil); r.status != http.StatusOK {
		t.Errorf("settings.manage DELETE %s: %d %s", keyTestCount, r.status, r.body)
	}
	op := te.delegate(core.CapSystemManage)
	if r := te.do(t, op, http.MethodPatch, "/api/v1/admin/settings", map[string]any{"maintenance.message": "soon"}, nil); r.status != http.StatusOK {
		t.Errorf("system.manage PATCH: %d %s", r.status, r.body)
	}
	netops := te.delegate(core.CapNetworkManage)
	netops.ElevatedUntil = te.now.Add(-time.Minute)
	if r := te.do(t, netops, http.MethodPatch, "/api/v1/admin/settings", map[string]any{"mdns.mode": "off"}, nil); r.status != http.StatusForbidden ||
		r.code != "elevation_required" {
		t.Errorf("network.manage PATCH mdns without step-up: %d %s", r.status, r.code)
	}
	netops.ElevatedUntil = te.now.Add(time.Minute)
	if r := te.do(t, netops, http.MethodPatch, "/api/v1/admin/settings", map[string]any{"mdns.mode": "off"}, nil); r.status != http.StatusOK {
		t.Errorf("network.manage PATCH mdns: %d %s", r.status, r.body)
	}
	for _, path := range []string{"/api/v1/admin/network", "/api/v1/admin/mdns"} {
		if r := te.do(t, netops, http.MethodGet, path, nil, nil); r.status != http.StatusOK {
			t.Errorf("network.manage GET %s: %d", path, r.status)
		}
		if r := te.do(t, settingsDelegate, http.MethodGet, path, nil, nil); r.status != http.StatusForbidden {
			t.Errorf("settings.manage GET %s: %d", path, r.status)
		}
	}
	// The e-mail test sends with the SMTP settings: administrators only.
	if r := te.do(t, te.delegate(core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage, core.CapSystemManage),
		http.MethodPost, "/api/v1/admin/settings/email/test", map[string]string{"to": "a@example.org"}, nil); r.status != http.StatusForbidden {
		t.Errorf("delegate e-mail test: %d", r.status)
	}
	// Over an API token the permissions need the admin scope.
	tok := te.delegate(core.CapSettingsManage)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	if r := te.do(t, tok, http.MethodGet, "/api/v1/admin/settings", nil, nil); r.status != http.StatusForbidden || r.msg != `token lacks scope "admin"` {
		t.Errorf("delegate token without admin scope: %d %q", r.status, r.msg)
	}
	tok.Scopes = []string{core.ScopeAdmin}
	if keys := listed(tok); len(keys) == 0 || slices.Contains(keys, keyTestFlag) {
		t.Errorf("delegate admin-scope token lists %v", keys)
	}
	// Built-in administrators need the admin scope for every key, as before.
	adminTok := te.admin(true)
	adminTok.Via, adminTok.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	if r := te.do(t, adminTok, http.MethodGet, "/api/v1/admin/settings", nil, nil); r.status != http.StatusForbidden || r.code != "forbidden" {
		t.Errorf("admin token without admin scope: %d %s", r.status, r.code)
	}
}
