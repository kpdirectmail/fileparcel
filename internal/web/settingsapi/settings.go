package settingsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// listSettings is GET /admin/settings[?section=]: the whole catalog (or one
// section) with current values and defaults; secrets are masked by the store.
func (a *api) listSettings(w http.ResponseWriter, r *http.Request) {
	st := a.settings(w, r)
	if st == nil {
		return
	}
	cat, err := st.Catalog(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	out := make([]core.SettingView, 0, len(cat))
	section := r.URL.Query().Get("section")
	p := mw.Principal(r)
	for _, v := range cat {
		if (section == "" || v.Section == section) && listable(p, v) {
			out = append(out, v)
		}
	}
	httpx.OK(w, out)
}

// patchSettings is PATCH /admin/settings {key: value, …}. Keys of sensitive
// sections need elevation; access-policy keys go through the lockout guard
// and passkey-related keys through the passkey guard (?force=1 overrides
// both). Validation, persistence, audit and the settings.changed event are
// the store's job (core.Settings.Set).
func (a *api) patchSettings(w http.ResponseWriter, r *http.Request) {
	st := a.settings(w, r)
	if st == nil {
		return
	}
	changes, err := httpx.Decode[map[string]json.RawMessage](r, maxSettingsBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if len(changes) == 0 {
		httpx.OK(w, core.SettingsResult{Applied: []string{}, RestartRequired: []string{}})
		return
	}
	cat, err := st.Catalog(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	views := byKey(cat)
	if err := a.checkKeys(r, views, keysOf(changes)); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := a.checkElevation(r, views, keysOf(changes)); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := a.policyGuard(r, changes); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := a.passkeyGuard(r, changes); err != nil {
		httpx.Error(w, r, err)
		return
	}
	res, err := st.Set(r.Context(), mw.Principal(r), changes)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if res.Applied == nil {
		res.Applied = []string{}
	}
	if res.RestartRequired == nil {
		res.RestartRequired = []string{}
	}
	res.Warnings = append(a.certWarnings(changes), a.extraWarnings(changes)...)
	httpx.OK(w, res)
}

// namesInCert are the list settings whose entries are expected to end up in
// the local certificate (their own descriptions say so).
var namesInCert = []string{"tls.extra_sans", "network.extra_hosts"}

// certWarnings reports names that were just accepted into tls.extra_sans or
// network.extra_hosts although the local CA may not sign them: the leaf drops
// them, nothing is reissued and no error is raised, yet the access URLs and
// the strict Host check keep advertising the name, so the first client to use
// it fails with a certificate name mismatch.
func (a *api) certWarnings(changes map[string]json.RawMessage) []string {
	var names []string
	for _, k := range namesInCert {
		raw, ok := changes[k]
		if !ok {
			continue
		}
		var l []string
		if json.Unmarshal(raw, &l) != nil {
			continue
		}
		names = append(names, l...)
	}
	if len(names) == 0 || a.d == nil || a.d.Certs == nil {
		return nil
	}
	c, ok := a.d.Certs.(interface{ UnsignableNames([]string) []string })
	if !ok {
		return nil
	}
	bad := c.UnsignableNames(names)
	if len(bad) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("the local certificate cannot cover %s: the local CA's name constraints do not "+
		"permit %s. Regenerate the CA (Admin → Certificates, or \"fileparcel ca regenerate\") to include %s — "+
		"every device that trusts the current CA has to trust the new one.",
		plural(len(bad), "this name", "these names"), strings.Join(bad, ", "),
		plural(len(bad), "it", "them"))}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// resetSetting is DELETE /admin/settings/{key}: restore the default (a
// secret is cleared) and answer the updated catalog entry.
func (a *api) resetSetting(w http.ResponseWriter, r *http.Request) {
	st := a.settings(w, r)
	if st == nil {
		return
	}
	key := chi.URLParam(r, "key")
	cat, err := st.Catalog(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	views := byKey(cat)
	v, ok := views[key]
	if !ok {
		httpx.Error(w, r, core.NotFoundf("unknown setting %q", key))
		return
	}
	if err := a.checkKeys(r, views, []string{key}); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := a.checkElevation(r, views, []string{key}); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if !v.Secret && len(v.Default) > 0 {
		def := map[string]json.RawMessage{key: v.Default}
		if err := a.policyGuard(r, def); err != nil {
			httpx.Error(w, r, err)
			return
		}
		if err := a.passkeyGuard(r, def); err != nil {
			httpx.Error(w, r, err)
			return
		}
	}
	if err := st.Reset(r.Context(), mw.Principal(r), key); err != nil {
		httpx.Error(w, r, err)
		return
	}
	cat, err = st.Catalog(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if nv, ok := byKey(cat)[key]; ok {
		v = nv
	}
	httpx.OK(w, v)
}

// checkElevation requires an open step-up window when one of keys belongs
// to a sensitive section. Unknown keys are left to the store (422).
func (a *api) checkElevation(r *http.Request, views map[string]core.SettingView, keys []string) error {
	for _, k := range keys {
		if v, ok := views[k]; ok && Sensitive(v.Section) && !a.elevated(r) {
			return core.ErrElevationRequired
		}
	}
	return nil
}

// policyGuard applies the lockout guard to changes of the access-policy
// settings: the resulting policy (current policy with changes applied) must
// still admit the requester unless ?force=1. Values that do not decode are
// left to the store's validation.
func (a *api) policyGuard(r *http.Request, changes map[string]json.RawMessage) error {
	field := ""
	for _, k := range []string{keyAccessMode, keyAllowCIDRs, keyDenyCIDRs} {
		if _, ok := changes[k]; ok && field == "" {
			field = k
		}
	}
	if field == "" || forced(r) || a.d == nil || a.d.Network == nil {
		return nil
	}
	p := a.d.Network.Policy()
	if raw, ok := changes[keyAccessMode]; ok {
		if json.Unmarshal(raw, &p.Mode) != nil {
			return nil
		}
	}
	for key, dst := range map[string]*[]string{keyAllowCIDRs: &p.Allow, keyDenyCIDRs: &p.Deny} {
		if raw, ok := changes[key]; ok {
			var l []string
			if json.Unmarshal(raw, &l) != nil {
				return nil
			}
			*dst = l
		}
	}
	if addr, denied := refusedAddr(a.d.Network, p, requesterAddrs(r)); denied {
		return lockoutError(field, addr, "force")
	}
	return nil
}

// passkeyGuard refuses changes that shut out the accounts whose only second
// factor is a passkey — their next sign-in stops at a password-only session
// with no usable method, recoverable only with "fileparcel user reset-2fa":
// turning auth.passkeys off, and moving the passkey domain (RP ID; see
// rpIDChange), because credentials are bound to the RP ID they were enrolled
// under. ?force=1 confirms, like the access-policy guard; the message leaves
// the how to each client (a dialog, --force).
func (a *api) passkeyGuard(r *http.Request, changes map[string]json.RawMessage) error {
	if forced(r) || a.d == nil || a.d.Auth == nil {
		return nil
	}
	field, effect := "", ""
	if raw, ok := changes[keyPasskeys]; ok {
		var on bool
		if json.Unmarshal(raw, &on) == nil && !on {
			field, effect = keyPasskeys, "could not sign in any more"
		}
	}
	if field == "" {
		k, from, to := a.rpIDChange(changes)
		if k == "" {
			return nil
		}
		field, effect = k, fmt.Sprintf("would lose their passkeys: the passkey domain changes from %s to %s", from, to)
	}
	c, ok := a.d.Auth.(interface {
		PasskeyOnlyAccounts(context.Context) (int, error)
	})
	if !ok {
		return nil
	}
	n, err := c.PasskeyOnlyAccounts(r.Context())
	if err != nil || n == 0 {
		return nil
	}
	return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: field,
		Message: fmt.Sprintf("%d account(s) have no second factor other than a passkey and %s; "+
			"ask them to add an authenticator app first, or confirm the change to make it anyway", n, effect)}
}

// rpIDChange reports whether changes move the passkey domain (the WebAuthn
// RP ID): the first key of auth.webauthn_rp_id, mdns.name and server.name in
// changes, with the domain before and after, or "" when it stays. It follows
// the fallback of auth's rpConfig — auth.webauthn_rp_id when set, else
// "<mdns.name, else server.name>.local" — on the configured names on both
// sides, so a collision suffix of the effective mDNS name
// ("fileparcel-2.local") does not count as a change. The RP ID in use
// (Auth.RPID, which may carry that suffix) is what passkeys are bound to:
// ending up on it is no move, and pinning auth.webauthn_rp_id to anything
// else is one. Values that do not decode are left to the store's validation.
func (a *api) rpIDChange(changes map[string]json.RawMessage) (field, from, to string) {
	next := map[string]string{}
	for _, k := range []string{keyRPID, keyMDNSName, keyServerName} {
		raw, ok := changes[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", "", ""
		}
		if field == "" {
			field = k
		}
		next[k] = s
	}
	if field == "" || a.d.Env == nil || a.d.Settings == nil {
		return "", "", ""
	}
	cur := func(k string) string { return a.d.Settings.String(k) }
	after := func(k string) string {
		if v, ok := next[k]; ok {
			return v
		}
		return cur(k)
	}
	from, to = a.configuredRPID(cur), a.configuredRPID(after)
	live := ""
	if a.d.Auth != nil {
		live = normRPID(a.d.Auth.RPID())
	}
	switch {
	case live != "" && to == live:
		return "", "", ""
	case live != "" && (from != to || normRPID(after(keyRPID)) != ""):
		return field, live, to
	case from != to:
		return field, from, to
	}
	return "", "", ""
}

// normRPID is an RP ID as auth compares it: lower case, no trailing dot.
func normRPID(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// configuredRPID is the RP ID the settings read through get configure
// (auth's rpConfig without the live mDNS name).
func (a *api) configuredRPID(get func(string) string) string {
	if id := normRPID(get(keyRPID)); id != "" {
		return id
	}
	name := get(keyMDNSName)
	if name == "" {
		name = get(keyServerName)
	}
	if name == "" && a.d.Env != nil && a.d.Config != nil {
		name = a.d.Config.Server.Name
	}
	if name == "" {
		name = "fileparcel"
	}
	return strings.ToLower(name) + ".local"
}

func byKey(cat []core.SettingView) map[string]core.SettingView {
	m := make(map[string]core.SettingView, len(cat))
	for _, v := range cat {
		m[v.Key] = v
	}
	return m
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// testEmail is POST /admin/settings/email/test (Adm): sends the notify
// "test" template to the given address with the SMTP settings that are
// stored right now, so an administrator can check them before relying on
// them. The notify service reports a bad address as 422 invalid and a
// delivery problem as 503 carrying the SMTP error.
func (a *api) testEmail(w http.ResponseWriter, r *http.Request) {
	n := a.notify(w, r)
	if n == nil {
		return
	}
	in, err := httpx.Decode[core.EmailTestInput](r, maxSettingsBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if strings.TrimSpace(in.To) == "" {
		httpx.Error(w, r, core.Invalid("to", "an e-mail address is required"))
		return
	}
	if err := n.Test(r.Context(), in.To); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}
