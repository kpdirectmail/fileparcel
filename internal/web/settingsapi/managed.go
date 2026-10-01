package settingsapi

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"fileparcel/internal/core"
)

// Managed settings (Tailscale Funnel/Serve, DESIGN §10.6, §11.2): the
// funnel.* keys the Funnel and Serve routes store only after tailscaled
// accepted the change. Written through PATCH /admin/settings they would say
// Funnel is on while tailscaled publishes nothing (or the other way round),
// and would skip the typed confirmation and the owner/admin rule for
// weakening sign-in over the internet.

// Keys of the Funnel/Serve state and of the server ports (registered by
// tsingress and config); see ingressWarnings.
const (
	keyFunnelMode      = "funnel.mode"
	keyFunnelPort      = "funnel.port"
	keyFunnelServe     = "funnel.serve"
	keyFunnelServePort = "funnel.serve_port"
	keyHTTPSPort       = "server.https_port"
	keyHTTPPort        = "server.http_port"
)

// managedGuard refuses (409 conflict, field = the key) a PATCH or DELETE of
// a key that another route manages (core.SettingView.Managed), for every
// caller: the admin socket and the offline CLI use those routes too.
func managedGuard(v core.SettingView) error {
	if v.Managed == "" {
		return nil
	}
	what, cmd := "Tailscale Funnel", "fileparcel network funnel"
	if strings.HasSuffix(v.Managed, "/serve") {
		what, cmd = "Tailscale Serve", "fileparcel network tailscale-serve"
	}
	return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: v.Key,
		Message: fmt.Sprintf("%s manages this setting: change it in Admin → Network & VPN or with %q", what, cmd)}
}

// ingressWarnings warns when a PATCH moves FileParcel's own HTTPS or HTTP
// port onto the port of a wanted Funnel or Serve entry: Tailscale would take
// that port over on the tailnet address, so FileParcel removes its entry
// (tsingress, check port.fileparcel) and it stays off until it is turned on
// again with another port.
func (a *api) ingressWarnings(changes map[string]json.RawMessage) []string {
	if a.d == nil || a.d.Env == nil || a.d.Settings == nil {
		return nil
	}
	st := a.d.Settings
	var ports []int
	for _, k := range []string{keyHTTPSPort, keyHTTPPort} {
		raw, ok := changes[k]
		if !ok {
			continue
		}
		var p int
		if json.Unmarshal(raw, &p) == nil && p > 0 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil
	}
	var out []string
	if mode := st.String(keyFunnelMode); mode == core.FunnelShares || mode == core.FunnelApp {
		if p := int(st.Int(keyFunnelPort)); slices.Contains(ports, p) {
			out = append(out, fmt.Sprintf("Tailscale Funnel uses port %d: FileParcel removes its Funnel entry, because "+
				"Tailscale would take that port over on the tailnet address. Turn Funnel on again with another port "+
				"(Admin → Network & VPN).", p))
		}
	}
	if st.Bool(keyFunnelServe) {
		if p := int(st.Int(keyFunnelServePort)); slices.Contains(ports, p) {
			out = append(out, fmt.Sprintf("Tailscale Serve uses port %d: FileParcel removes its Serve entry, because "+
				"Tailscale would take that port over on the tailnet address. Turn Serve on again with another port "+
				"(Admin → Network & VPN).", p))
		}
	}
	return out
}
