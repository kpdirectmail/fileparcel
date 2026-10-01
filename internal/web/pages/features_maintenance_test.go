package pages

import (
	"testing"

	"fileparcel/internal/web/mw"
)

// TestMaintenanceFeature: features.maintenance follows maintenance.enabled,
// in the boot of the sign-in page too (it tells visitors before they sign in).
func TestMaintenanceFeature(t *testing.T) {
	e := newEnv(t)
	if Features(e.d, nil)["maintenance"] {
		t.Fatal("maintenance on by default")
	}
	e.s.set(mw.KeyMaintenanceEnabled, true)
	if !Features(e.d, nil)["maintenance"] {
		t.Fatal("features.maintenance does not follow maintenance.enabled")
	}
	b := bootOf(t, e.do(t, "GET", "/login", nil, "").Body.String())
	if f, _ := b["features"].(map[string]any); f["maintenance"] != true {
		t.Fatalf("login boot features %v", b["features"])
	}
	if Features(nil, nil)["maintenance"] {
		t.Fatal("maintenance without deps")
	}
}
