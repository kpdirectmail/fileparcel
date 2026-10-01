package pages

import "testing"

// TestZipBootHints pins the two hints of the upload dialog: the flag
// zip_legacy_encryption (features, also in GET /me) and the limit
// zip_password_min (boot only), on anonymous and signed-in pages alike, and
// that they follow the settings.
func TestZipBootHints(t *testing.T) {
	e := newEnv(t)
	check := func(legacy bool, min float64) {
		t.Helper()
		for _, page := range []struct{ path, cookie string }{{"/login", ""}, {"/files", "full"}} {
			b := bootOf(t, e.do(t, "GET", page.path, nil, page.cookie).Body.String())
			f, _ := b["features"].(map[string]any)
			if got, ok := f["zip_legacy_encryption"].(bool); !ok || got != legacy {
				t.Errorf("%s: features.zip_legacy_encryption = %v, want %v", page.path, f["zip_legacy_encryption"], legacy)
			}
			l, _ := b["limits"].(map[string]any)
			if got, ok := l["zip_password_min"].(float64); !ok || got != min {
				t.Errorf("%s: limits.zip_password_min = %v, want %v", page.path, l["zip_password_min"], min)
			}
		}
		if got := Features(e.d, nil)["zip_legacy_encryption"]; got != legacy {
			t.Errorf("Features: zip_legacy_encryption = %v", got)
		}
	}
	check(true, 12) // defaults (the keys are registered by package uploads)
	e.s.set(settingZipLegacyEncryption, false)
	e.s.set(settingZipPasswordMin, 16)
	check(false, 16)
	e.s.set(settingZipLegacyEncryption, true)
	e.s.set(settingZipPasswordMin, 3) // clamped like the service clamps it
	check(true, 8)
	e.s.set(settingZipPasswordMin, 1000)
	check(true, 64)
	if l := bootLimits(nil); len(l) != 1 || l["zip_password_min"] != 12 {
		t.Fatalf("bootLimits without deps: %v", l)
	}
}
