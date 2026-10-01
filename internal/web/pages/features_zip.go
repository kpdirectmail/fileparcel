package pages

import "fileparcel/internal/app"

// Password-protected .zip on upload (DESIGN §8.1, §13.6). The settings are
// registered by package uploads; web packages do not import services, so
// their keys are literals here.
const (
	settingZipLegacyEncryption = "storage.zip_legacy_encryption"
	settingZipPasswordMin      = "storage.zip_password_min"
	// defaultZipPasswordMin and its range mirror uploads.DefaultZipPasswordMin
	// and the bounds the service clamps the setting to.
	defaultZipPasswordMin = 12
	zipPasswordMinFloor   = 8
	zipPasswordMinCeil    = 64
)

// zipFeatures adds zip_legacy_encryption: whether the upload dialog offers
// ZipCrypto next to AES-256 (storage.zip_legacy_encryption).
func zipFeatures(d *app.Deps, f map[string]bool) {
	f["zip_legacy_encryption"] = boolSetting(d, settingZipLegacyEncryption, true)
}

// bootLimits are the numeric limits of the page boot (Boot.Limits, boot
// only): zip_password_min is the shortest .zip password the server accepts
// (storage.zip_password_min, clamped as the service clamps it), which the
// upload dialog checks before it sends anything. Never nil.
func bootLimits(d *app.Deps) map[string]int64 {
	n := intSetting(d, settingZipPasswordMin, defaultZipPasswordMin)
	return map[string]int64{"zip_password_min": min(max(n, zipPasswordMinFloor), zipPasswordMinCeil)}
}
