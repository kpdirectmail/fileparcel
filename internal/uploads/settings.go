package uploads

import "fileparcel/internal/settings"

// Setting keys owned by this package (DESIGN §11.2, storage section, unit E).
// The other storage.* keys read here (max_file_gb, default_quota_gb,
// zip_compression) are registered by the files unit.
const (
	SettingParallel    = "storage.upload_parallel"
	SettingExpiryHours = "storage.upload_expiry_hours"
	// Password-protected zip-on-upload (DESIGN §8.1): the shortest .zip
	// password accepted, and whether the weak ZipCrypto method may be chosen.
	SettingZipPasswordMin      = "storage.zip_password_min"
	SettingZipLegacyEncryption = "storage.zip_legacy_encryption"

	settingMaxFileGB      = "storage.max_file_gb"
	settingDefaultQuotaGB = "storage.default_quota_gb"
	settingZipCompression = "storage.zip_compression"
)

// Defaults of the settings above (also used when no settings store is wired;
// DefaultZipPasswordMin is in zippassword.go).
const (
	DefaultParallel            = 4
	DefaultExpiryHours         = 48
	DefaultZipLegacyEncryption = true
)

func init() {
	settings.Register(settings.Def{
		Key: SettingParallel, Section: "storage", Order: 60, Type: settings.TypeInt,
		Default: DefaultParallel, Min: 1, Max: 16,
		Label:       "Parallel upload parts",
		Description: "How many 8 MiB parts a browser uploads at the same time.",
	})
	settings.Register(settings.Def{
		Key: SettingExpiryHours, Section: "storage", Order: 61, Type: settings.TypeInt,
		Default: DefaultExpiryHours, Min: 1, Max: 720,
		Label: "Unfinished upload expiry (hours)",
		Description: "Uploads that are not completed within this time are cancelled and their " +
			"partial data is deleted by the hourly maintenance job.",
	})
	// Orders 71/72: right after storage.zip_compression (70, files unit).
	settings.Register(settings.Def{
		Key: SettingZipPasswordMin, Section: "storage", Order: 71, Type: settings.TypeInt,
		Default: DefaultZipPasswordMin, Min: zipPasswordMinFloor, Max: zipPasswordMinCeil,
		Label: "Minimum .zip password length",
		Description: "Shortest password accepted for a password-protected .zip created on upload. The .zip " +
			"format's key derivation is fast (PBKDF2-SHA1, 1000 rounds), so short passwords can be guessed offline.",
	})
	settings.Register(settings.Def{
		Key: SettingZipLegacyEncryption, Section: "storage", Order: 72, Type: settings.TypeBool,
		Default: DefaultZipLegacyEncryption,
		Label:   "Allow ZipCrypto for protected .zip files",
		Description: "ZipCrypto opens in the unzip built into Windows and macOS but can usually be broken " +
			"without the password. AES-256 is always available. Turning this off does not affect uploads " +
			"already started.",
	})
}
