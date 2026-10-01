package keys

import "fileparcel/internal/settings"

// Settings owned by package keys (DESIGN §11.2).
const (
	settingCipher    = "storage.cipher"
	settingWebUnlock = "keys.web_unlock"

	cipherAuto   = "auto"
	cipherAESGCM = "aes-gcm"
	cipherChaCha = "chacha20-poly1305"
)

func init() {
	settings.Register(settings.Def{
		Key: settingCipher, Section: "storage", Order: 85, Type: settings.TypeEnum,
		Default: cipherAuto, Enum: []string{cipherAuto, cipherAESGCM, cipherChaCha},
		Label: "Blob cipher",
		Description: "Cipher for newly written files. auto picks AES-256-GCM on CPUs with AES instructions and " +
			"ChaCha20-Poly1305 otherwise (e.g. Raspberry Pi 4). Existing files keep their cipher.",
	})
	settings.Register(settings.Def{
		Key: settingWebUnlock, Section: "keys", Order: 10, Type: settings.TypeEnum,
		Default: "lan", Enum: []string{"lan", "any", "off"},
		Label: "Web unlock",
		Description: "Where the sealed server may be unlocked from the /unlock page: lan (local and VPN networks), " +
			"any, or off (only with \"fileparcel keys unlock\" on the server).",
	})
}
