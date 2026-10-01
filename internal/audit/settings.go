package audit

import "fileparcel/internal/settings"

// Setting keys owned by the audit package (DESIGN §11.2, section "audit").
const (
	// SettingRetentionDays is how long audit rows are kept (0 = forever).
	SettingRetentionDays = "audit.retention_days"
	// SettingMirrorJSONL mirrors every committed row to logs/audit.jsonl.
	SettingMirrorJSONL = "audit.mirror_jsonl"
)

func init() {
	settings.Register(settings.Def{
		Key: SettingRetentionDays, Section: "audit", Order: 10,
		Type: settings.TypeInt, Default: 365, Min: 0, Max: 36500,
		Label:       "Audit log retention (days)",
		Description: "Audit entries older than this are pruned daily (the hash chain keeps an authenticated anchor). 0 keeps entries forever.",
	})
	settings.Register(settings.Def{
		Key: SettingMirrorJSONL, Section: "audit", Order: 20,
		Type: settings.TypeBool, Default: false,
		Label:       "Mirror audit log to logs/audit.jsonl",
		Description: "Append every audit entry as one JSON line to logs/audit.jsonl (rotated like the server log), e.g. for log shippers.",
	})
}
