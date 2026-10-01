package shares

import "fileparcel/internal/settings"

// Setting keys of the sharing section (DESIGN §11.2, unit E).
const (
	SettingLinksEnabled      = "sharing.links_enabled"
	SettingRequirePassword   = "sharing.require_password"
	SettingMaxExpiryDays     = "sharing.max_expiry_days"
	SettingDefaultExpiryDays = "sharing.default_expiry_days"
	SettingRequestsEnabled   = "sharing.requests_enabled"
	SettingAllowGuestsShare  = "sharing.allow_guests_share"
	// SettingAccessLogDays is applied by the daily maintenance.db_optimize
	// job (package jobs), which deletes older share_access_log rows.
	SettingAccessLogDays = "sharing.access_log_days"

	settingAdminFiles   = "auth.admin_can_access_files" // registered by auth
	settingNotifyEvents = "notify.events"               // registered by notify
	settingLoginPerMin  = "ratelimit.login_per_min"     // registered by ratelimit
)

// Defaults of the settings above (used when no settings store is wired).
const (
	DefaultMaxExpiryDays     = 0
	DefaultDefaultExpiryDays = 7
	DefaultAccessLogDays     = 365
)

func init() {
	settings.Register(settings.Def{
		Key: SettingLinksEnabled, Section: "sharing", Order: 10, Type: settings.TypeBool, Default: true,
		Label:       "Allow share links",
		Description: "Users may create public links to files and folders they manage. Turning this off disables existing links too.",
	})
	settings.Register(settings.Def{
		Key: SettingRequirePassword, Section: "sharing", Order: 20, Type: settings.TypeBool, Default: false,
		Label:       "Require a password for new links",
		Description: "New share links and file requests must be protected by a password.",
	})
	settings.Register(settings.Def{
		Key: SettingMaxExpiryDays, Section: "sharing", Order: 30, Type: settings.TypeInt,
		Default: DefaultMaxExpiryDays, Min: 0, Max: 3650,
		Label:       "Maximum link lifetime (days)",
		Description: "Counted from the creation of a link: owners may shorten the expiry but never extend it beyond this. 0 = links may be created without expiry.",
	})
	settings.Register(settings.Def{
		Key: SettingDefaultExpiryDays, Section: "sharing", Order: 40, Type: settings.TypeInt,
		Default: DefaultDefaultExpiryDays, Min: 0, Max: 3650,
		Label:       "Default link lifetime (days)",
		Description: "Expiry proposed for new links; 0 = no expiry by default (capped by the maximum).",
	})
	settings.Register(settings.Def{
		Key: SettingRequestsEnabled, Section: "sharing", Order: 50, Type: settings.TypeBool, Default: true,
		Label:       "Allow file requests",
		Description: "Users may create public upload links (file requests) for folders they manage.",
	})
	settings.Register(settings.Def{
		Key: SettingAllowGuestsShare, Section: "sharing", Order: 60, Type: settings.TypeBool, Default: false,
		Label:       "Guests may share",
		Description: "Allow accounts with the built-in Guest role to create share links and file requests. Custom roles use their own permissions.",
	})
	settings.Register(settings.Def{
		Key: SettingAccessLogDays, Section: "sharing", Order: 70, Type: settings.TypeInt,
		Default: DefaultAccessLogDays, Min: 0, Max: 3650,
		Label:       "Access log retention (days)",
		Description: "Access-log entries of share links and file requests (with the visitors' IP addresses) older than this are deleted daily. 0 = keep them as long as the link exists.",
	})
}
