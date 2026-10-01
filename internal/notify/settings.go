package notify

import (
	"fmt"
	"net/mail"
	"net/netip"
	"slices"
	"strings"

	"fileparcel/internal/settings"
)

// Setting keys owned by the notify package (DESIGN §11.2, section "email").
const (
	// SettingHost is the SMTP server host name or IP ("" disables e-mail).
	SettingHost = "smtp.host"
	// SettingPort is the SMTP server port.
	SettingPort = "smtp.port"
	// SettingTLS is the transport security: starttls | tls | none.
	SettingTLS = "smtp.tls"
	// SettingUsername is the SMTP AUTH PLAIN user ("" = no authentication).
	SettingUsername = "smtp.username"
	// SettingPassword is the SMTP AUTH PLAIN password (secret).
	SettingPassword = "smtp.password"
	// SettingFrom is the sender address ("Name <addr>" or "addr").
	SettingFrom = "smtp.from"
	// SettingEvents lists the notification categories that are sent.
	SettingEvents = "notify.events"
)

// TLS modes (smtp.tls).
const (
	TLSStartTLS = "starttls" // plain connection upgraded with STARTTLS (required)
	TLSImplicit = "tls"      // TLS from the first byte (SMTPS, usually port 465)
	TLSNone     = "none"     // no encryption (authentication refused)
)

// Notification categories (notify.events). Invites and test mails are always sent.
const (
	EventShareUpload = "share.upload" // uploads through a file request (to the share owner)
	EventSecurity    = "security"     // lockouts, new passkeys/tokens, MFA resets (to the account owner)
)

// knownEvents lists the valid notify.events entries.
var knownEvents = []string{EventShareUpload, EventSecurity}

func init() {
	settings.Register(settings.Def{
		Key: SettingHost, Section: "email", Order: 10, Type: settings.TypeString, Default: "",
		Label:       "SMTP server",
		Description: "Host name or IP address of the mail server. Leave empty to disable e-mail notifications.",
		Validate:    validateHost,
	})
	settings.Register(settings.Def{
		Key: SettingPort, Section: "email", Order: 20, Type: settings.TypeInt, Default: 587, Min: 1, Max: 65535,
		Label:       "SMTP port",
		Description: "587 for STARTTLS (submission), 465 for implicit TLS, 25 for plain SMTP.",
	})
	settings.Register(settings.Def{
		Key: SettingTLS, Section: "email", Order: 30, Type: settings.TypeEnum, Default: TLSStartTLS,
		Enum:        []string{TLSStartTLS, TLSImplicit, TLSNone},
		Label:       "SMTP encryption",
		Description: "starttls upgrades the connection (and fails if the server cannot), tls encrypts from the start, none sends in clear text (no login possible).",
	})
	settings.Register(settings.Def{
		Key: SettingUsername, Section: "email", Order: 40, Type: settings.TypeString, Default: "",
		Label:       "SMTP username",
		Description: "User name for SMTP authentication (AUTH PLAIN, only over TLS). Leave empty if the server needs no login.",
		Validate:    validateNoControl,
	})
	settings.Register(settings.Def{
		Key: SettingPassword, Section: "email", Order: 50, Type: settings.TypeSecret, Default: "",
		Label:       "SMTP password",
		Description: "Password for SMTP authentication (stored encrypted).",
	})
	settings.Register(settings.Def{
		Key: SettingFrom, Section: "email", Order: 60, Type: settings.TypeString, Default: "",
		Label:       "Sender address",
		Description: `From address of notification e-mails, e.g. "FileParcel <files@example.com>". Defaults to the SMTP username when that is an e-mail address.`,
		Validate:    validateFrom,
	})
	settings.Register(settings.Def{
		Key: SettingEvents, Section: "email", Order: 70, Type: settings.TypeStrings,
		Default:     []string{EventShareUpload, EventSecurity},
		Label:       "Notifications",
		Description: `Which notifications are e-mailed: "share.upload" (uploads through file requests, to the request owner) and "security" (lockouts, new passkeys or tokens, two-factor resets, to the affected user). Invitations are always sent when requested.`,
		Validate:    validateEvents,
	})
}

// validateHost accepts "" or a host name / IP address without scheme, port or path.
func validateHost(v any) error {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	if len(s) > 253 {
		return fmt.Errorf("host name too long")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	for _, r := range s {
		ok := r == '-' || r == '.' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("expected a host name or IP address (no scheme or port)")
		}
	}
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "-") || strings.Contains(s, "..") {
		return fmt.Errorf("invalid host name")
	}
	return nil
}

func validateNoControl(v any) error {
	s, _ := v.(string)
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("must not contain control characters")
	}
	return nil
}

// validateFrom accepts "" or an RFC 5322 address with an optional display name.
func validateFrom(v any) error {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	if err := validateNoControl(s); err != nil {
		return err
	}
	if _, err := mail.ParseAddress(s); err != nil {
		return fmt.Errorf(`expected an e-mail address such as "files@example.com" or "FileParcel <files@example.com>"`)
	}
	return nil
}

func validateEvents(v any) error {
	l, _ := v.([]string)
	for _, e := range l {
		if !slices.Contains(knownEvents, e) {
			return fmt.Errorf("unknown notification %q (known: %s)", e, strings.Join(knownEvents, ", "))
		}
	}
	return nil
}
