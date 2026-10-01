package auth

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"fileparcel/internal/settings"
)

// Defaults of the auth.* settings (DESIGN §11.2).
const (
	DefaultPasswordMin     = 12
	DefaultSessionIdleMin  = 720
	DefaultSessionMaxDays  = 30
	DefaultLockoutThresh   = 10
	DefaultLockoutBaseMin  = 15
	DefaultStepUpMin       = 10
	Require2FAOff          = "off"
	Require2FAAdmins       = "admins"
	Require2FAAll          = "all"
	DefaultRequire2FA      = Require2FAAdmins
	minPasswordMinSetting  = 8
	maxPasswordMinSetting  = 128
	maxSessionIdleMinutes  = 525_600 // one year
	maxSessionLifetimeDays = 365
)

func init() {
	settings.Register(settings.Def{
		Key: "auth.password_min", Section: "auth", Order: 10, Type: settings.TypeInt,
		Default: DefaultPasswordMin, Min: minPasswordMinSetting, Max: maxPasswordMinSetting,
		Label:       "Minimum password length",
		Description: "Minimum number of characters of new passwords. Common passwords and passwords containing the username are always rejected.",
	})
	settings.Register(settings.Def{
		Key: "auth.require_2fa", Section: "auth", Order: 20, Type: settings.TypeEnum,
		Default: DefaultRequire2FA, Enum: []string{Require2FAOff, Require2FAAdmins, Require2FAAll},
		Label: "Require two-factor authentication",
		Description: "Users in scope must set up an authenticator app or a passkey before they can use FileParcel. " +
			"\"admins\" covers owners, admins and every role with a server permission.",
	})
	settings.Register(settings.Def{
		Key: "auth.passkeys", Section: "auth", Order: 30, Type: settings.TypeBool, Default: true,
		Label: "Passkeys",
		Description: "Allow signing in and confirming your identity with passkeys (WebAuthn). Passkeys need a trusted certificate. " +
			"Turning this off shuts out accounts whose only second factor is a passkey until an administrator resets their two-factor authentication, " +
			"so while such accounts exist it has to be confirmed.",
	})
	settings.Register(settings.Def{
		Key: "auth.webauthn_rp_id", Section: "auth", Order: 40, Type: settings.TypeString, Default: "",
		Label:       "Passkey domain (RP ID)",
		Description: "Domain passkeys are bound to. Empty = <mDNS name>.local. Changing it makes existing passkeys unusable.",
		Validate:    validateRPID,
	})
	settings.Register(settings.Def{
		Key: "auth.webauthn_origins", Section: "auth", Order: 50, Type: settings.TypeStrings, Default: []string{},
		Label: "Extra passkey origins",
		Description: "Additional https:// origins allowed for passkeys. Empty = the passkey domain, the public URL and the other names this " +
			"server serves under that domain (extra hosts, extra SANs, ACME domains), at the HTTPS port. Add an origin for a reverse proxy on another name or port.",
		Validate: validateOrigins,
	})
	settings.Register(settings.Def{
		Key: "auth.session_idle_min", Section: "auth", Order: 60, Type: settings.TypeInt,
		Default: DefaultSessionIdleMin, Min: 5, Max: maxSessionIdleMinutes,
		Label:       "Session idle timeout (minutes)",
		Description: "Browser sessions end after this much inactivity.",
	})
	settings.Register(settings.Def{
		Key: "auth.session_max_days", Section: "auth", Order: 70, Type: settings.TypeInt,
		Default: DefaultSessionMaxDays, Min: 1, Max: maxSessionLifetimeDays,
		Label:       "Remembered session lifetime (days)",
		Description: "Absolute lifetime of sessions created with \"remember me\"; other sessions end with the browser or after 24 hours.",
	})
	settings.Register(settings.Def{
		Key: "auth.lockout_threshold", Section: "auth", Order: 80, Type: settings.TypeInt,
		Default: DefaultLockoutThresh, Min: 3, Max: 1000,
		Label:       "Lockout threshold",
		Description: "Consecutive failed sign-ins before an account is temporarily locked.",
	})
	settings.Register(settings.Def{
		Key: "auth.lockout_base_min", Section: "auth", Order: 90, Type: settings.TypeInt,
		Default: DefaultLockoutBaseMin, Min: 1, Max: 1440,
		Label:       "Lockout duration (minutes)",
		Description: "First lockout duration; it doubles with every further lockout, up to 24 hours.",
	})
	settings.Register(settings.Def{
		Key: "auth.stepup_min", Section: "auth", Order: 100, Type: settings.TypeInt,
		Default: DefaultStepUpMin, Min: 1, Max: 120,
		Label:       "Identity confirmation window (minutes)",
		Description: "How long sensitive actions stay unlocked after confirming your identity.",
	})
	settings.Register(settings.Def{
		Key: "auth.admin_can_access_files", Section: "auth", Order: 110, Type: settings.TypeBool, Default: false,
		Label:       "Administrators can access all files",
		Description: "Lets owners and admins manage every space; every such access is audited. Custom roles never get this.",
	})
}

// validateRPID accepts "" or a lowercase-able DNS name (never an IP address,
// never a URL): WebAuthn RP IDs are registrable domains (DESIGN §18.1).
func validateRPID(v any) error {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	if err := checkDomain(s); err != nil {
		return err
	}
	return nil
}

func checkDomain(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("domain too long")
	}
	if net.ParseIP(strings.Trim(s, "[]")) != nil {
		return fmt.Errorf("must be a domain name, not an IP address")
	}
	if strings.ContainsAny(s, ":/ ") {
		return fmt.Errorf("must be a bare domain such as fileparcel.local (no scheme, port or path)")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid domain %q", s)
		}
		for i, c := range label {
			alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !alnum && !(c == '-' && i > 0 && i < len(label)-1) {
				return fmt.Errorf("invalid domain %q", s)
			}
		}
	}
	return nil
}

// validateOrigins accepts https origins ("https://host[:port]", no path).
func validateOrigins(v any) error {
	list, _ := v.([]string)
	for _, o := range list {
		if _, err := normalizeOrigin(o); err != nil {
			return err
		}
	}
	return nil
}

// normalizeOrigin validates an https origin and returns it lowercased,
// without a trailing slash.
func normalizeOrigin(o string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(o))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not an https origin such as https://files.example.com:8443", o)
	}
	return "https://" + strings.ToLower(u.Host), nil
}
