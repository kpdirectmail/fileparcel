package pages

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/settings"
)

// Setting keys of the "general" section (DESIGN §11.2, owner: unit I).
const (
	KeyInstanceName = "ui.instance_name"
	KeyAccentColor  = "ui.accent_color"
	KeyDefaultTheme = "ui.default_theme"
	KeyLoginMessage = "ui.login_message"
	KeyDefaultView  = "ui.default_view"
)

// Defaults of the ui.* settings.
const (
	DefaultInstanceName = "FileParcel"
	DefaultAccentColor  = "#2b7ad6" // = tokens.css --fp-brand oklch(0.58 0.16 255), the logo and manifest blue
)

// Limits of the free-text ui.* settings.
const (
	MaxInstanceName = 64
	MaxLoginMessage = 2000
)

func init() {
	settings.Register(settings.Def{Key: KeyInstanceName, Section: "general", Order: 10, Type: settings.TypeString,
		Default: DefaultInstanceName, Label: "Instance name",
		Description: "Shown in the browser title, the sign-in page, the installed app and e-mails.",
		Validate:    validateInstanceName})
	settings.Register(settings.Def{Key: KeyAccentColor, Section: "general", Order: 20, Type: settings.TypeColor,
		Default: DefaultAccentColor, Label: "Accent colour",
		Description: "Brand colour of buttons and links (#rrggbb). A lighter variant is derived for dark mode."})
	settings.Register(settings.Def{Key: KeyDefaultTheme, Section: "general", Order: 30, Type: settings.TypeEnum,
		Default: "system", Enum: []string{"light", "dark", "system"}, Label: "Default theme",
		Description: "Theme for visitors and users who have not chosen one (system follows the device)."})
	settings.Register(settings.Def{Key: KeyLoginMessage, Section: "general", Order: 40, Type: settings.TypeString,
		Default: "", Label: "Sign-in message",
		Description: "Optional notice shown on the sign-in page (plain text).", Validate: validateLoginMessage})
	settings.Register(settings.Def{Key: KeyDefaultView, Section: "general", Order: 50, Type: settings.TypeEnum,
		Default: "list", Enum: []string{"list", "grid"}, Label: "Default file view",
		Description: "Initial layout of folder listings for users who have not chosen one."})
}

func validateInstanceName(v any) error {
	s, _ := v.(string)
	switch {
	case strings.TrimSpace(s) == "":
		return errors.New("must not be empty")
	case s != strings.TrimSpace(s):
		return errors.New("must not start or end with spaces")
	case utf8.RuneCountInString(s) > MaxInstanceName:
		return errors.New("must be at most 64 characters")
	case strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) }) >= 0:
		return errors.New("must not contain control characters")
	}
	return nil
}

func validateLoginMessage(v any) error {
	s, _ := v.(string)
	switch {
	case utf8.RuneCountInString(s) > MaxLoginMessage:
		return errors.New("must be at most 2000 characters")
	case strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) >= 0:
		return errors.New("must not contain control characters")
	}
	return nil
}
