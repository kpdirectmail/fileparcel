package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/core"
)

// Template names accepted by Send (the tmpl argument of core.Notify.Send).
//
// The data argument is any value that marshals to a JSON object: a
// map[string]any or a struct with json tags. Every value is rendered as text
// (numbers without exponent, lists joined with ", "); missing keys render as
// "". Keys per template (all optional unless noted):
//
//	invite          url (required), inviter, role, expires_at (RFC 3339), note, email
//	share_upload    share_title, owner, uploader, files (count), bytes, folder, url, file_names (list)
//	                (also accepted as "share.upload" with the keys title, owner_name and
//	                at, the shape the shares service sends)
//	security_alert  kind (lockout | passkey_added | totp_added | token_created | mfa_reset |
//	                password_reset | email_changed | other), username, name (passkey/token name;
//	                for email_changed the masked new address, "" = removed), actor, ip, time (RFC 3339),
//	                locked_until (RFC 3339), detail (free text for "other")
//	test            (none)
//
// Every template also receives "instance" (ui.instance_name) and "time"
// (defaults to now).
const (
	TemplateInvite        = "invite"
	TemplateShareUpload   = "share_upload"
	TemplateSecurityAlert = "security_alert"
	TemplateTest          = "test"
)

// templateAliases maps alternative template names to the canonical ones.
// "share.upload" is the notify.events category name, which the shares
// service uses as the template name.
var templateAliases = map[string]string{
	EventShareUpload: TemplateShareUpload,
}

// Security alert kinds (security_alert "kind").
const (
	AlertLockout       = "lockout"
	AlertPasskeyAdded  = "passkey_added"
	AlertTOTPAdded     = "totp_added"
	AlertTokenCreated  = "token_created"
	AlertMFAReset      = "mfa_reset"
	AlertPasswordReset = "password_reset"
	AlertEmailChanged  = "email_changed" // sent to the previous address
)

// Limits on rendered content.
const (
	maxFieldLen   = 2000 // bytes per data value
	maxSubjectLen = 200  // runes
	maxBodyLen    = 64 << 10
)

// tmplDef is one notification template.
type tmplDef struct {
	category string            // notify.events category; "" = always sent
	fields   []string          // data keys (missing → "")
	required []string          // keys that must be non-empty
	aliases  map[string]string // alternative data key → canonical key (used when the canonical key is empty)
	subject  *template.Template
	body     *template.Template
}

var funcs = template.FuncMap{
	"bytes":    humanBytes,
	"datetime": humanTime,
	"title":    alertTitle,
}

func mustTmpl(name, text string) *template.Template {
	return template.Must(template.New(name).Funcs(funcs).Option("missingkey=zero").Parse(text))
}

var templates = map[string]*tmplDef{
	TemplateInvite: {
		fields:   []string{"url", "inviter", "role", "expires_at", "note", "email"},
		required: []string{"url"},
		subject:  mustTmpl("invite.subject", `{{if .inviter}}{{.inviter}} invited you to {{.instance}}{{else}}Your invitation to {{.instance}}{{end}}`),
		body: mustTmpl("invite.body", `Hello,

{{if .inviter}}{{.inviter}} has invited you{{else}}You have been invited{{end}} to join {{.instance}}{{if .role}} as {{.role}}{{end}}.

Create your account with this link:

    {{.url}}
{{if .expires_at}}
The invitation expires on {{datetime .expires_at}}.
{{end}}{{if .note}}
Message from {{if .inviter}}{{.inviter}}{{else}}the administrator{{end}}:

{{.note}}
{{end}}
The link is personal: do not forward it. If you did not expect this
invitation you can ignore this e-mail.
`),
	},
	TemplateShareUpload: {
		category: EventShareUpload,
		fields:   []string{"share_title", "owner", "uploader", "files", "bytes", "folder", "url", "file_names"},
		aliases:  map[string]string{"title": "share_title", "owner_name": "owner", "at": "time"},
		subject:  mustTmpl("share_upload.subject", `New upload{{if .share_title}} to "{{.share_title}}"{{end}}`),
		body: mustTmpl("share_upload.body", `Hello{{if .owner}} {{.owner}}{{end}},

{{if .uploader}}{{.uploader}}{{else}}Someone{{end}} uploaded {{if .files}}{{.files}} file(s){{else}}files{{end}}{{if .bytes}} ({{bytes .bytes}}){{end}} through your file request{{if .share_title}} "{{.share_title}}"{{end}}{{if .folder}} into the folder "{{.folder}}"{{end}}.
{{if .file_names}}
Files: {{.file_names}}
{{end}}{{if .url}}
Open the folder: {{.url}}
{{end}}
You receive this e-mail because notifications are enabled for this file
request on {{.instance}}.
`),
	},
	TemplateSecurityAlert: {
		category: EventSecurity,
		fields:   []string{"kind", "username", "name", "actor", "ip", "locked_until", "detail"},
		subject:  mustTmpl("security_alert.subject", `Security alert: {{title .kind}}`),
		body: mustTmpl("security_alert.body", `Hello{{if .username}} {{.username}}{{end}},

{{if eq .kind "lockout"}}Your {{.instance}} account was temporarily locked after too many failed sign-in attempts{{if .locked_until}} (until {{datetime .locked_until}}){{end}}.
If this was not you, someone may be trying to guess your password: consider changing it and enabling two-factor authentication.
{{else if eq .kind "passkey_added"}}A new passkey{{if .name}} "{{.name}}"{{end}} was added to your {{.instance}} account.
{{else if eq .kind "totp_added"}}An authenticator app was set up for two-factor sign-in on your {{.instance}} account.
{{else if eq .kind "token_created"}}A new API token{{if .name}} "{{.name}}"{{end}} was created for your {{.instance}} account{{if .actor}} by the administrator {{.actor}}{{end}}.
{{else if eq .kind "mfa_reset"}}{{if .actor}}The administrator {{.actor}}{{else}}An administrator{{end}} removed the two-factor authentication methods (authenticator app, recovery codes and passkeys) of your {{.instance}} account.
You may be asked to set up two-factor authentication again at your next sign-in.
{{else if eq .kind "password_reset"}}{{if .actor}}The administrator {{.actor}}{{else}}An administrator{{end}} set a new password for your {{.instance}} account.
{{else if eq .kind "email_changed"}}The e-mail address of your {{.instance}} account was {{if .name}}changed to {{.name}}{{else}}removed{{end}}.
Security alerts for this account are no longer sent to this address.
{{else}}{{if .detail}}{{.detail}}{{else}}A security-relevant change was made to your {{.instance}} account.{{end}}
{{end}}
Time: {{datetime .time}}{{if .ip}}
IP address: {{.ip}}{{end}}

If this was you, no action is needed. Otherwise contact your administrator
immediately.
`),
	},
	TemplateTest: {
		subject: mustTmpl("test.subject", `Test e-mail from {{.instance}}`),
		body: mustTmpl("test.body", `This is a test e-mail from {{.instance}}, sent at {{datetime .time}}.

If you can read this, e-mail notifications are configured correctly.
`),
	},
}

// rendered is a rendered notification.
type rendered struct {
	category string
	subject  string
	body     string
}

// render validates data and executes tmpl. common holds the fields every
// template receives (instance, time); data values win except for instance.
func render(tmpl string, data any, common map[string]string) (*rendered, error) {
	name := tmpl
	if canonical, ok := templateAliases[name]; ok {
		name = canonical
	}
	def, ok := templates[name]
	if !ok {
		return nil, core.Invalid("template", fmt.Sprintf("unknown notification template %q", tmpl))
	}
	m, err := normalize(data)
	if err != nil {
		return nil, err
	}
	for alias, key := range def.aliases {
		if m[key] == "" && m[alias] != "" {
			m[key] = m[alias]
		}
	}
	vals := make(map[string]string, len(def.fields)+len(common))
	for _, f := range def.fields {
		vals[f] = m[f]
	}
	for k, v := range common {
		if cur, ok := m[k]; ok && cur != "" && k != "instance" {
			v = cur
		}
		vals[k] = v
	}
	for _, f := range def.required {
		if vals[f] == "" {
			return nil, core.Invalid(f, fmt.Sprintf("notification template %q needs %q", tmpl, f))
		}
	}
	var sb, bb bytes.Buffer
	if err := def.subject.Execute(&sb, vals); err != nil {
		return nil, fmt.Errorf("notify: render %s subject: %w", tmpl, err)
	}
	if err := def.body.Execute(&bb, vals); err != nil {
		return nil, fmt.Errorf("notify: render %s body: %w", tmpl, err)
	}
	body := bb.String()
	if len(body) > maxBodyLen {
		body = truncate(body, maxBodyLen)
	}
	return &rendered{category: def.category, subject: cleanSubject(sb.String()), body: body}, nil
}

// normalize turns data into a flat map of display strings.
func normalize(data any) (map[string]string, error) {
	out := map[string]string{}
	if data == nil {
		return out, nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, core.Invalid("data", "notification data is not serializable")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, core.Invalid("data", "notification data must be an object")
	}
	for k, v := range m {
		out[k] = cleanText(display(v))
	}
	return out, nil
}

// display renders one JSON value as text.
func display(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s := display(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// cleanText removes control characters (except newline and tab), normalizes
// line endings and bounds the length of a data value.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r == '\r':
			return '\n'
		case unicode.IsControl(r), r == '\u2028', r == '\u2029': // line/paragraph separators
			return -1
		}
		return r
	}, s)
	return truncate(s, maxFieldLen)
}

// cleanSubject makes a single header-safe line (no CR/LF) of at most maxSubjectLen runes.
func cleanSubject(s string) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if utf8.RuneCountInString(s) > maxSubjectLen {
		r := []rune(s)
		s = string(r[:maxSubjectLen-1]) + "…"
	}
	return s
}

// truncate cuts s to at most n bytes at a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// humanBytes renders a byte count ("1.5 GiB"); non-numbers are returned as is.
func humanBytes(s string) string {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 || math.IsInf(f, 0) || math.IsNaN(f) {
		return s
	}
	const unit = 1024
	if f < unit {
		return fmt.Sprintf("%d B", int64(f))
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	i := -1
	for f >= unit && i < len(units)-1 {
		f /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// humanTime renders an RFC 3339 time as "Mon, 02 Jan 2006 15:04 UTC"; other
// strings are returned unchanged.
func humanTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return s
	}
	return t.UTC().Format("Mon, 02 Jan 2006 15:04 MST")
}

// alertTitle is the subject suffix of a security alert kind.
func alertTitle(kind string) string {
	switch kind {
	case AlertLockout:
		return "account temporarily locked"
	case AlertPasskeyAdded:
		return "new passkey added"
	case AlertTOTPAdded:
		return "authenticator app added"
	case AlertTokenCreated:
		return "new API token created"
	case AlertMFAReset:
		return "two-factor authentication reset"
	case AlertPasswordReset:
		return "password reset by an administrator"
	case AlertEmailChanged:
		return "e-mail address changed"
	}
	return "account activity"
}
