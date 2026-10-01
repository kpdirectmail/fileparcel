package users

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"

	"golang.org/x/text/unicode/norm"
)

// Input limits.
const (
	maxUsernameLen    = 64
	maxDisplayNameLen = 100 // runes
	maxEmailLen       = 254
	maxPrefsBytes     = 16 << 10
	maxGroupNameLen   = 100 // runes
	maxDescriptionLen = 1000
	maxNoteLen        = 1000
	maxGroupIDs       = 100
)

// usernameRe: 1–64 ASCII letters, digits, '.', '_' or '-', starting and
// ending with a letter or digit.
var usernameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$`)

// reservedUsernames cannot be registered (case-insensitive).
var reservedUsernames = map[string]bool{
	"system": true, // core.SystemPrincipal
	"root":   true,
	"me":     true,
}

// CleanUsername validates a username and returns it trimmed.
func CleanUsername(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !usernameRe.MatchString(s) {
		return "", core.Invalid("username", "use 1 to 64 letters, digits, dots, dashes or underscores, starting and ending with a letter or digit")
	}
	low := strings.ToLower(s)
	if reservedUsernames[low] || strings.HasPrefix(low, ids.PrefixUser+"_") {
		return "", core.Invalid("username", fmt.Sprintf("the username %q is reserved", s))
	}
	return s, nil
}

// cleanDisplayName normalizes a display name (NFC, inner whitespace
// collapsed; no control, text-direction or other invisible characters —
// names.IsHiddenFormat: the name is what the share and grant pickers show);
// "" is returned as is, and so is a name of nothing but joiners and
// direction marks.
func cleanDisplayName(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", core.Invalid("display_name", "display name is not valid UTF-8")
	}
	s = strings.Join(strings.FieldsFunc(norm.NFC.String(s), unicode.IsSpace), " ")
	if strings.ContainsFunc(s, unicode.IsControl) {
		return "", core.Invalid("display_name", "display name must not contain control characters")
	}
	if strings.ContainsFunc(s, names.IsBidiControl) {
		return "", core.Invalid("display_name", "display name must not contain text-direction control characters")
	}
	if strings.ContainsFunc(s, names.IsHiddenFormat) {
		return "", core.Invalid("display_name", "display name must not contain invisible characters such as a zero-width space")
	}
	if strings.TrimSpace(names.LabelKey(s)) == "" {
		return "", nil
	}
	if utf8.RuneCountInString(s) > maxDisplayNameLen {
		return "", core.Invalid("display_name", fmt.Sprintf("display name is longer than %d characters", maxDisplayNameLen))
	}
	return s, nil
}

// cleanEmail validates an optional bare e-mail address ("" allowed).
func cleanEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > maxEmailLen {
		return "", core.Invalid("email", "e-mail address is too long")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" || strings.ContainsAny(s, "\r\n<>\"") {
		return "", core.Invalid("email", "expected an e-mail address like name@example.com")
	}
	return s, nil
}

// cleanPrefs validates a preferences object (nil → "{}").
func cleanPrefs(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "{}", nil
	}
	if len(raw) > maxPrefsBytes {
		return "", core.Invalid("prefs", "preferences are too large")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return "", core.Invalid("prefs", "preferences must be a JSON object")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", core.Invalid("prefs", "preferences must be a JSON object")
	}
	return string(b), nil
}

// cleanQuota validates an optional quota (nil = default, 0 = unlimited).
func cleanQuota(q *int64, field string) (*int64, error) {
	if q == nil {
		return nil, nil
	}
	if *q < 0 {
		return nil, core.Invalid(field, "quota must be 0 (unlimited) or a positive number of bytes")
	}
	v := *q
	return &v, nil
}

// cleanGroupIDs validates and deduplicates group ids.
func cleanGroupIDs(in []string) ([]string, error) {
	if len(in) > maxGroupIDs {
		return nil, core.Invalid("group_ids", fmt.Sprintf("at most %d groups", maxGroupIDs))
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, g := range in {
		g = strings.TrimSpace(g)
		if !ids.Valid(ids.PrefixGroup, g) {
			return nil, core.Invalid("group_ids", fmt.Sprintf("%q is not a group id", truncate(g, 40)))
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out, nil
}

// checkPHC rejects anything that is not an argon2id PHC string.
func checkPHC(phc string) error {
	if _, err := crypt.ParsePHC(phc); err != nil {
		return core.Invalid("password", "invalid password hash")
	}
	return nil
}

// cleanGroupName validates a group name: it names the group's root folder,
// so it follows the node name rules (NFC, at most names.MaxNameBytes bytes,
// no '/', '\', control or text-direction control characters), plus a limit
// of maxGroupNameLen characters and, as for role names, no other invisible
// characters (names.IsHiddenFormat). Checking the byte limit here too gives
// long names in non-Latin scripts a group message instead of a late "name
// is longer than 255 bytes" from the root folder.
func cleanGroupName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", core.Invalid("name", "group name must not be empty")
	}
	if !utf8.ValidString(s) {
		return "", core.Invalid("name", "group name is not valid UTF-8")
	}
	s = norm.NFC.String(s) // may grow: check the limits on the stored form
	if utf8.RuneCountInString(s) > maxGroupNameLen {
		return "", core.Invalid("name", fmt.Sprintf("group name is longer than %d characters", maxGroupNameLen))
	}
	if len(s) > names.MaxNameBytes {
		return "", core.Invalid("name", "group name is too long")
	}
	if s == "." || s == ".." || strings.ContainsAny(s, `/\`) || strings.ContainsFunc(s, unicode.IsControl) ||
		strings.ContainsFunc(s, names.IsBidiControl) {
		return "", core.Invalid("name", `group name must not contain "/", "\", control or text-direction characters`)
	}
	if strings.ContainsFunc(s, names.IsHiddenFormat) {
		return "", core.Invalid("name", "group name must not contain invisible characters such as a zero-width space")
	}
	if names.LabelKey(s) == "" {
		return "", core.Invalid("name", "group name must not be empty")
	}
	return s, nil
}

// cleanDescription validates a group description or invite note.
func cleanLongText(s, field string, max int) (string, error) {
	if !utf8.ValidString(s) {
		return "", core.Invalid(field, "text is not valid UTF-8")
	}
	s = strings.TrimSpace(norm.NFC.String(s))
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) {
		return "", core.Invalid(field, "text must not contain control characters")
	}
	if utf8.RuneCountInString(s) > max {
		return "", core.Invalid(field, fmt.Sprintf("text is longer than %d characters", max))
	}
	return s, nil
}

// truncate cuts s to n bytes at a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// userFields is a validated account to insert.
type userFields struct {
	username    string
	displayName string
	email       string
	role        core.Role // the base (users.role)
	roleID      string    // the custom role (users.role_id), "" for built-in roles
	phc         string
	mustChange  bool
	quota       *int64
	groupIDs    []string
}

// validateNewUser validates and normalizes the input of Create/Bootstrap.
// The role is a built-in one here (default member); Create resolves
// in.RoleID and the final base in its transaction (resolveAssignment).
func validateNewUser(in core.NewUser) (*userFields, error) {
	f := &userFields{mustChange: in.MustChangePassword}
	var err error
	if f.username, err = CleanUsername(in.Username); err != nil {
		return nil, err
	}
	if f.displayName, err = cleanDisplayName(in.DisplayName); err != nil {
		return nil, err
	}
	if f.displayName == "" {
		f.displayName = f.username
	}
	if f.email, err = cleanEmail(in.Email); err != nil {
		return nil, err
	}
	f.role = in.Role
	if f.role == "" {
		f.role = core.RoleMember
	}
	if !f.role.Valid() {
		return nil, core.Invalid("role", "role must be owner, admin, member or guest")
	}
	if f.quota, err = cleanQuota(in.QuotaBytes, "quota_bytes"); err != nil {
		return nil, err
	}
	if f.groupIDs, err = cleanGroupIDs(in.GroupIDs); err != nil {
		return nil, err
	}
	if in.PasswordHash != "" {
		if err := checkPHC(in.PasswordHash); err != nil {
			return nil, err
		}
		f.phc = in.PasswordHash
	}
	return f, nil
}
