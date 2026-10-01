package auth

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// minDistinctRunes rejects passwords such as "aaaaaaaaaaaa" or "abababababab".
const minDistinctRunes = 4

// CheckPasswordPolicy implements core.Auth. A password must:
//   - be valid UTF-8 without control characters, at most MaxPasswordBytes;
//   - have at least auth.password_min characters (runes);
//   - not equal or contain the username or the local part of the e-mail
//     address (case-insensitive; only for names of 3+ characters);
//   - use at least 4 distinct characters;
//   - not be one of the ~2000 most common passwords (crypt/commonpw.txt), also
//     after lowercasing, undoing common letter substitutions ("p@ssw0rd") and
//     stripping up to 6 leading/trailing digits and symbols ("Summer2024!").
//
// Violations are 422 invalid errors on the field "password".
func (s *Service) CheckPasswordPolicy(pw string, u *core.User) error {
	return s.checkPolicy(pw, u, "password")
}

// CheckDefaultPasswordPolicy applies the password policy with the default
// settings (auth.password_min = DefaultPasswordMin), for callers without a
// service: the installer checks an owner password before it changes
// anything, so that a dry run is a reliable preview.
func CheckDefaultPasswordPolicy(pw string, u *core.User) error {
	return (&Service{env: &core.Env{}}).checkPolicy(pw, u, "password")
}

func (s *Service) checkPolicy(pw string, u *core.User, field string) error {
	if !utf8.ValidString(pw) {
		return core.Invalid(field, "the password contains invalid characters")
	}
	if len(pw) > MaxPasswordBytes {
		return core.Invalid(field, fmt.Sprintf("the password must be at most %d bytes long", MaxPasswordBytes))
	}
	for _, r := range pw {
		if unicode.IsControl(r) {
			return core.Invalid(field, "the password must not contain control characters")
		}
	}
	min := s.settingInt("auth.password_min", DefaultPasswordMin)
	if n := utf8.RuneCountInString(pw); int64(n) < min {
		return core.Invalid(field, fmt.Sprintf("the password must be at least %d characters long", min))
	}
	lower := strings.ToLower(pw)
	if u != nil {
		if name := strings.ToLower(strings.TrimSpace(u.Username)); name != "" &&
			(lower == name || (utf8.RuneCountInString(name) >= 3 && strings.Contains(lower, name))) {
			return core.Invalid(field, "the password must not contain your username")
		}
		if local, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(u.Email)), "@"); ok &&
			utf8.RuneCountInString(local) >= 3 && strings.Contains(lower, local) {
			return core.Invalid(field, "the password must not contain your e-mail address")
		}
	}
	if distinctRunes(lower) < minDistinctRunes {
		return core.Invalid(field, "the password is too simple; use more different characters")
	}
	if IsCommonPassword(pw) {
		return core.Invalid(field, "this password is too common; choose something less predictable (a short sentence works well)")
	}
	return nil
}

func distinctRunes(s string) int {
	seen := map[rune]struct{}{}
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}

// IsCommonPassword reports whether pw is (a trivial variation of) one of the
// embedded common passwords (crypt.IsCommonPassword, which holds the list).
func IsCommonPassword(pw string) bool { return crypt.IsCommonPassword(pw) }
