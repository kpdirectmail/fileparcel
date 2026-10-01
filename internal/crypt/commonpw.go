package crypt

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// commonPasswordsTxt is the embedded common-password list (commonpw.txt:
// the most frequent entries of the zxcvbn frequency list, docs/THIRD_PARTY.md).
//
//go:embed commonpw.txt
var commonPasswordsTxt string

var (
	commonOnce sync.Once
	commonSet  map[string]struct{}
)

// commonPasswords returns the embedded list (lowercase) as a set.
func commonPasswords() map[string]struct{} {
	commonOnce.Do(func() {
		commonSet = make(map[string]struct{}, 2048)
		sc := bufio.NewScanner(strings.NewReader(commonPasswordsTxt))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			commonSet[strings.ToLower(line)] = struct{}{}
		}
	})
	return commonSet
}

// maxAffixLen bounds the digits/symbols stripped around a common word
// ("Password2024!" → "password").
const maxAffixLen = 6

// leet undoes common character substitutions.
var leet = strings.NewReplacer("@", "a", "4", "a", "3", "e", "1", "i", "!", "i", "0", "o", "$", "s", "5", "s", "7", "t", "+", "t")

// IsCommonPassword reports whether pw is (a trivial variation of) one of the
// embedded common passwords: also after lowercasing, removing spaces,
// undoing common letter substitutions ("p@ssw0rd") and stripping up to 6
// leading/trailing digits and symbols ("Summer2024!"). It serves the account
// password policy (auth) and the .zip passwords of uploads (uploads).
func IsCommonPassword(pw string) bool {
	set := commonPasswords()
	lower := strings.ToLower(strings.TrimSpace(pw))
	candidates := []string{lower, strings.ReplaceAll(lower, " ", "")}
	if core := stripAffixes(lower); core != lower {
		candidates = append(candidates, core)
	}
	for _, c := range append([]string(nil), candidates...) {
		candidates = append(candidates, leet.Replace(c))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, ok := set[c]; ok {
			return true
		}
		// "password" + "2024!": check the core with digits/symbols removed at
		// both ends (after the substitution pass, "p4ssw0rd99" → "password99").
		if core := stripAffixes(c); core != c && core != "" {
			if _, ok := set[core]; ok {
				return true
			}
		}
	}
	return false
}

// stripAffixes removes up to maxAffixLen digits/symbols from each end.
func stripAffixes(s string) string {
	isAffix := func(r rune) bool { return !unicode.IsLetter(r) }
	trim := func(s string, fromEnd bool) string {
		for i := 0; i < maxAffixLen && s != ""; i++ {
			var r rune
			var size int
			if fromEnd {
				r, size = utf8.DecodeLastRuneInString(s)
			} else {
				r, size = utf8.DecodeRuneInString(s)
			}
			if !isAffix(r) {
				break
			}
			if fromEnd {
				s = s[:len(s)-size]
			} else {
				s = s[size:]
			}
		}
		return s
	}
	return trim(trim(s, true), false)
}
