// Package names implements the file and folder name rules of DESIGN §6 and
// the relative-path rules of the upload protocol (§8.1), so that files
// (commit, mkdir, rename) and uploads (batch validation) can never disagree
// about which names are valid:
//
//   - names are NFC-normalized, 1–255 bytes of UTF-8;
//   - no "/", "\", NUL or other control characters; not "." or "..";
//   - no bidirectional embedding, override or isolate characters
//     (IsBidiControl), which could make "invoice\u202Efdp.exe" display as
//     "invoiceexe.pdf";
//   - no leading/trailing spaces: Clean trims U+0020 at both ends (it does
//     not reject), so " a.txt" from a user's disk becomes "a.txt";
//   - trailing dots are allowed (Windows-unsafe, see TrailingDot);
//   - uniqueness is case-insensitive: Key = NFC(casefold(NFC(name))), stored
//     in nodes.name_key.
//
// Relative paths ("Trip/day1/a.jpg") are at most 4096 bytes and 64 segments
// deep, never absolute, never contain "." or ".." segments; every segment
// follows the name rules.
//
// mime.go derives the stored media type of a file from its name and a sniff
// of its first bytes (DetectMIME, MIMEFromName; DESIGN §8.2).
//
// Leaf utility (imports only core, the standard library and x/text):
// importable by any package, like qr. Owned by unit D.
package names

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"fileparcel/internal/core"
)

// Limits (DESIGN §6, §8.1).
const (
	MaxNameBytes = 255
	MaxPathBytes = 4096
	MaxDepth     = 64
)

// Clean validates and normalizes one name. It returns the NFC form to store
// in nodes.name, its uniqueness key for nodes.name_key, or a 422 error
// (core.Invalid on field "name").
func Clean(name string) (nfc, key string, err error) {
	nfc, err = clean(name)
	if err != nil {
		return "", "", core.Invalid("name", err.Error())
	}
	return nfc, Key(nfc), nil
}

func clean(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("name is not valid UTF-8")
	}
	s := strings.Trim(norm.NFC.String(name), " ")
	switch {
	case s == "":
		return "", fmt.Errorf("name must not be empty")
	case len(s) > MaxNameBytes:
		return "", fmt.Errorf("name is longer than %d bytes", MaxNameBytes)
	case s == "." || s == "..":
		return "", fmt.Errorf("name must not be %q", s)
	}
	for _, r := range s {
		switch {
		case r == '/' || r == '\\':
			return "", fmt.Errorf("name must not contain %q", r)
		case r == 0 || unicode.IsControl(r):
			return "", fmt.Errorf("name must not contain control characters")
		case IsBidiControl(r):
			return "", fmt.Errorf("name must not contain text-direction control characters")
		}
	}
	return s, nil
}

// IsBidiControl reports whether r is an explicit bidirectional embedding,
// override or isolate character (U+202A–U+202E, U+2066–U+2069). They are
// format characters (Cf), not controls, so unicode.IsControl misses them,
// yet they reorder the text that follows: "invoice\u202Efdp.exe" displays
// as "invoiceexe.pdf". Names reject them. The implicit marks LRM, RLM and ALM
// (U+200E, U+200F, U+061C) stay allowed: they act only as one strong
// character, cannot reverse a Latin run such as an extension, and occur in
// real right-to-left file names.
func IsBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// IsHiddenFormat reports whether r is an invisible format character (Unicode
// category Cf) that a label people pick from a list — a role, group or
// display name — must not contain: the zero-width space U+200B, the word
// joiner U+2060, the byte order mark U+FEFF, the soft hyphen U+00AD, the
// text-direction controls (IsBidiControl) and the rest of Cf. They render as
// nothing, so "finance\u200B" looks exactly like "finance", and a name made
// of a single U+2060 like no name at all. The joiners ZWNJ and ZWJ (U+200C,
// U+200D: Persian and Indic scripts, emoji sequences) and the implicit
// direction marks LRM, RLM and ALM (U+200E, U+200F, U+061C; see
// IsBidiControl) stay allowed; LabelKey ignores them when labels are
// compared. File and folder names keep their own rules (Clean).
func IsHiddenFormat(r rune) bool {
	if isLabelMark(r) {
		return false
	}
	return unicode.Is(unicode.Cf, r)
}

// isLabelMark reports whether r is one of the format characters labels may
// contain (IsHiddenFormat): ZWNJ, ZWJ, LRM, RLM, ALM.
func isLabelMark(r rune) bool {
	switch r {
	case 0x200C, 0x200D, 0x200E, 0x200F, 0x061C:
		return true
	}
	return false
}

// LabelKey is the uniqueness key of a label (role and group names): Key of
// the label without the joiners and direction marks IsHiddenFormat allows,
// so "finance\u200D" and "finance" are the same name, and a label made of
// nothing else has the key "" (an empty name).
func LabelKey(name string) string {
	return Key(strings.Map(func(r rune) rune {
		if isLabelMark(r) {
			return -1
		}
		return r
	}, name))
}

// Key returns the case-insensitive uniqueness key of a (clean) name:
// NFC(casefold(NFC(name))). Use it for nodes.name_key and every name
// comparison.
func Key(name string) string {
	// cases.Caser is stateful: create one per call (cheap) instead of sharing.
	return norm.NFC.String(cases.Fold().String(norm.NFC.String(name)))
}

// SplitRelPath validates an upload rel_path ("Trip/day1/a.jpg") and returns
// its cleaned segments (NFC; see Clean). One trailing "/" is tolerated
// (directory entries). Errors are core.Invalid on field "rel_path".
func SplitRelPath(p string) ([]string, error) {
	bad := func(format string, a ...any) ([]string, error) {
		return nil, core.Invalid("rel_path", fmt.Sprintf(format, a...))
	}
	switch {
	case p == "":
		return bad("path must not be empty")
	case len(p) > MaxPathBytes:
		return bad("path is longer than %d bytes", MaxPathBytes)
	case !utf8.ValidString(p):
		return bad("path is not valid UTF-8")
	case strings.HasPrefix(p, "/"):
		return bad("path must be relative")
	}
	p = strings.TrimSuffix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) > MaxDepth {
		return bad("path is deeper than %d levels", MaxDepth)
	}
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		switch seg {
		case "":
			return bad("path contains an empty segment")
		case ".", "..":
			return bad("path must not contain %q", seg)
		}
		c, err := clean(seg)
		if err != nil {
			return bad("%s: %v", strconv.Quote(seg), err)
		}
		out = append(out, c)
	}
	return out, nil
}

// Numbered returns the n-th conflict-free variant of name (DESIGN §6
// conflict policy "rename"): "name (n).ext" for files, "name (n)" for
// folders. n <= 0 returns name. A leading dot does not start an extension
// (".bashrc" → ".bashrc (1)"). The base is shortened (at a rune boundary) so
// the result stays within MaxNameBytes — but never below its first rune:
// against an absurdly long extension the extension is shortened instead, so
// the result always keeps something of both. The result never starts or ends
// with a space, the rule Clean enforces everywhere else.
func Numbered(name string, n int, isDir bool) string {
	if n <= 0 {
		return name
	}
	base, ext := name, ""
	if !isDir {
		if i := strings.LastIndexByte(name, '.'); i > 0 {
			base, ext = name[:i], name[i:]
		}
	}
	suffix := " (" + strconv.Itoa(n) + ")"
	for len(base)+len(suffix)+len(ext) > MaxNameBytes {
		_, size := utf8.DecodeLastRuneInString(base)
		if size == 0 || size == len(base) {
			break // keep the first rune of what the user called the file
		}
		base = base[:len(base)-size]
	}
	for len(base)+len(suffix)+len(ext) > MaxNameBytes { // absurdly long extension
		_, size := utf8.DecodeLastRuneInString(ext)
		if size == 0 {
			break
		}
		ext = ext[:len(ext)-size]
	}
	return strings.Trim(base+suffix+ext, " ")
}

// TrailingDot reports whether name ends with a dot, which Windows strips
// (allowed; callers may show a portability warning).
func TrailingDot(name string) bool { return strings.HasSuffix(name, ".") }
