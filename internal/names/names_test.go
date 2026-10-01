package names

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"fileparcel/internal/core"
)

func TestClean(t *testing.T) {
	ok := map[string]string{
		"a.txt":                  "a.txt",
		"  spaced  ":             "spaced",
		"e\u0301t\u00e9":         "\u00e9t\u00e9", // NFD → NFC
		"trailing.":              "trailing.",
		"...":                    "...",
		strings.Repeat("x", 255): strings.Repeat("x", 255),
	}
	// Implicit direction marks (RLM, LRM, ALM), joiners (ZWJ, ZWNJ) and
	// emoji tag characters are format characters too, but not bidi
	// overrides: real names carry them.
	for _, in := range []string{"\u05e9\u05dc\u05d5\u05dd\u200f.txt", "a\u200eb\u061cc",
		"\U0001F469\u200d\U0001F4BB.txt", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645.txt",
		"\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"} {
		ok[in] = in
	}
	for in, want := range ok {
		got, key, err := Clean(in)
		if err != nil || got != want || key == "" {
			t.Errorf("Clean(%q) = %q %q %v, want %q", in, got, key, err, want)
		}
	}
	for _, in := range []string{"", "   ", ".", "..", "a/b", `a\b`, "a\x00b", "a\tb", "a\x7fb", "\xff",
		strings.Repeat("x", 256), strings.Repeat("é", 128), "a\u0085b",
		// Bidi embeddings, overrides and isolates reorder what follows them:
		// "invoice\u202efdp.exe" displays as "invoiceexe.pdf".
		"invoice\u202efdp.exe", "a\u202ab", "a\u202bb", "a\u202cb", "a\u202db",
		"a\u2066b\u2069.txt", "a\u2067b", "a\u2068b", "\u2069"} {
		if _, _, err := Clean(in); err == nil || !errors.Is(err, core.ErrInvalid) || core.AsError(err).Field != "name" {
			t.Errorf("Clean(%q) accepted or wrong error: %v", in, err)
		}
	}
}

// IsBidiControl is Unicode's Bidi_Control set without the implicit marks.
func TestIsBidiControl(t *testing.T) {
	marks := map[rune]bool{0x061C: true, 0x200E: true, 0x200F: true}
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		want := unicode.Is(unicode.Bidi_Control, r) && !marks[r]
		if IsBidiControl(r) != want {
			t.Errorf("IsBidiControl(%U) = %v", r, !want)
		}
		if want {
			n++
		}
	}
	if n != 9 {
		t.Fatalf("%d bidi controls, want 9", n)
	}
}

func TestKey(t *testing.T) {
	if Key("Straße") != Key("STRASSE") || Key("É") != Key("é") || Key("a") == Key("b") {
		t.Fatal("case folding / normalization")
	}
}

func TestSplitRelPath(t *testing.T) {
	got, err := SplitRelPath("Trip/day1/ a.jpg")
	if err != nil || strings.Join(got, "|") != "Trip|day1|a.jpg" {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := SplitRelPath("Trip/empty/"); err != nil || len(got) != 2 {
		t.Fatalf("trailing slash: %v %v", got, err)
	}
	deep := strings.TrimSuffix(strings.Repeat("d/", MaxDepth), "/")
	if _, err := SplitRelPath(deep); err != nil {
		t.Fatalf("max depth rejected: %v", err)
	}
	for _, in := range []string{"", "/abs", "a/../b", "..", "./a", "a//b", "a/./b", deep + "/x",
		strings.Repeat("a", MaxPathBytes+1), "a/b\\c", "a/\x01", "dir/invoice\u202efdp.exe", "a\u2067b/c"} {
		if _, err := SplitRelPath(in); err == nil || core.AsError(err).Field != "rel_path" {
			t.Errorf("SplitRelPath(%q) accepted or wrong error: %v", in, err)
		}
	}
}

func TestNumbered(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		dir  bool
		want string
	}{
		{"a.txt", 1, false, "a (1).txt"},
		{"a.txt", 0, false, "a.txt"},
		{"archive.tar.gz", 2, false, "archive.tar (2).gz"},
		{".bashrc", 1, false, ".bashrc (1)"},
		{"photos.2024", 3, true, "photos.2024 (3)"},
		{"noext", 1, false, "noext (1)"},
	}
	for _, c := range cases {
		if got := Numbered(c.in, c.n, c.dir); got != c.want {
			t.Errorf("Numbered(%q,%d,%v) = %q, want %q", c.in, c.n, c.dir, got, c.want)
		}
	}
	long := strings.Repeat("é", 127) + ".txt" // 258 bytes before numbering
	if got := Numbered(long, 12, false); len(got) > MaxNameBytes || !strings.HasSuffix(got, " (12).txt") {
		t.Fatalf("long: %d %q", len(got), got)
	}
	// An extension longer than the whole budget must not eat the name: the
	// result used to be just " (1)" — a leading space, no name, no
	// extension, and a name Clean itself would rewrite.
	huge := []struct {
		in  string
		n   int
		dir bool
	}{
		{"a." + strings.Repeat("x", 253), 1, false},
		{"é." + strings.Repeat("x", 300), 7, false},
		{strings.Repeat("x", 300), 3, false},
		{strings.Repeat("x", 300), 3, true},
		{"." + strings.Repeat("x", 300), 1, false},
	}
	for _, c := range huge {
		got := Numbered(c.in, c.n, c.dir)
		suffix := " (" + strconv.Itoa(c.n) + ")"
		switch {
		case len(got) > MaxNameBytes:
			t.Errorf("Numbered(%d bytes, %d) = %d bytes", len(c.in), c.n, len(got))
		case got != strings.Trim(got, " "):
			t.Errorf("Numbered(%d bytes, %d) = %q: leading or trailing space", len(c.in), c.n, got)
		case !strings.HasPrefix(got, c.in[:1]):
			t.Errorf("Numbered(%q…, %d) = %q: the name itself is gone", c.in[:8], c.n, got)
		case !strings.Contains(got, suffix):
			t.Errorf("Numbered(%d bytes, %d) = %q: no %q", len(c.in), c.n, got, suffix)
		}
		if _, _, err := Clean(got); err != nil {
			t.Errorf("Numbered(%d bytes, %d) = %q: Clean refuses it: %v", len(c.in), c.n, got, err)
		}
	}
}
