package jobs

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateUTF8(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcdef", 3, "abc"},
		{"aé", 2, "a"},   // é is 2 bytes: never split it
		{"aé", 3, "aé"},  // fits exactly
		{"€€", 4, "€"},   // € is 3 bytes
		{"€€", 2, ""},    // no whole rune fits
		{"x😀y", 4, "x"},  // 4-byte rune
		{"x😀y", 5, "x😀"}, // rune fits
		{"abc", 0, ""},
	}
	for _, c := range cases {
		got := truncateUTF8(c.in, c.n)
		if got != c.want || !utf8.ValidString(got) || len(got) > max(c.n, 0) && c.n < len(c.in) {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
	long := strings.Repeat("é", maxErrorLen) // 2 bytes each
	msg := errorMessage(errors.New(long))
	if !utf8.ValidString(msg) || len(msg) > maxErrorLen+len("…") || !strings.HasSuffix(msg, "…") {
		t.Fatalf("errorMessage: invalid or too long (%d bytes)", len(msg))
	}
	rj := &runningJob{}
	rj.Progress(1, 2, strings.Repeat("€", maxNoteLen))
	if !utf8.ValidString(rj.note) || len(rj.note) > maxNoteLen || !rj.dirty {
		t.Fatalf("progress note: invalid or too long (%d bytes)", len(rj.note))
	}
}
