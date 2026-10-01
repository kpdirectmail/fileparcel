package ziputil

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestZipRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(&buf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	mod := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	must(t, w.AddDir("Trip/empty", mod))
	must(t, w.AddFile("Trip/day1/notes.txt", mod, 11, strings.NewReader("hello world")))
	must(t, w.AddFile("Trip/day1/Notes.txt", mod, 3, strings.NewReader("dup")))
	must(t, w.AddFile("../../etc/passwd", mod, 1, strings.NewReader("x")))
	must(t, w.AddFile("photo.JPG", mod, 4, strings.NewReader("jpeg")))
	must(t, w.AddFile("ünïcødé ✓.md", mod, 2, strings.NewReader("ok")))
	must(t, w.Close())
	if w.Written() != int64(buf.Len()) {
		t.Fatalf("Written %d != %d", w.Written(), buf.Len())
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	methods := map[string]uint16{}
	for _, f := range zr.File {
		methods[f.Name] = f.Method
		if strings.HasSuffix(f.Name, "/") {
			got[f.Name] = "<dir>"
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(b)
	}
	want := map[string]string{
		"Trip/empty/":             "<dir>",
		"Trip/day1/notes.txt":     "hello world",
		"Trip/day1/Notes (1).txt": "dup",
		"etc/passwd":              "x",
		"photo.JPG":               "jpeg",
		"ünïcødé ✓.md":            "ok",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("entry %q = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if methods["photo.JPG"] != zip.Store {
		t.Errorf("jpg should be stored")
	}
}

func TestSizeMismatch(t *testing.T) {
	w, _ := New(io.Discard, Options{Compression: CompressionStore})
	if err := w.AddFile("a", time.Time{}, 5, strings.NewReader("abc")); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("short: %v", err)
	}
	w2, _ := New(io.Discard, Options{Compression: CompressionStore})
	if err := w2.AddFile("a", time.Time{}, 2, strings.NewReader("abc")); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("long: %v", err)
	}
}

func TestTar(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(&buf, Options{Format: FormatTar})
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.AddDir("d", time.Now()))
	must(t, w.AddFile("d/f.txt", time.Now(), 3, strings.NewReader("abc")))
	must(t, w.Close())
	tr := tar.NewReader(&buf)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if strings.Join(names, ",") != "d/,d/f.txt" {
		t.Fatalf("names %v", names)
	}
}

func TestSanitizePath(t *testing.T) {
	cases := map[string]string{
		"/a/b":         "a/b",
		"a/../b":       "a/b",
		`a\b`:          "a_b",
		"./x/./y":      "x/y",
		"a/\x01b":      "a/_b",
		"..":           "",
		"  spaced  /f": "spaced/f",
	}
	for in, want := range cases {
		if got := SanitizePath(in); got != want {
			t.Errorf("SanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
