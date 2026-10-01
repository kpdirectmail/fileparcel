package ziputil

import (
	"archive/zip"
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCollisionsAndMethods(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(&buf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	mod := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	must(t, w.AddFile("a", mod, 1, strings.NewReader("1")))
	must(t, w.AddFile("a/b.txt", mod, 2, strings.NewReader("22"))) // parent "a" is a file → "a (1)/"
	must(t, w.AddFile("A/c.txt", mod, 1, strings.NewReader("3")))  // same renamed dir, case-insensitive
	must(t, w.AddDir("x", mod))
	must(t, w.AddDir("X", mod)) // duplicate dir: no second entry
	must(t, w.AddFile("big.txt", mod, 1000, strings.NewReader(strings.Repeat("z", 1000))))
	must(t, w.Close())
	if err := w.AddDir("late", mod); err == nil {
		t.Fatal("write after Close accepted")
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	methods := map[string]uint16{}
	for _, f := range zr.File {
		got = append(got, f.Name)
		methods[f.Name] = f.Method
		if !f.Modified.Equal(mod) && !strings.HasSuffix(f.Name, "/") {
			t.Errorf("%s modified %v", f.Name, f.Modified)
		}
	}
	sort.Strings(got)
	want := "a,a (1)/b.txt,a (1)/c.txt,big.txt,x/"
	if strings.Join(got, ",") != want {
		t.Fatalf("entries %v, want %s", got, want)
	}
	if methods["big.txt"] != zip.Deflate {
		t.Errorf("txt should be deflated")
	}
}

// TestRenamedDirNeverMerges pins that a directory renamed because a file
// holds its name gets a numbered name nothing else uses: it used to reuse an
// existing folder of that name and mix the two folders' contents.
func TestRenamedDirNeverMerges(t *testing.T) {
	mod := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, c := range []struct {
		name string
		add  []string // "d:" adds a directory, anything else a file
		want string
	}{
		{"existing numbered dir", []string{"report", "report (1)/x.txt", "report/x.txt", "report/y.txt", "REPORT/z.txt"},
			"report,report (1)/x.txt,report (2)/x.txt,report (2)/y.txt,report (2)/z.txt"},
		{"numbered dir after the rename", []string{"report", "report/x.txt", "report (1)/y.txt", "report/w.txt", "report (1)/v.txt"},
			"report,report (1) (1)/v.txt,report (1) (1)/y.txt,report (1)/w.txt,report (1)/x.txt"},
		{"nested", []string{"a", "a/b", "a/b/c.txt", "a (1)/b/d.txt"},
			"a,a (1) (1)/b/d.txt,a (1)/b,a (1)/b (1)/c.txt"},
		{"directory entry", []string{"report", "report/x.txt", "d:report (1)", "d:report"},
			"report,report (1) (1)/,report (1)/,report (1)/x.txt"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			w, err := New(&buf, Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range c.add {
				if d, ok := strings.CutPrefix(p, "d:"); ok {
					must(t, w.AddDir(d, mod))
				} else {
					must(t, w.AddFile(p, mod, 1, strings.NewReader("x")))
				}
			}
			must(t, w.Close())
			zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range zr.File {
				got = append(got, f.Name)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != c.want {
				t.Fatalf("entries %v, want %s", got, c.want)
			}
		})
	}
}

func TestBadOptions(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, Options{Format: "rar"}); err == nil {
		t.Fatal("unknown format accepted")
	}
	if _, err := New(&bytes.Buffer{}, Options{Compression: "max"}); err == nil {
		t.Fatal("unknown compression accepted")
	}
}
