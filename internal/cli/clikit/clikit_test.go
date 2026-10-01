package clikit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

// referenceHash computes the content hash straight from its definition
// (DESIGN §7.3): "fp1:" + hex(SHA-256(concat(SHA-256(chunk_k)))).
func referenceHash(data []byte) string {
	outer := sha256.New()
	for off := 0; off < len(data); off += ChunkSize {
		sum := sha256.Sum256(data[off:min(off+ChunkSize, len(data))])
		outer.Write(sum[:])
	}
	return "fp1:" + hex.EncodeToString(outer.Sum(nil))
}

func TestChunkSizeIsPartSize(t *testing.T) {
	if ChunkSize != core.PartSize {
		t.Fatalf("ChunkSize %d != core.PartSize %d", ChunkSize, core.PartSize)
	}
}

func TestContentHasher(t *testing.T) {
	sizes := []int{0, 1, 65535, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2*ChunkSize + 5}
	for _, n := range sizes {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + i>>9)
		}
		want := referenceHash(data)
		// One write.
		h := NewContentHasher()
		h.Write(data)
		if h.Size() != int64(n) {
			t.Fatalf("%d: Size %d", n, h.Size())
		}
		if got := h.Sum(); got != want {
			t.Fatalf("%d: got %s want %s", n, got, want)
		}
		// Odd-sized writes crossing chunk boundaries.
		h = NewContentHasher()
		for off := 0; off < n; {
			step := min(n-off, 1+off%100003)
			h.Write(data[off : off+step])
			off += step
		}
		if got := h.Sum(); got != want {
			t.Fatalf("%d (split): got %s want %s", n, got, want)
		}
		if !ComparableContentHash(want) {
			t.Fatalf("%d: hash not comparable", n)
		}
	}
	// The empty input hashes the empty concatenation.
	empty := sha256.Sum256(nil)
	if got := NewContentHasher().Sum(); got != "fp1:"+hex.EncodeToString(empty[:]) {
		t.Fatalf("empty: %s", got)
	}
	for _, bad := range []string{"", "sha256:abc", "fp1:abc", "fp2:" + strings.Repeat("a", 64)} {
		if ComparableContentHash(bad) {
			t.Errorf("%q comparable", bad)
		}
	}
	p := filepath.Join(t.TempDir(), "f")
	data := bytes.Repeat([]byte("xyz"), 1000)
	os.WriteFile(p, data, 0o600)
	if got, err := ContentHashFile(p); err != nil || got != referenceHash(data) {
		t.Fatalf("ContentHashFile %s %v", got, err)
	}
	if _, err := ContentHashFile(p + ".missing"); err == nil {
		t.Fatal("missing file hashed")
	}
}

func TestRetry(t *testing.T) {
	b := Backoff{Initial: time.Millisecond, Max: 3 * time.Millisecond, Attempts: 4}
	transient := errors.New("transient")
	permanent := errors.New("permanent")
	retryable := func(err error) bool { return errors.Is(err, transient) }

	calls := 0
	err := Retry(context.Background(), b, retryable, func(attempt int) error {
		calls++
		if attempt != calls {
			t.Fatalf("attempt %d on call %d", attempt, calls)
		}
		if calls < 3 {
			return transient
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("success after retries: %v %d", err, calls)
	}
	calls = 0
	err = Retry(context.Background(), b, retryable, func(int) error { calls++; return transient })
	if !errors.Is(err, transient) || calls != 4 {
		t.Fatalf("exhausted: %v %d", err, calls)
	}
	calls = 0
	err = Retry(context.Background(), b, retryable, func(int) error { calls++; return permanent })
	if !errors.Is(err, permanent) || calls != 1 {
		t.Fatalf("permanent: %v %d", err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Retry(ctx, b, retryable, func(int) error { t.Fatal("called"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled before start: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	calls = 0
	err = Retry(ctx, Backoff{Initial: time.Hour, Attempts: 5}, nil, func(int) error {
		calls++
		cancel()
		return transient
	})
	if !errors.Is(err, transient) || calls != 1 {
		t.Fatalf("canceled while waiting: %v %d", err, calls)
	}
	if err := Retry(context.Background(), Backoff{}, nil, func(int) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestProgress(t *testing.T) {
	var buf safeBuffer
	p := NewProgress(&buf, true, "up", 1000)
	start := time.Unix(1000, 0)
	p.start = start
	p.now = func() time.Time { return start.Add(2 * time.Second) }
	p.Add(500)
	p.SetNote("1/2 files")
	line := p.Line()
	for _, want := range []string{"up [############------------]", " 50%", "500 B / 1000 B", "250 B/s", "ETA 2s", "1/2 files"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q lacks %q", line, want)
		}
	}
	p.SetTotal(0)
	if l := p.Line(); strings.Contains(l, "%") || strings.Contains(l, "ETA") {
		t.Fatalf("unknown total: %q", l)
	}
	p.SetFormat(Count)
	p.SetTotal(4)
	p.Add(-498)
	if l := p.Line(); !strings.Contains(l, "2 / 4") {
		t.Fatalf("count format: %q", l)
	}
	p.Start(time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	p.Finish()
	p.Finish()
	out := buf.String()
	if !strings.Contains(out, "\r") || !strings.HasSuffix(out, "\r\x1b[K") {
		t.Fatalf("drawn output %q", out)
	}
	// Disabled: counts, never writes.
	var quiet bytes.Buffer
	q := NewProgress(&quiet, false, "x", 10)
	q.Start(time.Millisecond)
	q.Add(3)
	q.Finish()
	if quiet.Len() != 0 || q.Done() != 3 || q.Enabled() {
		t.Fatalf("disabled progress wrote %q", quiet.String())
	}
	if Bytes(0) != "0 B" || Bytes(1536) != "1.5 KiB" || Bytes(200<<20) != "200 MiB" || Bytes(-2048) != "-2.0 KiB" {
		t.Fatalf("Bytes: %s %s %s", Bytes(1536), Bytes(200<<20), Bytes(-2048))
	}
	if shortDuration(75*time.Second) != "1m15s" || shortDuration(3*time.Hour+5*time.Minute) != "3h05m" {
		t.Fatal("shortDuration")
	}
}

func TestCountingReaderWriter(t *testing.T) {
	p := NewProgress(io.Discard, false, "", 0)
	cr := &CountingReader{R: strings.NewReader("hello world"), P: p}
	io.Copy(io.Discard, cr)
	if p.Done() != 11 {
		t.Fatalf("read %d", p.Done())
	}
	cr.Undo()
	if p.Done() != 0 {
		t.Fatalf("after undo %d", p.Done())
	}
	var out bytes.Buffer
	cw := &CountingWriter{W: &out, P: p}
	io.WriteString(cw, "abc")
	if p.Done() != 3 || out.String() != "abc" {
		t.Fatal("writer")
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestWriteMarkdown(t *testing.T) {
	root := &cobra.Command{Use: "tool", Short: "A tool"}
	root.PersistentFlags().Bool("json", false, "print JSON")
	grp := &cobra.Command{Use: "grp", Short: "Group of things", Aliases: []string{"g"},
		Example: "  tool grp sub x", Run: func(*cobra.Command, []string) {}}
	grp.PersistentFlags().String("mode", "", "group mode")
	sub := &cobra.Command{Use: "sub <arg>", Short: "Do | pipe", Long: "Long text\nwith lines.",
		Example: "    tool grp sub a\n    tool grp sub b --n 2", Run: func(*cobra.Command, []string) {}}
	sub.Flags().Int("n", 1, "how many")
	sub.Flags().StringP("out", "o", "", "output file")
	sub.Flags().Bool("secret", false, "hidden flag")
	sub.Flags().MarkHidden("secret")
	hidden := &cobra.Command{Use: "hidden", Short: "Nope", Hidden: true, Run: func(*cobra.Command, []string) {}}
	topic := &cobra.Command{Use: "topicname", Short: "A help topic", Long: "Topic text."} // not a command
	cp := &cobra.Command{Use: "cp", Short: "Copy <src>",
		Long: "Stored in <HOME>/x.\n\nPaths:\n  /Team/<group>/…   team\n  # comment",
		Run:  func(*cobra.Command, []string) {}}
	cp.Flags().String("name", "", `device name (default "<user> device")`)
	grp.AddCommand(sub, cp)
	root.AddCommand(grp, hidden, topic)

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, root, MarkdownOptions{Intro: "Intro text."}); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	for _, want := range []string{
		"# Command reference", "Intro text.", "## Contents", "- [`tool grp`](#tool-grp) — Group of things",
		"  - [`tool grp sub`](#tool-grp-sub) — Do \\| pipe", "## Global flags", "| `--json` |  |  | print JSON |",
		"## tool grp", "**Aliases:** `g`", "| [`sub`](#tool-grp-sub) | Do \\| pipe |", "### tool grp sub",
		"Do | pipe.", "Long text\nwith lines.", "tool grp sub <arg> [flags]", "| `-o, --out` | string |  | output file |",
		"| `--n` | int | `1` | how many |", "**Inherited flags**\n\n| Flag | Type | Default | Description |\n|---|---|---|---|\n| `--mode` | string |  | group mode |",
		"```sh\ntool grp sub a\ntool grp sub b --n 2\n```",
		"tool grp [flags]\ntool grp <command>",
		// Help text is escaped: placeholders are not HTML tags, and an
		// indented list keeps its layout (and its "#" lines) in a fence.
		"Copy \\<src>.", "Stored in \\<HOME>/x.", "Paths:\n```text\n/Team/<group>/…   team\n# comment\n```",
		`device name (default "\<user> device")`, "— Copy \\<src>",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q\n%s", want, md)
		}
	}
	for _, unwanted := range []string{"hidden", "--secret", "--help"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("markdown contains %q", unwanted)
		}
	}
	// Inherited flags exclude the global ones (documented once).
	if strings.Count(md, "print JSON") != 1 {
		t.Error("global flags repeated")
	}
	var again bytes.Buffer
	WriteMarkdown(&again, root, MarkdownOptions{Intro: "Intro text."})
	if again.String() != md {
		t.Error("not deterministic")
	}
	var lvl bytes.Buffer
	WriteMarkdown(&lvl, root, MarkdownOptions{Title: "CLI", BaseLevel: 3})
	if !strings.HasPrefix(lvl.String(), "## CLI\n") || !strings.Contains(lvl.String(), "\n### tool grp\n") {
		t.Errorf("base level 3:\n%s", lvl.String()[:80])
	}
}

// Help topics get their own section after the commands, with their text
// as the terminal shows it; they are not commands.
func TestMarkdownHelpTopics(t *testing.T) {
	root := &cobra.Command{Use: "tool", Short: "A tool"}
	cmd := &cobra.Command{Use: "run", Short: "Run it", Run: func(*cobra.Command, []string) {}}
	paths := &cobra.Command{Use: "paths", Short: "How to write paths",
		Long: "Paths:\n\n  /My files/…   yours\n  # not a heading\n\n  tool run <x>"}
	flags := &cobra.Command{Use: "flags", Short: "Global flags", Long: "Flags work everywhere."}
	root.AddCommand(cmd, paths, flags)
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, root, MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	topics := strings.Index(md, "\n## Help topics\n")
	if topics < 0 || topics < strings.Index(md, "\n## tool run\n") {
		t.Fatalf("no help topics section after the commands:\n%s", md)
	}
	for _, want := range []string{
		"- [Help topics](#help-topics)",
		// Sorted by name, below the section, each with its Short and its text
		// verbatim (placeholders and "#" lines too).
		"### tool help flags\n\nGlobal flags.\n\n```text\nFlags work everywhere.\n```",
		"### tool help paths\n\nHow to write paths.\n\n```text\nPaths:\n\n  /My files/…   yours\n  # not a heading\n\n  tool run <x>\n```",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q\n%s", want, md)
		}
	}
	if strings.Index(md, "### tool help flags") > strings.Index(md, "### tool help paths") {
		t.Error("topics are not sorted by name")
	}
	for _, unwanted := range []string{"## tool paths", "(#tool-paths)", "(#tool-flags)"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("a help topic is documented as a command: %q", unwanted)
		}
	}
	// No topics, no section.
	bare := &cobra.Command{Use: "tool"}
	bare.AddCommand(&cobra.Command{Use: "run", Run: func(*cobra.Command, []string) {}})
	buf.Reset()
	WriteMarkdown(&buf, bare, MarkdownOptions{})
	if strings.Contains(buf.String(), "Help topics") {
		t.Errorf("help topics section without topics:\n%s", buf.String())
	}
}

// With command groups on the root, the contents list the top-level
// commands under the group titles in group order (not by name); commands
// in a group stay sorted by name, and ungrouped ones come last.
func TestMarkdownGroupedContents(t *testing.T) {
	root := &cobra.Command{Use: "tool"}
	root.AddGroup(&cobra.Group{ID: "b", Title: "Second & more:"}, &cobra.Group{ID: "a", Title: "First:"})
	run := func(*cobra.Command, []string) {}
	zed := &cobra.Command{Use: "zed", Short: "Z", GroupID: "b", Run: run}
	zed.AddCommand(&cobra.Command{Use: "sub", Short: "S", Run: run})
	root.AddCommand(
		zed,
		&cobra.Command{Use: "alpha", Short: "A", GroupID: "b", Run: run},
		&cobra.Command{Use: "mid", Short: "M", GroupID: "a", Run: run},
		&cobra.Command{Use: "loose", Short: "L", Run: run},
		&cobra.Command{Use: "empty", Short: "E", GroupID: "none", Hidden: true, Run: run},
	)
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, root, MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	want := "- [Global flags](#global-flags)\n\n" +
		"**Second \\& more**\n\n" +
		"- [`tool alpha`](#tool-alpha) — A\n- [`tool zed`](#tool-zed) — Z\n  - [`tool zed sub`](#tool-zed-sub) — S\n\n" +
		"**First**\n\n- [`tool mid`](#tool-mid) — M\n\n" +
		"**More commands**\n\n- [`tool loose`](#tool-loose) — L\n\n## Global flags"
	if !strings.Contains(md, want) {
		t.Errorf("grouped contents:\n%s\nwant:\n%s", md, want)
	}
	// The command sections themselves stay in name order.
	if !(strings.Index(md, "## tool alpha") < strings.Index(md, "## tool loose") &&
		strings.Index(md, "## tool loose") < strings.Index(md, "## tool mid") &&
		strings.Index(md, "## tool mid") < strings.Index(md, "## tool zed")) {
		t.Errorf("command sections not in name order:\n%s", md)
	}
}

func TestMarkdownHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"fileparcel client-cert issue": "fileparcel-client-cert-issue",
		"A_b C!?":                      "a_b-c",
		"über x":                       "über-x",
	} {
		if got := Anchor(in); got != want {
			t.Errorf("Anchor(%q) = %q", in, got)
		}
	}
	if got := dedent("    a\n      b\n\n    c"); got != "a\n  b\n\nc" {
		t.Errorf("dedent %q", got)
	}
	if got := cell(" a|b\nc "); got != `a\|b c` {
		t.Errorf("cell %q", got)
	}
	if got := cell(`a <b> c & d\e *`); got != `a \<b> c \& d\\e \*` {
		t.Errorf("cell escaping %q", got)
	}
	if got := mdLong("Plain <x>.\n# not a heading\n\nList:\n  a   one\n\n    b <y>\n\nAfter."); got !=
		"Plain \\<x>.\n\\# not a heading\n\nList:\n```text\na   one\n\n  b <y>\n```\n\nAfter." {
		t.Errorf("mdLong %q", got)
	}
	if ensurePeriod("x") != "x." || ensurePeriod("y?") != "y?" || ensurePeriod("") != "" {
		t.Error("ensurePeriod")
	}
}

// The redrawn line must fit on one terminal row ("\r" only returns to the
// start of the last row, so a wrapped line leaves a stale row per redraw):
// the label and the amounts stay, the bar, rate, ETA and note follow as far
// as they fit, and a label too long for the row is shortened.
func TestProgressFitsTerminalWidth(t *testing.T) {
	var buf safeBuffer
	p := NewProgress(&buf, true, "uploading", 3400<<20)
	start := time.Unix(1000, 0)
	p.start = start
	p.now = func() time.Time { return start.Add(40 * time.Second) }
	p.Add(1200 << 20)
	p.SetNote("3/10 files")
	full := p.Line()
	if cols(full) <= 79 {
		t.Fatalf("test line too short to matter: %q", full)
	}
	if got := p.fit(0); got != full {
		t.Fatalf("unknown width changed the line: %q", got)
	}
	for _, width := range []int{80, 60, 40, 20, 8} {
		p.cols = func() int { return width }
		p.draw()
		p.draw()
		for _, seg := range strings.Split(buf.String(), "\r")[1:] {
			seg = strings.TrimSuffix(seg, "\x1b[K")
			if n := cols(seg); n > width-1 {
				t.Errorf("width %d: %q is %d columns", width, seg, n)
			}
		}
		buf = safeBuffer{}
	}
	at80 := p.fit(79)
	if strings.Contains(at80, "files") || !strings.Contains(at80, "[") || !strings.Contains(at80, "GiB / 3.3 GiB") {
		t.Errorf("width 80 should drop the note but keep the bar and amounts: %q", at80)
	}
	at60 := p.fit(59)
	if strings.Contains(at60, "[") || !strings.Contains(at60, "MiB/s") || !strings.Contains(at60, "ETA") {
		t.Errorf("width 60 should give up the bar for the rate and ETA: %q", at60)
	}
	at40 := p.fit(39)
	if !strings.Contains(at40, "35%") || strings.Contains(at40, "[") {
		t.Errorf("width 40 should keep the amounts, not the bar: %q", at40)
	}

	// A long (and wide) file name is shortened before the amounts are cut.
	q := NewProgress(&buf, true, "報告書-最終版-2026年度-第二四半期.pdf", 100)
	q.Add(45)
	got := q.fit(39)
	if cols(got) > 39 || !strings.Contains(got, "45%  45 B / 100 B") || !strings.Contains(got, "…") {
		t.Errorf("long label: %q (%d columns)", got, cols(got))
	}
	if cutCols("abcdef", 4) != "abc…" || cutCols("ab", 4) != "ab" || cols("日本") != 4 {
		t.Error("cutCols/cols")
	}
}
