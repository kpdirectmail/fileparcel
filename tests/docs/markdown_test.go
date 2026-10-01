package docs_test

// Markdown checks that are about how GitHub renders the documents, and a few
// numbers the prose repeats from the code.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/ziputil"
)

// codeSpans returns the contents of the inline code spans of one line
// (backtick runs of equal length; a backslash escapes the next character
// outside a span).
func codeSpans(line string) []string {
	var out []string
	for i := 0; i < len(line); {
		switch line[i] {
		case '\\':
			i += 2
			continue
		case '`':
		default:
			i++
			continue
		}
		j := i
		for j < len(line) && line[j] == '`' {
			j++
		}
		run := line[i:j]
		end := -1
		for k := j; k+len(run) <= len(line); k++ {
			if line[k:k+len(run)] == run && (k+len(run) == len(line) || line[k+len(run)] != '`') && line[k-1] != '`' {
				end = k
				break
			}
		}
		if end < 0 {
			i = j
			continue
		}
		out = append(out, line[j:end])
		i = end + len(run)
	}
	return out
}

// unescapedPipe reports whether s holds a "|" that no backslash escapes.
func unescapedPipe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' && (i == 0 || s[i-1] != '\\') {
			return true
		}
	}
	return false
}

// TestTableCodeSpansEscapePipes: GitHub splits a table row into cells at every
// unescaped "|" before it looks at code spans, so a `a|b` inside a table cell
// cuts the cell (and drops the rest of the row). Inside tables a pipe in code
// is written `a\|b`, which GitHub shows as a|b.
func TestTableCodeSpansEscapePipes(t *testing.T) {
	docs, err := filepath.Glob(filepath.Join(repoRoot(t), "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append(docs, filepath.Join(repoRoot(t), "README.md")) {
		rel, _ := filepath.Rel(repoRoot(t), p)
		rel = filepath.ToSlash(rel)
		fence := false
		for n, line := range strings.Split(read(t, rel), "\n") {
			trimmed := strings.TrimLeft(line, " \t")
			if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
				fence = !fence
				continue
			}
			if fence || !strings.HasPrefix(trimmed, "|") {
				continue
			}
			for _, span := range codeSpans(line) {
				if unescapedPipe(span) {
					t.Errorf("%s:%d: the code span `%s` in a table has an unescaped |; write \\| (GitHub splits the cell there)", rel, n+1, span)
				}
			}
		}
	}
}

func TestCodeSpans(t *testing.T) {
	got := codeSpans("| `a\\|b` | x ``c`d`` \\`e | `f")
	want := []string{"a\\|b", "c`d"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("codeSpans = %q, want %q", got, want)
	}
	if !unescapedPipe("a|b") || unescapedPipe("a\\|b") {
		t.Fatal("unescapedPipe")
	}
}

// TestZipPasswordMaxDocumented: the documents give the longest .zip password
// ziputil accepts (7-Zip cannot open a longer AES-256 one).
func TestZipPasswordMaxDocumented(t *testing.T) {
	n := fmt.Sprint(ziputil.MaxPasswordLen)
	mustContain(t, "docs/SECURITY.md", oneLine(read(t, "docs/SECURITY.md")), "up to "+n+",",
		"ziputil.MaxPasswordLen bounds a .zip password.")
	mustContain(t, "docs/FILEPARCEL.md", oneLine(manualProse(t)), "at most "+n+" (",
		"ziputil.MaxPasswordLen bounds a .zip password.")
	mustContain(t, "docs/COMMANDS.md", oneLine(read(t, "docs/COMMANDS.md")), "at most "+n+",",
		"ziputil.MaxPasswordLen bounds a .zip password.")
}
