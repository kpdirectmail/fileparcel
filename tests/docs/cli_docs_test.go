package docs_test

// Checks that keep the documentation of the command line from drifting
// (DESIGN §12, §17):
//
//   - TestCLIReferenceUpToDate: the generated command reference in
//     docs/COMMANDS.md is exactly what scripts/gen-cli-docs.sh would write
//     now, so "go test ./..." catches a help text changed without
//     regenerating it; no other document carries a copy of it.
//   - TestDocsUseCanonicalCommands: documents, web pages, Go strings and the
//     install scripts name commands and flags by their current names, never
//     by the old ones that only keep working for existing scripts
//     (internal/cli/legacy.go).

import (
	"bytes"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"fileparcel/internal/cli"
)

// cliDoc is the document that holds the generated command reference.
const cliDoc = "docs/COMMANDS.md"

// Markers of the generated command reference in docs/COMMANDS.md (the
// ones scripts/gen-cli-docs.sh splices between).
const (
	cliBegin   = "<!-- BEGIN GENERATED CLI REFERENCE -->"
	cliEnd     = "<!-- END GENERATED CLI REFERENCE -->"
	cliComment = "<!-- Regenerate with scripts/gen-cli-docs.sh; edit the command help texts in internal/cli instead. -->"
)

// generatedReference is what scripts/gen-cli-docs.sh puts between the
// markers: its comment line, a blank line, "fileparcel docs --markdown"
// with every heading outside fenced code one level down, and a blank line.
func generatedReference(t *testing.T) string {
	t.Helper()
	root := cli.NewRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs([]string{"docs", "--markdown"})
	if err := root.Execute(); err != nil {
		t.Fatalf("fileparcel docs --markdown: %v\n%s", err, errb.String())
	}
	var b strings.Builder
	b.WriteString(cliComment + "\n\n")
	fence := false
	heading := regexp.MustCompile(`^(#{1,5}) `)
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~"):
			fence = !fence
		case !fence && heading.MatchString(line):
			line = "#" + line
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

func TestCLIReferenceUpToDate(t *testing.T) {
	// One copy only: the manual and the other documents link to it.
	docs, err := filepath.Glob(filepath.Join(repoRoot(t), "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append(docs, filepath.Join(repoRoot(t), "README.md")) {
		rel, _ := filepath.Rel(repoRoot(t), p)
		if rel = filepath.ToSlash(rel); rel != cliDoc && strings.Contains(read(t, rel), cliBegin) {
			t.Errorf("%s carries a generated command reference; it belongs in %s only (link to it instead)", rel, cliDoc)
		}
	}

	doc := read(t, cliDoc)
	_, rest, ok := strings.Cut(doc, cliBegin+"\n")
	if !ok {
		t.Fatalf("%s has no line %s", cliDoc, cliBegin)
	}
	have, _, ok := strings.Cut(rest, cliEnd)
	if !ok {
		t.Fatalf("%s has no line %s", cliDoc, cliEnd)
	}
	want := generatedReference(t)
	if have == want {
		return
	}
	hl, wl := strings.Split(have, "\n"), strings.Split(want, "\n")
	for i := range max(len(hl), len(wl)) {
		h, w := "(end)", "(end)"
		if i < len(hl) {
			h = hl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if h != w {
			t.Fatalf("the command reference in %s is out of date; run scripts/gen-cli-docs.sh\n"+
				"first difference in line %d of the reference:\n  document: %q\n  program:  %q", cliDoc, i+1, h, w)
		}
	}
}

// ---------- canonical names ----------

// valueFlags are the global flags that take a value (skipped with it);
// every other global flag is a switch.
var valueFlags = []string{"--home", "--server", "--token", "--token-file", "--ca-file", "--fingerprint", "--as", "--passphrase-file"}

var globalSwitches = []string{"--json", "-y", "--yes", "--no-color", "--offline", "--passphrase-stdin"}

// invocation is one "fileparcel …" found in a text.
type invocation struct {
	where string // file:line
	words []string
}

// programStarts returns the offsets just after every "fileparcel " that is
// a program name: at the start of the text or after white space, a slash
// ("./fileparcel") or an opening quote or bracket, and followed by white
// space ("fileparcel.local" is not one). Occurrences may follow each other
// ("docker compose exec fileparcel fileparcel status").
func programStarts(line string) []int {
	const name = "fileparcel"
	var out []int
	for i := 0; ; {
		j := strings.Index(line[i:], name)
		if j < 0 {
			return out
		}
		start, end := i+j, i+j+len(name)
		i = end
		if start > 0 && !strings.ContainsRune(" \t/\"'`([", rune(line[start-1])) {
			continue
		}
		rest := strings.TrimLeft(line[end:], " \t")
		if len(rest) == len(line[end:]) {
			continue // not followed by white space
		}
		out = append(out, len(line)-len(rest))
	}
}

// shellWords splits the rest of a line after "fileparcel " into shell words:
// quotes group, and an unquoted | ; & ) < > # or backtick ends the command.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'' || ch == '"':
			end := strings.IndexByte(s[i+1:], ch)
			if end < 0 {
				return append(words, cur.String()+s[i+1:])
			}
			cur.WriteString(s[i+1 : i+1+end])
			inWord = true
			i += end + 1
		case ch == ' ' || ch == '\t':
			flush()
		case strings.IndexByte("|;&)<>#`\n\\", ch) >= 0:
			flush()
			return words
		default:
			cur.WriteByte(ch)
			inWord = true
		}
	}
	flush()
	return words
}

// invocations returns every "fileparcel <words>" in text (a document
// fragment, a string literal or a script); line counts from firstLine.
func invocations(where string, firstLine int, text string) []invocation {
	var out []invocation
	for i, line := range strings.Split(text, "\n") {
		for _, at := range programStarts(line) {
			if words := shellWords(line[at:]); len(words) > 0 {
				out = append(out, invocation{where: where + ":" + strconv.Itoa(firstLine+i), words: words})
			}
		}
	}
	return out
}

// stripGlobals removes global flags (and their values) from the front and
// from between the words.
func stripGlobals(words []string) []string {
	var out []string
	for i := 0; i < len(words); i++ {
		w := words[i]
		name, _, hasValue := strings.Cut(w, "=")
		switch {
		case slices.Contains(valueFlags, name):
			if !hasValue {
				i++
			}
		case slices.Contains(globalSwitches, name):
		default:
			out = append(out, w)
		}
	}
	return out
}

// legacyUse returns why words use an old name ("" when they do not). The
// first word must be a command, an alias or an old name; anything else
// ("fileparcel account", "fileparcel %s") is not an invocation.
func legacyUse(root *cobra.Command, legacy []cli.LegacyName, words []string) (why string, isInvocation bool) {
	words = stripGlobals(words)
	if len(words) == 0 {
		return "", false
	}
	oldCommands := map[string]bool{}
	oldFlags := map[string]bool{} // "user create --generate"
	for _, l := range legacy {
		if l.Flag == "" {
			oldCommands[l.Command] = true
		} else {
			oldFlags[l.Command+" --"+l.Flag] = true
		}
	}
	cmd := root
	var typed []string
	rest := words
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		var next *cobra.Command
		for _, c := range cmd.Commands() {
			if c.Name() == rest[0] || slices.Contains(c.Aliases, rest[0]) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		typed = append(typed, rest[0])
		cmd, rest = next, rest[1:]
		if oldCommands[strings.Join(typed, " ")] {
			return "old command name " + strconv.Quote("fileparcel "+strings.Join(typed, " ")), true
		}
	}
	if cmd == root {
		return "", false
	}
	path := strings.Join(typed, " ")
	for _, w := range rest {
		if !strings.HasPrefix(w, "--") {
			continue
		}
		name, _, _ := strings.Cut(w, "=")
		if oldFlags[path+" "+name] {
			return "old flag " + name + " of " + strconv.Quote("fileparcel "+path), true
		}
	}
	return "", true
}

// markdownCode returns the code of a Markdown document that names commands:
// fenced blocks and inline code spans, outside the generated blocks and
// the sections that list old names on purpose ("Renamed commands",
// "Legacy names"). Each piece comes with its first line number.
func markdownCode(doc string) (pieces []string, lines []int) {
	var skip, fence bool
	skipLevel := 0
	var block strings.Builder
	blockStart := 0
	inlineCode := regexp.MustCompile("`([^`\n]+)`")
	heading := regexp.MustCompile(`^(#{1,6}) (.*)$`)
	for i, line := range strings.Split(doc, "\n") {
		n := i + 1
		switch strings.TrimSpace(line) {
		case cliBegin, "<!-- BEGIN GENERATED SETTINGS REFERENCE -->":
			skip = true
			continue
		case cliEnd, "<!-- END GENERATED SETTINGS REFERENCE -->":
			skip = false
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(line, " "), "```") {
			if fence && block.Len() > 0 && !skip && skipLevel == 0 {
				pieces, lines = append(pieces, block.String()), append(lines, blockStart)
			}
			block.Reset()
			fence, blockStart = !fence, n+1
			continue
		}
		if fence {
			block.WriteString(line + "\n")
			continue
		}
		if m := heading.FindStringSubmatch(line); m != nil {
			level := len(m[1])
			title := strings.TrimLeft(m[2], "0123456789. ") // "12.4 Legacy names"
			switch {
			case strings.EqualFold(title, "Renamed commands") || strings.EqualFold(title, "Legacy names"):
				skipLevel = level
			case skipLevel > 0 && level <= skipLevel:
				skipLevel = 0
			}
		}
		if skip || skipLevel > 0 {
			continue
		}
		for _, m := range inlineCode.FindAllStringSubmatch(line, -1) {
			pieces, lines = append(pieces, m[1]), append(lines, n)
		}
	}
	return pieces, lines
}

// goStrings returns the string literals of a Go file with their lines.
func goStrings(t *testing.T, path string, src []byte) (strs []string, lines []int) {
	t.Helper()
	fset := token.NewFileSet()
	file := fset.AddFile(path, fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(pos token.Position, msg string) { t.Errorf("%s: %s", pos, msg) }, 0)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return strs, lines
		}
		if tok != token.STRING {
			continue
		}
		v, err := strconv.Unquote(lit)
		if err != nil {
			continue
		}
		strs, lines = append(strs, v), append(lines, fset.Position(pos).Line)
	}
}

// TestDocsUseCanonicalCommands: every "fileparcel …" in README.md,
// CONTRIBUTING.md and docs/*.md (code only), the web pages' scripts, the string literals of
// the Go code and the install files uses today's command and flag names.
func TestDocsUseCanonicalCommands(t *testing.T) {
	repo := repoRoot(t)
	root := cli.NewRootCmd()
	legacy := cli.LegacyNames()
	var found []invocation

	docs, err := filepath.Glob(filepath.Join(repo, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append([]string{filepath.Join(repo, "README.md"), filepath.Join(repo, "CONTRIBUTING.md")}, docs...) {
		rel, _ := filepath.Rel(repo, p)
		pieces, lines := markdownCode(read(t, rel))
		for i, piece := range pieces {
			found = append(found, invocations(rel, lines[i], piece)...)
		}
	}
	for _, rel := range []string{"install.sh", "uninstall.sh", "Dockerfile", "docker-compose.yml"} {
		if _, err := os.Stat(filepath.Join(repo, rel)); err == nil {
			found = append(found, invocations(rel, 1, read(t, rel))...)
		}
	}
	walk := func(dir, ext string, fn func(rel string, data []byte)) {
		err := filepath.WalkDir(filepath.Join(repo, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ext) {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repo, p)
			fn(filepath.ToSlash(rel), data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	walk("web/static/js", ".js", func(rel string, data []byte) {
		found = append(found, invocations(rel, 1, string(data))...)
	})
	walk("internal", ".go", func(rel string, data []byte) {
		if strings.HasSuffix(rel, "_test.go") {
			return
		}
		strs, lines := goStrings(t, rel, data)
		for i, s := range strs {
			found = append(found, invocations(rel, lines[i], s)...)
		}
	})

	checked := 0
	for _, inv := range found {
		why, ok := legacyUse(root, legacy, inv.words)
		if !ok {
			continue
		}
		checked++
		if why != "" {
			t.Errorf("%s: %q uses the %s; use the current name (fileparcel help renamed)",
				inv.where, "fileparcel "+strings.Join(inv.words, " "), why)
		}
	}
	if checked < 100 {
		t.Errorf("only %d invocations checked; the scan is broken", checked)
	}
}

// The checker itself: old names are found, current ones and non-commands
// are not.
func TestLegacyUseDetection(t *testing.T) {
	root := cli.NewRootCmd()
	legacy := cli.LegacyNames()
	for line, want := range map[string]string{
		"fileparcel user add bob --generate":                   `old command name "fileparcel user add"`,
		"fileparcel user create bob --generate":                `old flag --generate of "fileparcel user create"`,
		"fileparcel --home /x mdns status":                     `old command name "fileparcel mdns"`,
		"sudo fileparcel restore bak_x --identity f":           `old command name "fileparcel restore"`,
		"fileparcel backup restore x --identity=f":             `old flag --identity of "fileparcel backup restore"`,
		"fileparcel share list --all":                          `old flag --all of "fileparcel share list"`,
		"./fileparcel keys export-recovery":                    `old command name "fileparcel keys export-recovery"`,
		"fileparcel request close shr_x --reopen":              `old flag --reopen of "fileparcel request close"`,
		"fileparcel client-cert issue bob --days 90":           `old flag --days of "fileparcel client-cert issue"`,
		"fileparcel user create bob --generate-password":       "",
		"fileparcel network mdns status | grep x":              "",
		"fileparcel files restore '/My files/a --all'":         "",
		"docker compose exec fileparcel fileparcel status":     "",
		"docker compose exec fileparcel fileparcel user add b": `old command name "fileparcel user add"`,
		"fileparcel --json share list --all-users --user bob":  "",
	} {
		invs := invocations("x", 1, line)
		got := ""
		for _, inv := range invs {
			if why, ok := legacyUse(root, legacy, inv.words); ok && why != "" {
				got = why
			}
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", line, got, want)
		}
	}
	for _, line := range []string{"the fileparcel account", "fileparcel.local", "fileparcel %s", "fileparcel"} {
		for _, inv := range invocations("x", 1, line) {
			if _, ok := legacyUse(root, legacy, inv.words); ok {
				t.Errorf("%q taken for an invocation", line)
			}
		}
	}
}
