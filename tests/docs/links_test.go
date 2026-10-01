package docs_test

// Relative links between the documents: every link, image and reference
// definition in README.md, CONTRIBUTING.md and docs/*.md that points inside the repository
// must name a file that exists, and a #fragment must name a heading of the
// target document the way GitHub turns headings into anchors.

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

var (
	atxHeading  = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$`)
	closingHash = regexp.MustCompile(`[ \t]+#+$`)
	htmlTag     = regexp.MustCompile(`</?[A-Za-z][^>]*>`)
	htmlAnchor  = regexp.MustCompile(`<a\s[^>]*\b(?:id|name)="([^"]+)"`)
	mdLink      = regexp.MustCompile(`\[([^\]]*)\]\(([^)]*)\)`)
	inlineLink  = regexp.MustCompile(`\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+"[^"]*")?\s*\)`)
	refDef      = regexp.MustCompile(`(?m)^ {0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)`)
	htmlRef     = regexp.MustCompile(`\b(?:src|href)="([^"]+)"`)
	urlScheme   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)
	emphasis    = regexp.MustCompile(`\*+|~~|(^|[^\p{L}\p{N}])_+|_+($|[^\p{L}\p{N}])`)
)

// markdownDocs lists README.md, CONTRIBUTING.md and docs/*.md, relative to
// the repository root.
func markdownDocs(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	docs, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := []string{"README.md", "CONTRIBUTING.md"}
	for _, p := range docs {
		rel, _ := filepath.Rel(root, p)
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// proseLines returns the lines of doc with fenced code blocks blanked out and
// inline code spans removed, so neither headings nor links are read from code.
func proseLines(doc string) []string {
	lines := strings.Split(doc, "\n")
	fence := ""
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			}
			lines[i] = ""
			continue
		}
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fence = trimmed[:3]
			lines[i] = ""
			continue
		}
		lines[i] = stripCodeSpans(line)
	}
	return lines
}

// stripCodeSpans drops the inline code spans of one line, backticks and all,
// using the same rules as codeSpans.
func stripCodeSpans(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] == '\\' && i+1 < len(line) {
			b.WriteString(line[i : i+2])
			i += 2
			continue
		}
		if line[i] != '`' {
			b.WriteByte(line[i])
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
			b.WriteString(run)
			i = j
			continue
		}
		i = end + len(run)
	}
	return b.String()
}

// headingText is what GitHub shows for a heading's source text: code spans
// keep their content, links keep their text, emphasis and HTML tags go.
func headingText(src string) string {
	var b strings.Builder
	rest := src
	for _, span := range codeSpans(src) {
		i := strings.Index(rest, span)
		if i < 0 {
			break
		}
		// Everything before the span, minus the backticks that open it.
		b.WriteString(plainInline(strings.TrimRight(rest[:i], "`")))
		b.WriteString(span)
		rest = strings.TrimLeft(rest[i+len(span):], "`")
	}
	b.WriteString(plainInline(rest))
	return b.String()
}

func plainInline(s string) string {
	s = mdLink.ReplaceAllString(s, "$1")
	s = htmlTag.ReplaceAllString(s, "")
	s = emphasis.ReplaceAllString(s, "$1$2")
	return strings.ReplaceAll(s, `\`, "")
}

// githubSlug turns heading text into the anchor GitHub gives it: lower case,
// punctuation and symbols dropped (except - and _), each space a hyphen.
func githubSlug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(text)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// anchors returns every fragment a link into doc may use: the heading slugs
// (the second heading with the same slug gets "-1", and so on) and explicit
// <a id="..."> / <a name="..."> anchors.
func anchors(doc string) map[string]bool {
	out := map[string]bool{}
	seen := map[string]int{}
	for _, line := range strings.Split(doc, "\n") {
		for _, m := range htmlAnchor.FindAllStringSubmatch(line, -1) {
			out[m[1]] = true
		}
	}
	lines := strings.Split(doc, "\n")
	fence := ""
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fence = trimmed[:3]
			continue
		}
		m := atxHeading.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		slug := githubSlug(headingText(closingHash.ReplaceAllString(m[2], "")))
		if n, dup := seen[slug]; dup {
			seen[slug] = n + 1
			slug += "-" + strconv.Itoa(n+1)
		} else {
			seen[slug] = 0
		}
		out[slug] = true
	}
	return out
}

func TestGitHubSlug(t *testing.T) {
	for src, want := range map[string]string{
		"Install on a Raspberry Pi":                  "install-on-a-raspberry-pi",
		"6a. Roles and permissions":                  "6a-roles-and-permissions",
		"Tailscale Funnel, Serve and VPNs":           "tailscale-funnel-serve-and-vpns",
		"Trust FileParcel's certificate":             "trust-fileparcels-certificate",
		"`fileparcel role add` — make a role":        "fileparcel-role-add--make-a-role",
		"Known limitations in **v4**":                "known-limitations-in-v4",
		"The `max_upload_size` setting":              "the-max_upload_size-setting",
		"See [the manual](FILEPARCEL.md) for _more_": "see-the-manual-for-more",
		"20.1 Figures (§20)":                         "201-figures-20",
	} {
		if got := githubSlug(headingText(src)); got != want {
			t.Errorf("githubSlug(%q) = %q, want %q", src, got, want)
		}
	}
}

// TestRelativeLinks checks every repository-relative link of README.md and
// docs/*.md: the target exists and, for a Markdown target, the #fragment is
// one of its heading anchors.
func TestRelativeLinks(t *testing.T) {
	root := repoRoot(t)
	docs := markdownDocs(t)
	anchorCache := map[string]map[string]bool{}
	anchorsOf := func(rel string) map[string]bool {
		if a, ok := anchorCache[rel]; ok {
			return a
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil
		}
		a := anchors(string(b))
		anchorCache[rel] = a
		return a
	}
	checked := 0
	for _, rel := range docs {
		lines := proseLines(read(t, rel))
		// Link text may wrap onto the next line; the target never does, so the
		// joined text finds "](target)" wherever the line breaks.
		text := strings.Join(lines, "\n")
		var targets []string
		for _, m := range inlineLink.FindAllStringSubmatch(text, -1) {
			targets = append(targets, m[1])
		}
		for _, m := range refDef.FindAllStringSubmatch(text, -1) {
			targets = append(targets, m[1])
		}
		for _, m := range htmlRef.FindAllStringSubmatch(text, -1) {
			targets = append(targets, m[1])
		}
		for _, target := range targets {
			target = strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">")
			if target == "" || urlScheme.MatchString(target) || strings.HasPrefix(target, "//") {
				continue
			}
			checked++
			path, frag, _ := strings.Cut(target, "#")
			dest := rel
			if path != "" {
				p, err := url.PathUnescape(path)
				if err != nil {
					t.Errorf("%s: link %q: %v", rel, target, err)
					continue
				}
				dest = filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(rel), p)))
				if strings.HasPrefix(dest, "../") {
					t.Errorf("%s: link %q leaves the repository", rel, target)
					continue
				}
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(dest))); err != nil {
					t.Errorf("%s: link %q: %s does not exist", rel, target, dest)
					continue
				}
			}
			if frag == "" || !strings.HasSuffix(dest, ".md") {
				continue
			}
			if !anchorsOf(dest)[frag] {
				t.Errorf("%s: link %q: %s has no heading with the anchor #%s", rel, target, dest, frag)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no relative links found; the link pattern is broken")
	}
}

// TestDocImagesUsed: every picture in docs/images is shown by some document
// and stays small enough for the repository and a phone on a slow link.
func TestDocImagesUsed(t *testing.T) {
	root := repoRoot(t)
	var all strings.Builder
	for _, rel := range markdownDocs(t) {
		all.WriteString(read(t, rel))
	}
	images, err := filepath.Glob(filepath.Join(root, "docs", "images", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range images {
		name := filepath.Base(p)
		if !strings.Contains(all.String(), "images/"+name) {
			t.Errorf("docs/images/%s is not used by README.md or docs/*.md", name)
		}
		if fi, err := os.Stat(p); err == nil && fi.Size() > 512<<10 {
			t.Errorf("docs/images/%s is %d KB; keep screenshots under 512 KB", name, fi.Size()>>10)
		}
	}
}
