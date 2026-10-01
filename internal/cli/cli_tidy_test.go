package cli

// Tests of the command-line infrastructure (DESIGN §12: help groups and
// topics, errors and suggestions, legacy names, flag conventions).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// pendingCommands are commands the tidy-up spec names that do not exist yet
// (the v4 CLI work added access, role, network vpn/funnel/tailscale-serve
// and whoami step by step; none is left). Help texts and hints may mention a
// pending command; the tests skip their checks until it exists.
// TestPendingCommandsStillPending fails as soon as one is added, so the
// change that adds it must delete its entry here, which turns the skipped
// checks on.
var pendingCommands []string

func isPending(path string) bool {
	for _, p := range pendingCommands {
		if path == p || strings.HasPrefix(path, p+" ") {
			return true
		}
	}
	return false
}

func TestPendingCommandsStillPending(t *testing.T) {
	root := NewRootCmd()
	for _, p := range pendingCommands {
		if commandExists(root, p) {
			t.Errorf("%q exists now: remove it from pendingCommands", p)
		}
	}
}

// ---------- help ----------

func TestRootHelpGroups(t *testing.T) {
	res := runArgs(t, "", "--help")
	if res.code != 0 {
		t.Fatalf("--help: %+v", res)
	}
	out := res.stdout
	titles := []string{"Getting started:", "Files & sharing:", "People & access:", "Server & network:", "Security:",
		"Backups & maintenance:", "Install & service:"}
	last := -1
	for _, title := range titles {
		i := strings.Index(out, "\n"+title+"\n")
		if i <= last {
			t.Errorf("group %q missing or out of order", title)
		}
		last = i
	}
	for _, want := range []string{"Common tasks:", "Help topics:", "fileparcel <command> [flags]"} {
		if !strings.Contains(out, want) {
			t.Errorf("root help lacks %q", want)
		}
	}
	if strings.Contains(out, "More commands:") || strings.Contains(out, "Additional help topics") {
		t.Error("root help has an ungrouped section")
	}
	root := NewRootCmd()
	groups := map[string]bool{}
	for _, g := range root.Groups() {
		groups[g.ID] = true
	}
	for _, c := range root.Commands() {
		if !c.IsAvailableCommand() && c.Name() != "help" {
			continue
		}
		if !groups[c.GroupID] {
			t.Errorf("visible top-level command %q has no group (add it to topLevelGroup)", c.Name())
		}
	}
	// Every "Common tasks" line runs a command that exists.
	for _, line := range strings.Split(rootLong, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "fileparcel ") {
			continue
		}
		words := shellWords(t, strings.TrimPrefix(line, "fileparcel "))
		if isPending(strings.Join(words[:min(2, len(words))], " ")) || isPending(words[0]) {
			continue
		}
		c, _, err := root.Find(words)
		if err != nil || c == root || c.Hidden || strings.Fields(commandKey(c))[0] != words[0] {
			t.Errorf("common task %q does not run a command (%v)", line, err)
		}
	}
}

func TestSubGroups(t *testing.T) {
	root := NewRootCmd()
	for path := range subGroups {
		parent := findCommand(root, path)
		if parent == nil {
			t.Errorf("sections of %q: no such command", path)
			continue
		}
		ids := map[string]bool{}
		for _, g := range parent.Groups() {
			ids[g.ID] = true
		}
		for _, c := range parent.Commands() {
			if c.IsAvailableCommand() && !ids[c.GroupID] {
				t.Errorf("%s: %q is in no section (add it to subGroups)", parent.CommandPath(), c.Name())
			}
		}
		res := runArgs(t, "", append(strings.Fields(path), "--help")...)
		if res.code != 0 || strings.Contains(res.stdout, "More commands:") {
			t.Errorf("%s --help: %+v", path, res)
		}
	}
}

func TestHelpTopics(t *testing.T) {
	root := NewRootCmd()
	phrases := map[string]string{"connect": "admin.sock", "flags": "FILEPARCEL_TOKEN", "paths": "/My files", "values": "7d",
		"permissions": "access check", "scripting": "Exit codes", "renamed": "network mdns"}
	var names []string
	for _, c := range root.Commands() {
		if c.IsAdditionalHelpTopicCommand() {
			names = append(names, c.Name())
		}
	}
	slices.Sort(names)
	if strings.Join(names, " ") != "connect flags paths permissions renamed scripting values" {
		t.Fatalf("topics %v", names)
	}
	for name, phrase := range phrases {
		for _, args := range [][]string{{"help", name}, {name}} {
			res := runArgs(t, "", args...)
			if res.code != 0 || !strings.Contains(res.stdout, phrase) || strings.Contains(res.stdout, "Usage:") {
				t.Errorf("%v: exit %d, %q missing or a usage block shown:\n%s%s", args, res.code, phrase, res.stdout, res.stderr)
			}
		}
		// A topic name is no other top-level command's name or alias.
		for _, c := range root.Commands() {
			if !c.IsAdditionalHelpTopicCommand() && (c.Name() == name || slices.Contains(c.Aliases, name)) {
				t.Errorf("topic %q collides with %s", name, c.CommandPath())
			}
		}
	}
	// "help" runs the help of a command and refuses a word that is none.
	a, b := runArgs(t, "", "help", "user", "create"), runArgs(t, "", "user", "create", "--help")
	if a.code != 0 || a.stdout != b.stdout {
		t.Errorf("help user create differs from user create --help:\n%s\n---\n%s", a.stdout, b.stdout)
	}
	if res := runArgs(t, "", "help", "user", "lsit"); res.code != ExitUsage || !strings.Contains(res.stderr, "list") {
		t.Errorf("help user lsit: %+v", res)
	}
}

func TestCompactGlobalFlags(t *testing.T) {
	res := runArgs(t, "", "user", "list", "--help")
	if !strings.Contains(res.stdout, "Global flags: --home DIR") || strings.Contains(res.stdout, "--fingerprint string") {
		t.Errorf("user list --help lists the global flags in full:\n%s", res.stdout)
	}
	if res := runArgs(t, "", "--help"); !strings.Contains(res.stdout, "--fingerprint") ||
		!strings.Contains(res.stdout, "Global flags (work with every command):") {
		t.Errorf("root help lacks the global flags:\n%s", res.stdout)
	}
	if res := runArgs(t, "", "network", "--help"); !strings.Contains(res.stdout, "\n  fileparcel network [flags]\n") {
		t.Errorf("network --help lacks its bare use line:\n%s", res.stdout)
	}
	if res := runArgs(t, "", "cert", "sans", "--help"); !strings.Contains(res.stdout, "\n  fileparcel cert sans [flags]\n") {
		t.Errorf("cert sans --help lacks its bare use line:\n%s", res.stdout)
	}
	if res := runArgs(t, "", "maintenance", "on", "--help"); !strings.Contains(res.stdout, "Flags from the parent command:\n      --message string") ||
		!strings.Contains(res.stdout, "Global flags: --home DIR") {
		t.Errorf("maintenance on --help lacks --message:\n%s", res.stdout)
	}
	if res := runArgs(t, "", "maintenance", "--help"); !strings.Contains(res.stdout, "\n  fileparcel maintenance [flags]\n") ||
		!strings.Contains(res.stdout, "fileparcel maintenance <command> [flags]") {
		t.Errorf("maintenance --help use lines:\n%s", res.stdout)
	}
	if res := runArgs(t, "", "user", "--help"); strings.Contains(res.stdout, "fileparcel user [flags]") ||
		!strings.Contains(res.stdout, "fileparcel user <command> [flags]") {
		t.Errorf("user --help use lines:\n%s", res.stdout)
	}
	// Flags a non-root parent passes down are listed in full.
	root := NewRootCmd()
	parent := &cobra.Command{Use: "demo", Short: "Demo", RunE: func(*cobra.Command, []string) error { return nil }}
	parent.PersistentFlags().String("message", "", "the notice to show")
	child := &cobra.Command{Use: "on", Short: "On", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return nil }}
	parent.AddCommand(child)
	root.AddCommand(parent)
	var out bytes.Buffer
	child.SetOut(&out)
	if err := child.Help(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Flags from the parent command:\n      --message string") ||
		strings.Contains(out.String(), "--fingerprint") || !strings.Contains(out.String(), "Global flags: --home DIR") {
		t.Errorf("inherited parent flags:\n%s", out.String())
	}
}

// TestNoCommandPersistentPreRun: cobra runs only the nearest
// PersistentPreRun(E), so one on any command would skip the root's
// checkInvocation (stdin rule, secret-prompt guard, --token-file).
func TestNoCommandPersistentPreRun(t *testing.T) {
	root := NewRootCmd()
	if root.PersistentPreRunE == nil {
		t.Fatal("root has no checkInvocation")
	}
	walkCommands(root, func(c *cobra.Command) {
		if c != root && (c.PersistentPreRun != nil || c.PersistentPreRunE != nil) {
			t.Errorf("%s sets PersistentPreRun", c.CommandPath())
		}
		if c.Runnable() && (c.RunE == nil || c.Args == nil) && !strings.HasPrefix(c.Name(), "__") && c.Name() != "help" {
			t.Errorf("%s: runnable without RunE or Args", c.CommandPath())
		}
	})
}

// ---------- help texts ----------

// exampleInvocation matches a fileparcel invocation inside an example line
// (it ends at a pipe, a list operator or a closing parenthesis).
var exampleInvocation = regexp.MustCompile(`fileparcel(\s+[^\s|;&)]+)+`)

// useToken is one placeholder or literal of a Use line after the name.
var useToken = regexp.MustCompile(`^(<[a-z0-9|._-]+>|\[[^\]]+\]|--[a-z-]+|[A-Z]+|\(.*\)|\|)(\.\.\.)?$`)

// useTokens splits the words of a Use line after the command name; "( … )"
// and "[ … ]" stay one token each.
func useTokens(use string) []string {
	_, rest, _ := strings.Cut(use, " ")
	var out []string
	var cur strings.Builder
	depth := 0
	for _, r := range rest {
		switch {
		case r == '(' || r == '[':
			depth++
		case r == ')' || r == ']':
			depth--
		case r == ' ' && depth == 0:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// exampleTarget follows the words of an invocation (without "fileparcel")
// down the tree like cobra, skipping flags and their values. It returns
// the command reached, the word after it when that word names no
// subcommand of a group (an unknown command), and the command words used.
func exampleTarget(root *cobra.Command, words []string) (c *cobra.Command, unknown string, used []string) {
	c = root
	for i := 0; i < len(words); i++ {
		w := words[i]
		if strings.HasPrefix(w, "-") && w != "-" {
			name := strings.TrimLeft(w, "-")
			if strings.Contains(name, "=") {
				continue
			}
			c.InheritedFlags() // merges the parents' flags into Flags()
			var f *pflag.Flag
			if strings.HasPrefix(w, "--") {
				f = c.Flags().Lookup(name)
			} else if len(name) == 1 {
				f = c.Flags().ShorthandLookup(name)
			}
			if f != nil && f.NoOptDefVal == "" {
				i++ // the flag's value
			}
			continue
		}
		var next *cobra.Command
		for _, s := range c.Commands() {
			if s.Name() == w || slices.Contains(s.Aliases, w) {
				next = s
				break
			}
		}
		if next == nil {
			if c.HasAvailableSubCommands() {
				return c, w, used // no example passes a positional word to a group
			}
			return c, "", used
		}
		used = append(used, w)
		c = next
	}
	return c, "", used
}

// isLegacyAlias reports whether word, used below parent, is the old name
// of a renamed command.
func isLegacyAlias(parent *cobra.Command, word string) bool {
	path := strings.TrimSpace(commandKey(parent) + " " + word)
	for _, la := range legacyAliases {
		if la.Old == path {
			return true
		}
	}
	return false
}

// TestEveryCommandDocumented holds every visible command to the help
// conventions of DESIGN §12: a short Short, a Long, 2–4 examples that run
// the command itself, placeholders in the canonical form.
func TestEveryCommandDocumented(t *testing.T) {
	root := NewRootCmd()
	visible := func(c *cobra.Command) bool {
		for p := c; p != nil; p = p.Parent() {
			if p.Hidden {
				return false
			}
		}
		return true
	}
	isAncestor := func(a, c *cobra.Command) bool {
		for p := c; p != nil; p = p.Parent() {
			if p == a {
				return true
			}
		}
		return false
	}
	walkCommands(root, func(c *cobra.Command) {
		if c.Name() == "help" || strings.HasPrefix(c.Name(), "__") || c.IsAdditionalHelpTopicCommand() || !visible(c) {
			return
		}
		path := c.CommandPath()
		short := strings.TrimSpace(c.Short)
		switch {
		case short == "":
			t.Errorf("%s: no Short", path)
		case utf8.RuneCountInString(short) > 64:
			t.Errorf("%s: Short has %d characters (at most 64)", path, utf8.RuneCountInString(short))
		case strings.HasSuffix(short, "."):
			t.Errorf("%s: Short ends with a period", path)
		case !unicode.IsUpper([]rune(short)[0]):
			t.Errorf("%s: Short does not start with a capital letter", path)
		}
		long := strings.TrimSpace(c.Long)
		if long == "" || long == short {
			t.Errorf("%s: no Long (or the same as Short)", path)
		}
		for _, line := range strings.Split(c.Long, "\n") {
			if !strings.HasPrefix(line, " ") && utf8.RuneCountInString(line) > 80 {
				t.Errorf("%s: Long line longer than 80 characters: %q", path, line)
			}
		}
		for _, old := range []string{"Requires elevation", "Requires confirmation", "requires elevation"} {
			if strings.Contains(c.Long, old) {
				t.Errorf("%s: Long says %q (use elevationNote or confirmNote)", path, old)
			}
		}
		if c.Runnable() && (c.RunE == nil || c.Args == nil) {
			t.Errorf("%s: runnable without RunE or Args", path)
		}
		if c == root {
			return // its examples are the "Common tasks" of the Long (TestRootHelpGroups)
		}
		for _, tok := range useTokens(c.Use) {
			if !useToken.MatchString(tok) || tok == "<username>" || tok == "<old-name>" {
				t.Errorf("%s: Use token %q is not a canonical placeholder", path, tok)
			}
		}
		lines := strings.Split(strings.Trim(c.Example, "\n"), "\n")
		maxLines := 4
		if key := commandKey(c); key == "install" || key == "files put" {
			maxLines = 5
		}
		if len(lines) < 2 || len(lines) > maxLines {
			t.Errorf("%s: %d example lines (2 to %d)", path, len(lines), maxLines)
		}
		for _, line := range lines {
			if !strings.HasPrefix(line, "  ") || strings.TrimSpace(line) == "" {
				t.Errorf("%s: example line %q is not indented by two spaces", path, line)
			}
			matches := exampleInvocation.FindAllString(line, -1)
			if len(matches) == 0 {
				t.Errorf("%s: example line %q runs no fileparcel command", path, line)
			}
			self, checked := false, 0
			for _, m := range matches {
				target, unknown, used := exampleTarget(root, shellWords(t, m)[1:])
				if unknown != "" {
					if !isPending(strings.TrimSpace(commandKey(target) + " " + unknown)) {
						t.Errorf("%s: example %q: %q is not a command of %q", path, m, unknown, target.CommandPath())
					}
					continue
				}
				checked++
				if !visible(target) {
					t.Errorf("%s: example %q runs the hidden %q", path, m, target.CommandPath())
				}
				p := root
				for _, w := range used {
					if isLegacyAlias(p, w) {
						t.Errorf("%s: example %q uses the old name %q", path, m, w)
					}
					p, _, _ = p.Find([]string{w})
				}
				self = self || isAncestor(c, target)
			}
			if checked > 0 && !self {
				t.Errorf("%s: example line %q does not run %s or one of its commands", path, line, path)
			}
		}
	})
}

// ---------- legacy names ----------

// legacyTree reads testdata/legacy_paths.txt: every command path before the
// tidy-up with its aliases.
func legacyTree(t *testing.T) (paths []string, aliases map[string][]string) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "legacy_paths.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	aliases = map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, al, _ := strings.Cut(line, "|")
		path = strings.TrimSpace(path)
		paths = append(paths, path)
		aliases[path] = strings.Fields(al)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 178 {
		t.Fatalf("legacy_paths.txt has %d paths, want 178 (179 with the root)", len(paths))
	}
	return paths, aliases
}

// canonicalPath is the path below "fileparcel" of c, with a legacy copy
// mapped onto the command it copies.
func canonicalPath(c *cobra.Command) string {
	p := commandKey(c)
	for _, lc := range legacyCommands {
		if p == lc.Old || strings.HasPrefix(p, lc.Old+" ") {
			return lc.New + strings.TrimPrefix(p, lc.Old)
		}
	}
	return p
}

// parseInvocation resolves and parses args like cobra's Execute, without
// running the command.
func parseInvocation(root *cobra.Command, args []string) (*cobra.Command, error) {
	c, rest, err := root.Find(args)
	if err != nil {
		return nil, err
	}
	if err := c.ParseFlags(rest); err != nil {
		return c, c.FlagErrorFunc()(c, err)
	}
	if err := c.ValidateArgs(c.Flags().Args()); err != nil {
		return c, err
	}
	if err := c.ValidateRequiredFlags(); err != nil {
		return c, err
	}
	return c, c.ValidateFlagGroups()
}

func TestLegacyInvocations(t *testing.T) {
	paths, aliases := legacyTree(t)
	for _, p := range paths {
		root := NewRootCmd()
		words := strings.Fields(p)
		c, rest, err := root.Find(words)
		if err != nil || len(rest) != 0 || c == root || !c.Runnable() {
			t.Errorf("%q no longer resolves to a runnable command (%v, rest %v)", p, err, rest)
			continue
		}
		for _, a := range aliases[p] {
			alt := append(slices.Clone(words[:len(words)-1]), a)
			if ac, _, err := root.Find(alt); err != nil || ac != c {
				t.Errorf("alias %q of %q resolves to %v (%v)", strings.Join(alt, " "), p, ac, err)
			}
		}
	}
	type flagWant map[string]string // flag → value ("" = only Changed)
	cases := []struct {
		args  string
		path  string // canonical command path below "fileparcel"
		flags flagWant
		pos   []string // positional arguments
	}{
		{"mdns status", "network mdns status", nil, nil},
		{"mdns mode builtin", "network mdns mode", nil, []string{"builtin"}},
		{"bonjour status", "network mdns status", nil, nil},
		{"restore x --identity f --dry-run", "backup restore", flagWant{"identity-file": "f", "dry-run": "true"}, []string{"x"}},
		{"keys export-recovery", "keys recovery-key", nil, nil},
		{"user add bob --generate", "user create", flagWant{"generate-password": "true"}, []string{"bob"}},
		{"users add bob --generate", "user create", flagWant{"generate-password": "true"}, []string{"bob"}},
		{"user passwd bob --generate", "user reset-password", flagWant{"generate-password": "true"}, []string{"bob"}},
		{"user quota bob 5G", "user set-quota", nil, []string{"bob", "5G"}},
		{"share revoke shr_x", "share delete", nil, []string{"shr_x"}},
		{"share list --all", "share list", flagWant{"all-users": "true"}, nil},
		{"request list --all --user alice", "request list", flagWant{"all-users": "true", "user": "alice"}, nil},
		{"token list --all", "token list", flagWant{"inactive": "true"}, nil},
		{"invite list --all", "invite list", flagWant{"inactive": "true"}, nil},
		{"client-cert list --all", "client-cert list", flagWant{"inactive": "true"}, nil},
		{"client-cert issue bob --out b.p12 --days 90", "client-cert issue", flagWant{"output": "b.p12", "days": "90"}, []string{"bob"}},
		{"backup create --out /tmp/x", "backup create", flagWant{"output": "/tmp/x"}, nil},
		{"request close shr_x --reopen", "request close", flagWant{"reopen": "true"}, []string{"shr_x"}},
		{"cert sans --add a --remove b", "cert sans", flagWant{"add": "[a]", "remove": "[b]"}, nil},
		{"token create --name laptop", "token create", flagWant{"name": "laptop"}, nil},
		{"maintenance on --message m", "maintenance on", flagWant{"message": "m"}, []string{}},
		{"maintenance --message m on", "maintenance on", flagWant{"message": "m"}, []string{}},
		{"maintenance ON", "maintenance", nil, []string{"ON"}},         // the parent runs "on"
		{"maintenance Enable", "maintenance", nil, []string{"Enable"}}, // … and aliases, in any case
		{"maintenance enable", "maintenance on", nil, []string{}},
		{"group rename a b --description d", "group rename", flagWant{"description": "d"}, []string{"a", "b"}},
		{"install --non-interactive --dir /x", "install", flagWant{"non-interactive": "true", "dir": "/x"}, nil},
		{"init --home /x --non-interactive", "init", flagWant{"home": "/x", "non-interactive": "true"}, nil},
		{"uninstall --home /x --yes --keep-data", "uninstall", flagWant{"home": "/x", "yes": "true", "keep-data": "true"}, nil},
		{"upgrade --dry-run z.zip", "upgrade", flagWant{"dry-run": "true"}, []string{"z.zip"}},
		{"logs --lines 5", "logs", flagWant{"lines": "5"}, nil},
		{"audit export --format jsonl -o f --force", "audit export", flagWant{"format": "jsonl", "output": "f", "force": "true"}, nil},
		{"-y keys rotate --kek --purpose blob", "keys rotate", flagWant{"yes": "true", "kek": "true", "purpose": "blob"}, nil},
		// Service managers, Docker, installers and the repository's scripts.
		{"serve --home /h", "serve", flagWant{"home": "/h"}, nil},
		{"serve --home /h --foreground --dev", "serve", flagWant{"foreground": "true", "dev": "true"}, nil},
		{"serve --init-if-missing", "serve", flagWant{"init-if-missing": "true"}, nil},
		{"healthcheck", "healthcheck", nil, nil},
		{"version", "version", nil, nil},
		{"version --json", "version", flagWant{"json": "true"}, nil},
		{"status", "status", nil, nil},
		{"init --home /h --admin admin --admin-password-file /p --access private --non-interactive", "init",
			flagWant{"admin": "admin", "admin-password-file": "/p", "access": "private"}, nil},
		{"init --home /h --generate-password --non-interactive", "init", flagWant{"generate-password": "true"}, nil},
		{"--offline config set server.https_port 18443", "config set", flagWant{"offline": "true"}, []string{"server.https_port", "18443"}},
		{"--offline --json config list --all", "config list", flagWant{"all": "true", "json": "true"}, nil},
		{"--json config get x.y", "config get", nil, []string{"x.y"}},
		{"docs --markdown -o /tmp/ref.md", "docs", flagWant{"markdown": "true", "output": "/tmp/ref.md"}, nil},
		{"backup list", "backup list", nil, nil},
		{"keys unlock --passphrase-stdin", "keys unlock", flagWant{"passphrase-stdin": "true"}, nil},
		{"maintenance status", "maintenance status", nil, []string{}},
		{"--json maintenance status", "maintenance status", flagWant{"json": "true"}, []string{}},
		{"maintenance off", "maintenance off", nil, []string{}},
		{"maintenance", "maintenance", nil, []string{}},
		{"user list", "user list", nil, nil},
		{"files ls /My files", "files ls", nil, nil}, // the shell passed "/My files" as one word below
		{"service start", "service start", nil, nil},
		{"service install --start", "service install", flagWant{"start": "true"}, nil},
		{"cert tailscale enable", "cert tailscale enable", nil, nil},
		{"backup identity generate", "backup identity generate", nil, nil},
		{"logs", "logs", nil, nil},
		{"doctor", "doctor", nil, nil},
		{"audit export --format jsonl -o f --force", "audit export", nil, nil},
	}
	for _, tc := range cases {
		args := strings.Fields(tc.args)
		if tc.args == "files ls /My files" {
			args = []string{"files", "ls", "/My files"}
		}
		root := NewRootCmd()
		c, err := parseInvocation(root, args)
		if err != nil {
			t.Errorf("%q: %v", tc.args, err)
			continue
		}
		if got := canonicalPath(c); got != tc.path {
			t.Errorf("%q runs %q, want %q", tc.args, got, tc.path)
		}
		for name, want := range tc.flags {
			f := c.Flags().Lookup(name)
			if f == nil || !f.Changed || want != "" && f.Value.String() != want {
				t.Errorf("%q: --%s = %v, want %q", tc.args, name, f, want)
			}
		}
		if tc.pos != nil && !slices.Equal(c.Flags().Args(), tc.pos) {
			t.Errorf("%q: arguments %q, want %q", tc.args, c.Flags().Args(), tc.pos)
		}
	}
	// Every option install.sh and uninstall.sh pass through exists.
	root := NewRootCmd()
	for cmd, flags := range map[string][]string{
		"install": {"dir", "port", "http-port", "name", "service", "boot", "no-boot", "symlink", "no-symlink", "admin",
			"generate-password", "admin-password-file", "admin-password-stdin", "admin-email", "sealed", "passphrase-file",
			"access", "allow", "upgrade", "force", "dry-run", "yes", "non-interactive", "home"},
		"uninstall": {"keep-data", "purge", "final-backup", "backup-to", "remove-user", "dry-run", "yes", "home"},
	} {
		c := findCommand(root, cmd)
		c.InheritedFlags() // merges the global flags into Flags()
		for _, name := range flags {
			if c.Flags().Lookup(name) == nil {
				t.Errorf("%s --%s is gone (the installer scripts pass it)", cmd, name)
			}
		}
	}
}

func TestLegacyHidden(t *testing.T) {
	root := NewRootCmd()
	for _, lc := range legacyCommands {
		c := findCommand(root, lc.Old)
		if c == nil || !c.Hidden {
			t.Errorf("legacy copy %q missing or visible", lc.Old)
		}
	}
	oldLine := func(name string) *regexp.Regexp { return regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(name) + `\s`) }
	if res := runArgs(t, "", "--help"); oldLine("mdns").MatchString(res.stdout) || oldLine("restore").MatchString(res.stdout) {
		t.Errorf("root help lists a legacy command:\n%s", res.stdout)
	}
	if res := runArgs(t, "", "keys", "--help"); oldLine("export-recovery").MatchString(res.stdout) {
		t.Errorf("keys help lists export-recovery:\n%s", res.stdout)
	}
	md := runArgs(t, "", "docs", "--markdown").stdout
	for _, h := range []string{"fileparcel mdns", "fileparcel restore", "fileparcel keys export-recovery"} {
		if regexp.MustCompile(`(?m)^#+ ` + regexp.QuoteMeta(h) + `$`).MatchString(md) {
			t.Errorf("docs --markdown documents %q", h)
		}
	}
	for args, bad := range map[string][]string{"__complete ": {"mdns", "restore"}, "__complete keys ": {"export-recovery"}} {
		res := runArgs(t, "", append(strings.Fields(args), "")...)
		for _, b := range bad {
			if regexp.MustCompile(`(?m)^` + b + `(\t|$)`).MatchString(res.stdout) {
				t.Errorf("%q completes %q:\n%s", args, b, res.stdout)
			}
		}
	}
	for _, lf := range legacyFlags {
		res := runArgs(t, "", append(strings.Fields(lf.Command), "--help")...)
		if regexp.MustCompile(`--` + lf.Old + `(\s|,|$)`).MatchString(res.stdout) {
			t.Errorf("%s --help shows the legacy flag --%s", lf.Command, lf.Old)
		}
		if !strings.Contains(res.stdout, "--"+lf.New) {
			t.Errorf("%s --help lacks --%s", lf.Command, lf.New)
		}
	}
	renamed := runArgs(t, "", "help", "renamed").stdout
	for _, lc := range legacyCommands {
		if !strings.Contains(renamed, "fileparcel "+lc.Old) || !strings.Contains(renamed, "fileparcel "+lc.New) {
			t.Errorf("help renamed lacks %s → %s", lc.Old, lc.New)
		}
	}
	for _, la := range legacyAliases {
		if !strings.Contains(renamed, "fileparcel "+la.Old) {
			t.Errorf("help renamed lacks %s", la.Old)
		}
	}
	for _, lf := range legacyFlags {
		if !strings.Contains(renamed, "--"+lf.Old+" (") {
			t.Errorf("help renamed lacks --%s", lf.Old)
		}
	}
	for _, n := range legacyNotes {
		if !strings.Contains(renamed, n.Old) || !strings.Contains(renamed, n.New) {
			t.Errorf("help renamed lacks %s", n.Old)
		}
	}
}

func TestLegacyNoticeOnlyOnTTY(t *testing.T) {
	// "restore" with --server fails at once, after the notice would print.
	args := []string{"--server", "https://files.example.lan", "--token", "x", "restore", "bak_x", "-y"}
	res := runArgs(t, "", args...)
	if res.code != ExitUsage || strings.Contains(res.stderr, "note:") {
		t.Fatalf("no terminal: %+v", res)
	}
	orig := legacyNoticeTTY
	t.Cleanup(func() { legacyNoticeTTY = orig })
	legacyNoticeTTY = func(*cobra.Command) bool { return true }
	res = runArgs(t, "", args...)
	if !strings.Contains(res.stderr, `note: "fileparcel restore" is now "fileparcel backup restore"; the old name keeps working.`) {
		t.Fatalf("terminal: %+v", res)
	}
	if res := runArgs(t, "", append([]string{"--json"}, args...)...); strings.Contains(res.stderr, "note:") {
		t.Fatalf("--json: %+v", res)
	}
	// The canonical name never prints the notice.
	if res := runArgs(t, "", "--server", "https://files.example.lan", "--token", "x", "backup", "restore", "bak_x", "-y"); strings.Contains(res.stderr, "note:") {
		t.Fatalf("canonical name: %+v", res)
	}
}

// ---------- unknown commands and flags ----------

func TestUnknownSubcommandSuggests(t *testing.T) {
	res := runArgs(t, "", "user", "lsit")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "Did you mean this?\n\tlist\n") ||
		!strings.Contains(res.stderr, `Run "fileparcel user --help" to see all commands.`) {
		t.Errorf("user lsit: %+v", res)
	}
	for _, args := range [][]string{{"service", "frobnicate"}, {"maintenance", "sideways"}, {"network", "sideways"},
		{"cert", "sans", "sideways"}, {"frobnicate"}} {
		if res := runArgs(t, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	res = runArgs(t, "", "--json", "user", "lsit")
	var doc struct {
		Error struct{ Code, Message, Hint string }
	}
	if res.code != ExitUsage || json.Unmarshal([]byte(res.stderr), &doc) != nil || doc.Error.Code != "usage" ||
		doc.Error.Hint != `did you mean "fileparcel user list"?` || !strings.Contains(doc.Error.Message, `unknown command "lsit"`) {
		t.Errorf("--json user lsit: %+v %+v", res, doc)
	}
	// Suggestions are never run: prefix matching stays off.
	if res := runArgs(t, "", "user", "li"); res.code != ExitUsage || !strings.Contains(res.stderr, "\tlist") {
		t.Errorf("user li: %+v", res)
	}
}

func TestTaskWordHints(t *testing.T) {
	root := NewRootCmd()
	for word := range taskHints {
		if c, _, err := root.Find([]string{word}); err == nil && c != root {
			t.Errorf("taskHints key %q is a command or topic (%s)", word, c.CommandPath())
		}
	}
	for word, want := range map[string]string{"upload": "files put", "passwd": "user reset-password",
		"funnel": "network funnel", "headscale": "network vpn", "grant": "access", "start": "service start",
		"mfa": "user reset-2fa"} {
		res := runArgs(t, "", word)
		if res.code != ExitUsage {
			t.Errorf("%s: %+v", word, res)
		}
		if isPending(want) {
			if strings.Contains(res.stderr, "\t"+want+"\n") {
				t.Errorf("%s suggests %q, which does not exist yet", word, want)
			}
			continue
		}
		if !strings.Contains(res.stderr, "\t"+want+"\n") {
			t.Errorf("%s: want the suggestion %q: %s", word, want, res.stderr)
		}
	}
	// A mistyped old top-level name points at the new one.
	if res := runArgs(t, "", "mnds"); !strings.Contains(res.stderr, "\tnetwork mdns\n") {
		t.Errorf("mnds: %+v", res)
	}
	// The owner's word for roles is an alias, not a hint.
	for _, w := range []string{"class", "classes"} {
		if c, _, err := root.Find([]string{w}); err != nil || c.Name() != "role" {
			t.Errorf("%s does not run role: %v", w, err)
		}
	}
}

func TestUnknownFlagSuggests(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"user", "list", "--rol", "x"}, []string{"unknown flag --rol", "Did you mean this?\n\t--role\n"}},
		{[]string{"share", "show", "shr_x", "--inactive"}, []string{`"--inactive" belongs to "fileparcel share list"`}},
		{[]string{"uninstall", "--dir", "/x"}, []string{"\t--home\n"}},
		{[]string{"role", "create", "x", "--allow", "a"}, []string{"unknown flag --allow", "\t--add\n"}},
		{[]string{"user", "create", "bob", "--password"}, []string{"\t--password-stdin\n", "\t--generate-password\n"}},
		{[]string{"user", "list", "-Z"}, []string{`-Z is not a flag of "fileparcel user list"`, "-q (--query)"}},
		{[]string{"share", "create", "x", "--expires"}, []string{"--expires needs a value, e.g. --expires 7d"}},
		{[]string{"audit", "list", "--limit", "soon"}, []string{`--limit must be a whole number (got "soon")`}},
		{[]string{"gc", "--min-age", "soon"}, []string{"--min-age must be a duration such as 30m, 12h or 7d"}},
	} {
		res := runArgs(t, "", tc.args...)
		if res.code != ExitUsage {
			t.Errorf("%v: exit %d", tc.args, res.code)
		}
		for _, w := range tc.want {
			if !strings.Contains(res.stderr, w) {
				t.Errorf("%v: %q missing in:\n%s", tc.args, w, res.stderr)
			}
		}
	}
	if res := runArgs(t, "", "uninstall", "--dir", "/x"); strings.Contains(res.stderr, "belongs to") {
		t.Errorf("top-level commands are not siblings: %s", res.stderr)
	}
}

func TestArgsErrorsFriendly(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"user", "create"}, []string{`"fileparcel user create" needs <user>`, "Usage:   fileparcel user create <user> [flags]",
			"Example: fileparcel user create alice"}},
		{[]string{"files", "ls", "/My", "files/Docs"}, []string{`got 2: "/My", "files/Docs"`,
			`hint: put quotes around paths with spaces: "/My files/Docs"`}},
		{[]string{"status", "extra"}, []string{`takes no arguments (unknown command "extra")`}},
		{[]string{"install", "--boot", "--no-boot"}, []string{"use only one of --boot and --no-boot"}},
		{[]string{"upgrade"}, []string{"needs <release.zip|binary>"}},
		{[]string{"user", "set-quota", "bob"}, []string{"needs <user> <size|unlimited|default>, got 1"}},
		{[]string{"token", "create"}, []string{`"fileparcel token create" needs <name>`}},
		{[]string{"cert", "sans", "add"}, []string{"needs <name|ip>..."}},
	} {
		res := runArgs(t, "", tc.args...)
		if res.code != ExitUsage {
			t.Errorf("%v: exit %d (%s)", tc.args, res.code, res.stderr)
		}
		for _, w := range tc.want {
			if !strings.Contains(res.stderr, w) {
				t.Errorf("%v: %q missing in:\n%s", tc.args, w, res.stderr)
			}
		}
	}
}

func TestFriendlyCobraError(t *testing.T) {
	for in, want := range map[string]string{
		"if any flags in the group [boot no-boot] are set none of the others can be; [boot no-boot] were all set": "use only one of --boot and --no-boot",
		"if any flags in the group [a b c] are set they must all be set; missing [c]":                             "--a and --b need --c",
		"if any flags in the group [a b] are set they must all be set; missing [b]":                               "--a needs --b",
		"at least one of the flags in the group [kek master data] is required":                                    "use one of --kek, --master or --data",
		`required flag(s) "cert" not set`:                                                                         "--cert is required",
		`required flag(s) "cert", "key" not set`:                                                                  "--cert and --key are required",
	} {
		err := friendlyCobraError(errors.New(in))
		if err == nil || err.Error() != want || !isUsage(err) {
			t.Errorf("%q → %v", in, err)
		}
	}
	other := errors.New("boom")
	if friendlyCobraError(other) != other {
		t.Error("other errors must pass through")
	}
}

func TestLevenshtein(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"", "", 0}, {"list", "list", 0}, {"lsit", "list", 1}, {"lsit", "edit", 2}, {"LIST", "list", 0},
		{"kitten", "sitting", 3}, {"", "abc", 3}, {"ab", "ba", 1}, {"héllo", "hello", 1}, {"ca", "abc", 3},
	} {
		if got := levenshtein(tc.a, tc.b); got != tc.want || levenshtein(tc.b, tc.a) != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ---------- secrets and standard input ----------

func TestSecretPromptGuard(t *testing.T) {
	for _, args := range [][]string{
		{"share", "create", "x", "--password", "hunter2"},
		{"share", "create", "x", "--password=hunter2"},
		{"share", "create", "--password", "hunter2", "x"},
		{"request", "create", "/My files/In", "--password", "hunter2"},
		{"share", "edit", "shr_x", "--password", "hunter2"},
	} {
		res := runArgs(t, "", args...)
		if res.code != ExitUsage || strings.Contains(res.stderr, "hunter2") || !strings.Contains(res.stderr, "--password takes no value") {
			t.Errorf("%v: %+v", args, res)
		}
	}
	// The zip password: a word after it would name the file inside the zip.
	for _, args := range [][]string{
		{"files", "put", "a", "b", "--zip", "z", "--zip-password", "hunter2"},
		{"files", "put", "a", "b", "--zip", "z", "--zip-password=hunter2"},
		{"files", "put", "a", "b", "--zip", "z", "--zip-password", "--", "hunter2"},
	} {
		res := runArgs(t, "", args...)
		if res.code != ExitUsage || strings.Contains(res.stderr, "hunter2") || !strings.Contains(res.stderr, "--zip-password takes no value") ||
			!strings.Contains(res.stderr, "--zip-password-stdin / --zip-password-file") {
			t.Errorf("%v: %+v", args, res)
		}
	}
	// JSON errors do not echo it either.
	if res := runArgs(t, "", "--json", "share", "create", "x", "--password=hunter2"); res.code != ExitUsage || strings.Contains(res.stderr, "hunter2") {
		t.Errorf("--json: %+v", res)
	}
	// A flag after --password is fine; without a terminal the prompt fails
	// with advice instead of hanging.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	root := NewRootCmd()
	var stderr bytes.Buffer
	root.SetIn(devNull)
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	code := run(context.Background(), root, []string{"share", "create", "x", "--password", "--expires", "7d"}, &stderr)
	if code != ExitFailure || !strings.Contains(stderr.String(), "use --password-stdin or --password-file") {
		t.Errorf("prompt without a terminal: exit %d, %s", code, stderr.String())
	}
	// Only prompt flags are guarded: a -stdin flag may be followed by a path.
	if err := checkSecretPrompts(findCommand(NewRootCmd(), "share create"), []string{"share", "create", "--password-stdin", "x"}); err != nil {
		t.Errorf("--password-stdin x: %v", err)
	}
	// Words after "--" are arguments, never flags.
	if err := checkSecretPrompts(findCommand(NewRootCmd(), "share create"), []string{"share", "create", "--", "--password", "x"}); err != nil {
		t.Errorf("after --: %v", err)
	}
}

func TestStdinFlagsExclusive(t *testing.T) {
	t.Setenv("FILEPARCEL_HOME", filepath.Join(t.TempDir(), "none"))
	for _, args := range [][]string{
		{"user", "create", "x", "--password-stdin", "--passphrase-stdin"},
		{"--passphrase-stdin", "share", "create", "x", "--password-stdin"},
		{"config", "set", "smtp.password", "--passphrase-stdin"},
		{"init", "--home", "/nonexistent/x", "--admin-password-stdin", "--passphrase-stdin", "--sealed"},
		{"files", "put", "a", "b", "--zip", "z", "--zip-password-stdin", "--passphrase-stdin"},
	} {
		res := runArgs(t, "", args...)
		if res.code != ExitUsage || !strings.Contains(res.stderr, "cannot both read standard input") {
			t.Errorf("%v: %+v", args, res)
		}
	}
	// A --X-file alternative is named when the command has one.
	res := runArgs(t, "", "user", "create", "x", "--password-stdin", "--passphrase-stdin")
	if !strings.Contains(res.stderr, "use --passphrase-file or --password-file for one of them") {
		t.Errorf("advice: %s", res.stderr)
	}
}

// ---------- flag conventions ----------

func TestWaitFlags(t *testing.T) {
	root := NewRootCmd()
	for _, p := range []string{"backup create", "backup verify", "keys rotate", "jobs run", "service start", "service restart"} {
		c := findCommand(root, p)
		if c == nil || c.Flags().Lookup("wait") == nil || c.Flags().Lookup("no-wait") == nil {
			t.Errorf("%s lacks --wait/--no-wait", p)
			continue
		}
		args := append(strings.Fields(p), "--wait", "--no-wait")
		if p == "backup verify" || p == "jobs run" {
			args = append(args, "x")
		}
		if res := runArgs(t, "", args...); res.code != ExitUsage || !strings.Contains(res.stderr, "use only one of --no-wait and --wait") {
			t.Errorf("%v: %+v", args, res)
		}
	}
	// Each help states the default once.
	for p, def := range map[string]string{"backup create": "no-wait", "backup verify": "wait", "keys rotate": "wait",
		"jobs run": "no-wait", "service start": "wait"} {
		c := findCommand(root, p)
		if !strings.HasSuffix(c.Flags().Lookup(def).Usage, "(default)") {
			t.Errorf("%s: --%s usage %q", p, def, c.Flags().Lookup(def).Usage)
		}
	}
	// --output needs the finished backup.
	if res := runArgs(t, "", "backup", "create", "-o", t.TempDir(), "--no-wait"); res.code != ExitUsage {
		t.Errorf("backup create -o --no-wait: %+v", res)
	}
}

func TestWaitFlagsDecide(t *testing.T) {
	for _, tc := range []struct {
		args []string
		def  bool
		want bool
	}{
		{nil, false, false}, {nil, true, true}, {[]string{"--wait"}, false, true}, {[]string{"--no-wait"}, true, false},
		{[]string{"--wait=false"}, true, false}, {[]string{"--no-wait=false"}, false, true},
	} {
		cmd := &cobra.Command{Use: "x"}
		w := addWaitFlags(cmd, tc.def, "done")
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		if w.Wait() != tc.want || w.Explicit() != (len(tc.args) > 0) {
			t.Errorf("%v (default %v): Wait %v", tc.args, tc.def, w.Wait())
		}
	}
}

func TestDurationFlags(t *testing.T) {
	root := NewRootCmd()
	c, err := parseInvocation(root, []string{"gc", "--dry-run", "--min-age", "2d"})
	if err != nil || c.Flags().Lookup("min-age").Value.String() != "2d" {
		t.Fatalf("gc --min-age 2d: %v", err)
	}
	if res := runArgs(t, "", "gc", "--help"); !strings.Contains(res.stdout, "(default 2d)") {
		t.Errorf("gc --help:\n%s", res.stdout)
	}
	for _, args := range [][]string{{"healthcheck", "--timeout", "1m"}, {"healthcheck", "--timeout", "500ms"},
		{"audit", "list", "--interval", "1d12h"}} {
		if _, err := parseInvocation(NewRootCmd(), args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	var d time.Duration
	cmd := &cobra.Command{Use: "x"}
	durationVar(cmd.Flags(), &d, "every", 0, "interval")
	if err := cmd.ParseFlags([]string{"--every", "1w"}); err != nil || d != 7*24*time.Hour {
		t.Errorf("1w: %v %v", d, err)
	}
	if err := cmd.ParseFlags([]string{"--every", "-5m"}); err == nil {
		t.Error("a negative duration was accepted")
	}
}

func TestExpiryFlags(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("POST", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.TokenInput](r)
		writeJSON(w, 201, core.TokenCreated{Token: &core.APIToken{ID: ids.New(ids.PrefixToken), Name: in.Name, Scopes: in.Scopes}, Secret: "fpt_x"})
	})
	f.handle("GET", "/api/v1/me/mfa", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, core.MFAStatus{}) })
	if res := f.run(t, "", "token", "create", "t", "--expires", "2099-12-31"); res.code != 0 {
		t.Fatalf("token create --expires DATE: %+v", res)
	}
	var ti core.TokenInput
	_ = json.Unmarshal(f.body("POST /api/v1/me/tokens"), &ti)
	if ti.ExpiresAt == nil || ti.ExpiresAt.Local().Format("2006-01-02 15:04:05") != "2099-12-31 23:59:59" {
		t.Errorf("token expiry %v", ti.ExpiresAt)
	}
	for _, args := range [][]string{{"invite", "create", "--expires", "never"}, {"client-cert", "issue", "bob", "--expires", "never"},
		{"client-cert", "issue", "bob", "--expires", "30d", "--days", "30"}, {"client-cert", "issue", "bob", "--expires", "11000d"}} {
		if res := f.run(t, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]int{"365d": 365, "12h": 1, "1d1h": 2, "2w": 14} {
		if got, err := expiryDays(in, now); err != nil || got != want {
			t.Errorf("expiryDays(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}

// ---------- server errors ----------

func TestNotFoundHint(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("GET", "/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.User]{Items: []core.User{}})
	})
	f.handle("GET", "/api/v1/shares/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.NotFoundf("share not found"))
	})
	res := f.run(t, "", "user", "show", "nobody")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `hint: list them with "fileparcel user list"`) {
		t.Errorf("user show nobody: %+v", res)
	}
	res = f.run(t, "", "share", "show", "shr_01j9zq3x4k6m8p0r2t4v6x8z0b")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `hint: list them with "fileparcel share list --inactive"`) {
		t.Errorf("share show: %+v", res)
	}
	res = f.run(t, "", "--json", "share", "show", "shr_01j9zq3x4k6m8p0r2t4v6x8z0b")
	var doc struct {
		Error struct{ Code, Message, Hint string }
	}
	if json.Unmarshal([]byte(res.stderr), &doc) != nil || doc.Error.Code != "not_found" || doc.Error.Message != "share not found" ||
		doc.Error.Hint != `list them with "fileparcel share list --inactive"` {
		t.Errorf("--json: %+v", res)
	}
	// A path's parent folder is named for files.
	for args, want := range map[string]string{
		"files info|/My files/Docs/a.pdf":      "fileparcel files ls '/My files/Docs'",
		"files ls|/Team/Nope":                  "fileparcel files ls /Team",
		"files ls|Documents":                   "fileparcel files ls",
		"files put|./a.txt|./b.txt|/Team/X/In": "fileparcel files ls /Team/X",
		"files restore|a.txt":                  "fileparcel files trash",
		"share create|/My files/x.pdf":         "fileparcel files ls '/My files'",
		"share show|shr_x":                     "fileparcel share list --inactive",
		"request create|/Team/Design/Incoming": "fileparcel files ls /Team/Design",
		"group add-member|Design|alice":        "fileparcel group list",
		"access list|/Team/Design/Nope":        "fileparcel files ls /Team/Design",
		"access check|bob|/Team/X/y.pdf":       "fileparcel files ls /Team/X",
		"role show|contractors":                "fileparcel role list",
		"network vpn allow|wg9":                "fileparcel network vpn list",
		"keys status":                          "",
	} {
		words := strings.Split(args, "|")
		c, err := parseInvocation(NewRootCmd(), append(strings.Fields(words[0]), words[1:]...))
		if err != nil {
			t.Fatalf("%s: %v", args, err)
		}
		if got := listHint(c); got != want {
			t.Errorf("%s: hint %q, want %q", args, got, want)
		}
	}
}

func TestCommandHints(t *testing.T) {
	t.Cleanup(func() { G = Globals{} })
	root := NewRootCmd()
	list := findCommand(root, "user list")
	create := findCommand(root, "group create")
	forbidden := &core.Error{Code: core.ErrForbidden.Code, Status: 403, Message: "forbidden"}
	G = Globals{Server: "https://x"}
	if err := explainErrorFor(list, forbidden); !strings.Contains(err.Error(), "the token's account or scopes do not allow this") ||
		!strings.Contains(err.Error(), `"fileparcel whoami" or "fileparcel role show <role>"`) {
		t.Errorf("remote 403: %v", err)
	}
	G = Globals{As: "bob"}
	if err := explainErrorFor(list, forbidden); !strings.Contains(err.Error(), "bob's role or access does not allow this; drop --as") {
		t.Errorf("socket 403 with --as: %v", err)
	}
	G = Globals{}
	if err := explainErrorFor(list, forbidden); strings.Contains(err.Error(), "hint:") {
		t.Errorf("socket 403 without --as: %v", err)
	}
	if err := explainErrorFor(list, &core.Error{Code: core.ErrInvalid.Code, Status: 422, Message: "bad", Field: "storage.trash_days"}); !strings.Contains(err.Error(), `"fileparcel config get storage.trash_days --json"`) {
		t.Errorf("setting 422: %v", err)
	}
	if err := explainErrorFor(create, &core.Error{Code: core.ErrConflict.Code, Status: 409, Message: "exists"}); !strings.Contains(err.Error(), `it already exists; see "fileparcel group list"`) {
		t.Errorf("409 on create: %v", err)
	}
	// An --as user that does not exist is named as such.
	G = Globals{As: "nobody"}
	if err := explainErrorFor(findCommand(root, "files ls"), &core.Error{Code: core.ErrNotFound.Code, Status: 404,
		Message: `user "nobody" not found`}); !strings.Contains(err.Error(), `--as nobody names no user; list them with "fileparcel user list"`) {
		t.Errorf("unknown --as user: %v", err)
	}
	G = Globals{}
	// No hint repeats what the message already says.
	if err := explainErrorFor(findCommand(root, "config get"), &core.Error{Code: core.ErrNotFound.Code, Status: 404,
		Message: `unknown setting "x.y" (see "fileparcel config list --all")`}); strings.Contains(err.Error(), "hint:") {
		t.Errorf("repeated hint: %v", err)
	}
	// Code and exit status survive the hint.
	err := explainErrorFor(list, &core.Error{Code: core.ErrNotFound.Code, Status: 404, Message: "x"})
	if ce := core.AsError(err); ce == nil || ce.Code != core.ErrNotFound.Code {
		t.Errorf("code lost: %v", err)
	}
	if err := explainErrorFor(list, nil); err != nil {
		t.Error("nil")
	}
}

func TestConnectionHints(t *testing.T) {
	dir := t.TempDir()
	_, err := Connect(Options{Home: dir})
	var he *hintError
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "is not a FileParcel home") || !strings.Contains(he.hint, "FILEPARCEL_HOME") {
		t.Errorf("not a home: %v", err)
	}
	sock := filepath.Join(dir, "admin.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = socketAccessError(sock, errors.New("permission denied"))
	if !errors.As(err, &he) || !strings.Contains(he.hint, "run the command as that user or") {
		t.Errorf("socket access: %v", err)
	}
}

// ---------- commands renamed or added with the registry ----------

func TestTokenCreatePositional(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("POST", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.TokenInput](r)
		writeJSON(w, 201, core.TokenCreated{Token: &core.APIToken{ID: ids.New(ids.PrefixToken), Name: in.Name}, Secret: "fpt_x"})
	})
	f.handle("GET", "/api/v1/me/mfa", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, core.MFAStatus{}) })
	for _, args := range [][]string{{"token", "create", "laptop"}, {"token", "create", "--name", "laptop"},
		{"token", "create", "laptop", "--name", "laptop"}} {
		if res := f.run(t, "", args...); res.code != 0 {
			t.Errorf("%v: %+v", args, res)
			continue
		}
		var ti core.TokenInput
		if _ = json.Unmarshal(f.body("POST /api/v1/me/tokens"), &ti); ti.Name != "laptop" {
			t.Errorf("%v: name %q", args, ti.Name)
		}
	}
	for _, args := range [][]string{{"token", "create"}, {"token", "create", "a", "--name", "b"}, {"token", "create", "a", "b"}} {
		if res := f.run(t, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	if res := runArgs(t, "", "token", "create", "--help"); strings.Contains(res.stdout, "--name") {
		t.Error("the legacy --name is shown in the help")
	}
}

// fakeShareStore serves /shares/{id} GET and PATCH for one share.
func fakeShareStore(f *fakeAPI, s *core.Share) *sync.Mutex {
	var mu sync.Mutex
	f.handle("GET", "/api/v1/shares/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if chi.URLParam(r, "id") != s.ID {
			writeErr(w, core.NotFoundf("share not found"))
			return
		}
		writeJSON(w, 200, s)
	})
	f.handle("PATCH", "/api/v1/shares/{id}", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.ShareUpdate](r)
		mu.Lock()
		defer mu.Unlock()
		if in.Disabled != nil {
			s.Status = map[bool]string{true: core.ShareDisabled, false: core.ShareActive}[*in.Disabled]
		}
		writeJSON(w, 200, s)
	})
	return &mu
}

func TestShareEnableDisable(t *testing.T) {
	f := newFakeAPI(t)
	s := &core.Share{ID: "shr_01j9zq3x4k6m8p0r2t4v6x8z0b", Kind: core.ShareLink, Status: core.ShareActive, NodeName: "a.pdf", URL: "/s/tok"}
	mu := fakeShareStore(f, s)
	status := func() string { mu.Lock(); defer mu.Unlock(); return s.Status }
	res := f.run(t, "", "share", "disable", s.ID)
	if res.code != 0 || status() != core.ShareDisabled || !strings.Contains(res.stdout, "disabled share link "+s.ID) {
		t.Fatalf("share disable: %+v", res)
	}
	res = f.run(t, "", "--json", "share", "enable", s.ID)
	var out core.Share
	if res.code != 0 || status() != core.ShareActive || json.Unmarshal([]byte(res.stdout), &out) != nil || out.ID != s.ID ||
		!strings.HasPrefix(out.URL, f.srv.URL) {
		t.Fatalf("share enable --json: %+v", res)
	}
	// A file request id is refused by the share commands.
	mu.Lock()
	s.Kind = core.ShareRequest
	mu.Unlock()
	if res := f.run(t, "", "share", "disable", s.ID); res.code != ExitUsage || !strings.Contains(res.stderr, "fileparcel request") {
		t.Fatalf("share disable of a request: %+v", res)
	}
}

func TestRequestReopen(t *testing.T) {
	f := newFakeAPI(t)
	s := &core.Share{ID: "shr_01j9zq3x4k6m8p0r2t4v6x8z0c", Kind: core.ShareRequest, Status: core.ShareActive, NodeName: "In"}
	mu := fakeShareStore(f, s)
	status := func() string { mu.Lock(); defer mu.Unlock(); return s.Status }
	if res := f.run(t, "", "request", "close", s.ID); res.code != 0 || status() != core.ShareDisabled || !strings.Contains(res.stdout, "closed file request") {
		t.Fatalf("request close: %+v", res)
	}
	if res := f.run(t, "", "request", "reopen", s.ID); res.code != 0 || status() != core.ShareActive || !strings.Contains(res.stdout, "reopened file request") {
		t.Fatalf("request reopen: %+v", res)
	}
	// The legacy form still works.
	f.run(t, "", "request", "close", s.ID)
	if res := f.run(t, "", "request", "close", s.ID, "--reopen"); res.code != 0 || status() != core.ShareActive {
		t.Fatalf("request close --reopen: %+v", res)
	}
}

func TestCertSansSubcommands(t *testing.T) {
	f := newFakeAPI(t)
	store := addSettingsRoutes(f)
	f.handle("GET", "/api/v1/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.CertStatus{Leaf: &core.CertInfo{Subject: "fileparcel", DNSNames: []string{"fileparcel.local"}}})
	})
	if res := f.run(t, "", "cert", "sans", "add", "files.home.arpa", "10.8.0.1"); res.code != 0 ||
		stored(store, "tls.extra_sans") != `["a.lan","files.home.arpa","10.8.0.1"]` {
		t.Fatalf("sans add: %+v %s", res, stored(store, "tls.extra_sans"))
	}
	if res := f.run(t, "", "cert", "sans", "rm", "a.lan"); res.code != 0 || stored(store, "tls.extra_sans") != `[]` {
		t.Fatalf("sans rm: %+v %s", res, stored(store, "tls.extra_sans"))
	}
	for _, args := range [][]string{{"cert", "sans"}, {"cert", "sans", "list"}, {"cert", "sans", "ls"}} {
		if res := f.run(t, "", args...); res.code != 0 || !strings.Contains(res.stdout, "fileparcel.local") {
			t.Fatalf("%v: %+v", args, res)
		}
	}
	a, b := f.run(t, "", "--json", "cert", "sans"), f.run(t, "", "--json", "cert", "sans", "list")
	if a.stdout != b.stdout || !strings.Contains(a.stdout, `"extra_sans"`) {
		t.Fatalf("JSON of cert sans and cert sans list differ:\n%s\n%s", a.stdout, b.stdout)
	}
	if res := f.run(t, "", "cert", "sans", "add", "bad name"); res.code != ExitUsage {
		t.Fatalf("bad name: %+v", res)
	}
}

// ---------- commands of the tidy-up ----------

func TestMaintenanceSubcommands(t *testing.T) {
	f := newFakeAPI(t)
	store := addSettingsRoutes(f,
		core.SettingView{Key: maintenanceKey, Type: "bool", Value: json.RawMessage("false"), Default: json.RawMessage("false")},
		core.SettingView{Key: maintenanceMessageKey, Type: "string", Value: json.RawMessage(`""`), Default: json.RawMessage(`""`)})
	for _, args := range [][]string{{"maintenance"}, {"maintenance", "status"}, {"maintenance", "STATUS"}} {
		if res := f.run(t, "", args...); res.code != 0 || !strings.Contains(res.stdout, "Maintenance mode: off") ||
			f.requested("PATCH /api/v1/admin/settings") != 0 {
			t.Fatalf("%v: %+v", args, res)
		}
	}
	a, b := f.run(t, "", "--json", "maintenance"), f.run(t, "", "--json", "maintenance", "status")
	if a.code != 0 || a.stdout != b.stdout || !strings.Contains(a.stdout, `"enabled": false`) {
		t.Fatalf("JSON of maintenance and maintenance status:\n%s\n%s", a.stdout, b.stdout)
	}
	// --message works before and after the word, and the old positional
	// words keep working in any case.
	for _, tc := range []struct {
		args    []string
		enabled string
		message string
	}{
		{[]string{"maintenance", "on", "--message", "back at 14:00"}, "true", `"back at 14:00"`},
		{[]string{"maintenance", "off"}, "false", `"back at 14:00"`},
		{[]string{"maintenance", "--message", "back at 15:00", "on"}, "true", `"back at 15:00"`},
		{[]string{"maintenance", "Disable"}, "false", `"back at 15:00"`},
		{[]string{"maintenance", "--message", "soon", "ON"}, "true", `"soon"`},
		{[]string{"maintenance", "OFF"}, "false", `"soon"`},
		{[]string{"maintenance", "enable"}, "true", `"soon"`},
	} {
		if res := f.run(t, "", tc.args...); res.code != 0 || stored(store, maintenanceKey) != tc.enabled ||
			stored(store, maintenanceMessageKey) != tc.message {
			t.Fatalf("%v: %+v (enabled %s, message %s)", tc.args, res, stored(store, maintenanceKey), stored(store, maintenanceMessageKey))
		}
	}
	for _, args := range [][]string{
		{"maintenance", "sideways"}, {"maintenance", "on", "off"}, {"maintenance", "status", "--message", "x"},
		{"maintenance", "--message", "x", "OFF"}, {"maintenance", "on", "extra"},
	} {
		if res := f.run(t, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	if res := f.run(t, "", "maintenance", "of"); res.code != ExitUsage || !strings.Contains(res.stderr, "Did you mean") ||
		!strings.Contains(res.stderr, "\toff\n") {
		t.Errorf("maintenance of: %+v", res)
	}
}

func TestGroupAddSeveral(t *testing.T) {
	f := newFakeAPI(t)
	gid := ids.New(ids.PrefixGroup)
	users := map[string]string{}
	for _, name := range []string{"alice", "bob", "carol"} {
		users[name] = ids.New(ids.PrefixUser)
	}
	f.handle("GET", "/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		out := []core.User{}
		if id := users[r.URL.Query().Get("q")]; id != "" {
			out = append(out, core.User{ID: id, Username: r.URL.Query().Get("q")})
		}
		writeJSON(w, 200, core.Page[core.User]{Items: out})
	})
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{{ID: gid, Name: "Design"}}})
	})
	f.handle("PUT", "/api/v1/admin/groups/{id}/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	f.handle("DELETE", "/api/v1/admin/groups/{id}/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	put := func(name string) int {
		return f.requested("PUT /api/v1/admin/groups/" + gid + "/members/" + users[name])
	}

	// One user: the object of old versions.
	res := f.run(t, "", "--json", "group", "add-member", "Design", "alice")
	var one memberResult
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &one) != nil ||
		one != (memberResult{GroupID: gid, UserID: users["alice"], Role: core.GroupRoleMember}) {
		t.Fatalf("one user: %+v", res)
	}
	// Several: an array, in order.
	res = f.run(t, "", "--json", "group", "add-member", "Design", "bob", "carol", "--manager")
	var several []memberResult
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &several) != nil || len(several) != 2 ||
		several[0].UserID != users["bob"] || several[1].UserID != users["carol"] || several[1].Role != core.GroupRoleManager {
		t.Fatalf("several users: %+v", res)
	}
	if res := f.run(t, "", "group", "add-member", "Design", "alice", "bob"); res.code != 0 ||
		!strings.Contains(res.stdout, `"alice" is now a member of "Design"`) || !strings.Contains(res.stdout, `"bob" is now a member`) {
		t.Fatalf("add-member text: %+v", res)
	}
	// It stops at the first error and says who was added.
	before := put("carol")
	res = f.run(t, "", "group", "add-member", "Design", "alice", "nobody", "carol")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `user "nobody" not found`) ||
		!strings.Contains(res.stderr, `"alice" was added before this error`) || put("carol") != before {
		t.Fatalf("add-member with an unknown user: %+v", res)
	}
	// remove-member: several users, JSON unchanged.
	res = f.run(t, "", "--json", "group", "remove-member", "Design", "alice", "bob")
	if res.code != 0 || strings.TrimSpace(res.stdout) != "{\n  \"ok\": true\n}" ||
		f.requested("DELETE /api/v1/admin/groups/"+gid+"/members/"+users["bob"]) != 1 {
		t.Fatalf("remove-member: %+v", res)
	}
	if res := f.run(t, "", "group", "add-member", "Design"); res.code != ExitUsage {
		t.Fatalf("add-member without users: %+v", res)
	}
}

func TestGroupShowEdit(t *testing.T) {
	f := newFakeAPI(t)
	g := core.Group{ID: ids.New(ids.PrefixGroup), Name: "Design", Description: "Design team", MemberCount: 1}
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{g}})
	})
	f.handle("GET", "/api/v1/admin/groups/{id}", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, g) })
	f.handle("GET", "/api/v1/admin/groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.GroupMember]{Items: []core.GroupMember{{UserID: "usr_a", Username: "alice", Role: core.GroupRoleManager}}})
	})
	f.handle("PATCH", "/api/v1/admin/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.GroupInput](r)
		out := g
		if in.Name != "" {
			out.Name = in.Name
		}
		if in.Description != nil {
			out.Description = *in.Description
		}
		writeJSON(w, 200, out)
	})
	res := f.run(t, "", "group", "show", "design")
	if res.code != 0 || !strings.Contains(res.stdout, "Team folder: /Team/Design") || !strings.Contains(res.stdout, "alice") ||
		!strings.Contains(res.stdout, "manager") {
		t.Fatalf("group show: %+v", res)
	}
	var out groupDetails
	res = f.run(t, "", "--json", "group", "show", g.ID)
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &out) != nil || out.Group == nil || out.Group.ID != g.ID ||
		len(out.Members) != 1 || out.Members[0].Username != "alice" {
		t.Fatalf("group show --json: %+v", res)
	}
	patch := "PATCH /api/v1/admin/groups/" + g.ID
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--description", "Product design team"}, `{"description":"Product design team"}`},
		{[]string{"--description", ""}, `{"description":""}`},
		{[]string{"--name", "Product Design"}, `{"name":"Product Design"}`},
	} {
		if res := f.run(t, "", append([]string{"group", "edit", "Design"}, tc.args...)...); res.code != 0 {
			t.Fatalf("group edit %v: %+v", tc.args, res)
		}
		if got := strings.TrimSpace(string(f.body(patch))); got != tc.want {
			t.Errorf("group edit %v sent %s, want %s", tc.args, got, tc.want)
		}
	}
	for _, args := range [][]string{{"group", "edit", "Design"}, {"group", "edit", "Design", "--name", " "}} {
		if res := f.run(t, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	// rename keeps its hidden --description.
	if res := f.run(t, "", "group", "rename", "Design", "Studio", "--description", "d"); res.code != 0 ||
		strings.TrimSpace(string(f.body(patch))) != `{"name":"Studio","description":"d"}` {
		t.Fatalf("group rename --description: %+v %s", res, f.body(patch))
	}
}

func TestNetworkStatusEqualsOverview(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("GET", "/api/v1/admin/network", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.NetworkOverview{Policy: core.AccessPolicy{Mode: core.AccessAllowlist, Allow: []string{"192.168.1.0/24"}},
			ClientIP: "192.168.1.5", URLs: []core.AccessURL{{URL: "https://192.168.1.10:8443/", Kind: core.URLKindIP, Label: "LAN"}}})
	})
	for _, extra := range [][]string{nil, {"--json"}} {
		bare := f.run(t, "", append(extra, "network")...)
		for _, sub := range []string{"status", "show"} {
			res := f.run(t, "", append(extra, "network", sub)...)
			if bare.code != 0 || res.code != 0 || res.stdout != bare.stdout || !strings.Contains(res.stdout, "192.168.1.10") {
				t.Fatalf("%v network %s differs from network:\n%s\n%s", extra, sub, res.stdout, bare.stdout)
			}
		}
	}
	if res := f.run(t, "", "network", "status", "extra"); res.code != ExitUsage {
		t.Fatalf("network status extra: %+v", res)
	}
}

func TestShareEditBooleans(t *testing.T) {
	if res := runArgs(t, "", "share", "edit", "--help"); res.code != 0 || strings.Contains(res.stdout, "(default true)") ||
		!strings.Contains(res.stdout, "--no-download") {
		t.Fatalf("share edit --help:\n%s", res.stdout)
	}
	f := newFakeAPI(t)
	s := &core.Share{ID: "shr_01j9zq3x4k6m8p0r2t4v6x8z0b", Kind: core.ShareLink, Status: core.ShareActive, NodeName: "a.pdf"}
	fakeShareStore(f, s)
	patch := "PATCH /api/v1/shares/" + s.ID
	sent := func(args ...string) map[string]any {
		t.Helper()
		if res := f.run(t, "", append([]string{"share", "edit", s.ID}, args...)...); res.code != 0 {
			t.Fatalf("share edit %v: %+v", args, res)
		}
		var body map[string]any
		if err := json.Unmarshal(f.body(patch), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, tc := range []struct {
		args []string
		want map[string]any
	}{
		{[]string{"--no-download"}, map[string]any{"allow_download": false}},
		{[]string{"--download"}, map[string]any{"allow_download": true}},
		{[]string{"--download=false"}, map[string]any{"allow_download": false}},
		{[]string{"--no-preview", "--upload"}, map[string]any{"allow_preview": false, "allow_upload": true}},
		{[]string{"--no-notify=false"}, map[string]any{"notify_owner": true}},
	} {
		body := sent(tc.args...)
		for k, v := range tc.want {
			if body[k] != v {
				t.Errorf("%v: %s = %v, want %v (body %v)", tc.args, k, body[k], v, body)
			}
		}
		// Switches not given are not sent.
		for _, k := range []string{"allow_download", "allow_preview", "allow_upload", "notify_owner"} {
			if _, ok := tc.want[k]; !ok {
				if _, sent := body[k]; sent {
					t.Errorf("%v: %s sent although not given (body %v)", tc.args, k, body)
				}
			}
		}
	}
	for _, args := range [][]string{{"--download", "--no-download"}, {"--no-upload", "--upload=false"}, {"--enable", "--disable"}} {
		if res := f.run(t, "", append([]string{"share", "edit", s.ID}, args...)...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
}

// shellWords splits a command line like a POSIX shell (quotes only).
func shellWords(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	var cur strings.Builder
	quote, in := rune(0), false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote, in = r, true
		case r == ' ' || r == '\t':
			if in || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if quote != 0 {
		t.Fatalf("unbalanced quotes in %q", s)
	}
	if in || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
