package cli

// Old command and flag names (DESIGN §12, "Legacy names"): every invocation
// that worked before the command tidy-up keeps working. A renamed command
// gets a hidden copy at its old path, built by the same constructor, so it
// has the same guards, confirmations and elevation (hidden is not weaker).
// A renamed flag is mapped onto the new one by pflag normalization, so the
// old name never appears in help, docs or completion. A renamed leaf
// command keeps its old name as an alias. "fileparcel help renamed" lists
// every entry. Renames go through this file, nowhere else.

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// legacyCommand keeps an old command path working as a hidden copy of the
// new one.
type legacyCommand struct {
	Old, New string                // "mdns" → "network mdns" (paths below "fileparcel")
	Build    func() *cobra.Command // the constructor the new path uses (called again for the copy)
	// KeepAliases keeps the constructor's aliases on the copy (the old
	// top-level "bonjour").
	KeepAliases bool
}

// legacyCommands is set in init: its constructors reach the error helpers,
// which read it, and Go refuses such an initialization cycle.
var legacyCommands []legacyCommand

func init() {
	legacyCommands = []legacyCommand{
		{Old: "mdns", New: "network mdns", Build: newMDNSCmd, KeepAliases: true},
		{Old: "restore", New: "backup restore", Build: newRestoreCmd},
		{Old: "keys export-recovery", New: "keys recovery-key", Build: newKeysRecoveryKeyCmd},
	}
}

// legacyFlag maps an old flag name onto a new one of the same type and
// meaning on one command (and its legacy copy).
type legacyFlag struct{ Command, Old, New string }

var legacyFlags = []legacyFlag{
	{"user create", "generate", "generate-password"},
	{"user reset-password", "generate", "generate-password"},
	{"backup create", "out", "output"},
	{"client-cert issue", "out", "output"},
	{"share list", "all", "all-users"},
	{"request list", "all", "all-users"},
	{"token list", "all", "inactive"},
	{"invite list", "all", "inactive"},
	{"client-cert list", "all", "inactive"},
	{"backup restore", "identity", "identity-file"},
}

// legacyAliases are renamed leaf commands whose old name stays a visible
// alias (the constructor sets it; docs must use the new name).
var legacyAliases = []struct{ Old, New string }{
	{"user add", "user create"}, {"user passwd", "user reset-password"},
	{"user quota", "user set-quota"}, {"share revoke", "share delete"},
}

// legacyNote is a compatibility flag of a constructor itself (a hidden
// flag of another type or meaning), listed in "help renamed".
type legacyNote struct {
	Old, New string   // as "help renamed" shows them
	Command  string   // the command that has the hidden flags
	Flags    []string // their names
}

var legacyNotes = []legacyNote{
	{"request close ID --reopen", "request reopen ID", "request close", []string{"reopen"}},
	{"token create --name NAME", "token create NAME", "token create", []string{"name"}},
	{"cert sans --add X / --remove X", "cert sans add X / remove X", "cert sans", []string{"add", "remove"}},
	{"--days N (client-cert issue)", "--expires Nd", "client-cert issue", []string{"days"}},
}

// LegacyName is an old command or flag name that keeps working
// (tests/docs checks that the documentation no longer uses them).
type LegacyName struct {
	// Command is the old command path below "fileparcel" ("user add",
	// "mdns") when Flag is empty; otherwise the path of the command that
	// takes the old flag.
	Command string
	// Flag is an old flag name without dashes ("generate").
	Flag string
}

// LegacyNames lists every old name of the registry: the old paths of
// renamed commands and leaf commands, and the old flags per command (also
// on the hidden copies of renamed commands).
func LegacyNames() []LegacyName {
	var out []LegacyName
	for _, lc := range legacyCommands {
		out = append(out, LegacyName{Command: lc.Old})
	}
	for _, la := range legacyAliases {
		out = append(out, LegacyName{Command: la.Old})
	}
	for _, lf := range legacyFlags {
		out = append(out, LegacyName{Command: lf.Command, Flag: lf.Old})
		for _, lc := range legacyCommands {
			if lf.Command == lc.New || strings.HasPrefix(lf.Command, lc.New+" ") {
				out = append(out, LegacyName{Command: lc.Old + strings.TrimPrefix(lf.Command, lc.New), Flag: lf.Old})
			}
		}
	}
	for _, n := range legacyNotes {
		for _, f := range n.Flags {
			out = append(out, LegacyName{Command: n.Command, Flag: f})
		}
	}
	return out
}

// legacyNoticeTTY reports whether the note of a legacy command is shown
// (tests replace it: they never run on a terminal).
var legacyNoticeTTY = stderrIsTerminal

// applyLegacy adds the hidden copies of renamed commands, maps renamed
// flags and checks the alias registry. A registry entry whose target does
// not exist is a programming error (NewRootCmd panics; every test fails).
func applyLegacy(root *cobra.Command) {
	for _, lc := range legacyCommands {
		oldWords := strings.Fields(lc.Old)
		parent := findCommand(root, strings.Join(oldWords[:len(oldWords)-1], " "))
		if parent == nil || findCommand(root, lc.New) == nil {
			panic(fmt.Sprintf("cli: legacy command %q: %q does not exist", lc.Old, lc.New))
		}
		c := lc.Build()
		_, rest, _ := strings.Cut(c.Use, " ")
		c.Use = strings.TrimSpace(oldWords[len(oldWords)-1] + " " + rest)
		c.Hidden = true
		c.GroupID = ""
		if !lc.KeepAliases {
			c.Aliases = nil
		}
		base := c.CommandPath() // not attached yet: its own name
		walkCommands(c, func(d *cobra.Command) {
			rel := strings.TrimPrefix(d.CommandPath(), base)
			legacyNotice(d, lc.Old+rel, lc.New+rel)
		})
		parent.AddCommand(c)
	}
	renames := map[string]map[string]string{}
	add := func(path, from, to string) {
		if renames[path] == nil {
			renames[path] = map[string]string{}
		}
		renames[path][from] = to
	}
	for _, lf := range legacyFlags {
		add(lf.Command, lf.Old, lf.New)
		for _, lc := range legacyCommands {
			if lf.Command == lc.New || strings.HasPrefix(lf.Command, lc.New+" ") {
				add(lc.Old+strings.TrimPrefix(lf.Command, lc.New), lf.Old, lf.New)
			}
		}
	}
	for path, m := range renames {
		c := findCommand(root, path)
		if c == nil {
			panic(fmt.Sprintf("cli: legacy flags of %q: no such command", path))
		}
		for from, to := range m {
			if c.Flags().Lookup(to) == nil || c.Flags().Lookup(from) != nil {
				panic(fmt.Sprintf("cli: legacy flag --%s of %q: --%s missing or the old name still defined", from, path, to))
			}
		}
		c.Flags().SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
			if to, ok := m[name]; ok {
				name = to
			}
			return pflag.NormalizedName(name)
		})
	}
	for _, la := range legacyAliases {
		c := findCommand(root, la.New)
		old := strings.Fields(la.Old)
		if c == nil || !slices.Contains(c.Aliases, old[len(old)-1]) {
			panic(fmt.Sprintf("cli: legacy alias %q: %q lacks the alias", la.Old, la.New))
		}
	}
	for _, n := range legacyNotes {
		c := findCommand(root, n.Command)
		for _, name := range n.Flags {
			if c == nil || c.Flags().Lookup(name) == nil || !c.Flags().Lookup(name).Hidden {
				panic(fmt.Sprintf("cli: legacy note %q: %q has no hidden --%s", n.Old, n.Command, name))
			}
		}
	}
}

// legacyNotice makes the legacy copy c print a one-line note on a terminal
// (never with --json, never to scripts and cron jobs, whose stderr is no
// terminal).
func legacyNotice(c *cobra.Command, oldPath, newPath string) {
	run := c.RunE
	if run == nil {
		return
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if !G.JSON && legacyNoticeTTY(cmd) {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: %q is now %q; the old name keeps working.\n",
				"fileparcel "+oldPath, "fileparcel "+newPath)
		}
		return run(cmd, args)
	}
}

// renamedText is the text of "fileparcel help renamed", built from the
// registry: renamed commands, renamed leaf commands, compatibility flags of
// the constructors and renamed flags.
func renamedText(root *cobra.Command) string {
	type row struct{ old, new string }
	var rows []row
	ellipsis := func(path string) string {
		if c := findCommand(root, path); c != nil && (c.HasSubCommands() || strings.Contains(c.Use, " ")) {
			return " …"
		}
		return ""
	}
	for _, lc := range legacyCommands {
		e := ellipsis(lc.New)
		rows = append(rows, row{"fileparcel " + lc.Old + e, "fileparcel " + lc.New + e})
	}
	for _, la := range legacyAliases {
		rows = append(rows, row{"fileparcel " + la.Old, "fileparcel " + la.New})
	}
	var flagNotes []row
	for _, n := range legacyNotes {
		if strings.HasPrefix(n.Old, "-") {
			flagNotes = append(flagNotes, row{n.Old, n.New})
			continue
		}
		rows = append(rows, row{"fileparcel " + n.Old, "fileparcel " + n.New})
	}
	type flagKey struct{ old, new string }
	var order []flagKey
	paths := map[flagKey][]string{}
	for _, lf := range legacyFlags {
		k := flagKey{lf.Old, lf.New}
		if paths[k] == nil {
			order = append(order, k)
		}
		paths[k] = append(paths[k], lf.Command)
	}
	for _, k := range order {
		to := "--" + k.new
		if c := findCommand(root, paths[k][0]); c != nil {
			if f := c.Flags().Lookup(k.new); f != nil && f.Shorthand != "" {
				to = "-" + f.Shorthand + ", " + to
			}
		}
		rows = append(rows, row{fmt.Sprintf("--%s (%s)", k.old, commandsLabel(paths[k])), to})
	}
	rows = append(rows, flagNotes...)
	width := 0
	for _, r := range rows {
		width = max(width, utf8.RuneCountInString(r.old))
	}
	width = min(width, 40)
	var b strings.Builder
	b.WriteString("These names were changed; the old ones keep working:\n")
	for _, r := range rows {
		pad := max(width-utf8.RuneCountInString(r.old), 0)
		fmt.Fprintf(&b, "\n  %s%s → %s", r.old, strings.Repeat(" ", pad), r.new)
	}
	return b.String()
}

// commandsLabel names several commands briefly: "user create,
// reset-password" (same group), "token, invite, client-cert list" (same
// verb), else a plain list.
func commandsLabel(paths []string) string {
	if len(paths) == 1 {
		return paths[0]
	}
	first := func(p string) string { w, _, _ := strings.Cut(p, " "); return w }
	last := func(p string) string { return p[strings.LastIndex(p, " ")+1:] }
	sameFirst, sameLast := true, true
	for _, p := range paths {
		if !strings.Contains(p, " ") {
			return strings.Join(paths, ", ")
		}
		sameFirst = sameFirst && first(p) == first(paths[0])
		sameLast = sameLast && last(p) == last(paths[0])
	}
	switch {
	case sameFirst:
		out := []string{paths[0]}
		for _, p := range paths[1:] {
			_, rest, _ := strings.Cut(p, " ")
			out = append(out, rest)
		}
		return strings.Join(out, ", ")
	case sameLast:
		heads := make([]string, len(paths))
		for i, p := range paths {
			heads[i] = strings.TrimSuffix(p, " "+last(p))
		}
		return strings.Join(heads, ", ") + " " + last(paths[0])
	}
	return strings.Join(paths, ", ")
}
