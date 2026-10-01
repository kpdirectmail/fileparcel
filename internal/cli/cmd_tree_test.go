package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"fileparcel/internal/cli/clikit"
)

// i2Commands are the top-level commands of this unit (DESIGN §12); the
// others (serve, init, install, …) belong to the platform unit.
var i2Commands = []string{"user", "invite", "group", "token", "files", "share", "request", "backup", "cert", "ca",
	"client-cert", "config", "network", "keys", "audit", "jobs", "db", "gc", "maintenance", "completion", "docs"}

// walkTree calls fn for c and every descendant (help and cobra's internal
// commands excluded).
func walkTree(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, s := range c.Commands() {
		if s.Name() == "help" || strings.HasPrefix(s.Name(), "__") {
			continue
		}
		walkTree(s, fn)
	}
}

func i2Tree(t *testing.T) []*cobra.Command {
	t.Helper()
	root := NewRootCmd()
	var out []*cobra.Command
	for _, name := range i2Commands {
		c, _, err := root.Find([]string{name})
		if err != nil || c == root || c.Name() != name {
			t.Fatalf("command %q is not registered (%v)", name, err)
		}
		walkTree(c, func(c *cobra.Command) { out = append(out, c) })
	}
	return out
}

// globalFlagNames are the persistent root flags (DESIGN §12).
var globalFlagNames = []string{"home", "json", "yes", "no-color", "offline", "server", "token", "ca-file", "fingerprint", "as"}

func TestCommandTreeNoDuplicates(t *testing.T) {
	root := NewRootCmd()
	for _, name := range globalFlagNames {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("global flag --%s missing", name)
		}
	}
	walkTree(root, func(c *cobra.Command) {
		seen := map[string]string{}
		for _, s := range c.Commands() {
			for _, n := range append([]string{s.Name()}, s.Aliases...) {
				if prev, dup := seen[n]; dup {
					t.Errorf("%s: %q is used by %q and %q", c.CommandPath(), n, prev, s.Name())
				}
				seen[n] = s.Name()
			}
		}
		// Local flags must not shadow the global (persistent) flags.
		if c != root {
			local := c.LocalNonPersistentFlags()
			for _, name := range globalFlagNames {
				if local.Lookup(name) != nil {
					t.Errorf("%s: flag --%s shadows a global flag", c.CommandPath(), name)
				}
			}
			if local.ShorthandLookup("y") != nil {
				t.Errorf("%s: flag -y shadows the global -y/--yes", c.CommandPath())
			}
		}
	})
}

// TestDesignCommandPaths checks that every command of DESIGN §12 exists.
func TestDesignCommandPaths(t *testing.T) {
	root := NewRootCmd()
	paths := []string{
		"user list", "user create", "user show", "user edit", "user reset-password", "user set-role", "user set-quota", "user disable",
		"user enable", "user delete", "user unlock", "user reset-2fa", "user sessions", "user revoke-sessions",
		"invite create", "invite list", "invite revoke",
		"group list", "group create", "group delete", "group rename", "group members", "group add-member", "group remove-member",
		"token list", "token create", "token revoke",
		"files ls", "files tree", "files put", "files get", "files mkdir", "files mv", "files cp", "files rm", "files restore",
		"files trash", "files info", "files search", "files versions",
		"share list", "share create", "share show", "share edit", "share delete", "share log", "share enable", "share disable",
		"request create", "request list", "request close", "request reopen", "request delete",
		"backup create", "backup list", "backup verify", "backup prune", "backup delete", "backup schedule show",
		"backup schedule set", "backup schedule disable", "backup schedule enable", "backup identity show",
		"backup identity generate", "backup export", "backup config show", "backup config set", "backup restore",
		"cert status", "cert renew", "cert sans", "cert sans list", "cert sans add", "cert sans remove", "cert upload", "cert clear-custom", "cert acme enable", "cert acme disable",
		"cert tailscale enable", "cert tailscale disable", "cert tailscale fetch",
		"ca show", "ca fingerprint", "ca export", "ca regenerate", "ca trust-help",
		"client-cert issue", "client-cert list", "client-cert revoke",
		"config list", "config get", "config set", "config unset", "config path", "config edit",
		"network urls", "network interfaces", "network policy", "network allow list", "network allow add",
		"network allow remove", "network deny add", "network deny remove", "network mode",
		"network mdns status", "network mdns enable", "network mdns disable", "network mdns name", "network mdns mode",
		"network mdns republish",
		"keys status", "keys unlock", "keys lock", "keys seal", "keys unseal", "keys passphrase", "keys rotate",
		"keys recovery-key", "keys verify",
		"audit list", "audit verify", "audit export",
		"jobs list", "jobs show", "jobs cancel", "jobs run",
		"db check", "db vacuum", "db migrate", "db stats", "gc", "maintenance", "completion", "docs",
	}
	for _, p := range paths {
		c, rest, err := root.Find(strings.Fields(p))
		if err != nil || len(rest) != 0 || c.CommandPath() != "fileparcel "+p {
			t.Errorf("missing command %q (found %q, rest %v, %v)", p, c.CommandPath(), rest, err)
		}
	}
	if c, _, _ := root.Find([]string{"docs"}); c == nil || !c.Hidden {
		t.Error("docs must be hidden")
	}
}

// TestHelpRenders runs --help for every command of the unit (no panics from
// flag definitions, usage templates render).
func TestHelpRenders(t *testing.T) {
	for _, c := range i2Tree(t) {
		args := append(strings.Fields(strings.TrimPrefix(c.CommandPath(), "fileparcel ")), "--help")
		res := runArgs(t, "", args...)
		if res.code != 0 || !strings.Contains(res.stdout, "Usage:") {
			t.Fatalf("%v: %+v", args, res)
		}
		if c.Example != "" && !strings.Contains(res.stdout, "Examples:") {
			t.Errorf("%v: examples not shown", args)
		}
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	for _, args := range [][]string{
		{"user", "add"},                  // missing argument
		{"user", "list", "--nope"},       // unknown flag
		{"user", "frobnicate"},           // unknown subcommand
		{"files", "put", "only-one"},     // too few arguments
		{"network", "mode", "sometimes"}, // invalid value (before connecting)
		{"token", "create", "--name", "x", "--scopes", "root"},
		{"keys", "rotate"},                      // no target
		{"keys", "rotate", "--kek", "--master"}, // two targets
		{"jobs", "show", "not-a-job"},
		{"completion", "tcsh"},
		{"docs"},
		{"maintenance", "sideways"},
		{"audit", "list", "--limit", "0"},
		{"share", "create", "x", "--expires", "soon"},
		{"backup", "create", "--scope", "half"},
		{"client-cert", "issue", "bob", "--days", "0"},
	} {
		res := runArgs(t, "", args...)
		if res.code != ExitUsage {
			t.Errorf("%v: exit %d, want %d (stderr %q)", args, res.code, ExitUsage, res.stderr)
		}
	}
}

func TestCompletion(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		res := runArgs(t, "", "completion", sh)
		if res.code != 0 || !strings.Contains(res.stdout, "fileparcel") || len(res.stdout) < 500 {
			t.Errorf("completion %s: exit %d, %d bytes", sh, res.code, len(res.stdout))
		}
	}
}

func TestDocsMarkdown(t *testing.T) {
	res := runArgs(t, "", "docs", "--markdown")
	if res.code != 0 {
		t.Fatalf("docs: %+v", res)
	}
	md := res.stdout
	// Deterministic.
	if again := runArgs(t, "", "docs", "--markdown"); again.stdout != md {
		t.Fatal("docs --markdown is not deterministic")
	}
	for _, want := range []string{"# Command reference", "## Global flags", "`--json`", "## Contents",
		"### fileparcel files put", "#### fileparcel backup schedule set", "**Usage**", "**Examples**", "**Flags**",
		"`--conflict`", "fileparcel files put <local>... <remote-folder> [flags]",
		// Help topics in their own section; contents grouped like --help.
		"- [Help topics](#help-topics)", "## Help topics", "### fileparcel help paths", "### fileparcel help renamed",
		"**Getting started**", "**Install \\& service**"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	// Every visible command has a heading and a contents entry.
	root := NewRootCmd()
	walkTree(root, func(c *cobra.Command) {
		if c == root || c.IsAdditionalHelpTopicCommand() {
			return
		}
		hidden := false
		for p := c; p != nil; p = p.Parent() {
			hidden = hidden || p.Hidden
		}
		heading := " " + c.CommandPath() + "\n"
		if hidden {
			if strings.Contains(md, "#"+heading) {
				t.Errorf("hidden command %s documented", c.CommandPath())
			}
			return
		}
		if !strings.Contains(md, "#"+heading) {
			t.Errorf("no heading for %s", c.CommandPath())
		}
		if !strings.Contains(md, "(#"+clikit.Anchor(c.CommandPath())+")") {
			t.Errorf("no contents link for %s", c.CommandPath())
		}
	})
	// -o writes the same document.
	out := filepath.Join(t.TempDir(), "ref.md")
	if res := runArgs(t, "", "docs", "--markdown", "-o", out, "--title", "CLI"); res.code != 0 {
		t.Fatalf("docs -o: %+v", res)
	}
	data, err := os.ReadFile(out)
	if err != nil || !bytes.HasPrefix(data, []byte("# CLI\n")) || !bytes.Contains(data, []byte("### fileparcel files put")) {
		t.Fatalf("docs -o output: %v %q", err, data[:min(len(data), 80)])
	}
	if !slices.Contains(strings.Split(md, "\n"), "## Contents") {
		t.Error("contents heading")
	}
}
