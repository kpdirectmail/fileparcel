package cli

// Help and usage of the command tree (DESIGN §12, "Help groups and topics"
// and "Errors and suggestions"): the groups of "fileparcel --help" and the
// sections of the big groups, the usage template, the help topics, the
// friendly texts of unknown commands, unknown flags, wrong argument counts
// and cobra's flag-group errors, and finishTree, which puts it all onto the
// tree NewRootCmd built. Top-level groups and sections are assigned here,
// never in the command constructors.

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"fileparcel/internal/core"
)

// Shared sentences of the help texts. A Long that ends with both puts
// confirmNote on the line before elevationNote.
const (
	// elevationNote ends the Long of commands that need step-up remotely
	// (elevationNoteFor when only some uses of a command do).
	elevationNote = `On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").`
	// confirmNote ends the Long of commands that ask before acting.
	confirmNote = `It asks before doing it; -y skips the question.`
	// filesPathNote ends the Long of the files, share and request commands.
	filesPathNote = `Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.`
)

// elevationNoteFor is elevationNote for a command of which only some uses
// need step-up remotely: elevationNoteFor("Inviting an admin").
func elevationNoteFor(what string) string {
	return what + ` needs an elevated admin token remotely;
on the server this always works (see "fileparcel help connect").`
}

// Command annotations.
const (
	// annBare marks a group that does something when run without a
	// subcommand (network shows the overview), so its help shows its own
	// use line.
	annBare = "fp:bare"
	// annList names the command that lists the objects of a group
	// ("fileparcel user list"); not-found errors point at it. "{parent}" is
	// replaced by the parent folder of the first path argument.
	annList = "fp:list"
)

// newRootGroups returns the groups of "fileparcel --help", in order.
func newRootGroups() []*cobra.Group {
	return []*cobra.Group{
		{ID: "start", Title: "Getting started:"},
		{ID: "files", Title: "Files & sharing:"},
		{ID: "people", Title: "People & access:"},
		{ID: "server", Title: "Server & network:"},
		{ID: "security", Title: "Security:"},
		{ID: "upkeep", Title: "Backups & maintenance:"},
		{ID: "install", Title: "Install & service:"},
	}
}

// topLevelGroup assigns every visible top-level command to a root group.
// A visible command missing here would be listed under "More commands:"
// (TestRootHelpGroups fails). Names of commands that do not exist yet are
// harmless.
var topLevelGroup = map[string]string{
	"doctor": "start", "help": "start", "open": "start", "status": "start",
	"files": "files", "request": "files", "share": "files",
	"access": "people", "group": "people", "invite": "people", "role": "people", "token": "people", "user": "people",
	"whoami": "people",
	"config": "server", "logs": "server", "network": "server",
	"audit": "security", "ca": "security", "cert": "security", "client-cert": "security", "keys": "security",
	"backup": "upkeep", "db": "upkeep", "gc": "upkeep", "jobs": "upkeep", "maintenance": "upkeep",
	"completion": "install", "healthcheck": "install", "init": "install", "install": "install", "serve": "install",
	"service": "install", "uninstall": "install", "upgrade": "install", "version": "install",
}

// helpSection is one section of a big group's help.
type helpSection struct {
	ID, Title string
	Commands  []string
}

// subGroups are the sections of the big groups, keyed by command path
// (without "fileparcel "). A section none of whose commands exist is left
// out.
var subGroups = map[string][]helpSection{
	"files": {
		{"browse", "Browse:", []string{"ls", "tree", "info", "search", "versions"}},
		{"transfer", "Upload and download:", []string{"put", "get"}},
		{"organize", "Organize:", []string{"mkdir", "mv", "cp", "rm", "trash", "restore"}},
	},
	"user": {
		{"accounts", "Accounts:", []string{"create", "list", "show", "edit", "disable", "enable", "delete"}},
		{"role", "Role and storage:", []string{"set-role", "set-quota"}},
		{"signin", "Sign-in and security:", []string{"reset-password", "reset-2fa", "unlock", "sessions", "revoke-sessions"}},
	},
	"network": {
		{"addresses", "Addresses:", []string{"status", "urls", "interfaces"}},
		{"policy", "Who may connect:", []string{"policy", "mode", "allow", "deny"}},
		{"remote", "Remote access:", []string{"vpn", "funnel", "tailscale-serve"}},
		{"local", "Local name:", []string{"mdns"}},
	},
	"backup": {
		{"backups", "Backups:", []string{"create", "list", "show", "verify", "restore", "delete"}},
		{"copies", "Copy archives:", []string{"export", "import"}},
		{"automatic", "Automatic backups:", []string{"schedule", "prune", "config", "identity"}},
	},
}

// rootLong is the Long of "fileparcel".
const rootLong = `FileParcel is a self-hosted, encrypted file-sharing server. This one program
is both the server and the tool to manage it.

On the server machine, commands talk to the running server through its
private admin socket, with full admin rights and no password. When the server
is stopped they work directly on the data instead. From another computer, add
--server URL --token TOKEN (see "fileparcel help connect").

Common tasks:
  fileparcel status                          Is the server running? Where is it?
  fileparcel open --qr                       Open the web app, or show QR codes for phones
  fileparcel user create alice --generate-password
                                             Create an account (the password is shown once)
  fileparcel invite create --qr              Let someone create their own account
  fileparcel files put ./photos "/My files"  Upload a folder
  fileparcel share create "/My files/a.pdf"  Share a file with a link
  fileparcel access grant /Team/Design --group Marketing
                                             Let another group see a team folder
  fileparcel backup create --wait            Back up everything now
  fileparcel doctor --fix                    Find and fix problems`

// usageTemplate replaces cobra's usage template: "fileparcel <command>
// [flags]" at the root, a group's own use line only when running it bare
// does something (annBare), group titles and sections, one line for the
// global flags on subcommand pages (flags inherited from a non-root parent
// are listed in full) and the help topics.
const usageTemplate = `Usage:{{if not .HasParent}}
  fileparcel <command> [flags]{{else}}{{if fpShowUseLine .}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} <command> [flags]{{end}}{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

More commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{if .HasParent}}Flags:{{else}}Global flags (work with every command):{{end}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if and .HasParent .HasAvailableInheritedFlags}}{{with fpParentFlags .}}

Flags from the parent command:
{{. | trimTrailingWhitespaces}}{{end}}

Global flags: {{fpGlobalFlagsLine}}{{end}}{{if .HasHelpSubCommands}}

Help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  fileparcel help {{rpad .Name 12}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Run "{{.CommandPath}} <command> --help" for details and examples.{{end}}
`

// globalFlagsLine is the one line that stands for the global flags on
// subcommand pages.
const globalFlagsLine = `--home DIR, --json, -y/--yes, --offline, --as USER, --server URL --token TOKEN, --no-color (all: fileparcel help flags)`

func init() {
	cobra.AddTemplateFunc("fpShowUseLine", showUseLine)
	cobra.AddTemplateFunc("fpParentFlags", parentFlagUsages)
	cobra.AddTemplateFunc("fpGlobalFlagsLine", func() string { return globalFlagsLine })
}

// showUseLine reports whether c's help shows c's own use line: runnable
// leaves, and groups that do something when run bare.
func showUseLine(c *cobra.Command) bool {
	return c.Runnable() && (!c.HasAvailableSubCommands() || c.Annotations[annBare] != "")
}

// parentFlagUsages lists the flags c inherits from parents other than the
// root ("maintenance --message"); "" when there are none.
func parentFlagUsages(c *cobra.Command) string {
	global := c.Root().PersistentFlags()
	fs := pflag.NewFlagSet("parent", pflag.ContinueOnError)
	c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		if global.Lookup(f.Name) == nil && !f.Hidden {
			fs.AddFlag(f)
		}
	})
	return fs.FlagUsages()
}

// ---------- help topics ----------

// helpTopic is a help topic: "fileparcel help <name>" and "fileparcel
// <name>" print its text.
type helpTopic struct{ Name, Short, Long string }

var helpTopics = []helpTopic{
	{"connect", "How commands reach the server (socket, offline, remote)", `Commands reach FileParcel in this order:

1. Admin socket. On the server machine, while the server runs, commands talk
   to it through <HOME>/run/admin.sock. Only the same system user (or root)
   can connect. It has full admin rights: no password, no second factor.
2. Offline. When the server is stopped, commands open the installation
   directly and run the same code in-process. --offline forces this (and fails
   while the server runs). A sealed master key needs its passphrase: typed at
   the prompt, or --passphrase-stdin / --passphrase-file.
3. Remote. --server https://HOST:8443 --token fpt_… (or $FILEPARCEL_TOKEN) uses
   the REST API with a personal API token ("fileparcel token create"). Check a
   certificate from the local CA with --ca-file ca.pem or --fingerprint SHA256.
   The token's account must meet the two-factor policy (auth.require_2fa).

Which installation: --home DIR, else $FILEPARCEL_HOME, else the directory the
fileparcel program is installed in.

Acting as a user: over the socket or offline, file, share, request and token
commands work as the first owner unless you pass --as USER; "access" commands
use the admin socket's full rights unless you pass --as USER. Remotely every
command acts as the token's user, with that user's role and access.
"fileparcel whoami" shows who a command acts as and what it may do.

Sensitive admin actions over the network need a recent identity confirmation;
use a token made with "fileparcel token create ops --scopes admin --elevated
--expires 7d". On the server itself this is never needed.

A system service runs as the "fileparcel" account ("_fileparcel" on macOS).
Run admin commands with sudo there: sudo fileparcel status (or
sudo -u fileparcel fileparcel status).

  fileparcel status
  fileparcel --as alice files ls
  fileparcel --server https://files.example.lan:8443 --token "$FILEPARCEL_TOKEN" user list`},
	{"flags", "Global flags and environment variables", `Global flags work with every command:

  --home DIR           the installation directory (default: $FILEPARCEL_HOME or
                       the directory the program is installed in)
  --json               print JSON instead of tables (errors too)
  -y, --yes            answer yes to every question; never prompt
  --no-color           no colours (also: NO_COLOR=1 or TERM=dumb)
  --offline            work on the data directly; the server must be stopped
  --as USER            act as USER (admin socket and offline only)
  --server URL         talk to a remote server (needs --token)
  --token TOKEN        API token for --server; prefer $FILEPARCEL_TOKEN, because
                       other users of the machine can see command lines
  --token-file FILE    API token for --server, from the first line of FILE
  --ca-file FILE       trust this CA certificate for --server
  --fingerprint SHA256 pin the server certificate for --server
  --passphrase-stdin, --passphrase-file FILE
                       master-key passphrase for offline commands on a sealed
                       installation (commands with their own flag of that name
                       keep their own meaning)

Environment variables:
  FILEPARCEL_HOME      installation directory
  FILEPARCEL_TOKEN     API token for --server
  FILEPARCEL_<SECTION>_<KEY>  override a fileparcel.toml value, e.g.
                       FILEPARCEL_SERVER_HTTPS_PORT=9443
  FILEPARCEL_ADMIN_USER, FILEPARCEL_ADMIN_EMAIL, FILEPARCEL_ADMIN_PASSWORD_FILE
                       owner account for "serve --init-if-missing" (Docker)
  FILEPARCEL_SUPERVISED=1  a supervisor restarts the server (exit code 75)
  NO_COLOR, TERM=dumb  no colours
  VISUAL, EDITOR       editor for "fileparcel config edit"`},
	{"paths", "How to write file and folder paths", `File commands take remote paths:

  /My files/…        your personal files ("My files" is the default, so
                     "Documents/a.pdf" means "/My files/Documents/a.pdf")
  /Team/<group>/…    the team folder of a group you belong to, or one
                     shared with you as a whole (a grant to you, one of
                     your groups or your role)
  nod_…[/sub/path]   any file or folder by id (also ones shared with you),
                     optionally followed by a path below it; "files info"
                     and --json output show ids
  /                  the top level: your spaces

Put quotes around paths with spaces: "/My files/Tax 2026".
Over the admin socket or offline, "/My files" is the first owner's, or that of
the user given with --as USER. Remotely it is the token user's.

  fileparcel files ls "/My files/Documents"
  fileparcel --as alice files ls /Team/Design
  fileparcel files info nod_01j9zq3x4k6m8p0r2t4v6x8z0b`},
	{"values", "Durations, dates, sizes, lists and secrets in flags", `Durations  30m, 12h, 7d, 2w, 1d12h.
Expiry     --expires takes a duration (7d), a date (2026-12-31, until the end
           of that day) or "never" where things may last forever (links,
           tokens, access grants). --since/--until take a duration back from
           now or a time (2026-09-01, 2026-09-01T12:00:00Z).
Sizes      500M, 10G, 1.5T (binary units; 10GB and 10GiB mean the same).
           Quotas also take "unlimited"; user quotas also "default".
Lists      Repeat the flag: --group Design --group Marketing. Flags whose
           help says "comma-separated" also take a,b,c.
On/off     --upload turns an option on; --no-upload or --upload=false turns
           it off.
Secrets    Never on the command line. --password asks without echo;
           --password-stdin reads the first line of standard input;
           --password-file FILE reads the first line of a file (chmod 600).
           Only one flag of a command can read standard input.
Names      Users, groups and roles by name or id (usr_…, grp_…, rol_…).
           Other objects by id: shr_ (links and file requests), bak_
           (backups), job_, tok_, inv_, ccr_ (client certificates), gnt_
           (access grants), nod_ (files and folders), ver_ (file versions).`},
	{"permissions", "Roles, groups and folder access explained", `What someone may do is decided in three layers:

1. Their role decides what they may do on the server. Built-in roles: owner,
   admin, member (the default) and guest; you can create your own
   ("fileparcel role create"). See what a role allows with
   "fileparcel role show ROLE", and all permissions with
   "fileparcel role permissions".
2. Their groups give them the team folders "/Team/<group>"
   ("fileparcel group").
3. Access grants give a user, a group or everyone with a role access to one
   folder or file: view (see and download), edit (also change, move and
   delete), manage (also share it and change its access)
   ("fileparcel access grant").

Access only adds up; nothing takes away what another layer gives. To see why
someone can open a folder: fileparcel access check USER PATH

  fileparcel role list
  fileparcel user set-role bob contractors
  fileparcel access grant /Team/Design --role contractors`},
	{"scripting", "JSON output, exit codes and non-interactive use", `For scripts and cron jobs:

  --json        one JSON document on stdout (JSON lines with --follow/-f);
                errors are {"error":{"code":…,"message":…,"hint":…}} on stderr
  -y            never prompt; without -y and without a terminal a question
                is an error (exit 1) instead of a hang (install and upgrade
                go ahead as with -y instead)
  --wait        commands that start a background job can wait for it;
                --no-wait returns at once (each command says its default)
  Exit codes    0 success, 1 error, 2 wrong usage or invalid input,
                75 the server asks its supervisor for a restart
  Secrets       --X-stdin / --X-file flags, never arguments
  Output        tables and results on stdout; questions, warnings, progress
                and notes on stderr

  fileparcel --json user list
  fileparcel -y backup create --wait --json
  printf '%s\n' "$PASS" | fileparcel user create bob --password-stdin`},
}

// newHelpTopics returns the help topic commands: non-runnable root
// children without subcommands, which cobra lists as "additional help
// topics" and prints (Long only) for "fileparcel help <name>" and
// "fileparcel <name>".
func newHelpTopics(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, t := range helpTopics {
		out = append(out, &cobra.Command{Use: t.Name, Short: t.Short, Long: t.Long})
	}
	out = append(out, &cobra.Command{Use: "renamed", Short: "Old command names and what they are called now",
		Long: renamedText(root)})
	return out
}

// newHelpCmd replaces cobra's help command, which prints the root help for
// "fileparcel help lsit" (the root accepts arguments so that it can reject
// them itself) instead of saying that there is no such command.
func newHelpCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "help [command|topic]",
		Short:   "Help about any command or topic",
		Long:    `Show the help of a command ("fileparcel help user create") or of a help topic ("fileparcel help paths").`,
		GroupID: "start",
		Args:    cobra.ArbitraryArgs,
		ValidArgsFunction: func(c *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			cmd, _, err := c.Root().Find(args)
			if err != nil || cmd == nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var out []cobra.Completion
			for _, s := range cmd.Commands() {
				if (s.IsAvailableCommand() || s.IsAdditionalHelpTopicCommand()) && strings.HasPrefix(s.Name(), toComplete) {
					out = append(out, cobra.CompletionWithDesc(s.Name(), s.Short))
				}
			}
			return out, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd, rest, err := c.Root().Find(args)
			if err != nil {
				return err
			}
			if words := stripFlagWords(rest); len(words) > 0 && cmd.HasSubCommands() {
				return unknownCommandError(cmd, words[0])
			}
			cmd.InitDefaultHelpFlag()
			return cmd.Help()
		},
	}
}

// stripFlagWords returns the words of args that are not flags.
func stripFlagWords(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// ---------- finishing the tree ----------

// finishTree puts the shared behaviour onto the tree NewRootCmd built: the
// legacy names (legacy.go), groups and sections, suggestions on every
// parent, friendly argument errors, error hints, shell completion
// (complete.go), the help command and topics, and the usage template.
func finishTree(root *cobra.Command) {
	applyLegacy(root)
	for _, c := range root.Commands() {
		if id, ok := topLevelGroup[c.Name()]; ok && !c.Hidden {
			c.GroupID = id
		}
	}
	for path, sections := range subGroups {
		parent := findCommand(root, path)
		if parent == nil {
			continue
		}
		for _, s := range sections {
			var members []*cobra.Command
			for _, name := range s.Commands {
				if sub := childCommand(parent, name); sub != nil && !sub.Hidden {
					members = append(members, sub)
				}
			}
			if len(members) == 0 {
				continue
			}
			parent.AddGroup(&cobra.Group{ID: s.ID, Title: s.Title})
			for _, m := range members {
				m.GroupID = s.ID
			}
		}
	}
	walkCommands(root, func(c *cobra.Command) {
		if c.HasSubCommands() {
			c.SuggestionsMinimumDistance = maxSuggestDistance // cobra's own suggestions (cobra defaults it on the root only)
		}
		if orig := c.Args; orig != nil {
			c.Args = func(cmd *cobra.Command, args []string) error {
				if err := orig(cmd, args); err != nil {
					return argsError(cmd, args, err)
				}
				return nil
			}
		}
	})
	wrapTreeErrors(root)
	addCompletions(root)
	root.AddCommand(newHelpTopics(root)...)
	root.SetHelpCommand(newHelpCmd())
	root.SetUsageTemplate(usageTemplate)
}

// walkCommands calls fn for c and every descendant.
func walkCommands(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, s := range c.Commands() {
		walkCommands(s, fn)
	}
}

// findCommand returns the command at path ("network mdns"; "" is root), by
// name only (aliases do not count), or nil.
func findCommand(root *cobra.Command, path string) *cobra.Command {
	c := root
	for _, name := range strings.Fields(path) {
		if c = childCommand(c, name); c == nil {
			return nil
		}
	}
	return c
}

// childCommand returns the child of c named name (not an alias), or nil.
func childCommand(c *cobra.Command, name string) *cobra.Command {
	for _, s := range c.Commands() {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// commandExists reports whether the words of path name an available
// command; flags, "(…)" notes and placeholders ("ROLE", "<path>") end the
// path. Hints only mention commands this build has.
func commandExists(root *cobra.Command, path string) bool {
	var words []string
	for _, w := range strings.Fields(path) {
		if strings.ContainsAny(w[:1], "-(<[") || strings.ToUpper(w) == w && strings.ToLower(w) != w {
			break
		}
		words = append(words, w)
	}
	if len(words) == 0 {
		return false
	}
	c, rest, err := root.Find(words)
	return err == nil && c != root && len(rest) == 0 && c.IsAvailableCommand()
}

// ---------- unknown commands ----------

// taskHints map words people type at the top level to the commands that
// do it (value: paths below "fileparcel"). Keys must not be command names,
// aliases or help topics (then they would run; "permissions" is the topic
// that points at "access"); suggestions only name commands that exist in
// this build.
var taskHints = map[string][]string{
	"upload": {"files put"}, "put": {"files put"},
	"download": {"files get"}, "get": {"files get"},
	"ls": {"files ls"}, "dir": {"files ls"}, "list": {"files ls"},
	"mkdir": {"files mkdir"},
	"rm":    {"files rm"}, "del": {"files rm"},
	"mv": {"files mv"}, "move": {"files mv"}, "rename": {"files mv"},
	"cp": {"files cp"}, "copy": {"files cp"},
	"search": {"files search"}, "find": {"files search"},
	"trash":   {"files trash"},
	"zip":     {"files put (--zip)", "files get (--zip)"},
	"adduser": {"user create"}, "useradd": {"user create"}, "add-user": {"user create"}, "create-user": {"user create"},
	"passwd": {"user reset-password"}, "password": {"user reset-password"},
	"2fa": {"user reset-2fa"}, "mfa": {"user reset-2fa"}, "totp": {"user reset-2fa"},
	"unlock": {"keys unlock", "user unlock"},
	"lock":   {"keys lock", "keys seal"}, "seal": {"keys lock", "keys seal"},
	"permission": {"access"}, "grant": {"access"}, "ungrant": {"access"},
	"share-with": {"access"},
	"start":      {"service start"}, "stop": {"service stop"}, "restart": {"service restart"},
	"funnel":    {"network funnel"},
	"tailscale": {"network funnel", "network vpn", "cert tailscale"},
	"headscale": {"network vpn"}, "vpn": {"network vpn"}, "wireguard": {"network vpn"}, "zerotier": {"network vpn"},
	"netbird": {"network vpn"}, "nebula": {"network vpn"},
	"firewall": {"network allow add"}, "allow": {"network allow add"},
	"deny": {"network deny add"}, "block": {"network deny add"},
	"url": {"network urls", "open (--qr)"}, "urls": {"network urls", "open (--qr)"},
	"address": {"network urls", "open (--qr)"}, "qr": {"network urls", "open (--qr)"},
	"update": {"upgrade"},
	"log":    {"logs"},
	"health": {"healthcheck", "doctor"},
}

// usageHintError is a usage error (exit status 2) with advice: hint lines
// under the message, candidates ("Did you mean this?"), a short usage block
// and a closing line pointing at --help. Suggestions never run anything.
type usageHintError struct {
	msg         string
	hints       []string // "hint: …" lines
	suggestions []string // shown one per line
	prefix      string   // command path the suggestions are relative to ("" for flags)
	lines       []string // "Usage:   …", "Example: …"
	help        string   // closing line
}

func (e *usageHintError) Error() string { return e.msg }

// text renders the error for a terminal (after "fileparcel: ").
func (e *usageHintError) text() string {
	var b strings.Builder
	b.WriteString(e.msg)
	for _, h := range e.hints {
		b.WriteString("\n  hint: " + h)
	}
	if len(e.suggestions) > 0 {
		title := "Did you mean this?"
		if len(e.suggestions) > 1 {
			title = "Did you mean one of these?"
		}
		b.WriteString("\n\n" + title)
		for _, s := range e.suggestions {
			b.WriteString("\n\t" + s)
		}
	}
	if len(e.lines) > 0 || e.help != "" {
		b.WriteString("\n")
		for _, l := range e.lines {
			b.WriteString("\n" + l)
		}
		if e.help != "" {
			b.WriteString("\n" + e.help)
		}
	}
	return b.String()
}

// jsonHint is the "hint" of the --json error: the hint lines, the
// suggestions as full commands and the usage block (the closing --help line
// only when there is nothing else).
func (e *usageHintError) jsonHint() string {
	parts := slices.Clone(e.hints)
	if len(e.suggestions) > 0 {
		q := make([]string, len(e.suggestions))
		for i, s := range e.suggestions {
			if e.prefix != "" {
				s = e.prefix + " " + s
			}
			q[i] = strconv.Quote(s)
		}
		parts = append(parts, "did you mean "+joinOr(q)+"?")
	}
	parts = append(parts, e.lines...)
	if len(parts) == 0 && e.help != "" {
		parts = append(parts, e.help)
	}
	return strings.Join(parts, "\n")
}

// unknownCommandError is the error for a word that is not a subcommand of
// cmd, with the closest subcommands (by name and alias), and at the root the
// tasks the word usually means, the new name of a mistyped old one and a
// help topic one typo away.
func unknownCommandError(cmd *cobra.Command, word string) error {
	var sugg []string
	add := func(s string) {
		if s != "" && !slices.Contains(sugg, s) {
			sugg = append(sugg, s)
		}
	}
	for _, s := range closestCommands(cmd, word) {
		add(s)
	}
	if !cmd.HasParent() {
		for _, h := range taskHints[strings.ToLower(word)] {
			if commandExists(cmd, h) {
				add(h)
			}
		}
		for _, lc := range legacyCommands {
			if !strings.Contains(lc.Old, " ") && levenshtein(word, lc.Old) <= 2 && commandExists(cmd, lc.New) {
				add(lc.New)
			}
		}
		for _, t := range cmd.Commands() {
			if t.IsAdditionalHelpTopicCommand() && levenshtein(word, t.Name()) <= 1 {
				add("help " + t.Name())
			}
		}
	}
	return &usageHintError{
		msg:         fmt.Sprintf("unknown command %q for %q", word, cmd.CommandPath()),
		suggestions: sugg,
		prefix:      cmd.CommandPath(),
		help:        fmt.Sprintf("Run %q to see all commands.", cmd.CommandPath()+" --help"),
	}
}

// maxSuggestDistance is the largest edit distance of a suggestion.
const maxSuggestDistance = 2

// closestCommands returns the available subcommands of cmd that word most
// likely meant: those whose SuggestFor lists word, else those whose name or
// alias is the fewest edits away (at most maxSuggestDistance), together with
// those whose name starts with word.
func closestCommands(cmd *cobra.Command, word string) []string {
	best := maxSuggestDistance + 1
	var out []string
	for _, sub := range cmd.Commands() {
		if !sub.IsAvailableCommand() {
			continue
		}
		d := maxSuggestDistance + 1
		for _, n := range append([]string{sub.Name()}, sub.Aliases...) {
			d = min(d, levenshtein(word, n))
		}
		if strings.HasPrefix(strings.ToLower(sub.Name()), strings.ToLower(word)) {
			d = min(d, 1)
		}
		if slices.ContainsFunc(sub.SuggestFor, func(s string) bool { return strings.EqualFold(s, word) }) {
			d = 0
		}
		switch {
		case d < best:
			best, out = d, []string{sub.Name()}
		case d == best && d <= maxSuggestDistance:
			out = append(out, sub.Name())
		}
	}
	return out
}

// rootArgs is the Args of the root: a word that is not a command.
func rootArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return unknownCommandError(cmd, args[0])
	}
	return nil
}

// ---------- unknown and bad flags ----------

// flagSynonyms suggest flags for words people try (keyed by command path
// below "fileparcel", then by the flag typed).
var flagSynonyms = map[string]map[string][]string{
	"role create":         {"allow": {"add"}, "deny": {"remove"}},
	"role edit":           {"allow": {"add"}, "deny": {"remove"}},
	"uninstall":           {"dir": {"home"}},
	"upgrade":             {"dir": {"home"}},
	"user create":         {"password": {"password-stdin", "generate-password"}},
	"user reset-password": {"password": {"password-stdin", "generate-password"}},
}

// commandKey is c's path below "fileparcel" ("user create").
func commandKey(c *cobra.Command) string {
	return strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), c.Root().Name()))
}

// flagError is the root's flag error function: pflag's parse errors
// rewritten with suggestions and examples. A value given to a secret-prompt
// flag or to a -stdin switch (--password-stdin=hunter2) is never echoed.
func flagError(c *cobra.Command, err error) error {
	if err == nil || errors.Is(err, pflag.ErrHelp) {
		return err
	}
	help := fmt.Sprintf("Run %q to see its flags.", c.CommandPath()+" --help")
	var inv *pflag.InvalidValueError
	if errors.As(err, &inv) {
		f := inv.GetFlag()
		if f.Annotations[annSecretPrompt] != nil {
			return secretPromptError(f)
		}
		if stdinSwitch(f) {
			return stdinSwitchError(f)
		}
		return &usageHintError{msg: invalidValueText(f, inv), help: help}
	}
	var ne *pflag.NotExistError
	if errors.As(err, &ne) {
		name := ne.GetSpecifiedName()
		if group := ne.GetSpecifiedShortnames(); group != "" {
			e := &usageHintError{msg: fmt.Sprintf("-%s is not a flag of %q", name, c.CommandPath()), help: help}
			if shorts := shorthandList(c); shorts != "" {
				e.hints = []string{"its short flags: " + shorts}
			}
			return e
		}
		return &usageHintError{
			msg:         fmt.Sprintf("unknown flag --%s for %q", name, c.CommandPath()),
			suggestions: flagSuggestions(c, name),
			hints:       siblingFlagHints(c, name),
			help:        help,
		}
	}
	var vr *pflag.ValueRequiredError
	if errors.As(err, &vr) {
		f := vr.GetFlag()
		return &usageHintError{msg: fmt.Sprintf("%s needs a value, e.g. --%s %s", flagDisplay(f), f.Name, flagExample(f)), help: help}
	}
	return &usageHintError{msg: err.Error(), help: help}
}

// flagDisplay is "--name", or "-n, --name" for a flag with a shorthand.
func flagDisplay(f *pflag.Flag) string {
	if f.Shorthand != "" {
		return "-" + f.Shorthand + ", --" + f.Name
	}
	return "--" + f.Name
}

var (
	reUsageExample = regexp.MustCompile(`e\.g\. ([^\s,;)]+)`)
	reParenExample = regexp.MustCompile(`\(([0-9][^\s,;)]*)\)`)
)

// flagExample is a sample value of f: its annExample annotation, an "e.g."
// or a parenthesised number in its help, else one by type.
func flagExample(f *pflag.Flag) string {
	if ex := f.Annotations[annExample]; len(ex) > 0 {
		return ex[0]
	}
	if m := reUsageExample.FindStringSubmatch(f.Usage); m != nil {
		return m[1]
	}
	if m := reParenExample.FindStringSubmatch(f.Usage); m != nil {
		return m[1]
	}
	name, _ := pflag.UnquoteUsage(f)
	switch f.Value.Type() {
	case "duration":
		return "7d"
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return "10"
	case "float32", "float64":
		return "1.5"
	}
	if name != "" && strings.ToUpper(name) == name {
		return name // a back-quoted name in the usage ("FILE")
	}
	return "VALUE"
}

// invalidValueText explains a value the flag's type refused.
func invalidValueText(f *pflag.Flag, inv *pflag.InvalidValueError) string {
	v := inv.GetValue()
	switch f.Value.Type() {
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return fmt.Sprintf("--%s must be a whole number (got %q)", f.Name, v)
	case "float32", "float64":
		return fmt.Sprintf("--%s must be a number (got %q)", f.Name, v)
	case "bool":
		return fmt.Sprintf("--%s is a switch: use --%s or --%s=false (got %q)", f.Name, f.Name, f.Name, v)
	case "duration":
		return fmt.Sprintf("--%s must be a duration such as 30m, 12h or 7d (got %q)", f.Name, v)
	}
	return inv.Error()
}

// flagSuggestions are the synonyms of name in flagSynonyms, then the flags
// of c the fewest edits away from name (at most maxSuggestDistance) and those
// that start with name.
func flagSuggestions(c *cobra.Command, name string) []string {
	var out []string
	add := func(n string) {
		if f := c.Flags().Lookup(n); f != nil && !f.Hidden && !slices.Contains(out, "--"+f.Name) {
			out = append(out, "--"+f.Name)
		}
	}
	for _, s := range flagSynonyms[commandKey(c)][name] {
		add(s)
	}
	best := maxSuggestDistance + 1
	var closest []string
	c.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		d := levenshtein(name, f.Name)
		if len(name) >= 2 && strings.HasPrefix(f.Name, name) {
			d = min(d, 1)
		}
		switch {
		case d < best:
			best, closest = d, []string{f.Name}
		case d == best && d <= maxSuggestDistance:
			closest = append(closest, f.Name)
		}
	})
	for _, n := range closest {
		add(n)
	}
	return out
}

// siblingFlagHints say which sibling commands have the flag c lacks
// ("--inactive" belongs to "fileparcel share list"). Top-level commands
// have no siblings in this sense: they do unrelated things.
func siblingFlagHints(c *cobra.Command, name string) []string {
	if !c.HasParent() || !c.Parent().HasParent() {
		return nil
	}
	global := c.Root().PersistentFlags()
	var out []string
	for _, s := range c.Parent().Commands() {
		if s == c || !s.IsAvailableCommand() {
			continue
		}
		if f := s.Flags().Lookup(name); f != nil && !f.Hidden && global.Lookup(f.Name) == nil {
			out = append(out, fmt.Sprintf("%q belongs to %q", "--"+f.Name, s.CommandPath()))
		}
	}
	return out
}

// shorthandList lists c's one-letter flags ("-f (--force), -l (--long)").
func shorthandList(c *cobra.Command) string {
	var out []string
	c.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Shorthand != "" && !f.Hidden {
			out = append(out, "-"+f.Shorthand+" (--"+f.Name+")")
		}
	})
	return strings.Join(out, ", ")
}

// ---------- argument counts ----------

var (
	reArgsExact   = regexp.MustCompile(`^accepts (\d+) arg\(s\), received (\d+)$`)
	reArgsAtLeast = regexp.MustCompile(`^requires at least (\d+) arg\(s\), only received (\d+)$`)
	reArgsAtMost  = regexp.MustCompile(`^accepts at most (\d+) arg\(s\), received (\d+)$`)
	reArgsBetween = regexp.MustCompile(`^accepts between (\d+) and (\d+) arg\(s\), received (\d+)$`)
)

// argsError rewrites cobra's own argument errors (wrong count, "unknown
// command" from NoArgs, "invalid argument" from OnlyValidArgs) into a
// message that names the arguments, shows the use line and an example.
// Errors of custom validators pass through. No argument value is printed
// while a secret-prompt flag is set.
func argsError(cmd *cobra.Command, args []string, err error) error {
	var ee *ExitCodeError
	var uh *usageHintError
	if errors.As(err, &ee) || errors.As(err, &uh) || core.AsError(err) != nil {
		return err
	}
	msg := err.Error()
	lo, hi := 0, -1 // hi -1: no upper bound
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	switch {
	case reArgsExact.MatchString(msg):
		m := reArgsExact.FindStringSubmatch(msg)
		lo, hi = atoi(m[1]), atoi(m[1])
	case reArgsAtLeast.MatchString(msg):
		lo = atoi(reArgsAtLeast.FindStringSubmatch(msg)[1])
	case reArgsAtMost.MatchString(msg):
		hi = atoi(reArgsAtMost.FindStringSubmatch(msg)[1])
	case reArgsBetween.MatchString(msg):
		m := reArgsBetween.FindStringSubmatch(msg)
		lo, hi = atoi(m[1]), atoi(m[2])
	case strings.HasPrefix(msg, "unknown command "):
		hi = 0
	case strings.HasPrefix(msg, "invalid argument "):
		return invalidArgError(cmd, args)
	default:
		return err
	}
	if serr := checkSecretPrompts(cmd, invocationArgs); serr != nil {
		return serr
	}
	secret := setSecretPromptFlag(cmd)
	hide := secret != nil
	path := cmd.CommandPath()
	e := &usageHintError{help: fmt.Sprintf("Run %q for more.", path+" --help")}
	if len(args) < lo {
		e.msg = fmt.Sprintf("%q needs %s", path, argPlaceholders(cmd))
		if len(args) > 0 {
			e.msg += ", got " + gotArgs(args, hide)
		}
	} else {
		switch {
		case hi == 0:
			e.msg = fmt.Sprintf("%q takes no arguments", path)
			if hide {
				e.msg += ", got " + gotArgs(args, true)
			} else {
				e.msg += fmt.Sprintf(" (unknown command %q)", args[0])
			}
		case lo == hi:
			e.msg = fmt.Sprintf("%q takes %s (%s), got %s", path, Plural(int64(hi), "argument"), argPlaceholders(cmd), gotArgs(args, hide))
		case lo == 0:
			e.msg = fmt.Sprintf("%q takes at most %s (%s), got %s", path, Plural(int64(hi), "argument"), argPlaceholders(cmd), gotArgs(args, hide))
		default:
			e.msg = fmt.Sprintf("%q takes %d to %d arguments (%s), got %s", path, lo, hi, argPlaceholders(cmd), gotArgs(args, hide))
		}
		if !hide {
			if q := quoteHint(args); q != "" {
				e.hints = append(e.hints, "put quotes around paths with spaces: "+q)
			}
		}
	}
	if hide {
		e.hints = append(e.hints, secretPromptAdvice(secret))
	}
	e.lines = usageBlock(cmd)
	return e
}

// needsArgsError is the usage error of a command run without the
// arguments it needs (for commands that check them in RunE).
func needsArgsError(cmd *cobra.Command) error {
	return &usageHintError{
		msg:   fmt.Sprintf("%q needs %s", cmd.CommandPath(), argPlaceholders(cmd)),
		lines: usageBlock(cmd),
		help:  fmt.Sprintf("Run %q for more.", cmd.CommandPath()+" --help"),
	}
}

// usageBlock is the "Usage:" and "Example:" lines of an argument error.
func usageBlock(cmd *cobra.Command) []string {
	lines := []string{"Usage:   " + cmd.UseLine()}
	if ex := firstExample(cmd); ex != "" {
		lines = append(lines, "Example: "+ex)
	}
	return lines
}

// invalidArgError is argsError for OnlyValidArgs: the word is not one of
// the command's ValidArgs.
func invalidArgError(cmd *cobra.Command, args []string) error {
	var bad string
	for _, a := range args {
		if !slices.Contains(cmd.ValidArgs, a) {
			bad = a
			break
		}
	}
	e := &usageHintError{
		msg:  fmt.Sprintf("%q is not one of %s", bad, strings.Join(cmd.ValidArgs, ", ")),
		help: fmt.Sprintf("Run %q for more.", cmd.CommandPath()+" --help"),
	}
	for _, v := range cmd.ValidArgs {
		if levenshtein(bad, v) <= 2 {
			e.suggestions = append(e.suggestions, v)
		}
	}
	return e
}

// argPlaceholders is the argument part of cmd's Use ("<user>").
func argPlaceholders(cmd *cobra.Command) string {
	_, rest, _ := strings.Cut(cmd.Use, " ")
	if rest = strings.TrimSpace(rest); rest == "" {
		return "arguments"
	}
	return rest
}

// gotArgs is `2: "/My", "files/Docs"`, or "2 arguments" when hidden.
func gotArgs(args []string, hide bool) string {
	if hide {
		return Plural(int64(len(args)), "argument")
	}
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = strconv.Quote(a)
	}
	return fmt.Sprintf("%d: %s", len(args), strings.Join(q, ", "))
}

// quoteHint rebuilds a path the shell split at a space ("/My" "files/Docs"
// → "/My files/Docs"), or "".
func quoteHint(args []string) string {
	for i, a := range args {
		if i+1 >= len(args) || !(strings.HasPrefix(a, "/My") || strings.HasPrefix(a, "/Team")) {
			continue
		}
		parts := []string{a}
		for _, next := range args[i+1:] {
			if strings.HasPrefix(next, "/") || strings.HasPrefix(next, "nod_") {
				break
			}
			parts = append(parts, next)
		}
		if len(parts) > 1 {
			return strconv.Quote(strings.Join(parts, " "))
		}
	}
	return ""
}

// firstExample is the first example line of cmd that runs fileparcel,
// without indentation or a trailing comment.
func firstExample(cmd *cobra.Command) string {
	for _, l := range strings.Split(cmd.Example, "\n") {
		l = strings.TrimSpace(l)
		if !strings.Contains(l, "fileparcel") {
			continue
		}
		if i := strings.Index(l, " #"); i > 0 {
			l = strings.TrimSpace(l[:i])
		}
		return l
	}
	return ""
}

// ---------- cobra's flag-group errors ----------

var (
	reGroupExclusive = regexp.MustCompile(`^if any flags in the group \[([^\]]*)\] are set none of the others can be; \[([^\]]*)\] were all set$`)
	reGroupTogether  = regexp.MustCompile(`^if any flags in the group \[([^\]]*)\] are set they must all be set; missing \[([^\]]*)\]$`)
	reGroupOneOf     = regexp.MustCompile(`^at least one of the flags in the group \[([^\]]*)\] is required$`)
	reRequiredFlags  = regexp.MustCompile(`^required flag\(s\) (.+) not set$`)
)

// friendlyCobraError rewrites cobra's flag-group and required-flag errors
// (which do not pass through the flag error function) as usage errors in
// plain words. Other errors are returned unchanged.
func friendlyCobraError(err error) error {
	var ee *ExitCodeError
	if err == nil || errors.As(err, &ee) || core.AsError(err) != nil {
		return err
	}
	dashed := func(list string) []string {
		var out []string
		for _, n := range strings.Fields(list) {
			out = append(out, "--"+strings.Trim(n, `"`))
		}
		return out
	}
	msg := err.Error()
	switch {
	case reGroupExclusive.MatchString(msg):
		m := reGroupExclusive.FindStringSubmatch(msg)
		return UsageError("use only one of %s", joinAnd(dashed(m[2])))
	case reGroupTogether.MatchString(msg):
		m := reGroupTogether.FindStringSubmatch(msg)
		missing := dashed(m[2])
		var set []string
		for _, f := range dashed(m[1]) {
			if !slices.Contains(missing, f) {
				set = append(set, f)
			}
		}
		verb := "needs"
		if len(set) > 1 {
			verb = "need"
		}
		return UsageError("%s %s %s", joinAnd(set), verb, joinAnd(missing))
	case reGroupOneOf.MatchString(msg):
		return UsageError("use one of %s", joinOr(dashed(reGroupOneOf.FindStringSubmatch(msg)[1])))
	case reRequiredFlags.MatchString(msg):
		names := dashed(strings.ReplaceAll(reRequiredFlags.FindStringSubmatch(msg)[1], ",", " "))
		if len(names) == 1 {
			return UsageError("%s is required", names[0])
		}
		return UsageError("%s are required", joinAnd(names))
	}
	return err
}

// ---------- distance ----------

// levenshtein is the edit distance of a and b: the insertions, deletions,
// substitutions and swaps of two neighbouring letters that turn one into the
// other (case-insensitive, by rune). Counting a swap as one edit keeps the
// commonest typo ("lsit") closer to what was meant ("list") than to other
// words ("edit").
func levenshtein(a, b string) int {
	ra, rb := []rune(strings.ToLower(a)), []rune(strings.ToLower(b))
	// d[i][j] is the distance of ra[:i] and rb[:j].
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
