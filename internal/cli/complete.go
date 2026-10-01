package cli

// Shell completion (DESIGN §12, "Shell completion"). cobra completes
// command and flag names itself; this file adds arguments and flag values:
//
//   - Static words: the values of enum flags (enumFlags) and the fixed words
//     of a few arguments ("user set-quota alice unlimited").
//   - Names and ids from the server: users, groups, roles, permissions,
//     setting keys, VPNs and interfaces, the ids of links, file requests,
//     tokens, invitations, backups, jobs, client certificates and access
//     grants, and remote paths (the entries of the parent folder of the
//     typed path). completeFrom connects only over the admin socket or with
//     --server, never offline (no home lock, no passphrase prompt), gives up
//     after completionTimeout and completes nothing on any error. Setting
//     keys, permissions and the built-in roles fall back to what this
//     program knows when no server answers.
//
// Arguments are completed by the placeholders of the command's Use line
// (argSource), so a new command gets completion by using the usual
// placeholders. Secrets are never completed.

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/settings"
)

// completionTimeout bounds everything one completion does with the server:
// the shell waits for it, and the user waits for the shell.
const completionTimeout = 1500 * time.Millisecond

// completionLimit caps the objects one completion lists.
const completionLimit = 1000

// compReq is one completion request.
type compReq struct {
	cmd  *cobra.Command
	args []string // the arguments before the word
	word string   // the word being completed

	client    *Client
	connected bool
}

// source returns the candidates for r.word ("value\tdescription");
// completeFrom keeps those that start with the word.
type source func(ctx context.Context, r *compReq) []cobra.Completion

// conn returns the server connection, made on first use: the admin socket
// of a running server or --server, never offline. nil when there is none.
func (r *compReq) conn(ctx context.Context) *Client {
	if !r.connected {
		r.connected = true
		r.client = completionClient(ctx)
	}
	return r.client
}

// completionClient connects like WithClient but only to a running server:
// --server (remote) or the admin socket of the home. Offline mode would
// take the home lock and may ask for the passphrase, so it is never used.
func completionClient(ctx context.Context) *Client {
	if G.Offline {
		return nil
	}
	opts := G.ConnectOptions()
	if opts.Server != "" {
		// The root's checkInvocation, which reads --token-file for commands,
		// does not run for completions.
		if G.TokenFile != "" && G.Token == "" {
			tok, err := ReadSecretFile(nil, G.TokenFile)
			if err != nil {
				return nil
			}
			opts.Token = strings.TrimSpace(tok)
		}
		c, err := connectRemote(opts)
		if err != nil {
			return nil
		}
		return c
	}
	h, err := home.Resolve(opts.Home)
	if err != nil || !h.Exists() {
		return nil
	}
	c, err := connectSocketContext(ctx, h, opts)
	if err != nil {
		return nil
	}
	return c
}

// completeFrom turns src into a cobra completion function. Candidates are
// filtered by the typed prefix; a candidate that ends in "/" (a folder)
// keeps the shell from adding a space.
func completeFrom(src source) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, word string) ([]cobra.Completion, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
		defer cancel()
		r := &compReq{cmd: cmd, args: args, word: word}
		defer func() {
			if r.client != nil {
				r.client.Close()
			}
		}()
		var out []cobra.Completion
		dir := cobra.ShellCompDirectiveNoFileComp
		for _, c := range src(ctx, r) {
			value, _, _ := strings.Cut(c, "\t")
			if strings.HasPrefix(value, word) {
				out = append(out, c)
				if strings.HasSuffix(value, "/") {
					dir |= cobra.ShellCompDirectiveNoSpace
				}
			}
		}
		return out, dir
	}
}

// words is a source of fixed words.
func words(values ...string) source {
	return func(context.Context, *compReq) []cobra.Completion { return values }
}

// ---------- registration ----------

// enumFlag lists the values of one enum flag of one command.
type enumFlag struct {
	Command, Flag string
	Values        []string
}

// enumFlags are the flags that take one of a few words. addCompletions
// panics when an entry names a command or flag that does not exist, so
// every test fails.
var enumFlags = []enumFlag{
	{"files put", "conflict", conflictWords},
	{"files mv", "conflict", conflictWords},
	{"files cp", "conflict", conflictWords},
	{"files ls", "sort", []string{"name", "size", "updated", "kind"}},
	{"files search", "kind", []string{core.KindFile, core.KindFolder}},
	{"files put", "zip-encryption", []string{core.ZipEncAES256, core.ZipEncZipCrypto}},
	{"audit export", "format", []string{"csv", "jsonl"}},
	{"audit list", "outcome", outcomeWords},
	{"audit export", "outcome", outcomeWords},
	{"ca export", "format", []string{"pem", "der", "mobileconfig"}},
	{"ca trust-help", "os", trustOSes},
	{"backup create", "scope", []string{core.BackupFull, core.BackupMetadata}},
	{"backup config set", "encryption", []string{core.BackupX25519, core.BackupPassphrase}},
	{"keys rotate", "purpose", []string{core.KEKBlob, core.KEKField}},
	{"cert acme enable", "challenge", []string{"dns", "http", "tls-alpn"}},
	{"cert acme enable", "dns-provider", []string{"cloudflare", "rfc2136"}},
	{"jobs list", "kind", allJobKinds},
	{"jobs list", "state", []string{core.JobQueued, core.JobRunning, core.JobSucceeded, core.JobFailed, core.JobCanceled}},
	{"user list", "status", []string{core.UserActive, core.UserDisabled}},
	{"token create", "scopes", core.AllScopes},
	{"init", "access", accessWords},
	{"install", "access", accessWords},
	{"install", "service", []string{"user", "system", "none"}},
	{"access grant", "level", grantLevelWords()},
	{"role create", "base", []string{string(core.RoleMember), string(core.RoleGuest)}},
	{"network funnel enable", "mode", []string{core.FunnelShares, core.FunnelApp}},
	{"network funnel enable", "port", funnelPortWords()},
}

var (
	conflictWords = []string{string(core.ConflictRename), string(core.ConflictReplace), string(core.ConflictSkip),
		string(core.ConflictFail)}
	accessWords  = []string{core.AccessPrivate, core.AccessAllowlist, core.AccessAny}
	outcomeWords = []string{core.OutcomeSuccess, core.OutcomeFailure, core.OutcomeDenied}
	// allJobKinds are the job kinds of DESIGN §9.7.
	allJobKinds = []string{core.JobUploadZip, core.JobThumbsGenerate, core.JobBackupCreate, core.JobBackupVerify,
		core.JobBackupPrune, core.JobKeysRotateKEK, core.JobKeysReencrypt, core.JobMaintSessions, core.JobMaintUploads,
		core.JobMaintTrash, core.JobMaintBlobGC, core.JobMaintAuditPrune, core.JobMaintDBOptimize, core.JobMaintVersions,
		core.JobCertsRenewCheck}
)

func grantLevelWords() []string {
	var out []string
	for _, l := range grantLevels {
		out = append(out, l.Word)
	}
	return out
}

func funnelPortWords() []string {
	var out []string
	for _, p := range funnelPorts {
		out = append(out, strconv.Itoa(p))
	}
	return out
}

// addCompletions registers the completion of arguments and flag values on
// the whole tree (finishTree).
func addCompletions(root *cobra.Command) {
	must := func(err error) {
		if err != nil {
			panic("cli: completion: " + err.Error())
		}
	}
	must(root.MarkPersistentFlagDirname("home"))
	must(root.RegisterFlagCompletionFunc("as", completeFrom(completeUsers)))
	for _, e := range enumFlags {
		c := findCommand(root, e.Command)
		if c == nil || c.Flags().Lookup(e.Flag) == nil {
			panic("cli: completion: no flag --" + e.Flag + " on " + e.Command)
		}
		src := words(e.Values...)
		if e.Flag == "scopes" {
			src = commaList(func(context.Context, *compReq) []cobra.Completion { return e.Values })
		}
		must(c.RegisterFlagCompletionFunc(e.Flag, completeFrom(src)))
	}
	walkCommands(root, func(c *cobra.Command) {
		if c.Hidden || c == root {
			return
		}
		if c.Runnable() && !c.HasSubCommands() && c.ValidArgs == nil && c.ValidArgsFunction == nil {
			c.ValidArgsFunction = argsCompletion(c)
		}
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if src := flagSource(c, f); src != nil {
				must(c.RegisterFlagCompletionFunc(f.Name, completeFrom(src)))
			}
		})
	})
}

// flagSource returns the server source of a name-valued flag of c, or nil.
func flagSource(c *cobra.Command, f *pflag.Flag) source {
	switch f.Value.Type() {
	case "string", "stringArray", "stringSlice":
	default:
		return nil // service install --user is a switch
	}
	if f.Hidden {
		return nil
	}
	top := topCommand(c)
	switch f.Name {
	case "user", "transfer-to":
		return completeUsers
	case "group":
		return completeGroups
	case "role":
		return completeRoles(top == "access")
	case "from", "reassign-to":
		if top == "role" {
			return completeRoles(false)
		}
	case "add", "remove", "set":
		if top == "role" {
			return commaList(permissionNames)
		}
	case "section":
		if top == "config" {
			return settingSections
		}
	}
	return nil
}

// topCommand is the name of c's top-level command ("files" for "files put").
func topCommand(c *cobra.Command) string {
	for c.HasParent() && c.Parent().HasParent() {
		c = c.Parent()
	}
	return c.Name()
}

// placeholders returns the argument placeholders of c's Use line
// ("<group>", "<user>..."); flags with their values and "(…)" groups are
// skipped.
func placeholders(c *cobra.Command) []string {
	var out []string
	depth := 0
	fields := strings.Fields(c.Use)
	for i, w := range fields {
		opening := strings.Count(w, "(")
		closing := strings.Count(w, ")")
		inGroup := depth > 0 || opening > 0
		depth += opening - closing
		switch {
		case i == 0 || inGroup || strings.HasPrefix(w, "-") || strings.HasPrefix(w, "[-"):
		case strings.HasPrefix(w, "<") || strings.HasPrefix(w, "["):
			out = append(out, w)
		}
	}
	return out
}

// argsCompletion completes the positional arguments of c by their
// placeholders: the n-th argument by the n-th placeholder, and any further
// one by the last placeholder when one of them repeats ("<user>...", or
// "<src>... <dest>", where every further word may be the last).
func argsCompletion(c *cobra.Command) cobra.CompletionFunc {
	phs := placeholders(c)
	repeats := slices.ContainsFunc(phs, func(ph string) bool { return strings.HasSuffix(ph, "...") })
	return func(cmd *cobra.Command, args []string, word string) ([]cobra.Completion, cobra.ShellCompDirective) {
		ph := ""
		switch n := len(args); {
		case n < len(phs):
			ph = phs[n]
		case repeats:
			ph = phs[len(phs)-1]
		}
		if ph == "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		src, localFiles := argSource(cmd, ph, word)
		if src == nil {
			if localFiles {
				return nil, cobra.ShellCompDirectiveDefault
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		out, dir := completeFrom(src)(cmd, args, word)
		if localFiles && len(out) == 0 {
			return nil, cobra.ShellCompDirectiveDefault // "backup restore ./x.fpbak"
		}
		return out, dir
	}
}

// remoteGroups are the top-level commands whose path arguments are remote
// paths ("/My files/…").
var remoteGroups = []string{"files", "share", "request", "access"}

// argSource returns the source that completes the placeholder ph of c.
// localFiles asks for the shell's file completion instead (or when src
// finds nothing).
func argSource(c *cobra.Command, ph, word string) (src source, localFiles bool) {
	top := topCommand(c)
	remote := slices.Contains(remoteGroups, top)
	switch strings.TrimSuffix(ph, "...") {
	case "<user>":
		return completeUsers, false
	case "<group>":
		return completeGroups, false
	case "<role>":
		return completeRoles(false), false
	case "<key>":
		return settingKeys, false
	case "[value]":
		return settingValues, false
	case "<job>":
		return completeJobs, false
	case "<backup>":
		return completeBackups, true // a backup file works too
	case "<vpn|interface>":
		return completeVPNs, false
	case "<interface>":
		return completeInterfaces, false
	case "<size|unlimited|default>":
		return words("unlimited", "default"), false
	case "<mesh|unknown|access|egress|overlay|local|none|auto>":
		var ws []string
		for _, r := range vpnRoles {
			ws = append(ws, r.Role)
		}
		return words(ws...), false
	case "<id|serial>":
		return completeClientCerts, false
	case "[gnt_…]":
		return completeGrants, false
	case "<id>":
		switch top {
		case "share":
			return completeShares(core.ShareLink), false
		case "request":
			return completeShares(core.ShareRequest), false
		case "token":
			return completeTokens, false
		case "invite":
			return completeInvites, false
		}
	case "<remote-folder>":
		// files put <local>... <remote-folder>: which argument is the last
		// is not known yet; a word that looks remote is completed remotely.
		if looksRemote(word) {
			return remotePaths(true), false
		}
		return nil, true
	case "<local>", "[local]", "<file>", "<release.zip|binary>":
		return nil, true
	case "<folder>":
		if remote {
			return remotePaths(true), false
		}
	case "<path>", "[path]", "<src>", "<dest>", "<remote>":
		if remote {
			return remotePaths(false), false
		}
		return nil, true // backup export <backup> <path>
	}
	return nil, false
}

// looksRemote reports whether a word of "files put" is a remote path.
func looksRemote(word string) bool {
	w := strings.ToLower(word)
	return strings.HasPrefix(w, "/my") || strings.HasPrefix(w, "/team") || strings.HasPrefix(w, "nod_")
}

// commaList completes the last item of a comma-separated list ("a,b,c"),
// leaving out the items already given.
func commaList(src source) source {
	return func(ctx context.Context, r *compReq) []cobra.Completion {
		head := ""
		if i := strings.LastIndex(r.word, ","); i >= 0 {
			head = r.word[:i+1]
		}
		given := strings.Split(strings.TrimSuffix(head, ","), ",")
		var out []cobra.Completion
		for _, c := range src(ctx, r) {
			value, _, _ := strings.Cut(c, "\t")
			if !slices.Contains(given, value) {
				out = append(out, cobra.Completion(head+c))
			}
		}
		return out
	}
}

// ---------- sources ----------

// actAsUser makes c act like withUserClient: over the admin socket without
// --as, as the first owner. false when that is not possible.
func actAsUser(ctx context.Context, c *Client) bool {
	if c.Mode() == ModeRemote || G.As != "" {
		return true
	}
	owner, err := firstOwner(ctx, c)
	if err != nil {
		return false
	}
	setClientActAs(c, owner)
	return true
}

func completeUsers(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil {
		return nil
	}
	var out []cobra.Completion
	users, err := listAll[core.User](ctx, c, api("/admin/users", "limit", limitParam(0)), completionLimit)
	if apiStatus(err) == http.StatusForbidden && r.word != "" {
		// Remote, without users.view: the directory (users.lookup).
		refs, lerr := listAll[core.UserRef](ctx, c, api("/users/lookup", "q", r.word), completionLimit)
		if lerr != nil {
			return nil
		}
		for _, u := range refs {
			out = append(out, cobra.CompletionWithDesc(u.Username, u.DisplayName))
		}
		return out
	}
	if err != nil {
		return nil
	}
	for _, u := range users {
		out = append(out, cobra.CompletionWithDesc(u.Username, u.DisplayName))
	}
	return out
}

func completeGroups(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil {
		return nil
	}
	groups, err := listAll[core.Group](ctx, c, api("/admin/groups", "limit", limitParam(0)), completionLimit)
	if apiStatus(err) == http.StatusForbidden {
		groups, err = listAll[core.Group](ctx, c, api("/groups"), completionLimit) // the caller's own groups
	}
	if err != nil {
		return nil
	}
	var out []cobra.Completion
	for _, g := range groups {
		out = append(out, cobra.CompletionWithDesc(g.Name, g.Description))
	}
	return out
}

// completeRoles completes role names: the built-in words (also without a
// server) and the custom roles; customOnly for access grants, whose
// subjects are custom roles only.
func completeRoles(customOnly bool) source {
	return func(ctx context.Context, r *compReq) []cobra.Completion {
		var out []cobra.Completion
		seen := map[string]bool{}
		if !customOnly {
			for _, rd := range core.BuiltinRoles(false) {
				out = append(out, cobra.CompletionWithDesc(rd.ID, shortDesc(rd.Description)))
				seen[rd.ID] = true
			}
		}
		c := r.conn(ctx)
		if c == nil {
			return out
		}
		roles, err := listRoles(ctx, c)
		if err != nil {
			return out
		}
		for _, rd := range roles {
			if rd.Builtin || core.Role(rd.ID).Valid() || seen[rd.Name] {
				continue
			}
			out = append(out, cobra.CompletionWithDesc(rd.Name, shortDesc(rd.Description)))
		}
		return out
	}
}

// permissionNames lists the permissions of the server's catalog, or of this
// program's when no server answers.
func permissionNames(ctx context.Context, r *compReq) []cobra.Completion {
	cat := core.Catalog()
	if c := r.conn(ctx); c != nil {
		if got, _, err := roleCatalog(ctx, c); err == nil {
			cat = got
		}
	}
	var out []cobra.Completion
	for _, info := range cat.Items {
		out = append(out, cobra.CompletionWithDesc(string(info.Name), info.Label))
	}
	return out
}

// settingViews returns the settings catalog: the server's, or the one this
// program registers when no server answers (secret values are never part
// of it).
func settingViews(ctx context.Context, r *compReq) []core.SettingView {
	if c := r.conn(ctx); c != nil {
		views, err := settingsCatalog(ctx, c)
		if err != nil {
			return nil
		}
		return views
	}
	var out []core.SettingView
	for _, d := range settings.Defs() {
		out = append(out, core.SettingView{Key: d.Key, Section: d.Section, Type: string(d.Type), Label: d.Label, Enum: d.Enum,
			Secret: d.Secret})
	}
	return out
}

func settingKeys(ctx context.Context, r *compReq) []cobra.Completion {
	var out []cobra.Completion
	for _, s := range settingViews(ctx, r) {
		out = append(out, cobra.CompletionWithDesc(s.Key, s.Label))
	}
	return out
}

// settingSections completes "config list --section": the sections of the
// settings catalog, in catalog order.
func settingSections(ctx context.Context, r *compReq) []cobra.Completion {
	var out []cobra.Completion
	for _, s := range settingViews(ctx, r) {
		if s.Section != "" && !slices.Contains(out, s.Section) {
			out = append(out, s.Section)
		}
	}
	return out
}

// settingValues completes the value of "config set <key> [value]": the
// words of an enum and true/false. Secrets are never completed.
func settingValues(ctx context.Context, r *compReq) []cobra.Completion {
	if len(r.args) == 0 {
		return nil
	}
	for _, s := range settingViews(ctx, r) {
		switch {
		case s.Key != r.args[0] || s.Secret:
		case s.Type == string(settings.TypeBool):
			return []cobra.Completion{"true", "false"}
		default:
			return s.Enum
		}
	}
	return nil
}

// overview returns GET /admin/network.
func overview(ctx context.Context, r *compReq) *core.NetworkOverview {
	c := r.conn(ctx)
	if c == nil {
		return nil
	}
	var ov core.NetworkOverview
	if err := c.Do(ctx, http.MethodGet, api("/admin/network"), nil, &ov); err != nil {
		return nil
	}
	return &ov
}

func completeVPNs(ctx context.Context, r *compReq) []cobra.Completion {
	ov := overview(ctx, r)
	if ov == nil {
		return nil
	}
	var out []cobra.Completion
	for _, v := range ov.VPNs {
		out = append(out, cobra.CompletionWithDesc(v.ID, v.Label))
	}
	return out
}

func completeInterfaces(ctx context.Context, r *compReq) []cobra.Completion {
	ov := overview(ctx, r)
	if ov == nil {
		return nil
	}
	var out []cobra.Completion
	for _, i := range ov.Interfaces {
		desc := i.Label
		if i.Role != "" {
			desc += " (" + i.Role + ")"
		}
		out = append(out, cobra.CompletionWithDesc(i.Name, desc))
	}
	return out
}

// completeShares completes the ids of the acting user's active links or
// file requests.
func completeShares(kind string) source {
	return func(ctx context.Context, r *compReq) []cobra.Completion {
		c := r.conn(ctx)
		if c == nil || !actAsUser(ctx, c) {
			return nil
		}
		shares, err := listAll[core.Share](ctx, c, api("/shares", "kind", kind, "limit", limitParam(0)), completionLimit)
		if err != nil {
			return nil
		}
		var out []cobra.Completion
		for _, s := range shares {
			if s.Kind == kind || s.Kind == "" {
				out = append(out, cobra.CompletionWithDesc(s.ID, firstNonEmpty(s.Title, s.NodeName)))
			}
		}
		return out
	}
}

func completeTokens(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil || !actAsUser(ctx, c) {
		return nil
	}
	tokens, err := listAll[core.APIToken](ctx, c, api("/me/tokens"), completionLimit)
	if err != nil {
		return nil
	}
	var out []cobra.Completion
	for _, t := range tokens {
		if t.RevokedAt == nil {
			out = append(out, cobra.CompletionWithDesc(t.ID, t.Name))
		}
	}
	return out
}

func completeInvites(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil {
		return nil
	}
	invites, err := listAll[core.Invite](ctx, c, api("/admin/invites", "limit", limitParam(0)), completionLimit)
	if err != nil {
		return nil
	}
	var out []cobra.Completion
	for _, inv := range invites {
		if inv.Status == "" || inv.Status == core.InviteActive {
			out = append(out, cobra.CompletionWithDesc(inv.ID, firstNonEmpty(inv.Email, inv.Note, string(inv.Role))))
		}
	}
	return out
}

func completeBackups(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil {
		return nil
	}
	backups, err := listAll[core.Backup](ctx, c, api("/admin/backups", "limit", "50"), 50)
	if err != nil {
		return nil
	}
	var out []cobra.Completion
	for _, b := range backups {
		out = append(out, cobra.CompletionWithDesc(b.ID, b.Scope+", "+HumanTime(b.CreatedAt)))
	}
	return out
}

// completeJobs completes recent job ids ("jobs cancel": only those still
// queued or running).
func completeJobs(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil {
		return nil
	}
	jobs, err := listAll[core.Job](ctx, c, api("/admin/jobs", "limit", "50"), 50)
	if err != nil {
		return nil
	}
	var out []cobra.Completion
	for _, j := range jobs {
		if r.cmd.Name() == "cancel" && jobTerminal(j.State) {
			continue
		}
		out = append(out, cobra.CompletionWithDesc(j.ID, j.Kind+", "+j.State))
	}
	return out
}

func completeClientCerts(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil {
		return nil
	}
	certs, err := listAll[core.ClientCert](ctx, c, api("/admin/client-certs", "limit", limitParam(0)), completionLimit)
	if err != nil {
		return nil
	}
	var out []cobra.Completion
	for _, cc := range certs {
		if cc.RevokedAt == nil {
			out = append(out, cobra.CompletionWithDesc(cc.ID, cc.Username+": "+cc.Name))
		}
	}
	return out
}

// completeGrants completes the ids of the grants on the path of
// "access revoke <path> [gnt_…]".
func completeGrants(ctx context.Context, r *compReq) []cobra.Completion {
	c := r.conn(ctx)
	if c == nil || len(r.args) == 0 {
		return nil
	}
	t, err := newResolver(c).resolveNode(ctx, r.args[0])
	if err != nil {
		return nil
	}
	grants, err := doList[core.Grant](ctx, c, http.MethodGet, api("/nodes/"+pathEsc(t.Node.ID)+"/grants"), nil)
	if err != nil {
		return nil
	}
	var out []cobra.Completion
	for _, g := range grants {
		out = append(out, cobra.CompletionWithDesc(g.ID, g.SubjectType+" "+firstNonEmpty(g.SubjectName, g.SubjectID)+": "+levelWord(g.Role)))
	}
	return out
}

// remotePaths completes remote paths: the entries of the folder the typed
// path is in, folders with a trailing "/" (foldersOnly: folders only).
// file, share and request commands act as withUserClient does; access
// commands with the admin socket's rights, or ("access check") as the user
// being checked.
func remotePaths(foldersOnly bool) source {
	return func(ctx context.Context, r *compReq) []cobra.Completion {
		roots := []cobra.Completion{"/" + myFilesName + "/", "/" + teamName + "/"}
		if r.word == "" {
			return roots
		}
		c := r.conn(ctx)
		if c == nil {
			return nil
		}
		switch {
		case topCommand(r.cmd) != "access":
			if !actAsUser(ctx, c) {
				return nil
			}
		case G.As == "" && r.cmd.Name() == "check" && len(r.args) > 0 && c.Mode() != ModeRemote:
			setClientActAs(c, r.args[0])
		}
		dir := ""
		if i := strings.LastIndex(r.word, "/"); i >= 0 {
			dir = r.word[:i+1]
		}
		lookup := dir
		if lookup == "" {
			lookup = "/" + myFilesName // relative paths are below "/My files"
		}
		res := newResolver(c)
		t, err := res.resolve(ctx, lookup)
		if err != nil || !t.IsDir() {
			return nil
		}
		var out []cobra.Completion
		switch {
		case t.Node == nil && t.Virtual == virtualTop:
			return roots
		case t.Node == nil:
			teams, err := res.allTeams(ctx)
			if err != nil {
				return nil
			}
			for _, ts := range teams {
				out = append(out, cobra.Completion(dir+ts.Name+"/"))
			}
			return out
		}
		kids, err := res.list(ctx, t.Node.ID)
		if err != nil {
			return nil
		}
		for _, n := range kids {
			switch {
			case n.IsDir():
				out = append(out, cobra.Completion(dir+n.Name+"/"))
			case !foldersOnly:
				out = append(out, cobra.Completion(dir+n.Name))
			}
		}
		return out
	}
}

// shortDesc shortens a description for a completion menu: its first
// sentence or clause, at most 60 characters.
func shortDesc(s string) string {
	if i := strings.IndexAny(s, ".;:"); i > 0 {
		s = s[:i]
	}
	return Truncate(strings.TrimSpace(s), 60)
}

// firstNonEmpty returns the first of values that is not empty.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
