package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

func init() { Register(newFilesCmd) }

func newFilesCmd() *cobra.Command {
	cmd := groupCmd("files", "Upload, download, browse and organize files",
		`Work with the files stored in FileParcel from the command line: list,
upload (verified parts retried on network errors, parallel, optional zip
bundling), download (resumable, verified), create folders, move, copy, delete,
restore from trash, search and inspect versions.

On the server, file commands act as the first owner unless --as USER; remotely
they act as the token's user.

`+filesPathNote,
		`  fileparcel files ls
  fileparcel files put ./photos "/My files/Pictures"
  fileparcel files get "/My files/Pictures/photos" --zip
  fileparcel --as alice files ls /Team/Design`, "file", "fs")
	put, restore := newFilesPutCmd(), newFilesRestoreCmd()
	cmd.AddCommand(newFilesLsCmd(), newFilesTreeCmd(), put, newFilesGetCmd(), newFilesMkdirCmd(),
		newFilesMoveCmd(false), newFilesMoveCmd(true), newFilesRmCmd(), restore, newFilesTrashCmd(),
		newFilesInfoCmd(), newFilesSearchCmd(), newFilesVersionsCmd())
	setListHint(cmd, "fileparcel files ls {parent}")
	setListHint(put, "fileparcel files ls {parent:last}") // the remote folder is the last argument
	setListHint(restore, "fileparcel files trash")
	return cmd
}

// progressEnabled reports whether transfer progress should be drawn.
func progressEnabled(cmd *cobra.Command, noProgress bool) bool {
	return !noProgress && !G.JSON && stderrIsTerminal(cmd)
}

// parseConflict validates a --conflict value.
func parseConflict(s string) (core.ConflictPolicy, error) {
	c := core.ConflictPolicy(strings.ToLower(strings.TrimSpace(s)))
	if !c.Valid() {
		return "", UsageError("invalid --conflict %q (rename, replace, skip or fail)", s)
	}
	return c, nil
}

// nodeName renders a node name for listings (folders end with "/").
func nodeName(n *core.Node) string {
	if n.IsDir() {
		return n.Name + "/"
	}
	return n.Name
}

func nodeSize(n *core.Node) string {
	if n.IsDir() {
		if n.ChildCount != nil {
			return Plural(*n.ChildCount, "item")
		}
		return ""
	}
	return HumanBytes(n.Size)
}

// ---------- ls ----------

func newFilesLsCmd() *cobra.Command {
	var sortBy string
	var desc, long bool
	cmd := &cobra.Command{
		Use:     "ls [path]",
		Aliases: []string{"list"},
		Short:   "List the contents of a folder",
		Long: `List the contents of a remote folder (default "/My files"). "/" lists the
top-level folders and "/Team" the team folders you can access. A file path
shows that file.

` + filesPathNote,
		Example: `  fileparcel files ls
  fileparcel files ls "/My files/Documents" --sort size --desc
  fileparcel files ls /Team/Design -l
  fileparcel files ls nod_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := "/" + myFilesName
			if len(args) == 1 {
				p = args[0]
			}
			switch sortBy {
			case "", "name", "size", "updated", "kind":
			default:
				return UsageError("invalid --sort %q (name, size, updated or kind)", sortBy)
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := r.resolve(ctx, p)
				if err != nil {
					return err
				}
				switch {
				case t.Virtual == virtualTop:
					return printVirtualTop(ctx, cmd, r)
				case t.Virtual == virtualTeam:
					return printTeams(ctx, cmd, r)
				case !t.Node.IsDir():
					nodes := []core.Node{*t.Node}
					return Print(cmd, nodes, func(w io.Writer) error { return renderNodes(w, nodes, long) })
				}
				q := api("/nodes/"+pathEsc(t.Node.ID)+"/children", "limit", limitParam(0), "sort", sortBy)
				if desc {
					q = withQuery(q, "desc", "true")
				}
				nodes, err := listAll[core.Node](ctx, c, q, 0)
				if err != nil {
					return err
				}
				return Print(cmd, nodes, func(w io.Writer) error {
					if len(nodes) == 0 {
						Infof(cmd, "%s is empty", t.Path)
						return nil
					}
					return renderNodes(w, nodes, long)
				})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&sortBy, "sort", "", "sort by name, size, updated or kind (default: folders first, by name)")
	f.BoolVar(&desc, "desc", false, "reverse the sort order")
	f.BoolVarP(&long, "long", "l", false, "also show type, permission and version columns")
	return cmd
}

func renderNodes(w io.Writer, nodes []core.Node, long bool) error {
	if long {
		t := NewTable("NAME", "SIZE", "MODIFIED", "TYPE", "PERM", "ID")
		for i := range nodes {
			n := &nodes[i]
			t.Add(nodeName(n), nodeSize(n), n.UpdatedAt, Dash(n.MIME), n.Perm.String(), n.ID)
		}
		return t.Render(w)
	}
	t := NewTable("NAME", "SIZE", "MODIFIED", "ID")
	for i := range nodes {
		n := &nodes[i]
		t.Add(nodeName(n), nodeSize(n), n.UpdatedAt, n.ID)
	}
	return t.Render(w)
}

// virtualEntry is the --json shape of the virtual folders "/" and "/Team".
type virtualEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	SpaceID string `json:"space_id,omitempty"`
	RootID  string `json:"root_id,omitempty"`
	Used    int64  `json:"used_bytes"`
	// Shared: a team folder shared with the user as a whole, not one of
	// their groups (Used is then unknown: 0).
	Shared bool `json:"shared,omitempty"`
}

func printVirtualTop(ctx context.Context, cmd *cobra.Command, r *resolver) error {
	var out []virtualEntry
	if r.me.SpaceID != "" {
		if sp := r.space(r.me.SpaceID); sp != nil {
			out = append(out, virtualEntry{Name: myFilesName, Path: "/" + myFilesName, SpaceID: sp.ID, RootID: sp.RootID, Used: sp.UsedBytes})
		}
	}
	teams, err := r.allTeams(ctx)
	if err != nil {
		return err
	}
	if len(teams) > 0 {
		out = append(out, virtualEntry{Name: teamName, Path: "/" + teamName})
	}
	return Print(cmd, out, func(w io.Writer) error {
		t := NewTable("NAME", "USED", "ID")
		for _, e := range out {
			used := ""
			if e.SpaceID != "" {
				used = HumanBytes(e.Used)
			}
			t.Add(e.Name+"/", used, e.RootID)
		}
		return t.Render(w)
	})
}

// printTeams lists "/Team": the team folders of the user's groups and those
// shared with the user as a whole (USED is only known for the former).
func printTeams(ctx context.Context, cmd *cobra.Command, r *resolver) error {
	teams, err := r.allTeams(ctx)
	if err != nil {
		return err
	}
	out := make([]virtualEntry, 0, len(teams))
	for _, t := range teams {
		out = append(out, virtualEntry{Name: t.Name, Path: "/" + teamName + "/" + t.Name, SpaceID: t.Space.ID, RootID: t.Space.RootID,
			Used: t.Space.UsedBytes, Shared: t.Shared})
	}
	return Print(cmd, out, func(w io.Writer) error {
		if len(out) == 0 {
			Infof(cmd, "no team folders (join a group to get one)")
			return nil
		}
		t := NewTable("NAME", "USED", "ID")
		for _, e := range out {
			used := HumanBytes(e.Used)
			if e.Shared {
				used = "shared with you"
			}
			t.Add(e.Name+"/", used, e.RootID)
		}
		return t.Render(w)
	})
}

// ---------- tree ----------

func newFilesTreeCmd() *cobra.Command {
	var depth int
	var dirsOnly bool
	cmd := &cobra.Command{
		Use:   "tree [path]",
		Short: "Show a folder and everything in it as a tree",
		Long: `Show the folders and files below a remote folder (default "/My files") as a
tree, with a summary of the number of folders, files and bytes. --json prints a
flat list of {node, path, depth} entries (parents before children).

` + filesPathNote,
		Example: `  fileparcel files tree
  fileparcel files tree "/Team/Design" --depth 2
  fileparcel files tree "/My files/Projects" --dirs-only --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := "/" + myFilesName
			if len(args) == 1 {
				p = args[0]
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := r.resolveFolder(ctx, p)
				if err != nil {
					return err
				}
				var entries []core.WalkEntry
				var walk func(n *core.Node, rel string, d int) error
				walk = func(n *core.Node, rel string, d int) error {
					if depth > 0 && d > depth {
						return nil
					}
					kids, err := r.list(ctx, n.ID)
					if err != nil {
						return err
					}
					for i := range kids {
						k := &kids[i]
						if dirsOnly && !k.IsDir() {
							continue
						}
						kp := k.Name
						if rel != "" {
							kp = rel + "/" + k.Name
						}
						entries = append(entries, core.WalkEntry{Node: *k, Path: kp, Depth: d - 1})
						if k.IsDir() {
							if err := walk(k, kp, d+1); err != nil {
								return err
							}
						}
					}
					return nil
				}
				if err := walk(t.Node, "", 1); err != nil {
					return err
				}
				return Print(cmd, entries, func(w io.Writer) error { return renderTree(w, t.Path, entries) })
			})
		},
	}
	cmd.Flags().IntVar(&depth, "depth", 0, "maximum depth (0 = unlimited)")
	cmd.Flags().BoolVarP(&dirsOnly, "dirs-only", "d", false, "show folders only")
	return cmd
}

// renderTree draws entries (parents before children, depth-first) with
// box-drawing connectors, followed by a summary line.
func renderTree(w io.Writer, root string, entries []core.WalkEntry) error {
	fmt.Fprintln(w, sanitizeCell(root))
	// last[i]: entry i is the last of its siblings (scan backwards).
	last := make([]bool, len(entries))
	var hasLater []bool
	for i := len(entries) - 1; i >= 0; i-- {
		d := max(entries[i].Depth, 0)
		for len(hasLater) <= d {
			hasLater = append(hasLater, false)
		}
		last[i] = !hasLater[d]
		hasLater[d] = true
		for j := d + 1; j < len(hasLater); j++ {
			hasLater[j] = false
		}
	}
	var files, dirs, bytes int64
	var ancLast []bool // ancLast[l]: the current ancestor at depth l is a last child
	for i, e := range entries {
		d := max(e.Depth, 0)
		var prefix strings.Builder
		for l := 0; l < d && l < len(ancLast); l++ {
			if ancLast[l] {
				prefix.WriteString("    ")
			} else {
				prefix.WriteString("│   ")
			}
		}
		conn := "├── "
		if last[i] {
			conn = "└── "
		}
		for len(ancLast) <= d {
			ancLast = append(ancLast, false)
		}
		ancLast[d] = last[i]
		extra := ""
		if e.Node.IsDir() {
			dirs++
		} else {
			files++
			bytes += e.Node.Size
			extra = "  " + Dim(HumanBytes(e.Node.Size))
		}
		fmt.Fprintf(w, "%s%s%s%s\n", prefix.String(), conn, sanitizeCell(nodeName(&e.Node)), extra)
	}
	_, err := fmt.Fprintf(w, "\n%s, %s, %s\n", Plural(dirs, "folder"), Plural(files, "file"), HumanBytes(bytes))
	return err
}

// ---------- put ----------

// zipPasswordFlags are the password flags of "files put --zip".
var zipPasswordFlags = []string{"zip-password", "zip-password-stdin", "zip-password-file", "zip-generate-password"}

// generatedZipPasswordLen is the length of a generated .zip password: 22
// base62 characters carry 128 bits (ids.Token(16)).
var generatedZipPasswordLen = ids.TokenLen(16)

// generateZipPassword returns a random base62 .zip password of
// generatedZipPasswordLen characters, or of min when the server asks for
// more (storage.zip_password_min, at most 64).
func generateZipPassword(min int) string {
	n := max(min, generatedZipPasswordLen)
	nBytes := n * 5 / 8 // a base62 character carries more than 5 bits
	for ids.TokenLen(nBytes) < n {
		nBytes++
	}
	return ids.Token(nBytes)[:n] // a prefix of uniform characters is uniform
}

// zipEncLabel describes the protection of a zip ("AES-256", "ZipCrypto, weak").
func zipEncLabel(enc string) string {
	switch enc {
	case core.ZipEncAES256:
		return "AES-256"
	case core.ZipEncZipCrypto:
		return "ZipCrypto, weak"
	}
	return enc
}

// putOutput is the --json output of "files put": the batch, plus the zip
// password when it was generated (its only copy).
type putOutput struct {
	*core.UploadBatch
	ZipPassword string `json:"zip_password,omitempty"`
}

func newFilesPutCmd() *cobra.Command {
	var conflict, zip, zipEnc string
	var parallel int
	var parents, noProgress bool
	var zipPW *secretInput
	cmd := &cobra.Command{
		Use:     "put <local>... <remote-folder>",
		Aliases: []string{"upload"},
		Short:   "Upload files and folders",
		Long: `Upload local files and folders (recursively, keeping the structure and empty
folders) into a remote folder. As in the web UI, system files inside folders
(.DS_Store, Thumbs.db, desktop.ini, .localized) are left out and counted.
Large files are sent in 8 MiB parts, several in parallel, each verified with
SHA-256 and retried on network errors. An upload that is interrupted or fails
is cancelled on the server; running the command again starts over.

--conflict decides what happens when a name already exists: rename (default:
"name (1).ext"), replace (adds a new version), skip or fail.

--zip NAME bundles everything into one .zip file built on the server (it
needs the running server). To protect that .zip with a password add
--zip-password (asked twice), --zip-password-stdin, --zip-password-file FILE
or --zip-generate-password (a strong password of 22 letters and digits, or as
many as storage.zip_password_min requires, is printed once). The password
is sent to the server once, kept encrypted only until the .zip is built, and
then forgotten: nobody can recover it. It must be at least 12 characters
long (server setting storage.zip_password_min) and at most 99 (7-Zip cannot
open an AES-256 .zip with a longer one), and use only letters, digits,
spaces and the symbols of a US keyboard.

The default --zip-encryption aes256 opens in 7-Zip, WinRAR, Keka, The
Unarchiver and most phone apps, but not in Windows Explorer, macOS Archive
Utility or plain unzip. zipcrypto opens there too, but it is weak: anyone
with the file can usually recover its contents without the password. File
and folder names inside a protected .zip stay readable.

With a single local file, the remote path may also name the new file
("files put report.pdf "/My files/Docs/Q3 report.pdf""), or an existing
file together with --conflict: replace adds the local file as a new version
of it, whatever its local name.

` + filesPathNote,
		Example: `  fileparcel files put report.pdf "/My files/Documents"
  fileparcel files put ./photos ./videos /Team/Design/Assets --parallel 8
  fileparcel files put ./contracts "/My files/Out" --zip contracts.zip --zip-password
  fileparcel files put ./scans "/My files" --zip scans.zip --zip-generate-password
  printf '%s\n' "$ZIP_PASSWORD" | fileparcel files put ./tax "/My files" --zip tax-2026.zip --zip-password-stdin`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cp, err := parseConflict(conflict)
			if err != nil {
				return err
			}
			o := putOptions{Conflict: cp, Parallel: parallel, Progress: progressEnabled(cmd, noProgress)}
			f := cmd.Flags()
			if f.Changed("zip") {
				if o.ZipName, err = zipName(zip); err != nil {
					return err
				}
			}
			if err := checkZipPasswordFlags(f, zipPW, zipEnc); err != nil {
				return err
			}
			if parallel < 0 || parallel > maxParallel {
				return UsageError("--parallel must be between 1 and %d", maxParallel)
			}
			srcs, remote := args[:len(args)-1], args[len(args)-1]
			for _, s := range srcs {
				if _, err := filepathStat(s); err != nil {
					return err
				}
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				if o.ZipName != "" {
					if err := requireServer(c, "--zip"); err != nil {
						return err
					}
				}
				// The password is read before anything is scanned or sent.
				generated := ""
				if zipPW.Given() {
					o.ZipEncryption = cmp.Or(strings.ToLower(strings.TrimSpace(zipEnc)), core.ZipEncAES256)
					if o.ZipEncryption == core.ZipEncZipCrypto {
						Warnf(cmd, "ZipCrypto is weak: anyone with the .zip can usually recover its files without the password. "+
							"Use it only for Windows Explorer or macOS Archive Utility.")
					}
					if zipPW.Generate {
						generated = generateZipPassword(0)
						o.ZipPassword, o.GeneratedPassword = generated, true
						// A server whose storage.zip_password_min is above
						// the generated length asks for a longer one.
						o.regenerate = func(n int) string {
							generated = generateZipPassword(n)
							return generated
						}
					} else if o.ZipPassword, err = zipPW.Read(cmd, true); err != nil {
						return err
					}
					if !G.JSON && generated != "" {
						o.created = func(*core.UploadBatch) {
							fmt.Fprintf(cmd.OutOrStdout(), "Zip password: %s\n", generated)
							Infof(cmd, "shown only once; FileParcel does not keep it")
						}
					}
				}
				r := newResolver(c)
				dest, rename, err := putDestination(ctx, r, remote, srcs, putTarget{parents: parents,
					conflictGiven: f.Changed("conflict"), zip: o.ZipName != ""})
				if err != nil {
					return err
				}
				entries, err := scanLocal(srcs, rename, func(format string, a ...any) { Warnf(cmd, format, a...) })
				if err != nil {
					return err
				}
				if len(entries) == 0 {
					return errors.New("nothing to upload")
				}
				res, err := upload(ctx, cmd, c, dest.Node.ID, entries, &o)
				if err != nil {
					// In JSON mode the generated password is printed only with
					// the result; once the zip may still be built, the error
					// must carry it or it is lost.
					var late *lateUploadError
					if generated != "" && G.JSON && errors.As(err, &late) {
						return fmt.Errorf("%w (the .zip may still be created; its password is %s)", err, generated)
					}
					return err
				}
				// The zip is committed with the conflict policy: under rename
				// it may be stored as "NAME (1).zip", under skip not at all
				// (no result node, every file skipped). Report what the
				// server did, not what was asked for.
				zipSkipped := o.ZipName != "" && res.Batch.ResultNodeID == "" && res.Skipped > 0
				zipStored := o.ZipName
				if o.ZipName != "" && res.Batch.ResultNodeID != "" {
					if n, err := r.getNode(ctx, res.Batch.ResultNodeID); err == nil && n.Name != "" {
						zipStored = n.Name
					}
				}
				return Print(cmd, putOutput{UploadBatch: res.Batch, ZipPassword: generated}, func(w io.Writer) error {
					rate := ""
					if secs := res.Elapsed.Seconds(); secs > 0.2 && res.Bytes > 0 {
						rate = fmt.Sprintf(", %s/s", HumanBytes(int64(float64(res.Bytes)/secs)))
					}
					if zipSkipped {
						Warnf(cmd, "%s already exists in %s; the zip was not stored (--conflict skip)", o.ZipName, dest.Path)
						return nil
					}
					if o.ZipName != "" {
						protected := ""
						if o.ZipEncryption != "" {
							protected = " (password-protected, " + zipEncLabel(cmp.Or(res.Batch.ZipEncryption, o.ZipEncryption)) + ")"
						}
						Successf(cmd, "uploaded %s (%s) as %s%s into %s in %s%s", Plural(int64(res.Files), "file"),
							HumanBytes(res.Bytes), zipStored, protected, dest.Path, HumanDuration(res.Elapsed), rate)
						return nil
					}
					if rename != "" && res.Skipped == 0 {
						// The single-file rename form: name the file that was
						// created, not the folder it landed in — the target
						// did not exist and is easy to mistake for a folder.
						// Under --conflict rename onto an existing file the
						// server picks "name (1).ext": report that one.
						stored := rename
						if i := slices.IndexFunc(res.Batch.Files, func(st core.UploadFileState) bool { return st.NodeID != "" }); i >= 0 {
							if n, err := r.getNode(ctx, res.Batch.Files[i].NodeID); err == nil && n.Name != "" {
								stored = n.Name
							}
						}
						Successf(cmd, "uploaded %s (%s) as %s in %s%s", filepath.Base(srcs[0]), HumanBytes(res.Bytes),
							strings.TrimSuffix(dest.Path, "/")+"/"+stored, HumanDuration(res.Elapsed), rate)
						return nil
					}
					Successf(cmd, "uploaded %s (%s) to %s in %s%s", Plural(int64(res.Committed), "file"), HumanBytes(res.Bytes),
						dest.Path, HumanDuration(res.Elapsed), rate)
					if res.Skipped > 0 {
						Infof(cmd, "%s skipped (already present; --conflict skip)", Plural(int64(res.Skipped), "file"))
					}
					return nil
				})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&conflict, "conflict", string(core.ConflictRename), "when a name exists: rename, replace, skip or fail")
	f.StringVar(&zip, "zip", "", "bundle everything into one zip file with this name on the server")
	zipPW = addSecretFlags(cmd, "zip-password", ".zip password", secretOpts{Prompt: true,
		PromptUsage: "protect the .zip with a password (asked twice on the terminal)", Generate: true,
		GenerateName: "zip-generate-password", GenerateUsage: "generate a strong .zip password and print it once"})
	f.StringVar(&zipEnc, "zip-encryption", "", "encryption of the protected .zip: aes256 (default, strong) or zipcrypto "+
		"(weak; for Windows Explorer and macOS Archive Utility)")
	f.IntVar(&parallel, "parallel", 0, fmt.Sprintf("parts in flight (1-%d; default: the server's storage.upload_parallel)", maxParallel))
	f.BoolVarP(&parents, "parents", "p", false, "create the remote folder (and missing parents) if needed")
	f.BoolVar(&noProgress, "no-progress", false, "do not draw a progress bar")
	return cmd
}

// checkZipPasswordFlags applies the rules of the zip password flags (usage
// errors before connecting): they and --zip-encryption need --zip, and
// --zip-encryption needs a password flag and a known value.
func checkZipPasswordFlags(f *pflag.FlagSet, pw *secretInput, enc string) error {
	used := slices.IndexFunc(append(slices.Clone(zipPasswordFlags), "zip-encryption"), f.Changed)
	if used < 0 {
		return nil
	}
	if !f.Changed("zip") {
		name := append(slices.Clone(zipPasswordFlags), "zip-encryption")[used]
		return UsageError("--%s needs --zip NAME (a password protects the .zip that --zip builds)", name)
	}
	if !f.Changed("zip-encryption") {
		return nil
	}
	if !pw.Given() {
		return UsageError("--zip-encryption needs a password flag (--zip-password, --zip-password-stdin, " +
			"--zip-password-file or --zip-generate-password)")
	}
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case core.ZipEncAES256, core.ZipEncZipCrypto:
		return nil
	}
	return UsageError("--zip-encryption must be aes256 or zipcrypto (got %q)", enc)
}

// isRegularFile reports whether the local path p is a regular file (a
// symlink to one counts).
func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// filepathStat stats a local source with a friendly error.
func filepathStat(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if !fileExists(abs) {
		return "", fmt.Errorf("%s: no such file or directory", p)
	}
	return abs, nil
}

// putTarget are the options of "files put" that decide how its remote path
// is read: -p, whether --conflict was given, and --zip (the remote path is
// then always the folder the .zip goes into).
type putTarget struct{ parents, conflictGiven, zip bool }

// putDestination resolves the remote folder of an upload. A single local
// file may be uploaded under a new name (remote = parent/newname), also
// onto an existing file when --conflict says what to do with it
// (conflictGiven: replace adds a version, rename keeps both, skip or fail).
func putDestination(ctx context.Context, r *resolver, remote string, srcs []string, o putTarget) (*target, string, error) {
	parents := o.parents
	t, err := r.resolve(ctx, remote)
	if err == nil {
		if t.Node == nil || !t.Node.IsDir() {
			if t.Node != nil && len(srcs) == 1 && isRegularFile(srcs[0]) && !o.zip {
				if !o.conflictGiven {
					return nil, "", core.Errorf(core.ErrConflict, "%s already exists as a file; add --conflict replace to "+
						"upload %s as a new version of it (or --conflict rename to keep both)", t.Path, filepath.Base(srcs[0]))
				}
				parent, err := r.getNode(ctx, t.Node.ParentID)
				if err != nil {
					return nil, "", err
				}
				pp := path.Dir(t.Path)
				if !strings.HasPrefix(t.Path, "/") { // an id path: nod_…
					pp = r.displayPath(ctx, parent)
				}
				return &target{Node: parent, Path: pp}, t.Node.Name, nil
			}
			return nil, "", core.Invalid("path", fmt.Sprintf("%s is not a folder", t.Path))
		}
		return t, "", nil
	}
	if !errors.Is(err, core.ErrNotFound) {
		return nil, "", err
	}
	// A team folder comes from a group: neither mkdir nor -p makes one.
	if p, perr := parseRemotePath(remote); perr == nil && p.Root == rootTeam && p.Group != "" {
		if _, terr := r.teamRoot(ctx, p.Group); terr != nil {
			return nil, "", &hintError{terr, `team folders come from groups; list yours with "fileparcel files ls /Team"`}
		}
	}
	// Single file → new name in an existing parent. An explicit -p says the
	// remote path names a folder, so the rename shorthand steps aside.
	if len(srcs) == 1 && !parents {
		if abs, _ := filepath.Abs(srcs[0]); abs != "" {
			if fi, statErr := os.Stat(abs); statErr == nil && fi.Mode().IsRegular() && !strings.HasSuffix(remote, "/") {
				parent, name, existing, perr := r.resolveNew(ctx, remote)
				if perr == nil && existing == nil {
					if _, _, cerr := names.Clean(name); cerr != nil {
						return nil, "", core.Invalid("name", fmt.Sprintf("invalid file name %q: %v", name, cerr))
					}
					return parent, name, nil
				}
			}
		}
	}
	if !parents {
		return nil, "", &hintError{err, "create it first (\"fileparcel files mkdir\") or pass -p/--parents"}
	}
	t, _, err = r.mkdirAll(ctx, remote)
	return t, "", err
}

// ---------- get ----------

func newFilesGetCmd() *cobra.Command {
	var asZip, asTar, force, noResume, noProgress bool
	var version string
	cmd := &cobra.Command{
		Use:     "get <remote> [local]",
		Aliases: []string{"download"},
		Short:   "Download a file, or a folder as a zip or tar file",
		Long: `Download a remote file, or a folder as a zip (default) or tar archive.

Files are written to "<local>.fpart" first (a shortened name when that would
be too long) and renamed when complete; an interrupted download resumes where
it stopped when you run the same command again, unless the remote file changed
in between (then it starts over). The size and the server's content hash are
verified. "-" as local writes to standard output. Folders and --zip/--tar are
streamed (not resumable). --version ID downloads an older version of a file
(see "fileparcel files versions").

` + filesPathNote,
		Example: `  fileparcel files get "/My files/Documents/report.pdf"
  fileparcel files get "/My files/Documents/report.pdf" ~/Downloads/
  fileparcel files get /Team/Design/Assets --tar -o assets.tar
  fileparcel files get "/My files/notes.txt" - | less`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if asZip && asTar {
				return UsageError("use only one of --zip and --tar")
			}
			local := ""
			if len(args) == 2 {
				local = args[1]
			}
			if o := cmd.Flags().Lookup("output"); o != nil && o.Changed {
				if local != "" {
					return UsageError("give the local path either as an argument or with -o, not both")
				}
				local = o.Value.String()
			}
			if version != "" && !ids.Valid(ids.PrefixVersion, version) {
				return UsageError("--version must be a version id (ver_…; see \"fileparcel files versions\")")
			}
			o := getOptions{Force: force, Resume: !noResume, Version: version, Progress: progressEnabled(cmd, noProgress)}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := r.resolveNode(ctx, args[0])
				if err != nil {
					return err
				}
				var res *getResult
				switch {
				case t.Node.IsDir() || asZip || asTar:
					if version != "" {
						return UsageError("--version only works for single files")
					}
					format := core.ArchiveZip
					if asTar {
						format = core.ArchiveTar
					}
					res, err = downloadArchive(ctx, cmd, c, []core.Node{*t.Node}, t.Node.Name, format, local, o)
				default:
					res, err = downloadFile(ctx, cmd, c, t.Node, local, o)
				}
				if err != nil {
					return err
				}
				if res.Path == "-" {
					return nil
				}
				return Print(cmd, res, func(w io.Writer) error {
					msg := fmt.Sprintf("downloaded %s (%s) to %s", t.Path, HumanBytes(res.Bytes), res.Path)
					if res.Resumed > 0 {
						msg += fmt.Sprintf(" (resumed at %s)", HumanBytes(res.Resumed))
					}
					if res.Verified {
						msg += ", verified"
					}
					Successf(cmd, "%s", msg)
					return nil
				})
			})
		},
	}
	f := cmd.Flags()
	f.BoolVar(&asZip, "zip", false, "download as a zip archive (default for folders)")
	f.BoolVar(&asTar, "tar", false, "download as a tar archive (for macOS Archive Utility and tar users)")
	f.StringP("output", "o", "", "local file or directory (same as the second argument)")
	addForceFlag(cmd, &force, "overwrite an existing local file")
	f.BoolVar(&noResume, "no-resume", false, "start over instead of resuming a partial download")
	f.StringVar(&version, "version", "", "download an older version (ver_… from \"files versions\")")
	f.BoolVar(&noProgress, "no-progress", false, "do not draw a progress bar")
	return cmd
}

// ---------- mkdir ----------

func newFilesMkdirCmd() *cobra.Command {
	var parents bool
	cmd := &cobra.Command{
		Use:   "mkdir <path>...",
		Short: "Create folders",
		Long: `Create remote folders. With -p/--parents missing parent folders are created
too and existing folders are not an error.

` + filesPathNote,
		Example: `  fileparcel files mkdir "/My files/Projects"
  fileparcel files mkdir -p "/Team/Design/2026/Q3/Drafts"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				var out []core.Node
				for _, p := range args {
					if parents {
						t, created, err := r.mkdirAll(ctx, p)
						if err != nil {
							return err
						}
						out = append(out, *t.Node)
						for _, cp := range created {
							Successf(cmd, "created %s", cp)
						}
						continue
					}
					parent, name, existing, err := r.resolveNew(ctx, p)
					if err != nil {
						return err
					}
					if existing != nil {
						return core.Errorf(core.ErrConflict, "%s already exists", p)
					}
					var n core.Node
					if err := c.Do(ctx, http.MethodPost, api("/nodes/"+pathEsc(parent.Node.ID)+"/folders"), core.NameInput{Name: name}, &n); err != nil {
						return err
					}
					r.forget(parent.Node.ID)
					out = append(out, n)
					Successf(cmd, "created %s/%s", parent.Path, n.Name)
				}
				if G.JSON {
					return PrintJSON(cmd.OutOrStdout(), out)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVarP(&parents, "parents", "p", false, "create missing parents; no error if the folder exists")
	return cmd
}

// ---------- mv / cp ----------

func newFilesMoveCmd(copyMode bool) *cobra.Command {
	var conflict string
	use, short, verb := "mv", "Move or rename files and folders", "moved"
	aliases := []string{"move", "rename"}
	long := `Move remote files and folders into a folder, or rename a single one:

  files mv SRC... DEST-FOLDER     move into an existing folder
  files mv SRC NEW-PATH           move and/or rename (NEW-PATH does not exist;
                                  a change of case only, "a.txt" → "A.txt",
                                  is a rename too)

--conflict (default fail) decides what happens when a name already exists in
DEST-FOLDER: rename, replace, skip or fail. It does not apply to NEW-PATH,
which is free by definition.`
	example := `  fileparcel files mv "/My files/a.txt" "/My files/Archive"
  fileparcel files mv "/My files/draft.docx" "/My files/final.docx"
  fileparcel files mv "/My files/Photos" /Team/Design --conflict rename`
	defConflict := core.ConflictFail
	if copyMode {
		use, short, verb = "cp", "Copy files and folders", "copied"
		aliases = []string{"copy"}
		long = `Copy remote files and folders into a folder, or copy a single one under a new
name. Copies are instant (file contents are shared, not duplicated).

  files cp SRC... DEST-FOLDER     copy into an existing folder
  files cp SRC NEW-PATH           copy under a new name (NEW-PATH does not exist)

--conflict (default rename) decides what happens when a name already exists in
DEST-FOLDER: rename, replace (files only), skip or fail. It does not apply to
NEW-PATH.`
		example = `  fileparcel files cp "/My files/report.pdf" /Team/Design
  fileparcel files cp "/My files/template.docx" "/My files/Letters/2026-09.docx"
  fileparcel files cp "/My files/Photos" "/My files/Backup"
  fileparcel files cp "/My files/a.pdf" "/My files/b.pdf" /Team/Design --conflict skip`
		defConflict = core.ConflictRename
	}
	cmd := &cobra.Command{
		Use:     use + " <src>... <dest>",
		Aliases: aliases,
		Short:   short,
		Long:    long + "\n\n" + filesPathNote,
		Example: example,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cp, err := parseConflict(conflict)
			if err != nil {
				return err
			}
			srcArgs, destArg := args[:len(args)-1], args[len(args)-1]
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				var srcs []core.Node
				for _, s := range srcArgs {
					t, err := r.resolveNode(ctx, s)
					if err != nil {
						return err
					}
					if t.Node.ParentID == "" {
						return core.Invalid("path", fmt.Sprintf("%s is a root folder and cannot be %s", t.Path, verb))
					}
					srcs = append(srcs, *t.Node)
				}
				endpoint := "/nodes/move"
				if copyMode {
					endpoint = "/nodes/copy"
				}
				// Destination: an existing folder, or a new name for a single source.
				dest, derr := r.resolve(ctx, destArg)
				newName := ""
				var destFolder *target
				switch {
				case !copyMode && len(srcs) == 1 && derr == nil && dest.Node != nil && dest.Node.ID == srcs[0].ID:
					// The destination resolves to the source itself: names
					// match case- and normalization-insensitively, so
					// "report.pdf" → "Report.pdf" is a rename the server
					// accepts (a node never clashes with itself).
					parent, name, _, err := r.resolveNew(ctx, destArg)
					if err != nil {
						return core.Invalid("path", fmt.Sprintf("%s is the item being moved; give it a new name", dest.Path))
					}
					nfc, _, err := names.Clean(name)
					if err != nil {
						return core.Invalid("name", fmt.Sprintf("invalid name %q: %v", name, err))
					}
					if nfc == srcs[0].Name {
						return core.Errorf(core.ErrConflict, "%s is already named %q", dest.Path, nfc)
					}
					destFolder, newName = parent, name
				case derr == nil && dest.Node != nil && dest.Node.IsDir():
					destFolder = dest
				case derr == nil && dest.Node == nil:
					return core.Invalid("path", fmt.Sprintf("%s is not a folder you can put files in", dest.Path))
				case derr == nil:
					return core.Errorf(core.ErrConflict, "%s already exists (to replace a file's content upload a new version with \"files put --conflict replace\")", dest.Path)
				case errors.Is(derr, core.ErrNotFound) && len(srcs) == 1:
					parent, name, _, err := r.resolveNew(ctx, destArg)
					if err != nil {
						return err
					}
					if _, _, err := names.Clean(name); err != nil {
						return core.Invalid("name", fmt.Sprintf("invalid name %q: %v", name, err))
					}
					destFolder, newName = parent, name
				default:
					return derr
				}
				var result []core.Node
				if newName != "" && !copyMode && destFolder.Node.ID == srcs[0].ParentID {
					// Plain rename in place.
					var n core.Node
					if err := c.Do(ctx, http.MethodPatch, api("/nodes/"+pathEsc(srcs[0].ID)), core.NameInput{Name: newName}, &n); err != nil {
						return err
					}
					result = []core.Node{n}
				} else {
					idList := make([]string, len(srcs))
					for i, n := range srcs {
						idList[i] = n.ID
					}
					policy := cp
					if newName != "" {
						// NEW-PATH is free, and the item is renamed to it below.
						// The server checks --conflict against the source's
						// current name, which must not trash, overwrite or skip
						// an unrelated item of that name (or, for cp into the
						// same folder, hand back the source itself): land it
						// under a free name first.
						policy = core.ConflictRename
					}
					moved, err := doList[core.Node](ctx, c, http.MethodPost, api(endpoint), core.MoveInput{IDs: idList, Dest: destFolder.Node.ID, Conflict: policy})
					if err != nil {
						return err
					}
					result = moved
					if newName != "" && len(result) == 1 && result[0].Name != newName {
						var n core.Node
						if err := c.Do(ctx, http.MethodPatch, api("/nodes/"+pathEsc(result[0].ID)), core.NameInput{Name: newName}, &n); err != nil {
							return fmt.Errorf("%s to %s but renaming to %q failed: %w", verb, destFolder.Path, newName, err)
						}
						result[0] = n
					}
				}
				return Print(cmd, result, func(w io.Writer) error {
					if len(result) == 0 {
						Infof(cmd, "nothing was %s (skipped because of name conflicts)", verb)
						return nil
					}
					for _, n := range result {
						Successf(cmd, "%s → %s/%s", verb, destFolder.Path, n.Name)
					}
					return nil
				})
			})
		},
	}
	cmd.Flags().StringVar(&conflict, "conflict", string(defConflict), "when a name exists in the destination: rename, replace, skip or fail")
	return cmd
}

// ---------- rm ----------

func newFilesRmCmd() *cobra.Command {
	var purge bool
	cmd := &cobra.Command{
		Use:     "rm <path>...",
		Aliases: []string{"delete", "trash-put"},
		Short:   "Move files and folders to the trash",
		Long: `Move remote files and folders to the trash; "fileparcel files restore" brings
them back until the trash retention (storage.trash_days) ends. --purge deletes
them for good right away (it asks first; -y skips the question).

` + filesPathNote,
		Example: `  fileparcel files rm "/My files/old.zip"
  fileparcel files rm "/My files/tmp" "/My files/scratch.txt"
  fileparcel files rm "/My files/secret.pdf" --purge -y`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				var nodes []core.Node
				var paths []string
				for _, p := range args {
					t, err := r.resolveNode(ctx, p)
					if err != nil {
						return err
					}
					if t.Node.ParentID == "" {
						return core.Invalid("path", fmt.Sprintf("%s is a root folder and cannot be deleted", t.Path))
					}
					nodes = append(nodes, *t.Node)
					paths = append(paths, t.Path)
				}
				if purge {
					if err := confirmOrAbort(cmd, fmt.Sprintf("Permanently delete %s? This cannot be undone.", strings.Join(paths, ", "))); err != nil {
						return err
					}
				}
				idList := make([]string, len(nodes))
				for i, n := range nodes {
					idList[i] = n.ID
				}
				if err := c.Do(ctx, http.MethodPost, api("/nodes/trash"), core.NodeIDsInput{IDs: idList}, nil); err != nil {
					return err
				}
				if purge {
					if err := c.Do(ctx, http.MethodPost, api("/trash/purge"), core.NodeIDsInput{IDs: idList}, nil); err != nil {
						return fmt.Errorf("moved to the trash, but purging failed: %w", err)
					}
				}
				verb := "moved to the trash"
				if purge {
					verb = "deleted permanently"
				}
				return done(cmd, map[string]any{"ids": idList, "purged": purge}, "%s %s", strings.Join(paths, ", "), verb)
			})
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "delete permanently instead of moving to the trash")
	return cmd
}

// ---------- trash / restore ----------

// listTrash returns every trashed item (trash roots) of the acting user.
// setDisplayPaths rewrites every node's Path to the addressable path the
// tables print ("/My files/…", "/Team/<group>/…"). The API returns a path
// relative to the node's space, which is ambiguous between spaces and cannot
// be fed back into the other "files" commands — and that field is what --json
// hands to a script. Every path is computed before the first assignment,
// because displayPath itself reads Path.
func setDisplayPaths(ctx context.Context, r *resolver, nodes []core.Node) {
	paths := make([]string, len(nodes))
	for i := range nodes {
		paths[i] = r.displayPath(ctx, &nodes[i])
	}
	for i := range nodes {
		nodes[i].Path = paths[i]
	}
}

func listTrash(ctx context.Context, c *Client) ([]core.Node, error) {
	return listAll[core.Node](ctx, c, api("/trash", "limit", limitParam(0)), 0)
}

// matchTrash finds a trashed item by id, full path ("/My files/Docs/a.txt"),
// space-relative path or unique name.
func matchTrash(ctx context.Context, r *resolver, items []core.Node, ref string) (*core.Node, error) {
	ref = strings.TrimSpace(ref)
	if ids.Valid(ids.PrefixNode, ref) {
		for i := range items {
			if items[i].ID == ref {
				return &items[i], nil
			}
		}
		return nil, core.Errorf(core.ErrNotFound, "%s is not in the trash", ref)
	}
	full := ref
	if p, err := parseRemotePath(ref); err == nil && p.Root != rootID {
		full = p.String()
	}
	key := names.Key(full)
	var byName []*core.Node
	for i := range items {
		it := &items[i]
		if names.Key(r.displayPath(ctx, it)) == key {
			return it, nil
		}
		if names.Key(it.Name) == names.Key(ref) {
			byName = append(byName, it)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return nil, core.Errorf(core.ErrNotFound, "%q is not in the trash (see \"fileparcel files trash\")", ref)
	}
	var cands []string
	for _, n := range byName {
		cands = append(cands, r.displayPath(ctx, n)+" ("+n.ID+")")
	}
	return nil, core.Errorf(core.ErrConflict, "%q matches several trashed items; use the full path or the id: %s", ref, strings.Join(cands, "; "))
}

func newFilesRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <path|id|name>...",
		Short: "Bring files and folders back from the trash",
		Long: `Restore trashed files and folders to their original location. Items are
matched by id, by their original path ("/My files/Docs/report.pdf") or by name
when unambiguous. An item whose folder is in the trash too goes to the top of
its space ("/My files" or the team folder; restore the folder first to keep
it in place), and a name that is taken there gets " (1)". "fileparcel files
trash" lists what is in the trash.`,
		Example: `  fileparcel files restore "/My files/Docs/report.pdf"
  fileparcel files restore report.pdf
  fileparcel files restore nod_01j9zq3x4k6m8p0r2t4v6x8z0b`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				items, err := listTrash(ctx, c)
				if err != nil {
					return err
				}
				var idList []string
				for _, a := range args {
					n, err := matchTrash(ctx, r, items, a)
					if err != nil {
						return err
					}
					if !slices.Contains(idList, n.ID) {
						idList = append(idList, n.ID)
					}
				}
				restored, err := doList[core.Node](ctx, c, http.MethodPost, api("/trash/restore"), core.NodeIDsInput{IDs: idList})
				if err != nil {
					return err
				}
				return Print(cmd, restored, func(w io.Writer) error {
					if len(restored) == 0 {
						Successf(cmd, "restored %s", Plural(int64(len(idList)), "item"))
						return nil
					}
					for i := range restored {
						Successf(cmd, "restored %s", r.displayPath(ctx, &restored[i]))
					}
					return nil
				})
			})
		},
	}
}

func newFilesTrashCmd() *cobra.Command {
	var empty bool
	cmd := &cobra.Command{
		Use:   "trash",
		Short: "List or empty the trash",
		Long: `List the items in the trash (original path, size, deletion time) or, with
--empty, delete everything in it for good that you may delete: the trash of
your own files and of the team folders you manage (it asks first; -y skips the
question). What stays needs its owner or a manager of the group. Items are
deleted automatically after storage.trash_days.`,
		Example: `  fileparcel files trash
  fileparcel files trash --json
  fileparcel files trash --empty -y`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				if empty {
					if err := confirmOrAbort(cmd, "Permanently delete everything in the trash that you may delete? This cannot be undone."); err != nil {
						return err
					}
					if err := c.Do(ctx, http.MethodDelete, api("/trash"), nil, nil); err != nil {
						return err
					}
					// The server purges only what the user may delete
					// permanently; the trash still lists the rest (items of
					// team folders they do not manage, or trashed in folders
					// shared with them).
					if left, err := listTrash(ctx, c); err == nil && len(left) > 0 {
						return done(cmd, map[string]any{"ok": true, "remaining": len(left)},
							"emptied what you may delete; %s left in the trash (deleting them needs the space owner or a group manager)",
							Plural(int64(len(left)), "item"))
					}
					return done(cmd, nil, "emptied the trash")
				}
				r := newResolver(c)
				items, err := listTrash(ctx, c)
				if err != nil {
					return err
				}
				setDisplayPaths(ctx, r, items)
				return Print(cmd, items, func(w io.Writer) error {
					if len(items) == 0 {
						Infof(cmd, "the trash is empty")
						return nil
					}
					t := NewTable("PATH", "SIZE", "DELETED", "ID")
					var total int64
					for i := range items {
						n := &items[i]
						p := n.Path
						if n.IsDir() {
							p += "/"
						}
						total += n.Size
						t.Add(p, nodeSize(n), n.TrashedAt, n.ID)
					}
					if err := t.Render(w); err != nil {
						return err
					}
					_, err := fmt.Fprintf(w, "\n%s\n", Plural(int64(len(items)), "item"))
					return err
				})
			})
		},
	}
	cmd.Flags().BoolVar(&empty, "empty", false, "permanently delete everything in the trash that you may delete")
	return cmd
}

// ---------- info ----------

// nodeInfo is the --json output of files info.
type nodeInfo struct {
	Path  string            `json:"path"`
	Node  *core.Node        `json:"node"`
	Stats *core.FolderStats `json:"stats,omitempty"`
}

func newFilesInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "info <path>",
		Aliases: []string{"stat", "show"},
		Short:   "Show details of a file or folder",
		Long: `Show the details of a remote file or folder: id, size, type, content hash,
times, your permission and, for folders, the number of files, folders and
bytes in it (all levels).

` + filesPathNote,
		Example: `  fileparcel files info "/My files/report.pdf"
  fileparcel files info /Team/Design --json
  fileparcel files info nod_01j9zq3x4k6m8p0r2t4v6x8z0b`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := r.resolveNode(ctx, args[0])
				if err != nil {
					return err
				}
				n := t.Node
				info := nodeInfo{Path: t.Path, Node: n}
				if ids.Valid(ids.PrefixNode, strings.SplitN(args[0], "/", 2)[0]) {
					info.Path = r.displayPath(ctx, n)
				}
				if n.IsDir() {
					var st core.FolderStats
					if err := c.Do(ctx, http.MethodGet, api("/nodes/"+pathEsc(n.ID)+"/stats"), nil, &st); err == nil {
						info.Stats = &st
					}
				}
				return Print(cmd, info, func(w io.Writer) error {
					kv := NewKV()
					kv.Add("Path", info.Path)
					kv.Add("Name", n.Name)
					kv.Add("Kind", n.Kind)
					kv.Add("ID", n.ID)
					if n.IsDir() {
						if info.Stats != nil {
							kv.Add("Contents", fmt.Sprintf("%s, %s, %s", Plural(info.Stats.Folders, "folder"),
								Plural(info.Stats.Files, "file"), HumanBytes(info.Stats.Bytes)))
						}
					} else {
						kv.Add("Size", fmt.Sprintf("%s (%d bytes)", HumanBytes(n.Size), n.Size))
						kv.Add("Type", n.MIME)
						kv.Add("Content hash", n.ContentHash)
						kv.Add("Version", n.VersionID)
						if n.ZipEncryption != "" {
							kv.Add("Protection", "password ("+zipEncLabel(n.ZipEncryption)+")")
						}
						kv.Add("Client modified", n.ClientMtime)
					}
					kv.Add("Created", n.CreatedAt)
					kv.Add("Modified", n.UpdatedAt)
					kv.Add("Permission", n.Perm.String())
					kv.Add("Starred", n.Starred)
					kv.Add("Space", n.SpaceID)
					return kv.Render(w)
				})
			})
		},
	}
}

// ---------- search ----------

func newFilesSearchCmd() *cobra.Command {
	var space, kind string
	var limit int
	cmd := &cobra.Command{
		Use:     "search <query>",
		Aliases: []string{"find"},
		Short:   "Find files and folders by name",
		Long: `Search the names of all files and folders you can access (substring match,
case-insensitive). --in limits the search to one space ("/My files" or
"/Team/<group>"); --kind to files or folders.`,
		Example: `  fileparcel files search invoice
  fileparcel files search "2026 Q3" --in /Team/Finance --kind file
  fileparcel files search .pdf --limit 20 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch kind {
			case "", core.KindFile, core.KindFolder:
			default:
				return UsageError("invalid --kind %q (file or folder)", kind)
			}
			if strings.TrimSpace(args[0]) == "" {
				return UsageError("the search query must not be empty")
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				spaceID := ""
				if space != "" {
					t, err := r.resolveNode(ctx, space)
					if err != nil {
						return err
					}
					// The server narrows a search to a whole space only; a
					// subfolder would silently search its entire space.
					if t.Node.ParentID != "" {
						return UsageError("--in takes a space (%q or %q), not a folder or file: %s", "/"+myFilesName, "/"+teamName+"/<group>", t.Path)
					}
					spaceID = t.Node.SpaceID
				}
				nodes, err := listAll[core.Node](ctx, c, api("/search", "q", args[0], "space", spaceID, "kind", kind, "limit", limitParam(limit)), limit)
				if err != nil {
					return err
				}
				setDisplayPaths(ctx, r, nodes)
				return Print(cmd, nodes, func(w io.Writer) error {
					if len(nodes) == 0 {
						Infof(cmd, "no matches for %q", args[0])
						return nil
					}
					t := NewTable("PATH", "SIZE", "MODIFIED", "ID")
					for i := range nodes {
						n := &nodes[i]
						p := n.Path
						if n.IsDir() {
							p += "/"
						}
						t.Add(p, nodeSize(n), n.UpdatedAt, n.ID)
					}
					return t.Render(w)
				})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&space, "in", "", `search only this space ("/My files" or "/Team/<group>")`)
	f.StringVar(&kind, "kind", "", "only files or only folders (file, folder)")
	f.IntVar(&limit, "limit", 100, "maximum number of results (0 = all)")
	return cmd
}

// ---------- versions ----------

func newFilesVersionsCmd() *cobra.Command {
	var restore string
	cmd := &cobra.Command{
		Use:   "versions <path>",
		Short: "List or restore older versions of a file",
		Long: `List the stored versions of a file (uploads with --conflict replace create
new versions; storage.versions_keep limits how many are kept). --restore makes
an older version the current one (the current content becomes a version too).
Download an old version with "fileparcel files get PATH --version ID".

` + filesPathNote,
		Example: `  fileparcel files versions "/My files/report.pdf"
  fileparcel files versions "/My files/report.pdf" --restore ver_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel files versions "/My files/report.pdf" --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if restore != "" && !ids.Valid(ids.PrefixVersion, restore) {
				return UsageError("--restore needs a version id (ver_…)")
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				r := newResolver(c)
				t, err := r.resolveNode(ctx, args[0])
				if err != nil {
					return err
				}
				if t.Node.IsDir() {
					return core.Invalid("path", fmt.Sprintf("%s is a folder; only files have versions", t.Path))
				}
				if restore != "" {
					var n core.Node
					if err := c.Do(ctx, http.MethodPost, api("/nodes/"+pathEsc(t.Node.ID)+"/versions/"+pathEsc(restore)+"/restore"), nil, &n); err != nil {
						return err
					}
					if n.ID == "" {
						n = *t.Node
					}
					return done(cmd, &n, "restored version %s of %s", restore, t.Path)
				}
				vs, err := doList[core.FileVersion](ctx, c, http.MethodGet, api("/nodes/"+pathEsc(t.Node.ID)+"/versions"), nil)
				if err != nil {
					return err
				}
				return Print(cmd, vs, func(w io.Writer) error {
					tb := NewTable("VERSION", "CREATED", "SIZE", "BY", "CURRENT")
					for _, v := range vs {
						by := v.CreatedByName
						if by == "" {
							by = v.CreatedBy
						}
						cur := ""
						if v.Current || v.ID == t.Node.VersionID {
							cur = "*"
						}
						tb.Add(v.ID, v.CreatedAt, HumanBytes(v.Size), by, cur)
					}
					return tb.Render(w)
				})
			})
		},
	}
	cmd.Flags().StringVar(&restore, "restore", "", "make this version (ver_…) the current one")
	return cmd
}
