package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() {
	Register(newShareCmd)
	Register(newRequestCmd)
}

func newShareCmd() *cobra.Command {
	cmd := groupCmd("share", "Share files and folders with a public link",
		`A share link lets anyone who has it open a file or folder, without an account.
Protect it with a password, let it expire or limit the number of downloads;
turn it off for a while ("disable") or delete it for good. The link is printed,
and with --qr also shown as a QR code for phones.

To give specific people or groups access instead of a public link, see
"fileparcel access".

`+filesPathNote,
		`  fileparcel share create "/My files/Slides.pdf" --expires 3d --qr
  fileparcel share list
  fileparcel share disable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel share delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b`, "shares", "link", "links")
	create := newShareCreateCmd()
	cmd.AddCommand(newShareListCmd(core.ShareLink), create, newShareShowCmd(core.ShareLink),
		newShareEditCmd(), newShareDeleteCmd(core.ShareLink), newShareLogCmd(core.ShareLink),
		newShareToggleCmd(core.ShareLink, true), newShareToggleCmd(core.ShareLink, false))
	setListHint(cmd, "fileparcel share list --inactive")
	setListHint(create, "fileparcel files ls {parent}") // what is missing is the file or folder
	return cmd
}

func newRequestCmd() *cobra.Command {
	cmd := groupCmd("request", "Collect files from others with an upload link",
		`A file request is a public link through which anyone can upload files into
one of your folders, without seeing its contents. Limit the size per file and
the total, require an uploader name, and close the request when done.

`+filesPathNote,
		`  fileparcel request create "/My files/Incoming" --title "Send me your photos" --max-size 2G --qr
  fileparcel request list
  fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b`, "requests")
	create := newRequestCreateCmd()
	cmd.AddCommand(create, newShareListCmd(core.ShareRequest), newShareShowCmd(core.ShareRequest),
		newRequestCloseCmd(), newShareToggleCmd(core.ShareRequest, false), newShareDeleteCmd(core.ShareRequest),
		newShareLogCmd(core.ShareRequest))
	setListHint(cmd, "fileparcel request list --inactive")
	setListHint(create, "fileparcel files ls {parent}") // what is missing is the folder
	return cmd
}

// ---------- helpers ----------

// shareNoun names the kind in messages.
func shareNoun(kind string) string {
	if kind == core.ShareRequest {
		return "file request"
	}
	return "share link"
}

// addSharePasswordFlags defines --password (asked on the terminal),
// --password-stdin and --password-file of a share link or file request.
func addSharePasswordFlags(cmd *cobra.Command) *secretInput {
	return addSecretFlags(cmd, "password", "link password", secretOpts{
		Prompt: true, PromptUsage: "protect the link with a password (asked twice on the terminal)"})
}

// readSharePassword reads the link password of the password flags; ok is
// false when none was given.
func readSharePassword(cmd *cobra.Command, pw *secretInput) (string, bool, error) {
	if !pw.Given() {
		return "", false, nil
	}
	v, err := pw.Read(cmd, true)
	return v, err == nil, err
}

// printShareCreated prints the link of a new or shown share.
func printShare(ctx context.Context, cmd *cobra.Command, c *Client, s *core.Share, qr bool, created bool) error {
	s.URL = absoluteURL(ctx, c, s.URL)
	return Print(cmd, s, func(w io.Writer) error {
		if created {
			Successf(cmd, "created %s %s for %s (%s)", shareNoun(s.Kind), s.ID, Dash(s.NodeName), shareLimits(s))
		} else if err := renderShare(w, s); err != nil {
			return err
		}
		if s.URL != "" {
			if !created {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, s.URL)
			if qr {
				return PrintQR(w, s.URL)
			}
		} else if created {
			Warnf(cmd, "the server did not return the link URL; see \"fileparcel share show %s\"", s.ID)
		}
		return nil
	})
}

// shareLimits summarises expiry/password/limits in one line.
func shareLimits(s *core.Share) string {
	var parts []string
	if s.ExpiresAt != nil {
		parts = append(parts, "expires "+HumanTime(*s.ExpiresAt))
	} else {
		parts = append(parts, "no expiry")
	}
	if s.HasPassword {
		parts = append(parts, "password")
	}
	if s.MaxDownloads != nil {
		parts = append(parts, fmt.Sprintf("max %d downloads", *s.MaxDownloads))
	}
	if s.Kind == core.ShareRequest {
		if s.UploadMaxFileBytes != nil {
			parts = append(parts, "max "+HumanBytes(*s.UploadMaxFileBytes)+" per file")
		}
		if s.UploadQuotaBytes != nil {
			parts = append(parts, "quota "+HumanBytes(*s.UploadQuotaBytes))
		}
	}
	return strings.Join(parts, ", ")
}

// shareStatusText is the Status column: an active link whose item is in the
// trash, or whose owner is disabled, answers "not found", so say so. A file
// request that is turned off is "closed", as "request close" and the web UI
// call it (the API says disabled for both kinds).
func shareStatusText(s *core.Share) string {
	status := s.Status
	if s.Kind == core.ShareRequest && status == core.ShareDisabled {
		status = "closed"
	}
	if s.Unavailable {
		return status + " (unavailable)"
	}
	return status
}

func renderShare(w io.Writer, s *core.Share) error {
	kv := NewKV()
	kv.Add("ID", s.ID)
	kv.Add("Kind", s.Kind)
	kv.Add("Status", shareStatusText(s))
	kv.Add("Item", fmt.Sprintf("%s (%s %s)", Dash(s.NodeName), Dash(s.NodeKind), s.NodeID))
	kv.Add("Title", s.Title)
	kv.Add("Message", s.Message)
	kv.Add("Password", s.HasPassword)
	kv.Add("Expires", expiryText(s.ExpiresAt))
	if s.Kind == core.ShareLink {
		kv.Add("Download", s.AllowDownload)
		kv.Add("Preview", s.AllowPreview)
		kv.Add("Uploads", s.AllowUpload)
		kv.Add("Downloads", downloadsText(s))
	} else {
		kv.Add("Uploader name required", s.RequireUploaderName)
		kv.Add("Max file size", limitText(s.UploadMaxFileBytes))
		kv.Add("Upload quota", limitText(s.UploadQuotaBytes))
		kv.Add("Uploaded", HumanBytes(s.UploadUsedBytes))
	}
	kv.Add("Notify on upload", s.NotifyOwner)
	kv.Add("Created", s.CreatedAt)
	kv.Add("Created by", s.CreatedByName)
	kv.Add("Last access", s.LastAccessAt)
	return kv.Render(w)
}

func expiryText(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return HumanTime(*t) + " (" + Ago(*t) + ")"
}

func limitText(n *int64) string {
	if n == nil {
		return "unlimited"
	}
	return HumanBytes(*n)
}

func downloadsText(s *core.Share) string {
	if s.MaxDownloads == nil {
		return strconv.FormatInt(s.DownloadCount, 10)
	}
	return fmt.Sprintf("%d/%d", s.DownloadCount, *s.MaxDownloads)
}

// getShare fetches a share and checks its kind.
func getShare(ctx context.Context, c *Client, id, kind string) (*core.Share, error) {
	id = strings.TrimSpace(id)
	var s core.Share
	if err := c.Do(ctx, http.MethodGet, api("/shares/"+pathEsc(id)), nil, &s); err != nil {
		return nil, err
	}
	if kind != "" && s.Kind != "" && s.Kind != kind {
		other := "share"
		if s.Kind == core.ShareRequest {
			other = "request"
		}
		return nil, core.Invalid("id", fmt.Sprintf("%s is a %s; use \"fileparcel %s …\"", id, shareNoun(s.Kind), other))
	}
	return &s, nil
}

// ---------- list / show / revoke / log (links and requests) ----------

func newShareListCmd(kind string) *cobra.Command {
	var allUsers, inactive bool
	var user string
	noun := shareNoun(kind) + "s"
	group := "share"
	long := `List your share links with status, limits and link. --inactive adds expired,
disabled and used-up ones. Admins list every user's share links with
--all-users (and --user USER for one user); another user's link is hidden
there unless auth.admin_can_access_files is on, and the URL column is then
left out.`
	if kind == core.ShareRequest {
		group = "request"
		long = `List your file requests with status, limits and link. --inactive adds expired
and closed ones. Admins list every user's file requests with --all-users (and
--user USER for one user); another user's link is hidden there unless
auth.admin_can_access_files is on, and the URL column is then left out.`
	}
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List your " + noun,
		Long:    long,
		Example: fmt.Sprintf(`  fileparcel %[1]s list
  fileparcel %[1]s list --inactive --json
  fileparcel %[1]s list --all-users --user alice`, group),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			all := allUsers
			if user != "" && !all {
				return UsageError("--user needs --all-users")
			}
			run := withUserClient
			if all {
				run = WithClient
			}
			return run(cmd, func(ctx context.Context, c *Client) error {
				status := "active"
				if inactive {
					status = ""
				}
				path := api("/shares", "kind", kind, "status", status, "limit", limitParam(0))
				if all {
					uid := ""
					if user != "" {
						u, err := resolveUser(ctx, c, user)
						if err != nil {
							return err
						}
						uid = u.ID
					}
					path = api("/admin/shares", "kind", kind, "status", status, "user_id", uid, "limit", limitParam(0))
				}
				shares, err := listAll[core.Share](ctx, c, path, 0)
				if err != nil {
					return err
				}
				kept := shares[:0]
				for _, s := range shares {
					if (s.Kind == "" || s.Kind == kind) && (inactive || s.Status == "" || s.Status == core.ShareActive) {
						kept = append(kept, s)
					}
				}
				shares = kept
				abs := newURLResolver(c)
				for i := range shares {
					shares[i].URL = abs.abs(ctx, shares[i].URL)
				}
				return Print(cmd, shares, func(w io.Writer) error {
					if len(shares) == 0 {
						Infof(cmd, "no %s", noun)
						return nil
					}
					// The server hides the link of another user's share
					// unless auth.admin_can_access_files is on, so --all-users can
					// leave the whole column empty: drop it instead of
					// printing a column of dashes.
					urls := slices.ContainsFunc(shares, func(s core.Share) bool { return s.URL != "" })
					headers := []string{"ID", "ITEM", "STATUS", "DOWNLOADS", "PASSWORD", "EXPIRES"}
					if kind == core.ShareRequest {
						headers = []string{"ID", "FOLDER", "TITLE", "STATUS", "UPLOADED", "EXPIRES"}
					}
					if urls {
						headers = append(headers, "URL")
					}
					if all {
						headers = append(headers, "OWNER")
					}
					t := NewTable(headers...)
					for i := range shares {
						s := &shares[i]
						exp := "never"
						if s.ExpiresAt != nil {
							exp = HumanTime(*s.ExpiresAt)
						}
						var row []any
						if kind == core.ShareRequest {
							row = []any{s.ID, s.NodeName, Truncate(s.Title, 30), shareStatusText(s), HumanBytes(s.UploadUsedBytes), exp}
						} else {
							row = []any{s.ID, s.NodeName, shareStatusText(s), downloadsText(s), s.HasPassword, exp}
						}
						if urls {
							row = append(row, s.URL)
						}
						if all {
							row = append(row, s.CreatedByName)
						}
						t.Add(row...)
					}
					if !urls && all {
						Infof(cmd, "links are hidden for other users' %s (auth.admin_can_access_files is off)", noun)
					}
					return t.Render(w)
				})
			})
		},
	}
	inactiveUsage := "include expired, disabled and exhausted " + noun
	if kind == core.ShareRequest {
		inactiveUsage = "include expired and closed " + noun
	}
	addInactiveFlag(cmd, &inactive, inactiveUsage)
	addAllUsersFlags(cmd, &allUsers, &user, noun)
	return cmd
}

func newShareShowCmd(kind string) *cobra.Command {
	var qr bool
	group := "share"
	if kind == core.ShareRequest {
		group = "request"
	}
	short := "Show a share link with its settings and counters"
	if kind == core.ShareRequest {
		short = "Show a file request and its link"
	}
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: short,
		Long: "Show the settings, counters and link of a " + shareNoun(kind) + `; --qr adds a QR code of
the link for phones.`,
		Example: fmt.Sprintf(`  fileparcel %[1]s show shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel %[1]s show shr_01j9zq3x4k6m8p0r2t4v6x8z0b --qr`, group),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getShare(ctx, c, args[0], kind)
				if err != nil {
					return err
				}
				return printShare(ctx, cmd, c, s, qr, false)
			})
		},
	}
	cmd.Flags().BoolVar(&qr, "qr", false, "print the link as a QR code")
	return cmd
}

func newShareDeleteCmd(kind string) *cobra.Command {
	group := "share"
	if kind == core.ShareRequest {
		group = "request"
	}
	return &cobra.Command{
		Use:     "delete <id>",
		Aliases: []string{"revoke", "rm"},
		Short:   "Delete a " + shareNoun(kind) + " for good",
		Long:    deleteShareLong(kind),
		Example: fmt.Sprintf(`  fileparcel %[1]s delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel %[1]s delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json`, group),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getShare(ctx, c, args[0], kind)
				if err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodDelete, api("/shares/"+pathEsc(s.ID)), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"revoked": s.ID}, "deleted %s %s (%s)", shareNoun(kind), s.ID, Dash(s.NodeName))
			})
		},
	}
}

// deleteShareLong is the Long of "share delete" and "request delete".
func deleteShareLong(kind string) string {
	if kind == core.ShareRequest {
		return `Delete a file request for good: its link stops working at once and cannot be
opened again. Files uploaded through it stay in the folder. To stop uploads
for a while, use "fileparcel request close".`
	}
	return `Delete a share link for good: it stops working at once and cannot be turned on
again. The shared files are not touched. To turn a link off for a while, use
"fileparcel share disable".`
}

func newShareLogCmd(kind string) *cobra.Command {
	var limit int
	group := "share"
	if kind == core.ShareRequest {
		group = "request"
	}
	short := "Show who opened or downloaded through a link"
	if kind == core.ShareRequest {
		short = "Show who uploaded through a file request"
	}
	cmd := &cobra.Command{
		Use:   "log <id>",
		Short: short,
		Long: "Show who used a " + shareNoun(kind) + `: views, downloads, uploads and password attempts
with time, IP address and browser.`,
		Example: fmt.Sprintf(`  fileparcel %[1]s log shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel %[1]s log shr_01j9zq3x4k6m8p0r2t4v6x8z0b --limit 20 --json`, group),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getShare(ctx, c, args[0], kind)
				if err != nil {
					return err
				}
				rows, err := listAll[core.ShareAccess](ctx, c, api("/shares/"+pathEsc(s.ID)+"/log", "limit", limitParam(limit)), limit)
				if err != nil {
					return err
				}
				return Print(cmd, rows, func(w io.Writer) error {
					if len(rows) == 0 {
						Infof(cmd, "no access recorded yet")
						return nil
					}
					t := NewTable("TIME", "ACTION", "IP", "BYTES", "UPLOADER", "USER AGENT")
					for _, a := range rows {
						b := ""
						if a.Bytes > 0 {
							b = HumanBytes(a.Bytes)
						}
						t.Add(a.At, a.Action, a.IP, b, a.Uploader, Truncate(a.UserAgent, 40))
					}
					return t.Render(w)
				})
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of entries (0 = all)")
	return cmd
}

// ---------- share create / edit ----------

func newShareCreateCmd() *cobra.Command {
	var in core.ShareInput
	var expires string
	var maxDownloads int64
	var noDownload, noPreview, qr bool
	var pw *secretInput
	cmd := &cobra.Command{
		Use:   "create <path>",
		Short: "Create a share link for a file or folder",
		Long: `Create a public link to a remote file or folder and print it.

--expires takes a duration (12h, 7d, 2w), a date (2026-12-31) or "never"
(default: sharing.default_expiry_days). --password asks for a password on the
terminal; scripts use --password-stdin or --password-file. --upload also lets
visitors upload into a shared folder.

` + filesPathNote,
		Example: `  fileparcel share create "/My files/Slides.pdf"
  fileparcel share create "/My files/Holiday" --expires 14d --qr
  echo 's3cret-pass' | fileparcel share create /Team/Design/Brand --password-stdin --max-downloads 10
  fileparcel share create "/My files/Video.mp4" --no-download --title "Preview only"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in.Kind = core.ShareLink
			exp, never, err := parseExpiry(expires, time.Now(), true)
			if err != nil {
				return err
			}
			in.ExpiresAt, in.NoExpiry = exp, never
			if cmd.Flags().Changed("max-downloads") {
				if maxDownloads < 1 {
					return UsageError("--max-downloads must be at least 1")
				}
				in.MaxDownloads = &maxDownloads
			}
			if noDownload {
				f := false
				in.AllowDownload = &f
			}
			if noPreview {
				f := false
				in.AllowPreview = &f
			}
			if noDownload && noPreview && !in.AllowUpload {
				return UsageError("--no-download and --no-preview together leave nothing to share")
			}
			password, ok, err := readSharePassword(cmd, pw)
			if err != nil {
				return err
			}
			if ok {
				in.Password = password
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				t, err := newResolver(c).resolveNode(ctx, args[0])
				if err != nil {
					return err
				}
				if t.Node.ParentID == "" {
					return core.Invalid("path", fmt.Sprintf("%s is a root folder; share a folder inside it", t.Path))
				}
				if in.AllowUpload && !t.Node.IsDir() {
					return UsageError("--upload needs a folder")
				}
				in.NodeID = t.Node.ID
				var s core.Share
				if err := c.Do(ctx, http.MethodPost, api("/shares"), in, &s); err != nil {
					return err
				}
				if s.NodeName == "" {
					s.NodeName = t.Node.Name
				}
				return printShare(ctx, cmd, c, &s, qr, true)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&expires, "expires", "", "validity: duration (7d), date (2026-12-31) or never (default: server setting)")
	pw = addSharePasswordFlags(cmd)
	f.Int64Var(&maxDownloads, "max-downloads", 0, "disable the link after this many downloads")
	f.BoolVar(&noDownload, "no-download", false, "view/preview only, no downloads")
	f.BoolVar(&noPreview, "no-preview", false, "no in-browser previews")
	f.BoolVar(&in.AllowUpload, "upload", false, "let visitors also upload into the shared folder")
	f.StringVar(&in.Title, "title", "", "title shown on the share page")
	f.StringVar(&in.Message, "message", "", "message shown on the share page")
	f.BoolVar(&in.NotifyOwner, "notify", false, "e-mail me about uploads through the link (needs --upload and SMTP)")
	f.BoolVar(&qr, "qr", false, "print the link as a QR code")
	return cmd
}

func newShareEditCmd() *cobra.Command {
	var title, message, expires, maxDownloads string
	var download, preview, upload, notify, noDownload, noPreview, noUpload, noNotify bool
	var disable, enable, noPassword bool
	var pw *secretInput
	cmd := &cobra.Command{
		Use:   "edit <id>",
		Short: "Change a share link's settings",
		Long: `Change the settings of a share link; only the flags you pass are changed.
--download turns downloads on, --no-download (or --download=false) turns them
off; the same goes for --preview, --upload and --notify. --max-downloads and
--expires take "none"/"never" to remove the limit.`,
		Example: `  fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --expires 30d
  fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --no-download --max-downloads none
  fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --password
  fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --no-password`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in, changed, err := shareUpdateFromFlags(cmd, shareFlagValues{
				title: title, message: message, expires: expires, maxDownloads: maxDownloads,
				download: download, preview: preview, upload: upload, notify: notify,
				noDownload: noDownload, noPreview: noPreview, noUpload: noUpload, noNotify: noNotify,
				disable: disable, enable: enable, noPassword: noPassword, password: pw,
			})
			if err != nil {
				return err
			}
			if !changed {
				return UsageError("nothing to change; see \"fileparcel share edit --help\"")
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getShare(ctx, c, args[0], "")
				if err != nil {
					return err
				}
				var out core.Share
				if err := c.Do(ctx, http.MethodPatch, api("/shares/"+pathEsc(s.ID)), in, &out); err != nil {
					return err
				}
				if out.ID == "" {
					out = *s
				}
				out.URL = absoluteURL(ctx, c, out.URL)
				return done(cmd, &out, "updated %s %s", shareNoun(out.Kind), out.ID)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&title, "title", "", "new title")
	f.StringVar(&message, "message", "", "new message")
	f.StringVar(&expires, "expires", "", "new validity: duration (7d), date or never")
	f.StringVar(&maxDownloads, "max-downloads", "", "download limit, or none")
	// Only the switches given are sent, so they default to false here: a
	// "(default true)" in the help would suggest that leaving one out turns
	// the option on.
	for _, b := range []struct {
		on, off     *bool
		name, usage string
	}{
		{&download, &noDownload, "download", "downloads"},
		{&preview, &noPreview, "preview", "in-browser previews"},
		{&upload, &noUpload, "upload", "uploads into the shared folder"},
		{&notify, &noNotify, "notify", "e-mails to the owner about new uploads"},
	} {
		f.BoolVar(b.on, b.name, false, "allow "+b.usage)
		f.BoolVar(b.off, "no-"+b.name, false, "turn off "+b.usage)
		cmd.MarkFlagsMutuallyExclusive(b.name, "no-"+b.name)
	}
	f.BoolVar(&disable, "disable", false, "turn the link off (reversible with --enable)")
	f.BoolVar(&enable, "enable", false, "turn a disabled link back on")
	cmd.MarkFlagsMutuallyExclusive("disable", "enable")
	f.BoolVar(&noPassword, "no-password", false, "remove the password")
	pw = addSharePasswordFlags(cmd)
	return cmd
}

// shareFlagValues carries the raw values of the share edit flags.
type shareFlagValues struct {
	title, message, expires, maxDownloads     string
	download, preview, upload, notify         bool
	noDownload, noPreview, noUpload, noNotify bool
	disable, enable, noPassword               bool
	password                                  *secretInput
}

// shareUpdateFromFlags builds a ShareUpdate from the flags that were set.
func shareUpdateFromFlags(cmd *cobra.Command, v shareFlagValues) (core.ShareUpdate, bool, error) {
	var in core.ShareUpdate
	f := cmd.Flags()
	changed := false
	set := func(name string) bool {
		if f.Changed(name) {
			changed = true
			return true
		}
		return false
	}
	if set("title") {
		in.Title = &v.title
	}
	if set("message") {
		in.Message = &v.message
	}
	if set("expires") {
		exp, never, err := parseExpiry(v.expires, time.Now(), true)
		if err != nil {
			return in, false, err
		}
		switch {
		case never:
			in.ExpiresAt = core.Null[time.Time]()
		case exp != nil:
			in.ExpiresAt = core.Some(*exp)
		default:
			return in, false, UsageError("--expires needs a value (7d, 2026-12-31 or never)")
		}
	}
	if set("max-downloads") {
		switch strings.ToLower(strings.TrimSpace(v.maxDownloads)) {
		case "none", "unlimited", "never", "off":
			in.MaxDownloads = core.Null[int64]()
		default:
			n, err := strconv.ParseInt(strings.TrimSpace(v.maxDownloads), 10, 64)
			if err != nil || n < 1 {
				return in, false, UsageError("--max-downloads must be a positive number or none")
			}
			in.MaxDownloads = core.Some(n)
		}
	}
	// --X sends its value (--X=false turns the option off too), --no-X the
	// opposite of its value.
	for _, b := range []struct {
		name    string
		on, off bool
		dst     **bool
	}{
		{"download", v.download, v.noDownload, &in.AllowDownload},
		{"preview", v.preview, v.noPreview, &in.AllowPreview},
		{"upload", v.upload, v.noUpload, &in.AllowUpload},
		{"notify", v.notify, v.noNotify, &in.NotifyOwner},
	} {
		on, off := set(b.name), set("no-"+b.name)
		switch {
		case on && off:
			return in, false, UsageError("use only one of --%s and --no-%s", b.name, b.name)
		case on:
			val := b.on
			*b.dst = &val
		case off:
			val := !b.off
			*b.dst = &val
		}
	}
	if v.disable && v.enable {
		return in, false, UsageError("use only one of --disable and --enable")
	}
	if set("disable") && v.disable {
		t := true
		in.Disabled = &t
	}
	if set("enable") && v.enable {
		fl := false
		in.Disabled = &fl
	}
	if v.password != nil && v.password.Given() && v.noPassword {
		return in, false, UsageError("use either a password flag or --no-password")
	}
	if v.password != nil {
		pw, ok, err := readSharePassword(cmd, v.password)
		if err != nil {
			return in, false, err
		}
		if ok {
			in.Password, changed = &pw, true
		}
	}
	if v.noPassword {
		empty := ""
		in.Password, changed = &empty, true
	}
	return in, changed, nil
}

// ---------- requests ----------

func newRequestCreateCmd() *cobra.Command {
	var in core.ShareInput
	var expires, maxSize, quota string
	var qr bool
	var pw *secretInput
	cmd := &cobra.Command{
		Use:   "create <folder>",
		Short: "Create an upload link into a folder",
		Long: `Create a public upload link into a remote folder and print it. Uploaders
cannot see the folder's contents. Uploads count against your quota.

--max-size limits each file, --quota the total of all uploads; --require-name
asks uploaders for their name (recorded with each upload). --password asks
for a password uploaders must enter; scripts use --password-stdin or
--password-file.

` + filesPathNote,
		Example: `  fileparcel request create "/My files/Incoming"
  fileparcel request create "/My files/Incoming/Wedding" --title "Wedding photos" --expires 30d --qr
  fileparcel request create /Team/Design/Submissions --max-size 500M --quota 20G --require-name --notify`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in.Kind = core.ShareRequest
			in.AllowUpload = true
			f := false
			in.AllowDownload, in.AllowPreview = &f, &f
			exp, never, err := parseExpiry(expires, time.Now(), true)
			if err != nil {
				return err
			}
			in.ExpiresAt, in.NoExpiry = exp, never
			for _, lim := range []struct {
				flag, val string
				dst       **int64
			}{{"max-size", maxSize, &in.UploadMaxFileBytes}, {"quota", quota, &in.UploadQuotaBytes}} {
				if lim.val == "" {
					continue
				}
				q, err := ParseQuota(lim.val)
				if err != nil {
					return UsageError("--%s: %v", lim.flag, err)
				}
				if q != nil && *q <= 0 {
					return UsageError("--%s must be positive (or unlimited)", lim.flag)
				}
				*lim.dst = q
			}
			password, ok, err := readSharePassword(cmd, pw)
			if err != nil {
				return err
			}
			if ok {
				in.Password = password
			}
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				t, err := newResolver(c).resolveFolder(ctx, args[0])
				if err != nil {
					return err
				}
				in.NodeID = t.Node.ID
				var s core.Share
				if err := c.Do(ctx, http.MethodPost, api("/shares"), in, &s); err != nil {
					return err
				}
				if s.NodeName == "" {
					s.NodeName = t.Node.Name
				}
				return printShare(ctx, cmd, c, &s, qr, true)
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&in.Title, "title", "", "title shown on the upload page")
	fl.StringVar(&in.Message, "message", "", "instructions shown on the upload page")
	fl.StringVar(&expires, "expires", "", "validity: duration (7d), date (2026-12-31) or never (default: server setting)")
	fl.StringVar(&maxSize, "max-size", "", "maximum size per file (e.g. 500M, 2G)")
	fl.StringVar(&quota, "quota", "", "maximum total size of all uploads (e.g. 20G)")
	fl.BoolVar(&in.RequireUploaderName, "require-name", false, "uploaders must enter their name")
	fl.BoolVar(&in.NotifyOwner, "notify", false, "e-mail me about new uploads (needs SMTP)")
	pw = addSharePasswordFlags(cmd)
	fl.BoolVar(&qr, "qr", false, "print the link as a QR code")
	return cmd
}

func newRequestCloseCmd() *cobra.Command {
	var reopen bool
	cmd := &cobra.Command{
		Use:   "close <id>",
		Short: "Stop accepting uploads (reopen later)",
		Long: `Close a file request: the link stops accepting uploads but is kept, so it can
be opened again with "fileparcel request reopen". "fileparcel request delete"
removes it for good.`,
		Example: `  fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				return setShareDisabled(ctx, cmd, c, args[0], core.ShareRequest, !reopen)
			})
		},
	}
	// Legacy: "request close ID --reopen" is "request reopen ID" (legacy.go).
	cmd.Flags().BoolVar(&reopen, "reopen", false, "accept uploads again")
	_ = cmd.Flags().MarkHidden("reopen")
	return cmd
}

// newShareToggleCmd returns "share disable" (disabled true), "share enable"
// or "request reopen": PATCH /shares/{id} {"disabled": …}, JSON output the
// share.
func newShareToggleCmd(kind string, disabled bool) *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withUserClient(cmd, func(ctx context.Context, c *Client) error {
				return setShareDisabled(ctx, cmd, c, args[0], kind, disabled)
			})
		},
	}
	switch {
	case kind == core.ShareRequest:
		cmd.Use = "reopen <id>"
		cmd.Short = "Accept uploads again on a closed file request"
		cmd.Long = `Open a closed file request again: its link accepts uploads with the settings
it had. A request that has expired or used up its upload quota still refuses
uploads; create a new one with "fileparcel request create".`
		cmd.Example = `  fileparcel request reopen shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel request reopen shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json`
	case disabled:
		cmd.Use = "disable <id>"
		cmd.Short = "Turn a share link off without deleting it"
		cmd.Long = `The link stops working until "fileparcel share enable". Nothing else changes;
its counters and settings are kept.`
		cmd.Example = `  fileparcel share disable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel share disable shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json`
	default:
		cmd.Use = "enable <id>"
		cmd.Short = "Turn a disabled share link back on"
		cmd.Long = `The link works again with the settings and counters it had. A link that has
expired or reached its download limit stays unavailable; change that with
"fileparcel share edit".`
		cmd.Example = `  fileparcel share enable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel share enable shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json`
	}
	return cmd
}

// setShareDisabled turns the share id of kind off (disabled) or on again
// and prints the share.
func setShareDisabled(ctx context.Context, cmd *cobra.Command, c *Client, id, kind string, disabled bool) error {
	s, err := getShare(ctx, c, id, kind)
	if err != nil {
		return err
	}
	var out core.Share
	if err := c.Do(ctx, http.MethodPatch, api("/shares/"+pathEsc(s.ID)), core.ShareUpdate{Disabled: &disabled}, &out); err != nil {
		return err
	}
	if out.ID == "" {
		out = *s
	}
	out.URL = absoluteURL(ctx, c, out.URL)
	verb := map[bool]string{true: "disabled", false: "enabled"}[disabled]
	if kind == core.ShareRequest {
		verb = map[bool]string{true: "closed", false: "reopened"}[disabled]
	}
	return done(cmd, &out, "%s %s %s (%s)", verb, shareNoun(kind), s.ID, Dash(s.NodeName))
}
