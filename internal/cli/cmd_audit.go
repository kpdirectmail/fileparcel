package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

func init() { Register(newAuditCmd) }

func newAuditCmd() *cobra.Command {
	cmd := groupCmd("audit", "Read, follow, verify and export the audit log",
		`The audit log records who did what: sign-ins, changes to users and share
links, downloads, settings, key and certificate operations and more. Every
entry is chained to the one before it with an HMAC, so "fileparcel audit
verify" notices entries that were changed or deleted afterwards.`,
		`  fileparcel audit list --since 24h
  fileparcel audit list --user alice --action auth. --follow
  fileparcel audit verify
  fileparcel audit export --format jsonl -o audit.jsonl --since 30d`)
	cmd.AddCommand(newAuditListCmd(), newAuditVerifyCmd(), newAuditExportCmd())
	return cmd
}

// auditFilter holds the filter flags shared by list and export.
type auditFilter struct {
	since, until, user, action, outcome, targetType, target, text string
}

func (f *auditFilter) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.since, "since", "", "only entries newer than a duration (24h, 7d) or time (RFC 3339 / 2006-01-02)")
	fl.StringVar(&f.until, "until", "", "only entries older than a duration or time")
	fl.StringVar(&f.user, "user", "", "only actions by this user (name or id)")
	fl.StringVar(&f.action, "action", "", `only this action ("auth.login") or prefix ("auth.")`)
	fl.StringVar(&f.outcome, "outcome", "", "only success, failure or denied")
	fl.StringVar(&f.targetType, "target-type", "", "only targets of this type (user, node, share, setting, …)")
	fl.StringVar(&f.target, "target", "", "only this target id")
	fl.StringVarP(&f.text, "query", "q", "", "free-text match on actor and target names")
}

// parseTimeFlag accepts a duration back from now ("24h", "7d"), an RFC 3339
// time or a date.
func parseTimeFlag(name, s string, now time.Time) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		u := t.UTC()
		return &u, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		u := t.UTC()
		return &u, nil
	}
	d, err := ParseDuration(s)
	if err != nil {
		return nil, UsageError("--%s: expected a duration (24h, 7d) or a time (2026-09-01, RFC 3339), got %q", name, s)
	}
	u := now.Add(-d).UTC()
	return &u, nil
}

// params builds the query parameters (the core.AuditQuery json names).
func (f *auditFilter) params(ctx context.Context, c *Client, now time.Time) ([]string, error) {
	switch f.outcome {
	case "", core.OutcomeSuccess, core.OutcomeFailure, core.OutcomeDenied:
	default:
		return nil, UsageError("invalid --outcome %q (success, failure or denied)", f.outcome)
	}
	since, err := parseTimeFlag("since", f.since, now)
	if err != nil {
		return nil, err
	}
	until, err := parseTimeFlag("until", f.until, now)
	if err != nil {
		return nil, err
	}
	kv := []string{"action", f.action, "outcome", f.outcome, "target_type", f.targetType, "target_id", f.target, "q", f.text}
	if since != nil {
		kv = append(kv, "since", since.Format(time.RFC3339Nano))
	}
	if until != nil {
		kv = append(kv, "until", until.Format(time.RFC3339Nano))
	}
	if f.user != "" {
		uid := f.user
		if !ids.Valid(ids.PrefixUser, uid) {
			u, err := resolveUser(ctx, c, f.user)
			if err != nil {
				return nil, err
			}
			uid = u.ID
		}
		kv = append(kv, "actor_id", uid)
	}
	return kv, nil
}

func renderAuditRow(t *Table, r *core.AuditRecord) {
	c := auditCells(r)
	t.Add(c[0], c[1], c[2], c[3], c[4], c[5])
}

// followLine renders audit cells in fixed-width columns (streaming output
// cannot be aligned by a table).
func followLine(c []string) string {
	pad := func(s string, n int) string {
		s = sanitizeCell(Truncate(s, n))
		if w := len([]rune(s)); w < n {
			s += strings.Repeat(" ", n-w)
		}
		return s
	}
	return strings.TrimRight(pad(c[0], 19)+"  "+pad(c[1], 20)+"  "+pad(c[2], 24)+"  "+pad(c[3], 8)+"  "+pad(c[4], 40)+"  "+sanitizeCell(c[5]), " ")
}

// auditCells returns TIME, ACTOR, ACTION, OUTCOME, TARGET, IP.
func auditCells(r *core.AuditRecord) []string {
	actor := r.ActorName
	if actor == "" {
		actor = r.ActorID
	}
	if r.ActorVia != "" && r.ActorVia != string(core.ViaSession) {
		actor += " (" + r.ActorVia + ")"
	}
	target := r.TargetName
	if target == "" {
		target = r.TargetID
	}
	if r.TargetType != "" && target != "" {
		target = r.TargetType + ":" + target
	}
	return []string{r.At.Local().Format("2006-01-02 15:04:05"), actor, r.Action, r.Outcome, Truncate(target, 40), r.IP}
}

func newAuditListCmd() *cobra.Command {
	var f auditFilter
	var limit int
	var follow bool
	var interval time.Duration
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "Show audit log entries",
		Long: `Show the newest audit log entries (oldest first), optionally filtered.
--follow keeps printing new entries as they arrive (Ctrl-C to stop); with
--json, followed entries are printed as one JSON object per line.`,
		Example: `  fileparcel audit list
  fileparcel audit list --since 7d --outcome failure
  fileparcel audit list --user alice --action share. --limit 20
  fileparcel audit list --follow --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > 10000 {
				return UsageError("--limit must be between 1 and 10000")
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				kv, err := f.params(ctx, c, time.Now())
				if err != nil {
					return err
				}
				path := api("/admin/audit", append(kv, "desc", "true", "limit", limitParam(limit))...)
				rows, err := listAll[core.AuditRecord](ctx, c, path, limit)
				if err != nil {
					return err
				}
				slices.SortFunc(rows, func(a, b core.AuditRecord) int { return compareInt(a.Seq, b.Seq) })
				if !follow {
					return Print(cmd, rows, func(w io.Writer) error {
						if len(rows) == 0 {
							Infof(cmd, "no matching audit entries")
							return nil
						}
						t := NewTable("TIME", "ACTOR", "ACTION", "OUTCOME", "TARGET", "IP")
						for i := range rows {
							renderAuditRow(t, &rows[i])
						}
						return t.Render(w)
					})
				}
				return followAudit(ctx, cmd, c, kv, rows, interval)
			})
		},
	}
	f.bind(cmd)
	cmd.Flags().IntVar(&limit, "limit", 50, "number of entries to show (the newest)")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new entries")
	durationVar(cmd.Flags(), &interval, "interval", 2*time.Second, "polling interval for --follow")
	return cmd
}

func compareInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// followAudit prints rows, then polls for entries with a higher seq until
// the context is canceled.
func followAudit(ctx context.Context, cmd *cobra.Command, c *Client, kv []string, rows []core.AuditRecord, interval time.Duration) error {
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}
	w := cmd.OutOrStdout()
	var lastSeq int64
	var lastAt time.Time
	emit := func(r *core.AuditRecord) error {
		if r.Seq > lastSeq {
			lastSeq = r.Seq
		}
		if r.At.After(lastAt) {
			lastAt = r.At
		}
		if G.JSON {
			return PrintJSONLine(w, r)
		}
		_, err := fmt.Fprintln(w, followLine(auditCells(r)))
		return err
	}
	if !G.JSON {
		if _, err := fmt.Fprintln(w, Bold(followLine([]string{"TIME", "ACTOR", "ACTION", "OUTCOME", "TARGET", "IP"}))); err != nil {
			return err
		}
	}
	for i := range rows {
		if err := emit(&rows[i]); err != nil {
			return err
		}
	}
	if lastAt.IsZero() {
		lastAt = time.Now().Add(-time.Minute)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		q := slices.Clone(kv)
		for i := 0; i+1 < len(q); i += 2 {
			if q[i] == "since" {
				q[i+1] = ""
			}
		}
		q = append(q, "since", lastAt.Add(-time.Second).UTC().Format(time.RFC3339Nano), "limit", limitParam(0))
		fresh, err := listAll[core.AuditRecord](ctx, c, api("/admin/audit", q...), 5000)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			Warnf(cmd, "polling the audit log failed: %v", err)
			continue
		}
		slices.SortFunc(fresh, func(a, b core.AuditRecord) int { return compareInt(a.Seq, b.Seq) })
		for i := range fresh {
			if fresh[i].Seq > lastSeq {
				if err := emit(&fresh[i]); err != nil {
					return err
				}
			}
		}
	}
}

func newAuditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check that the audit log was not tampered with",
		Long: `Recompute the HMAC chain over the whole audit log and report whether every
entry is intact. Exits with status 1 when the chain is broken (an entry was
modified, deleted or inserted outside FileParcel). Entries written while the
keys were locked prove nothing about their origin: those the sealing server
process did not write itself are reported (see the audit.reseal entries).`,
		Example: `  fileparcel audit verify
  fileparcel audit verify --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var v core.AuditVerify
				if err := c.Do(ctx, http.MethodGet, api("/admin/audit/verify"), nil, &v); err != nil {
					return err
				}
				if err := Print(cmd, &v, func(w io.Writer) error {
					if v.OK {
						Successf(cmd, "audit log intact: %s verified (seq %d–%d)", Plural(v.Checked, "entry"), v.FirstSeq, v.LastSeq)
						if v.Message != "" {
							Infof(cmd, "%s", v.Message)
						}
						return nil
					}
					_, err := fmt.Fprintf(w, "%s audit log chain broken at seq %d (%s checked): %s\n", Red("FAIL"), v.BrokenAt, Plural(v.Checked, "entry"), Dash(v.Message))
					return err
				}); err != nil {
					return err
				}
				if !v.OK {
					return &ExitCodeError{Code: ExitFailure}
				}
				return nil
			})
		},
	}
}

func newAuditExportCmd() *cobra.Command {
	var f auditFilter
	var format, out string
	var force bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Save the audit log as CSV or JSON lines",
		Long: `Write the audit log, or the entries the filters select, as CSV or JSON lines
to a file (-o) or standard output. An existing file is replaced only with -f.`,
		Example: `  fileparcel audit export > audit.csv
  fileparcel audit export --format jsonl -o audit.jsonl --since 30d
  fileparcel audit export --action auth.login --outcome failure`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "csv" && format != "jsonl" {
				return UsageError("invalid --format %q (csv or jsonl)", format)
			}
			if out != "" && out != "-" && !force && fileExists(out) {
				return fmt.Errorf("%s already exists (use --force to overwrite)", out)
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				kv, err := f.params(ctx, c, time.Now())
				if err != nil {
					return err
				}
				resp, err := c.Stream(ctx, http.MethodGet, api("/admin/audit/export", append(kv, "format", format)...), nil, nil)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if out == "" || out == "-" {
					_, err := io.Copy(cmd.OutOrStdout(), resp.Body)
					return err
				}
				part := out + partialSuffix
				fh, err := createPartial(part, "") // never through a planted symlink or into a planted file
				if err != nil {
					return err
				}
				n, cerr := io.Copy(fh, resp.Body)
				if err := fh.Close(); err != nil && cerr == nil {
					cerr = err
				}
				if cerr != nil {
					_ = os.Remove(part)
					return cerr
				}
				if err := os.Rename(part, out); err != nil {
					return err
				}
				Infof(cmd, "Wrote %s (%s)", out, HumanBytes(n))
				return nil
			})
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&format, "format", "csv", "csv or jsonl")
	addOutputFlag(cmd, &out, "output file (default: stdout)")
	addForceFlag(cmd, &force, "overwrite an existing output file")
	return cmd
}
