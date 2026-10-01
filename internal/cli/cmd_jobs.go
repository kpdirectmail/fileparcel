package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

func init() { Register(newJobsCmd) }

// knownJobKinds are ALL the job kinds of DESIGN §9.7, including the ones a
// job starts by itself. It is only used for the "not a known job kind" typo
// warning; what may be started by hand is core.RunnableJobKinds.
var knownJobKinds = []string{
	core.JobUploadZip, core.JobThumbsGenerate, core.JobBackupCreate, core.JobBackupVerify, core.JobBackupPrune,
	core.JobKeysRotateKEK, core.JobKeysReencrypt, core.JobMaintSessions, core.JobMaintUploads, core.JobMaintTrash,
	core.JobMaintBlobGC, core.JobMaintAuditPrune, core.JobMaintDBOptimize, core.JobMaintVersions, core.JobCertsRenewCheck,
}

func newJobsCmd() *cobra.Command {
	cmd := groupCmd("jobs", "List, follow and start background jobs",
		`Background jobs run inside the server: backups and their checks, .zip files
built on upload, thumbnails, key rotation and the regular upkeep (removing old
sessions and unfinished uploads, emptying old trash, freeing disk space,
pruning the audit log, tuning the database, renewing certificates).`,
		`  fileparcel jobs list
  fileparcel jobs list --state failed
  fileparcel jobs show job_01j9zq3x4k6m8p0r2t4v6x8z0b --wait
  fileparcel jobs run maintenance.trash --wait`, "job")
	cmd.AddCommand(newJobsListCmd(), newJobsShowCmd(), newJobsCancelCmd(), newJobsRunCmd())
	setListHint(cmd, "fileparcel jobs list")
	return cmd
}

func jobProgress(j *core.Job) string {
	switch {
	case j.ProgressTotal > 0:
		return fmt.Sprintf("%d%%", j.ProgressDone*100/j.ProgressTotal)
	case j.ProgressDone > 0:
		return fmt.Sprint(j.ProgressDone)
	}
	return ""
}

func jobDuration(j *core.Job) string {
	if j.StartedAt == nil {
		return ""
	}
	end := time.Now()
	if j.FinishedAt != nil {
		end = *j.FinishedAt
	}
	return HumanDuration(end.Sub(*j.StartedAt))
}

func newJobsListCmd() *cobra.Command {
	var kind, state string
	var limit int
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List recent jobs",
		Long:    "List background jobs, newest first, with state, progress, duration and error.",
		Example: `  fileparcel jobs list
  fileparcel jobs list --kind backup.create --limit 5
  fileparcel jobs list --state running --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch state {
			case "", core.JobQueued, core.JobRunning, core.JobSucceeded, core.JobFailed, core.JobCanceled:
			default:
				return UsageError("invalid --state %q (queued, running, succeeded, failed or canceled)", state)
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				jobs, err := listAll[core.Job](ctx, c, api("/admin/jobs", "kind", kind, "state", state, "limit", limitParam(limit)), limit)
				if err != nil {
					return err
				}
				slices.SortStableFunc(jobs, func(a, b core.Job) int { return b.CreatedAt.Compare(a.CreatedAt) })
				return Print(cmd, jobs, func(w io.Writer) error {
					if len(jobs) == 0 {
						Infof(cmd, "no jobs")
						return nil
					}
					t := NewTable("ID", "KIND", "STATE", "PROGRESS", "CREATED", "DURATION", "ERROR")
					for i := range jobs {
						j := &jobs[i]
						t.Add(j.ID, j.Kind, j.State, jobProgress(j), j.CreatedAt, jobDuration(j), Truncate(j.Error, 50))
					}
					return t.Render(w)
				})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&kind, "kind", "", "only jobs of this kind (e.g. backup.create)")
	f.StringVar(&state, "state", "", "only jobs in this state (queued, running, succeeded, failed, canceled)")
	f.IntVar(&limit, "limit", 50, "maximum number of jobs (0 = all)")
	return cmd
}

func renderJob(w io.Writer, j *core.Job) error {
	kv := NewKV()
	kv.Add("ID", j.ID)
	kv.Add("Kind", j.Kind)
	kv.Add("State", j.State)
	kv.Add("Progress", strings.TrimSpace(jobProgress(j)+" "+j.Note))
	kv.Add("Created", j.CreatedAt)
	kv.Add("Started", j.StartedAt)
	kv.Add("Finished", j.FinishedAt)
	kv.Add("Duration", jobDuration(j))
	kv.Add("Attempts", j.Attempts)
	kv.Add("Schedule", j.Schedule)
	kv.Add("Created by", j.CreatedBy)
	kv.Add("Error", j.Error)
	if err := kv.Render(w); err != nil {
		return err
	}
	for _, x := range []struct {
		name string
		raw  json.RawMessage
	}{{"Params", j.Params}, {"Result", j.Result}} {
		raw := bytes.TrimSpace(x.raw)
		if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
			continue
		}
		var buf bytes.Buffer
		if json.Indent(&buf, raw, "  ", "  ") == nil {
			fmt.Fprintf(w, "%s:\n  %s\n", x.name, buf.String())
		}
	}
	return nil
}

func newJobsShowCmd() *cobra.Command {
	var wait bool
	cmd := &cobra.Command{
		Use:   "show <job>",
		Short: "Show a job (and wait for it)",
		Long: `Show the details of a job with its parameters and result; --wait follows it
until it finishes (exit status 1 if it fails).`,
		Example: `  fileparcel jobs show job_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel jobs show job_01j9zq3x4k6m8p0r2t4v6x8z0b --wait`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !ids.Valid(ids.PrefixJob, args[0]) {
				return UsageError("%q is not a job id (job_…)", args[0])
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var j core.Job
				if wait {
					jp, err := waitJob(ctx, cmd, c, args[0], true, "waiting")
					if jp == nil {
						return err
					}
					j = *jp
					if perr := Print(cmd, &j, func(w io.Writer) error { return renderJob(w, &j) }); perr != nil {
						return perr
					}
					if err != nil {
						return &ExitCodeError{Code: ExitFailure, Err: err}
					}
					return nil
				}
				if err := c.Do(ctx, http.MethodGet, jobPath(args[0], true), nil, &j); err != nil {
					return err
				}
				return Print(cmd, &j, func(w io.Writer) error { return renderJob(w, &j) })
			})
		},
	}
	cmd.Flags().BoolVar(&wait, "wait", false, "wait until the job finishes")
	return cmd
}

func newJobsCancelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cancel <job>",
		Short: "Stop a queued or running job",
		Long: `Ask a queued or running job to stop. Jobs stop at the next safe point and
undo or clean up what they did.`,
		Example: `  fileparcel jobs cancel job_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel jobs cancel job_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !ids.Valid(ids.PrefixJob, args[0]) {
				return UsageError("%q is not a job id (job_…)", args[0])
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := c.Do(ctx, http.MethodPost, api("/admin/jobs/"+pathEsc(args[0])+"/cancel"), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"canceled": args[0]}, "cancellation of %s requested", args[0])
			})
		},
	}
}

func newJobsRunCmd() *cobra.Command {
	var params string
	var wait *waitFlags
	cmd := &cobra.Command{
		Use:   "run <kind>",
		Short: "Start a background job now",
		Long: `Start a background job of the given kind now, for example an upkeep task
outside its schedule. Kinds:
  ` + strings.Join(core.RunnableJobKinds, "\n  ") + `

--params passes a JSON object to the job. The command returns at once unless
--wait, which follows the job to the end.`,
		Example: `  fileparcel jobs run maintenance.trash --wait
  fileparcel jobs run maintenance.db_optimize
  fileparcel jobs run backup.create --params '{"scope":"metadata"}' --wait`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: core.RunnableJobKinds,
		RunE: func(cmd *cobra.Command, args []string) error {
			in := core.RunJobInput{Kind: args[0]}
			if params != "" {
				if !json.Valid([]byte(params)) || !strings.HasPrefix(strings.TrimSpace(params), "{") {
					return UsageError("--params must be a JSON object")
				}
				in.Params = json.RawMessage(params)
			}
			if !slices.Contains(knownJobKinds, in.Kind) {
				Warnf(cmd, "%q is not a known job kind; trying anyway", in.Kind)
			}
			if in.Kind == core.JobBackupVerify {
				var p struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(in.Params, &p) // no or other params: no id
				if strings.TrimSpace(p.ID) == "" {
					return UsageError(`backup.verify needs the backup: --params '{"id":"bak_…"}' (ids: "fileparcel backup list"), ` +
						`or run "fileparcel backup verify ID"`)
				}
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if c.Mode() == ModeOffline && in.Kind != core.JobBackupCreate && in.Kind != core.JobBackupVerify {
					// No job runner offline: run the job here and now. That
					// bypasses POST /admin/jobs/run, so apply its rules and
					// record its audit entry here.
					if err := checkInlineRun(in.Kind, in.Params); err != nil {
						return err
					}
					var params any
					if len(in.Params) > 0 {
						params = in.Params
					}
					if j, ok, err := runJobInline(ctx, cmd, c, in.Kind, params); ok {
						if j != nil {
							auditInlineRun(ctx, c, j)
						}
						if err != nil {
							return err
						}
						return done(cmd, j, "job %s (%s) finished in %s%s", j.ID, j.Kind, jobDuration(j), jobResultSuffix(j))
					}
				}
				var ref core.JobRef
				if err := c.Do(ctx, http.MethodPost, api("/admin/jobs/run"), in, &ref); err != nil {
					if strings.HasPrefix(in.Kind, "backup.") {
						return withListHint(err, "fileparcel backup list") // the backup of --params is missing
					}
					return err
				}
				if offlineJobWarning(cmd, c, ref.JobID) || !wait.Wait() {
					return done(cmd, &ref, "started job %s (%s)", ref.JobID, in.Kind)
				}
				j, err := waitJob(ctx, cmd, c, ref.JobID, true, in.Kind)
				if err != nil {
					return err
				}
				return done(cmd, j, "job %s (%s) finished in %s%s", j.ID, j.Kind, jobDuration(j), jobResultSuffix(j))
			})
		},
	}
	cmd.Flags().StringVar(&params, "params", "", "job parameters as a JSON object")
	wait = addWaitFlags(cmd, false, "the job finishes")
	return cmd
}

// checkInlineRun applies the rules of POST /admin/jobs/run (opsapi.runJob)
// to an offline run, which calls jobs.RunInline directly: only
// core.RunnableJobKinds may be started by hand, and the kinds run inline
// (all but backup.create and backup.verify) take no parameters.
func checkInlineRun(kind string, params json.RawMessage) error {
	if !slices.Contains(core.RunnableJobKinds, kind) {
		return core.Invalid("kind", "this job kind cannot be started by hand")
	}
	if p := string(bytes.TrimSpace(params)); p != "" && p != "null" && p != "{}" {
		return core.Invalid("params", "this job kind takes no parameters")
	}
	return nil
}

// auditInlineRun records the job.run entry that POST /admin/jobs/run writes
// for a hand-started job (also when the job failed: it was still started).
func auditInlineRun(ctx context.Context, c *Client, j *core.Job) {
	d := c.Deps()
	if d == nil || d.Env == nil || d.Audit == nil {
		return
	}
	d.Audit.Record(core.WithPrincipal(ctx, core.SystemPrincipal(core.ViaOffline)), core.AuditEntry{
		Action: core.ActJobRun, TargetType: "job", TargetID: j.ID, Details: map[string]any{"kind": j.Kind}})
}

// jobResultSuffix is ": " plus a finished job's result in a few words
// ("sessions 3, tickets 0"): the numbers, strings and yes/no values at the
// top of its result object, in order. The note is the label of the last
// progress step ("archive tickets"), not a result: it is used only for a
// job without a result.
func jobResultSuffix(j *core.Job) string {
	if s := resultSummary(j.Result); s != "" {
		return ": " + s
	}
	return noteSuffix(j.Note)
}

// resultSummary renders the scalar fields of a JSON object as "key value"
// pairs ("" when raw is not an object or has none).
func resultSummary(raw json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return ""
	}
	var parts []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		key, _ := tok.(string)
		var v any
		if err := dec.Decode(&v); err != nil {
			return ""
		}
		var text string
		switch x := v.(type) {
		case json.Number:
			text = x.String()
		case string:
			if x == "" {
				continue
			}
			text = Truncate(x, 60)
		case bool:
			text = YesNo(x)
		default:
			continue // lists and objects: see --json
		}
		parts = append(parts, strings.ReplaceAll(key, "_", " ")+" "+text)
	}
	return strings.Join(parts, ", ")
}

func noteSuffix(s string) string {
	if s == "" {
		return ""
	}
	return ": " + s
}
