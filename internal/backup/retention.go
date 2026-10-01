package backup

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// Policy is a GFS (grandfather-father-son) retention policy. A backup is
// kept when it is among the Last newest, or the newest of one of the Daily
// newest days, Weekly newest ISO weeks or Monthly newest months (local time).
type Policy struct {
	Last, Daily, Weekly, Monthly int
}

// Disabled reports whether the policy keeps everything (all counts zero).
func (p Policy) Disabled() bool {
	return p.Last <= 0 && p.Daily <= 0 && p.Weekly <= 0 && p.Monthly <= 0
}

// Item is a backup considered for retention.
type Item struct {
	ID        string
	CreatedAt time.Time
}

// Keep returns the ids of items to keep under p. Items may be in any order;
// buckets are computed in loc (time.Local when nil). A disabled policy keeps
// every item.
func (p Policy) Keep(items []Item, loc *time.Location) map[string]bool {
	keep := make(map[string]bool, len(items))
	if p.Disabled() {
		for _, it := range items {
			keep[it.ID] = true
		}
		return keep
	}
	if loc == nil {
		loc = time.Local
	}
	sorted := make([]Item, len(items))
	copy(sorted, items)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
		}
		return sorted[i].ID > sorted[j].ID
	})
	for i := 0; i < len(sorted) && i < p.Last; i++ {
		keep[sorted[i].ID] = true
	}
	bucket := func(n int, key func(time.Time) string) {
		if n <= 0 {
			return
		}
		seen := map[string]bool{}
		for _, it := range sorted {
			k := key(it.CreatedAt.In(loc))
			if seen[k] {
				continue
			}
			if len(seen) >= n {
				return
			}
			seen[k] = true
			keep[it.ID] = true
		}
	}
	bucket(p.Daily, func(t time.Time) string { return t.Format("2006-01-02") })
	bucket(p.Weekly, func(t time.Time) string {
		y, w := t.ISOWeek()
		return fmt.Sprintf("%d-W%02d", y, w)
	})
	bucket(p.Monthly, func(t time.Time) string { return t.Format("2006-01") })
	return keep
}

// policy reads the retention settings.
func (s *Service) policy() Policy {
	st := s.env.Settings
	if st == nil {
		return Policy{}
	}
	return Policy{
		Last:    int(st.Int(SettingKeepLast)),
		Daily:   int(st.Int(SettingKeepDaily)),
		Weekly:  int(st.Int(SettingKeepWeekly)),
		Monthly: int(st.Int(SettingKeepMonthly)),
	}
}

// PruneResult is the result of a backup.prune job.
type PruneResult struct {
	Deleted int `json:"deleted"`
}

// Prune implements core.Backups: applies the GFS policy separately to the
// ready scheduled backups of each scope (unless the policy is disabled) and
// removes the records of failed backups older than a week. It returns the
// number of deleted backups.
//
// Manual, imported, pre-upgrade and final backups are never pruned
// automatically (docs/FILEPARCEL.md, "Retention"): a pre-upgrade backup is
// the documented rollback path for a problem noticed long after the
// upgrade, so it must not compete for the scheduled backups' slots.
//
// A failed backup normally has no archive (it is renamed to its final name
// only once complete). One that has one — a row marked failed by an older
// version after a crash, for instance — holds a valid backup, so that record
// is kept with its file rather than deleted with it.
func (s *Service) Prune(ctx context.Context) (int, error) {
	pol := s.policy()
	byScope := map[string][]*core.Backup{}
	var failed []*core.Backup
	failCut := s.env.Now().Add(-failedRetention)
	rows, err := s.env.DB.Query(ctx, `SELECT `+backupCols+` FROM backups
		WHERE (state = 'ready' AND "trigger" = 'schedule') OR (state = 'failed' AND created_at < ?)`,
		db.Ms(failCut))
	if err != nil {
		return 0, fmt.Errorf("backup: prune: %w", err)
	}
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("backup: prune: %w", err)
		}
		if b.State == core.BackupFailed {
			if _, ok := s.archiveFile(b.FileName); ok {
				s.log.Warn("backup: a failed backup has a complete archive; not pruned (delete it by hand if it is not needed)",
					"backup", b.ID, "file", b.FileName)
				continue
			}
			failed = append(failed, b)
			continue
		}
		byScope[b.Scope] = append(byScope[b.Scope], b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("backup: prune: %w", err)
	}
	var victims []*core.Backup
	if !pol.Disabled() {
		for _, list := range byScope {
			items := make([]Item, len(list))
			for i, b := range list {
				items[i] = Item{ID: b.ID, CreatedAt: b.CreatedAt}
			}
			keep := pol.Keep(items, time.Local)
			for _, b := range list {
				if !keep[b.ID] {
					victims = append(victims, b)
				}
			}
		}
	}
	victims = append(victims, failed...)
	sys := core.SystemPrincipal(core.ViaOffline)
	sys.Username = "system:retention"
	// Carry the job's request id so the prune deletions link back to the job
	// (and, for a hand-started run, to its job.run audit entry).
	if p := core.PrincipalFrom(ctx); p != nil {
		sys.RequestID = p.RequestID
	}
	deleted := 0
	var errs []error
	for _, b := range victims {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		reason := "retention"
		if b.State == core.BackupFailed {
			reason = "failed backup cleanup"
		}
		if err := s.deleteBackup(ctx, sys, b, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted++
	}
	if deleted > 0 {
		s.log.Info("backup: pruned old backups", "deleted", deleted)
	}
	return deleted, errors.Join(errs...)
}

func (s *Service) jobPrune(ctx context.Context, h core.JobHandle) error {
	n, err := s.Prune(ctx)
	h.SetResult(PruneResult{Deleted: n})
	return err
}
