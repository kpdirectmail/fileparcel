package audit

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// Sort orders accepted by Query (AuditQuery.Sort).
const (
	SortNewest = "newest" // default: newest first
	SortOldest = "oldest" // oldest first
)

// Export formats.
const (
	FormatCSV   = "csv"
	FormatJSONL = "jsonl"
)

// exportBatch is the keyset page size used by Export and the mirror.
const exportBatch = 1000

// cursor is the keyset position of Query.
type cursor struct {
	Seq int64 `json:"s"`
}

func encodeCursor(seq int64) string {
	b, _ := json.Marshal(cursor{Seq: seq})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (int64, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	var c cursor
	if err != nil || json.Unmarshal(b, &c) != nil || c.Seq <= 0 {
		return 0, core.Invalid("cursor", "invalid cursor")
	}
	return c.Seq, nil
}

// likeEscape escapes the LIKE wildcards of s (ESCAPE '\').
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// filter builds the WHERE clause (without "WHERE") of q.
func filter(q core.AuditQuery) (string, []any, error) {
	var conds []string
	var args []any
	if q.Since != nil {
		conds = append(conds, "at >= ?")
		args = append(args, db.Ms(*q.Since))
	}
	if q.Until != nil {
		conds = append(conds, "at <= ?")
		args = append(args, db.Ms(*q.Until))
	}
	if q.ActorID != "" {
		conds = append(conds, "actor_id = ?")
		args = append(args, q.ActorID)
	}
	if a := strings.TrimSpace(q.Action); a != "" {
		switch {
		case strings.HasSuffix(a, ".*"):
			a = strings.TrimSuffix(a, "*")
			fallthrough
		case strings.HasSuffix(a, "."):
			conds = append(conds, `action LIKE ? ESCAPE '\'`)
			args = append(args, likeEscape(a)+"%")
		case a == "*":
		default:
			conds = append(conds, "action = ?")
			args = append(args, a)
		}
	}
	if q.Outcome != "" {
		switch q.Outcome {
		case core.OutcomeSuccess, core.OutcomeFailure, core.OutcomeDenied:
		default:
			return "", nil, core.Invalid("outcome", "must be success, failure or denied")
		}
		conds = append(conds, "outcome = ?")
		args = append(args, q.Outcome)
	}
	if q.TargetType != "" {
		conds = append(conds, "target_type = ?")
		args = append(args, q.TargetType)
	}
	if q.TargetID != "" {
		conds = append(conds, "target_id = ?")
		args = append(args, q.TargetID)
	}
	if t := strings.TrimSpace(q.Q); t != "" {
		if len(t) > 200 {
			return "", nil, core.Invalid("q", "search text is too long")
		}
		p := "%" + likeEscape(t) + "%"
		conds = append(conds, `(actor_name LIKE ? ESCAPE '\' OR target_name LIKE ? ESCAPE '\' OR target_id = ? OR ip = ?)`)
		args = append(args, p, p, t, t)
	}
	if len(conds) == 0 {
		return "1=1", nil, nil
	}
	return strings.Join(conds, " AND "), args, nil
}

// descending interprets AuditQuery.Sort (default newest first).
func descending(q core.AuditQuery) (bool, error) {
	switch q.Sort {
	case "", SortNewest:
		return true, nil
	case SortOldest:
		return false, nil
	case "seq", "at":
		return q.Desc, nil
	}
	return false, core.Invalid("sort", "sort must be newest or oldest")
}

// page reads up to limit rows matching where/args after the keyset position.
func (s *Service) page(ctx context.Context, where string, args []any, desc bool, after int64, limit int) ([]*row, error) {
	order, cmp := "ASC", ">"
	if desc {
		order, cmp = "DESC", "<"
	}
	a := append([]any(nil), args...)
	if after > 0 {
		where += " AND seq " + cmp + " ?"
		a = append(a, after)
	}
	a = append(a, limit)
	rows, err := s.env.DB.Query(ctx, `SELECT `+rowCols+` FROM audit_log WHERE `+where+
		` ORDER BY seq `+order+` LIMIT ?`, a...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Query lists audit rows matching q, newest first by default (Sort "oldest"
// reverses), keyset-paginated by seq. Action matches exactly, or as a prefix
// when it ends with "." or ".*"; Q searches actor/target names and matches
// target ids and IPs exactly.
func (s *Service) Query(ctx context.Context, q core.AuditQuery) (core.Page[core.AuditRecord], error) {
	where, args, err := filter(q)
	if err != nil {
		return core.Page[core.AuditRecord]{}, err
	}
	desc, err := descending(q)
	if err != nil {
		return core.Page[core.AuditRecord]{}, err
	}
	var after int64
	if q.Cursor != "" {
		if after, err = decodeCursor(q.Cursor); err != nil {
			return core.Page[core.AuditRecord]{}, err
		}
	}
	limit := q.EffectiveLimit()
	rows, err := s.page(ctx, where, args, desc, after, limit+1)
	if err != nil {
		return core.Page[core.AuditRecord]{}, err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		next = encodeCursor(rows[len(rows)-1].seq)
	}
	items := make([]core.AuditRecord, len(rows))
	for i, r := range rows {
		items[i] = r.record()
	}
	return core.NewPage(items, next), nil
}

// exportRecord is one exported row: the API record plus the chain hashes (hex).
type exportRecord struct {
	core.AuditRecord
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

var csvHeader = []string{"seq", "id", "at", "actor_id", "actor_name", "actor_via", "ip", "user_agent",
	"request_id", "action", "outcome", "target_type", "target_id", "target_name", "details", "prev_hash", "hash"}

// csvSafe neutralizes spreadsheet formula injection: cells starting with
// = + - @ or a control character are prefixed with a single quote.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + s
	}
	return s
}

// Export streams every row matching q (filters only; Cursor/Limit are
// ignored) in chronological order as "csv" (with a header row, formula
// injection neutralized) or "jsonl" (one JSON object per line). Both include
// the chain hashes in hex.
func (s *Service) Export(ctx context.Context, q core.AuditQuery, format string, w io.Writer) error {
	switch format {
	case FormatCSV, FormatJSONL:
	default:
		return core.Invalid("format", "format must be csv or jsonl")
	}
	where, args, err := filter(q)
	if err != nil {
		return err
	}
	var cw *csv.Writer
	var enc *json.Encoder
	if format == FormatCSV {
		cw = csv.NewWriter(w)
		if err := cw.Write(csvHeader); err != nil {
			return err
		}
	} else {
		enc = json.NewEncoder(w)
	}
	var after int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := s.page(ctx, where, args, false, after, exportBatch)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if cw != nil {
				rec := []string{strconv.FormatInt(r.seq, 10), r.id, db.FromMs(r.at).Format(time.RFC3339Nano),
					csvSafe(r.actorID), csvSafe(r.actorName), csvSafe(r.actorVia), csvSafe(r.ip), csvSafe(r.userAgent),
					csvSafe(r.requestID), csvSafe(r.action), r.outcome, csvSafe(r.targetType), csvSafe(r.targetID),
					csvSafe(r.targetName), csvSafe(r.details), hex.EncodeToString(r.prevHash), hex.EncodeToString(r.hash)}
				if err := cw.Write(rec); err != nil {
					return err
				}
			} else if err := enc.Encode(exportRecord{AuditRecord: r.record(),
				PrevHash: hex.EncodeToString(r.prevHash), Hash: hex.EncodeToString(r.hash)}); err != nil {
				return err
			}
		}
		if cw != nil {
			cw.Flush()
			if err := cw.Error(); err != nil {
				return err
			}
		}
		if len(rows) < exportBatch {
			return nil
		}
		after = rows[len(rows)-1].seq
	}
}
