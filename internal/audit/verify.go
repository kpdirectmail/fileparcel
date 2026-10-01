package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// pruneBatch is the number of rows deleted per transaction by Prune.
const pruneBatch = 5000

// Verify walks the whole chain in seq order inside one read snapshot:
//
//   - the first row must chain to the prune anchor (whose MAC must verify) or
//     to 32 zero bytes;
//   - every row must link to its predecessor and its hash must equal the MAC
//     (rows before the unsealed marker) or the unkeyed SHA-256 (rows from the
//     marker on, which are counted as unsealed, not as failures);
//   - the authenticated head checkpoint must name an existing row with the
//     same hash, which detects a truncated tail.
//
// Rows named by a sealed audit.reseal entry (sealed after an unlock without
// proof of origin, see the package doc) are reported in Message; they do not
// make the result fail.
//
// A broken chain is reported in the result (OK=false, BrokenAt, Message), not
// as an error. core.ErrKeysLocked is returned when sealed rows exist but the
// MAC key is unavailable.
func (s *Service) Verify(ctx context.Context) (*core.AuditVerify, error) {
	res := &core.AuditVerify{OK: true}
	macOK := s.macOf(purposeChain, zeroHash) != nil
	err := s.env.DB.Read(ctx, func(tx *sql.Tx) error {
		marker, hasMarker, err := metaInt(ctx, tx, metaUnsealed)
		if err != nil {
			return err
		}
		anchor, hasAnchor, err := readAnchor(ctx, tx)
		if err != nil {
			return err
		}
		hv, hasHead, err := getMeta(ctx, tx, metaHead)
		if err != nil {
			return err
		}
		var head checkpoint
		if hasHead {
			var ok bool
			if head, ok = parseHead(hv); !ok {
				return fail(res, 0, "the chain head checkpoint is malformed")
			}
		}
		if !macOK {
			// Without the key only a log that was never sealed can be checked.
			if hasAnchor || hasHead {
				return core.ErrKeysLocked
			}
			var first sql.NullInt64
			if err := tx.QueryRowContext(ctx, `SELECT min(seq) FROM audit_log`).Scan(&first); err != nil {
				return err
			}
			if first.Valid && (!hasMarker || marker > first.Int64) {
				return core.ErrKeysLocked
			}
		}
		if hasHead && !s.headValid(head) {
			return fail(res, head.seq, "the chain head checkpoint is not authentic")
		}
		// Invariants of an untampered log: the unsealed segment always starts
		// after the last sealed row, and pruned rows were sealed, so an anchor
		// implies a head checkpoint.
		if hasMarker && hasHead && marker <= head.seq {
			return fail(res, marker, fmt.Sprintf("rows from seq %d are marked unsealed but precede the sealed head (seq %d)", marker, head.seq))
		}
		if hasAnchor && !hasHead {
			return fail(res, anchor.seq, "the chain head checkpoint is missing")
		}

		prev := zeroHash
		if hasAnchor {
			if !s.anchorValid(anchor) {
				return fail(res, anchor.seq, "the prune anchor is not authentic")
			}
			prev = anchor.hash
			if hasHead && head.seq < anchor.seq {
				return fail(res, head.seq, "the chain head checkpoint precedes the prune anchor")
			}
		}
		headSeen := hasHead && hasAnchor && head.seq == anchor.seq
		if headSeen && !bytes.Equal(head.hash, anchor.hash) {
			return fail(res, head.seq, "the chain head checkpoint does not match the prune anchor")
		}

		rows, err := tx.QueryContext(ctx, `SELECT `+rowCols+` FROM audit_log ORDER BY seq`)
		if err != nil {
			return err
		}
		defer rows.Close()
		var unsealed, sealed, unverified int64
		var unverifiedSeqs []string
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			if res.Checked == 0 {
				res.FirstSeq = r.seq
				if hasAnchor && r.seq <= anchor.seq {
					return fail(res, r.seq, "a row precedes the prune anchor")
				}
			}
			res.LastSeq = r.seq
			canon := r.canonical()
			var want []byte
			inUnsealed := hasMarker && r.seq >= marker
			if inUnsealed {
				want = unkeyedChain(prev, canon)
				unsealed++
			} else {
				want = s.macChain(prev, canon)
				sealed++
			}
			if !bytes.Equal(r.prevHash, prev) {
				return fail(res, r.seq, fmt.Sprintf("row %d does not link to its predecessor (rows deleted or reordered)", r.seq))
			}
			if want == nil || !bytes.Equal(r.hash, want) {
				return fail(res, r.seq, fmt.Sprintf("row %d was modified (hash mismatch)", r.seq))
			}
			if hasHead && r.seq == head.seq {
				if !bytes.Equal(r.hash, head.hash) {
					return fail(res, r.seq, "the chain head checkpoint does not match its row")
				}
				headSeen = true
			}
			if !inUnsealed && r.action == core.ActAuditReseal {
				// Authenticated (sealed) entry: count the rows it names that
				// were not pruned since (Prune removes a prefix).
				var d resealDetails
				if json.Unmarshal([]byte(r.details), &d) == nil && d.Unverified > 0 && d.ToSeq >= res.FirstSeq {
					n := d.Unverified
					for _, q := range d.UnverifiedSeqs {
						if q < res.FirstSeq {
							n--
						} else if len(unverifiedSeqs) < 10 {
							unverifiedSeqs = append(unverifiedSeqs, strconv.FormatInt(q, 10))
						}
					}
					unverified += max(n, 0)
				}
			}
			res.Checked++
			prev = r.hash
		}
		if err := rows.Err(); err != nil {
			return err
		}
		switch {
		case hasHead && !headSeen:
			return fail(res, head.seq, fmt.Sprintf("rows up to seq %d are missing (log truncated)", head.seq))
		case !hasHead && sealed > 0:
			return fail(res, res.FirstSeq, "sealed rows exist but the chain head checkpoint is missing")
		case hasMarker && (res.Checked == 0 || marker > res.LastSeq):
			return fail(res, marker, "unsealed rows are missing (log truncated)")
		}
		var notes []string
		if unsealed > 0 {
			notes = append(notes, fmt.Sprintf("%d of %d rows are not sealed yet (written while the keys were locked)", unsealed, res.Checked))
		}
		if unverified > 0 {
			list := strings.Join(unverifiedSeqs, ", ")
			if int64(len(unverifiedSeqs)) < unverified {
				list += ", …"
			}
			were := "rows were"
			if unverified == 1 {
				were = "row was"
			}
			notes = append(notes, fmt.Sprintf("%d %s sealed after an unlock without proof of origin: written "+
				"while the keys were unavailable, but not by the server process that sealed them (seq %s; see the %s entries)",
				unverified, were, list, core.ActAuditReseal))
		}
		res.Message = strings.Join(notes, "; ")
		return nil
	})
	if errors.As(err, new(verifyFailure)) {
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// verifyFailure aborts the verification walk after fail filled the result.
type verifyFailure struct{}

func (verifyFailure) Error() string { return "audit chain broken" }

func fail(res *core.AuditVerify, seq int64, msg string) error {
	res.OK = false
	res.BrokenAt = seq
	res.Message = msg
	return verifyFailure{}
}

// Prune deletes the oldest rows whose time is before `before`, keeping the
// chain verifiable: only a contiguous prefix is removed (a newer row with an
// older timestamp stops the prefix), never rows that are still unsealed, and
// the last removed row becomes the authenticated anchor. Rows are deleted in
// batches of 5000 per transaction. Needs the MAC key (core.ErrKeysLocked).
func (s *Service) Prune(ctx context.Context, before time.Time) (int, error) {
	if s.macOf(purposeAnchor, zeroHash) == nil {
		return 0, core.ErrKeysLocked
	}
	total := 0
	for {
		n, err := s.pruneBatch(ctx, db.Ms(before))
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	if total > 0 {
		s.log.Info("audit: pruned old entries", "count", total, "before", before.UTC().Format(time.RFC3339))
	}
	return total, nil
}

// pruneBatch deletes up to pruneBatch rows of the prunable prefix.
func (s *Service) pruneBatch(ctx context.Context, beforeMs int64) (int, error) {
	deleted := 0
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		deleted = 0
		var first sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT min(seq) FROM audit_log`).Scan(&first); err != nil {
			return err
		}
		if !first.Valid {
			return nil
		}
		// The prefix ends before the first row that is not old enough.
		var stop sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT min(seq) FROM audit_log WHERE at >= ?`, beforeMs).Scan(&stop); err != nil {
			return err
		}
		end := int64(-1)
		if stop.Valid {
			end = stop.Int64 - 1
		} else if err := tx.QueryRowContext(ctx, `SELECT max(seq) FROM audit_log`).Scan(&end); err != nil {
			return err
		}
		if marker, ok, err := metaInt(ctx, tx, metaUnsealed); err != nil {
			return err
		} else if ok && end >= marker {
			end = marker - 1
		}
		end = min(end, first.Int64+pruneBatch-1)
		if end < first.Int64 {
			return nil
		}
		var h []byte
		if err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log WHERE seq <= ? ORDER BY seq DESC LIMIT 1`, end).Scan(&end, &h); err != nil {
			return err
		}
		m := s.macOf(purposeAnchor, be64(end), h)
		if m == nil {
			return core.ErrKeysLocked
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE seq <= ?`, end)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		deleted = int(n)
		if err := setMeta(ctx, tx, metaAnchorSeq, strconv.FormatInt(end, 10)); err != nil {
			return err
		}
		if err := setMeta(ctx, tx, metaAnchorHash, hex.EncodeToString(h)); err != nil {
			return err
		}
		return setMeta(ctx, tx, metaAnchorMAC, hex.EncodeToString(m))
	})
	return deleted, err
}
