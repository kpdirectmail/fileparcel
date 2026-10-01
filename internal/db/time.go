package db

import (
	"database/sql"
	"time"
)

// Ms converts t to Unix milliseconds (UTC). The zero time maps to 0.
func Ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// FromMs converts Unix milliseconds to a UTC time. 0 maps to the zero time.
func FromMs(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// NullMs converts an optional time for a nullable INTEGER column: nil or the
// zero time become NULL. Use it directly as a query argument.
func NullMs(t *time.Time) sql.NullInt64 {
	if t == nil || t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMilli(), Valid: true}
}

// NullTime is NullMs for a non-pointer time (zero time = NULL).
func NullTime(t time.Time) sql.NullInt64 { return NullMs(&t) }

// FromNullMs converts a scanned nullable INTEGER timestamp to *time.Time (nil for NULL).
func FromNullMs(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.UnixMilli(n.Int64).UTC()
	return &t
}

// NullString maps "" to NULL.
func NullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// NullInt64 maps a nil pointer to NULL.
func NullInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

// FromNullInt64 maps NULL to nil.
func FromNullInt64(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

// Bool converts a bool to the INTEGER 0/1 stored in boolean columns.
func Bool(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
