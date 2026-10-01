package core

import (
	"bytes"
	"encoding/json"
)

// Pagination limits (DESIGN §9.5).
const (
	DefaultPageLimit = 100
	MaxPageLimit     = 500
)

// PageReq is a keyset-pagination request, parsed from ?cursor=&limit=&sort=&desc=
// by httpx.PageReq. Cursor is opaque (httpx.EncodeCursor of the last row's
// sort key + id). Sort names are endpoint-specific (e.g. name|size|updated|kind).
type PageReq struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Sort   string `json:"sort,omitempty"`
	Desc   bool   `json:"desc,omitempty"`
}

// EffectiveLimit returns Limit clamped to 1..MaxPageLimit (DefaultPageLimit when <= 0).
func (q PageReq) EffectiveLimit() int {
	switch {
	case q.Limit <= 0:
		return DefaultPageLimit
	case q.Limit > MaxPageLimit:
		return MaxPageLimit
	}
	return q.Limit
}

// Page is one page of results. Items is never null in JSON when built with
// NewPage; NextCursor is empty on the last page.
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// NewPage returns a Page with a non-nil Items slice.
func NewPage[T any](items []T, next string) Page[T] {
	if items == nil {
		items = []T{}
	}
	return Page[T]{Items: items, NextCursor: next}
}

// MarshalJSON renders nil Items as [].
func (p Page[T]) MarshalJSON() ([]byte, error) {
	type page Page[T]
	if p.Items == nil {
		p.Items = []T{}
	}
	return json.Marshal(page(p))
}

// Opt is an optional PATCH field that distinguishes "absent" from "null":
//
//	absent        -> Set=false
//	"field":null  -> Set=true, Null=true
//	"field":v     -> Set=true, V=v
//
// Declare it with omitzero: `json:"expires_at,omitzero"`.
type Opt[T any] struct {
	Set  bool
	Null bool
	V    T
}

// Some returns a set, non-null Opt.
func Some[T any](v T) Opt[T] { return Opt[T]{Set: true, V: v} }

// Null returns a set, null Opt.
func Null[T any]() Opt[T] { return Opt[T]{Set: true, Null: true} }

// Ptr returns nil when unset or null, else &V.
func (o Opt[T]) Ptr() *T {
	if !o.Set || o.Null {
		return nil
	}
	v := o.V
	return &v
}

// IsZero reports whether the field is absent (for omitzero).
func (o Opt[T]) IsZero() bool { return !o.Set }

// UnmarshalJSON records presence and null-ness.
func (o *Opt[T]) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		o.Null = true
		var zero T
		o.V = zero
		return nil
	}
	o.Null = false
	return json.Unmarshal(b, &o.V)
}

// MarshalJSON renders null for unset/null values, else V.
func (o Opt[T]) MarshalJSON() ([]byte, error) {
	if !o.Set || o.Null {
		return []byte("null"), nil
	}
	return json.Marshal(o.V)
}
