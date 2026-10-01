package settings

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/logx"
)

// Mask replaces secret values wherever a value would otherwise be shown
// (Raw, audit details). A change that sends Mask back for a secret leaves the
// stored secret untouched, so a form can round-trip the masked value.
const Mask = "********"

// SecretAAD returns the field-encryption AAD of a secret setting
// ("settings.value|<key>"): a sealed value only opens under its own key.
func SecretAAD(key string) string { return "settings.value|" + key }

// writeTimeout bounds one Set/Reset transaction. The transaction does not
// inherit the caller's cancellation: once fileparcel.toml has been rewritten
// the database side must complete (or be undone) as a unit.
const writeTimeout = 30 * time.Second

// Service implements core.Settings (DESIGN §11). Store is an alias.
//
// Values of normal keys live in the settings table as canonical JSON (rows
// equal to the default are deleted); secret values are stored as the JSON
// string of Keys.SealField(SecretAAD(key), plaintext). Bootstrap keys
// (Def.Bootstrap: server.*, log.level) live in fileparcel.toml and are read
// from a private clone of env.Config; a change is written to the file as it
// is on disk then (atomic TOML rewrite, see applyBootstrap), which becomes
// the new private copy. Keys overridden by FILEPARCEL_* environment
// variables are reported in the catalog and refuse changes.
//
// The shared env.Config is never modified: it keeps the values the process
// started with (which is what restart-required keys mean) and other
// packages may read it concurrently without locks. Live readers use the
// getters, which reflect every change immediately.
//
// Reads never touch the database: they are served from an immutable snapshot
// behind an atomic pointer, rebuilt by every Set/Reset and reloaded from the
// database whenever settings.changed is published. Writers are serialised.
//
// Nothing here needs the master key except reading or writing a non-empty
// secret, so the store works while the keys are locked.
type Service struct {
	env *core.Env
	log *slog.Logger
	// conf is the store's private copy of the bootstrap configuration
	// (nil without env.Config). Only touched with mu held.
	conf *config.Config

	mu   sync.Mutex // serialises writers and reloads
	snap atomic.Pointer[snapshot]

	// startup holds the effective values of Restart keys when the process
	// started (RestartRequired compares against them).
	startup map[string]json.RawMessage

	stop      func()
	done      chan struct{}
	closeOnce sync.Once
}

// Store is the name used by DESIGN §11.3.
type Store = Service

var _ core.Settings = (*Service)(nil)

// row is one stored value (a settings table row, or the in-memory metadata
// of a bootstrap key changed by this process).
type row struct {
	raw json.RawMessage // canonical JSON; secrets: JSON string of the sealed value
	at  time.Time
	by  string
}

// snapshot is an immutable view of every value. Never modify one in place.
type snapshot struct {
	rows map[string]row             // settings table rows (every key, registered or not)
	boot map[string]json.RawMessage // canonical values of bootstrap keys (from the private config)
	meta map[string]row             // updated_at/by of bootstrap keys changed by this process
	vals map[string]any             // decoded effective values of registered non-secret keys
}

// New creates the store and loads the current values (constructor signature
// fixed by DESIGN §5.2). env may be nil and env.DB/env.Config may be nil (unit
// tests): values are then kept in memory only.
func New(env *core.Env) (*Service, error) {
	s := &Service{env: env, log: slog.Default()}
	if env != nil && env.Log != nil {
		s.log = env.Log
	}
	if env != nil && env.Config != nil {
		s.conf = env.Config.Clone()
	}
	s.mu.Lock()
	err := s.reloadLocked(context.Background())
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("settings: load: %w", err)
	}
	s.startup = map[string]json.RawMessage{}
	snap := s.snap.Load()
	for _, d := range Defs() {
		if d.Restart && !d.Secret {
			s.startup[d.Key] = s.effectiveRaw(snap, d)
		}
	}
	if env != nil && env.Bus != nil {
		ch, cancel := env.Bus.Subscribe(events.TopicSettingsChanged)
		s.stop, s.done = cancel, make(chan struct{})
		go s.watch(ch)
	}
	return s, nil
}

// Close stops the settings.changed watcher (io.Closer; called by wire's
// cleanup). It is idempotent.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		if s.stop != nil {
			s.stop()
			<-s.done
		}
	})
	return nil
}

// watch reloads the snapshot from the database on settings.changed, so rows
// written by another component (which must publish the event) become visible.
func (s *Service) watch(ch <-chan events.Event) {
	defer close(s.done)
	for range ch {
		// Coalesce bursts: one reload covers every event already queued.
		for drained := false; !drained; {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
			default:
				drained = true
			}
		}
		s.mu.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := s.reloadLocked(ctx); err != nil {
			s.log.Warn("settings: reload failed", "err", err)
		}
		cancel()
		s.mu.Unlock()
	}
}

// cfg returns the private bootstrap configuration (nil when there is none).
func (s *Service) cfg() *config.Config { return s.conf }

func (s *Service) db() *db.DB {
	if s.env == nil {
		return nil
	}
	return s.env.DB
}

// reloadLocked rebuilds the snapshot from the database and the private config.
// s.mu must be held. Without a database the in-memory rows are kept.
func (s *Service) reloadLocked(ctx context.Context) error {
	old := s.snap.Load()
	rows := map[string]row{}
	if d := s.db(); d != nil {
		rs, err := d.Query(ctx, `SELECT key, value, updated_at, updated_by FROM settings`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var (
				key, value string
				at         int64
				by         sql.NullString
			)
			if err := rs.Scan(&key, &value, &at, &by); err != nil {
				return err
			}
			rows[key] = row{raw: json.RawMessage(value), at: db.FromMs(at), by: by.String}
		}
		if err := rs.Err(); err != nil {
			return err
		}
	} else if old != nil {
		rows = old.rows
	}
	meta := map[string]row{}
	if old != nil {
		meta = old.meta
	}
	s.snap.Store(s.build(rows, meta))
	return nil
}

// build derives a complete snapshot (bootstrap values, decoded values) from rows.
func (s *Service) build(rows, meta map[string]row) *snapshot {
	sn := &snapshot{rows: rows, meta: meta, boot: map[string]json.RawMessage{}, vals: map[string]any{}}
	defs := Defs()
	if c := s.cfg(); c != nil {
		for _, d := range defs {
			if d.Bootstrap {
				if raw, ok := bootRaw(c, d); ok {
					sn.boot[d.Key] = raw
				}
			}
		}
	}
	for _, d := range defs {
		if d.Secret {
			continue
		}
		if r, ok := rows[d.Key]; ok && !d.Bootstrap {
			if _, _, err := d.Decode(r.raw); err != nil {
				s.log.Warn("settings: ignoring invalid stored value (using the default)", "key", d.Key, "err", err)
			}
		}
		raw := s.effectiveRaw(sn, d)
		_, v, err := d.Decode(raw)
		if err != nil {
			_, v, _ = d.Decode(d.DefaultJSON())
		}
		sn.vals[d.Key] = v
	}
	return sn
}

// bootRaw returns the canonical value of a bootstrap key from c.
func bootRaw(c *config.Config, d Def) (json.RawMessage, bool) {
	v, ok := c.Get(d.Key)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	canon, _, err := d.Decode(b)
	if err != nil {
		return nil, false
	}
	return canon, true
}

// effectiveRaw returns the current canonical value of d: the bootstrap value
// (from the snapshot, never the mutable configuration), the stored row (when
// it still validates) or the default. For secrets it returns the stored
// (sealed) JSON string, or the default.
func (s *Service) effectiveRaw(sn *snapshot, d Def) json.RawMessage {
	if d.Bootstrap {
		if raw, ok := sn.boot[d.Key]; ok {
			return raw
		}
	}
	if r, ok := sn.rows[d.Key]; ok {
		if d.Secret {
			return r.raw
		}
		if canon, _, err := d.Decode(r.raw); err == nil {
			return canon
		}
	}
	return d.DefaultJSON()
}

// ---------- reads ----------

// Raw returns the current canonical JSON value (the default when unset).
// Secrets return the masked form: "" when unset, Mask when set.
func (s *Service) Raw(key string) (json.RawMessage, error) {
	d, ok := Lookup(key)
	if !ok {
		return nil, core.NotFoundf("unknown setting %q", key)
	}
	sn := s.snap.Load()
	if d.Secret {
		if _, set := sn.rows[key]; set {
			return json.RawMessage(strconv.Quote(Mask)), nil
		}
		return json.RawMessage(`""`), nil
	}
	return slices.Clone(s.effectiveRaw(sn, d)), nil
}

// value returns the decoded value of a non-secret key (nil when unknown).
func (s *Service) value(key string) any {
	sn := s.snap.Load()
	if v, ok := sn.vals[key]; ok {
		return v
	}
	d, ok := Lookup(key) // registered after the snapshot was built
	if !ok || d.Secret {
		return nil
	}
	_, v, err := d.Decode(s.effectiveRaw(sn, d))
	if err != nil {
		return nil
	}
	return v
}

// Int returns an int setting (0 if unknown or not an int).
func (s *Service) Int(key string) int64 {
	n, _ := s.value(key).(int64)
	return n
}

// Bool returns a bool setting (false if unknown or not a bool).
func (s *Service) Bool(key string) bool {
	b, _ := s.value(key).(bool)
	return b
}

// String returns a string-like setting (durations are formatted, ints are
// decimal, bools "true"/"false"). Secrets return "" — use Secret.
func (s *Service) String(key string) string {
	switch x := s.value(key).(type) {
	case string:
		return x
	case time.Duration:
		return formatDuration(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// Strings returns a list setting (never nil; a copy).
func (s *Service) Strings(key string) []string {
	l, _ := s.value(key).([]string)
	if l == nil {
		return []string{}
	}
	return slices.Clone(l)
}

// Duration returns a duration setting (0 if unknown or not a duration).
func (s *Service) Duration(key string) time.Duration {
	d, _ := s.value(key).(time.Duration)
	return d
}

// Secret returns the plaintext of a secret setting ("" when unset). It needs
// the master key: ErrKeysLocked while locked, ErrCorrupt when the stored
// value fails authentication.
func (s *Service) Secret(key string) (string, error) {
	d, ok := Lookup(key)
	if !ok {
		return "", core.NotFoundf("unknown setting %q", key)
	}
	if !d.Secret {
		return "", core.Invalid(key, "not a secret setting")
	}
	r, ok := s.snap.Load().rows[key]
	if !ok {
		return "", nil
	}
	var sealed string
	if err := json.Unmarshal(r.raw, &sealed); err != nil {
		return "", core.Wrap(core.ErrCorrupt, "stored secret "+key+" is malformed", err)
	}
	if sealed == "" {
		return "", nil
	}
	if s.env == nil || s.env.Keys == nil {
		return "", core.ErrKeysLocked
	}
	pt, err := s.env.Keys.OpenField(SecretAAD(key), sealed)
	if err != nil {
		if ce := core.AsError(err); ce != nil {
			return "", err
		}
		return "", core.Wrap(core.ErrCorrupt, "stored secret "+key+" failed its integrity check", err)
	}
	return string(pt), nil
}

// RestartRequired lists the Restart keys whose value differs from the value
// the process started with (for SystemInfo.RestartRequired and the UI banner).
func (s *Service) RestartRequired() []string {
	sn := s.snap.Load()
	out := []string{}
	for key, start := range s.startup {
		d, ok := Lookup(key)
		if !ok {
			continue
		}
		if !bytes.Equal(s.effectiveRaw(sn, d), start) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// Catalog lists every registered setting with value and default. Secrets are
// masked (value and default null; is_set reports whether one is stored).
func (s *Service) Catalog(ctx context.Context) ([]core.SettingView, error) {
	sn := s.snap.Load()
	c := s.cfg()
	defs := Defs()
	out := make([]core.SettingView, 0, len(defs))
	for _, d := range defs {
		def := d.DefaultJSON()
		v := core.SettingView{
			Key: d.Key, Section: d.Section, Order: d.Order, Type: string(d.Type),
			Label: d.Label, Description: d.Description,
			Enum: slices.Clone(d.Enum), Restart: d.Restart, Secret: d.Secret, Bootstrap: d.Bootstrap,
			Managed: d.Managed,
		}
		if d.Max > d.Min {
			mn, mx := d.Min, d.Max
			v.Min, v.Max = &mn, &mx
		}
		if d.Secret {
			_, v.IsSet = sn.rows[d.Key]
			v.Value, v.Default = json.RawMessage("null"), json.RawMessage("null")
		} else {
			cur := s.effectiveRaw(sn, d)
			v.Value, v.Default = slices.Clone(cur), def
			v.IsSet = !bytes.Equal(cur, def)
		}
		if d.Bootstrap && c != nil && c.IsOverridden(d.Key) {
			v.OverriddenByEnv = config.EnvName(d.Key)
		}
		r, ok := sn.rows[d.Key]
		if d.Bootstrap && c != nil {
			r, ok = sn.meta[d.Key]
		}
		if ok && !r.at.IsZero() {
			at := r.at
			v.UpdatedAt, v.UpdatedBy = &at, r.by
		}
		out = append(out, v)
	}
	return out, nil
}

// ---------- writes ----------

// change is one validated, effective change.
type change struct {
	def   Def
	canon json.RawMessage // new canonical value (plaintext JSON string for secrets)
	val   any             // decoded new value
	prev  json.RawMessage // previous canonical value (secrets: raw row or default)
	store json.RawMessage // row value to store; nil = delete the row
	stale bool            // the stored row no longer validates (prev is the default)
}

// Set validates every change (type, enum, range, custom Validate) before
// applying anything, then applies them atomically: bootstrap keys by an
// atomic rewrite of fileparcel.toml, the others plus one settings.change
// audit entry per changed key (secrets masked) in one transaction. It then
// publishes settings.changed{keys} and reports the changed keys that need a
// restart. Keys whose value does not change are accepted (listed in Applied)
// without audit or event. Changing a key overridden by the environment is a
// 409 conflict; storing a non-empty secret needs the master key.
func (s *Service) Set(ctx context.Context, by *core.Principal, changes map[string]json.RawMessage) (*core.SettingsResult, error) {
	return s.apply(ctx, by, changes, false)
}

// Reset restores the default value of key (a secret is cleared). 404 for
// unknown keys; 409 when the key is overridden by the environment.
func (s *Service) Reset(ctx context.Context, by *core.Principal, key string) error {
	d, ok := Lookup(key)
	if !ok {
		return core.NotFoundf("unknown setting %q", key)
	}
	_, err := s.apply(ctx, by, map[string]json.RawMessage{key: d.DefaultJSON()}, true)
	return err
}

func (s *Service) apply(ctx context.Context, by *core.Principal, changes map[string]json.RawMessage, reset bool) (*core.SettingsResult, error) {
	res := &core.SettingsResult{Applied: []string{}, RestartRequired: []string{}}
	if len(changes) == 0 {
		return res, nil
	}
	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	s.mu.Lock()
	defer s.mu.Unlock()
	sn := s.snap.Load()
	c := s.cfg()

	var list []change
	for _, k := range keys {
		d, ok := Lookup(k)
		if !ok {
			return nil, core.Invalid(k, "unknown setting")
		}
		raw := changes[k]
		if d.Secret {
			var str string
			if json.Unmarshal(raw, &str) == nil && str == Mask {
				res.Applied = append(res.Applied, k) // masked round-trip: unchanged
				continue
			}
		}
		canon, v, err := d.Decode(raw)
		if err != nil {
			return nil, core.Invalid(k, err.Error())
		}
		ch := change{def: d, canon: canon, val: v, prev: s.effectiveRaw(sn, d)}
		if r, ok := sn.rows[k]; ok && !d.Secret && !(d.Bootstrap && c != nil) {
			// A stored row that no longer validates (an enum value removed
			// or a rule tightened by an upgrade) is in effect the default,
			// so setting the default must still remove it.
			_, _, err := d.Decode(r.raw)
			ch.stale = err != nil
		}
		if d.Bootstrap && c != nil && c.IsOverridden(k) {
			if bytes.Equal(canon, ch.prev) {
				res.Applied = append(res.Applied, k) // unchanged: a form may send it back
				continue
			}
			return nil, &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: k,
				Message: fmt.Sprintf("%s is set by the environment variable %s; change it there", k, config.EnvName(k))}
		}
		res.Applied = append(res.Applied, k)
		switch {
		case d.Secret:
			_, stored := sn.rows[k]
			if v.(string) == "" {
				if !stored {
					continue
				}
				ch.store = nil
			} else {
				ch.store = canon // sealed below
			}
		case bytes.Equal(canon, ch.prev) && !ch.stale:
			continue
		case d.Bootstrap && c != nil:
			// stored in fileparcel.toml, not in the table
		case bytes.Equal(canon, d.DefaultJSON()):
			ch.store = nil
		default:
			ch.store = canon
		}
		list = append(list, ch)
	}
	if len(list) == 0 {
		return res, nil
	}

	// Seal secrets before touching anything.
	for i := range list {
		if list[i].def.Secret && list[i].store != nil {
			sealed, err := s.seal(list[i].def.Key, list[i].val.(string))
			if err != nil {
				return nil, err
			}
			b, _ := json.Marshal(sealed)
			list[i].store = b
		}
	}

	undo, err := s.applyBootstrap(list)
	if err != nil {
		return nil, err
	}

	now := s.env.Now()
	who := actorName(ctx, by)
	actx := withActor(ctx, by)
	rows := maps(sn.rows)
	meta := maps(sn.meta)
	for _, ch := range list {
		switch {
		case ch.def.Bootstrap && c != nil:
			meta[ch.def.Key] = row{raw: ch.canon, at: now, by: who}
		case ch.store == nil:
			delete(rows, ch.def.Key)
		default:
			rows[ch.def.Key] = row{raw: ch.store, at: now, by: who}
		}
	}
	if d := s.db(); d != nil {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(actx), writeTimeout)
		err = d.Tx(tctx, func(tx *sql.Tx) error {
			for _, ch := range list {
				if !(ch.def.Bootstrap && c != nil) {
					if ch.store == nil {
						if _, err := tx.ExecContext(tctx, `DELETE FROM settings WHERE key = ?`, ch.def.Key); err != nil {
							return err
						}
					} else if _, err := tx.ExecContext(tctx, `INSERT INTO settings (key, value, updated_at, updated_by)
						VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value,
						updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
						ch.def.Key, string(ch.store), db.Ms(now), db.NullString(who)); err != nil {
						return err
					}
				}
				if s.env.Audit != nil {
					if err := s.env.Audit.RecordTx(tctx, tx, auditEntry(ch, reset)); err != nil {
						return err
					}
				}
			}
			return nil
		})
		cancel()
		if err != nil {
			undo()
			return nil, fmt.Errorf("settings: save: %w", err)
		}
	} else if s.env != nil && s.env.Audit != nil {
		for _, ch := range list {
			s.env.Audit.Record(actx, auditEntry(ch, reset))
		}
	}
	next := s.build(rows, meta)
	s.snap.Store(next)
	// log.level applies live. It changes with its own change, and also when
	// applyBootstrap picked up an edit made to fileparcel.toml meanwhile:
	// the level in effect must be the one shown.
	if lvl, _ := next.vals["log.level"].(string); lvl != "" && lvl != sn.vals["log.level"] {
		if err := logx.SetLevel(lvl); err != nil {
			s.log.Warn("settings: log level not applied", "err", err)
		}
	}

	changed := make([]string, 0, len(list))
	for _, ch := range list {
		changed = append(changed, ch.def.Key)
		// Removing a stale row leaves the value (the default) as it was.
		if ch.def.Restart && !(ch.stale && bytes.Equal(ch.canon, ch.prev)) {
			res.RestartRequired = append(res.RestartRequired, ch.def.Key)
		}
	}
	if s.env != nil && s.env.Bus != nil {
		s.env.Bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: changed}})
	}
	return res, nil
}

// seal encrypts a secret value for storage.
func (s *Service) seal(key, plaintext string) (string, error) {
	if s.env == nil || s.env.Keys == nil || s.env.Keys.State() != core.KeyStateUnlocked {
		return "", core.Wrap(core.ErrKeysLocked, "secret settings can only be changed while the server is unlocked", nil)
	}
	sealed, err := s.env.Keys.SealField(SecretAAD(key), []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("settings: seal %s: %w", key, err)
	}
	return sealed, nil
}

// applyBootstrap writes the bootstrap keys of list to fileparcel.toml. The
// changes are applied to the file as it is on disk now, not to the copy the
// store holds: the file may have been edited since the server started
// ("fileparcel config edit" says to restart later), and rewriting it from
// the old copy would silently revert those edits. The result is validated
// as a whole, saved atomically and becomes the store's configuration (so
// the catalog and RestartRequired show the edits too). On failure nothing is
// changed. The returned undo puts back the previous configuration and the
// exact previous file content if a later step fails.
func (s *Service) applyBootstrap(list []change) (undo func(), err error) {
	old := s.cfg()
	noop := func() {}
	if old == nil {
		return noop, nil
	}
	var order []string
	for _, ch := range list {
		if ch.def.Bootstrap {
			order = append(order, ch.def.Key)
		}
	}
	if len(order) == 0 {
		return noop, nil
	}
	c, orig := old.Clone(), []byte(nil)
	if old.Path() != "" {
		fresh, data, err := old.Reread()
		switch {
		case err == nil:
			c, orig = fresh, data
		case errors.Is(err, fs.ErrNotExist):
			// Deleted behind our back: Save recreates it from the copy.
		default:
			return nil, core.Errorf(core.ErrConflict, "%v; fix the file first (fileparcel config edit)", err)
		}
	}
	fileErr := c.Validate() // problems the file had before this change
	for _, ch := range list {
		if !ch.def.Bootstrap {
			continue
		}
		if _, ok := c.Get(ch.def.Key); !ok {
			return nil, fmt.Errorf("settings: bootstrap key %s is not in fileparcel.toml", ch.def.Key)
		}
		v := ch.val
		if dur, ok := v.(time.Duration); ok {
			v = formatDuration(dur)
		}
		if err := c.Set(ch.def.Key, v); err != nil {
			return nil, core.Invalid(ch.def.Key, err.Error())
		}
	}
	if err := c.Validate(); err != nil {
		if fileErr != nil && !slices.ContainsFunc(validationErrors(err), func(ve *config.ValidationError) bool {
			return slices.Contains(order, ve.Key)
		}) {
			// Not caused by this change: the file was edited into an invalid state.
			var msgs []string
			for _, ve := range validationErrors(fileErr) {
				msgs = append(msgs, ve.Key+": "+ve.Msg)
			}
			return nil, core.Errorf(core.ErrConflict, "fileparcel.toml has errors (%s); fix the file first (fileparcel config edit)",
				strings.Join(msgs, "; "))
		}
		return nil, validationError(err, order)
	}
	if c.Path() != "" {
		if err := c.Save(); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
	}
	s.conf = c
	return func() {
		s.conf = old
		if c.Path() == "" {
			return
		}
		var err error
		if orig != nil {
			err = c.RestoreFile(orig)
		} else {
			err = old.Save()
		}
		if err != nil {
			s.log.Error("settings: could not restore fileparcel.toml", "err", err)
		}
	}, nil
}

// validationErrors returns the per-key errors of a config.Validate error.
func validationErrors(err error) []*config.ValidationError {
	errs := []error{err}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		errs = joined.Unwrap()
	}
	var out []*config.ValidationError
	for _, e := range errs {
		var ve *config.ValidationError
		if errors.As(e, &ve) {
			out = append(out, ve)
		}
	}
	return out
}

// validationError maps a config.Validate error to a 422 on the most relevant key.
func validationError(err error, changed []string) error {
	all := validationErrors(err)
	for _, ve := range all {
		if slices.Contains(changed, ve.Key) {
			return core.Invalid(ve.Key, ve.Msg)
		}
	}
	if len(all) > 0 {
		return core.Invalid(all[0].Key, all[0].Msg)
	}
	return core.Wrap(core.ErrInvalid, err.Error(), err)
}

func auditEntry(ch change, reset bool) core.AuditEntry {
	details := map[string]any{"key": ch.def.Key}
	if ch.def.Secret {
		details["value"] = maskFor(ch.store != nil)
		details["previous"] = maskFor(len(ch.prev) > 0 && string(ch.prev) != `""`)
	} else {
		details["value"] = ch.canon
		details["previous"] = ch.prev
	}
	if reset {
		details["reset"] = true
	}
	if ch.stale {
		details["previous_invalid"] = true // an unusable stored value, in effect the default
	}
	return core.AuditEntry{Action: core.ActSettingsChange, TargetType: "setting", TargetID: ch.def.Key,
		TargetName: ch.def.Label, Details: details}
}

func maskFor(set bool) string {
	if set {
		return Mask
	}
	return ""
}

// withActor makes by the context principal (for audit) unless one is present.
func withActor(ctx context.Context, by *core.Principal) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if by != nil && core.PrincipalFrom(ctx) == nil {
		ctx = core.WithPrincipal(ctx, by)
	}
	return ctx
}

// actorName is the updated_by value: the username of by (or of the context
// principal), else its user id.
func actorName(ctx context.Context, by *core.Principal) string {
	p := by
	if p == nil && ctx != nil {
		p = core.PrincipalFrom(ctx)
	}
	switch {
	case p == nil:
		return ""
	case p.Username != "":
		return p.Username
	}
	return p.UserID
}

func maps(m map[string]row) map[string]row {
	out := make(map[string]row, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}
