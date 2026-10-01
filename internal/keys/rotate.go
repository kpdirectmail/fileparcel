package keys

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/settings"
)

// testHook, when set by tests, is called at named points of RotateMaster;
// a non-nil error aborts the rotation there (simulated crash).
var testHook func(stage string) error

func hook(stage string) error {
	if testHook != nil {
		return testHook(stage)
	}
	return nil
}

// sealedColumn describes a field-encrypted column (DESIGN §7.5).
type sealedColumn struct {
	table, pk, col string
	aadPrefix      string // AAD = aadPrefix + pk value
	json           bool   // the column holds a JSON string whose value is the sealed text (settings)
	// only, when set, returns the primary keys whose values may be sealed
	// (evaluated per query). The settings table also holds plain values,
	// and a plain string that happens to start with "v1:" must be neither
	// re-sealed nor counted as a (broken) reference.
	only func() []string
}

// sealedColumns are re-sealed by RotateKEK("field"). Identifiers are
// constants; values are always bound parameters.
var sealedColumns = []sealedColumn{
	{table: "totp_secrets", pk: "user_id", col: "secret_enc", aadPrefix: "totp_secrets.secret_enc|"},
	{table: "webauthn_credentials", pk: "id", col: "credential_enc", aadPrefix: "webauthn_credentials.credential_enc|"},
	{table: "invites", pk: "id", col: "token_enc", aadPrefix: "invites.token_enc|"},
	{table: "shares", pk: "id", col: "token_enc", aadPrefix: "shares.token_enc|"},
	{table: "settings", pk: "key", col: "value", aadPrefix: "settings.value|", json: true, only: secretSettingKeys},
	// The .zip passwords of protected uploads in flight (wiped to NULL when
	// the batch finishes; the compare-and-swap never brings one back).
	{table: "upload_batches", pk: "id", col: "zip_password_enc", aadPrefix: "upload_batches.zip_password_enc|"},
}

// secretSettingKeys lists the registered secret settings stored in the
// database (bootstrap keys live in fileparcel.toml and are never sealed).
func secretSettingKeys() []string {
	var out []string
	for _, d := range settings.Defs() {
		if d.Secret && !d.Bootstrap {
			out = append(out, d.Key)
		}
	}
	return out
}

// scope returns the extra SQL condition (" AND pk IN (…)") and its
// arguments that restrict c to the rows that may hold sealed values. skip
// is true when no row can.
func (c sealedColumn) scope() (cond string, args []any, skip bool) {
	if c.only == nil {
		return "", nil, false
	}
	keys := c.only()
	if len(keys) == 0 {
		return "", nil, true
	}
	args = make([]any, len(keys))
	for i, k := range keys {
		args[i] = k
	}
	return " AND " + c.pk + " IN (?" + strings.Repeat(", ?", len(keys)-1) + ")", args, false
}

// prefix returns the stored prefix of values sealed with kekID ("" = any).
func (c sealedColumn) prefix(kekID string) string {
	p := fieldVersion + ":"
	if kekID != "" {
		p += kekID + ":"
	}
	if c.json {
		p = `"` + p
	}
	return p
}

// maxSealedFile bounds the size of a sealed key file read during rotation.
const maxSealedFile = 1 << 20

// ---------- crash recovery ----------

// recoverNext completes or rolls back an interrupted RotateMaster: if
// keys/master.key.next exists, the file whose mk_id matches meta.mk_id
// (i.e. whose keyring transaction committed) wins and the other is removed.
func (s *Service) recoverNext(metaID string, hasMK bool) error {
	next := s.path + fileSuffixNx
	data, err := os.ReadFile(next)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	defer clear(data)
	kf, perr := parseKeyFile(data)
	dir := filepath.Dir(s.path)
	if perr == nil && hasMK && kf.MKID == metaID {
		if err := os.Rename(next, s.path); err != nil {
			return fmt.Errorf("keys: complete master key rotation: %w", err)
		}
		if err := syncDir(dir); err != nil {
			return fmt.Errorf("keys: %w", err)
		}
		s.log.Warn("completed an interrupted master key rotation", "mk_id", kf.MKID)
		return nil
	}
	if err := os.Remove(next); err != nil {
		return fmt.Errorf("keys: roll back master key rotation: %w", err)
	}
	_ = syncDir(dir)
	s.log.Warn("rolled back an interrupted master key rotation")
	return nil
}

// ---------- key material hold ----------

// errKeyMaterialHeld is returned when a rotation cannot start because the
// key material is being copied (a running backup).
var errKeyMaterialHeld = core.Errorf(core.ErrConflict,
	"a backup is copying the key material right now; start the rotation again when it has finished")

// errKeyRotationRunning is returned when a master key rotation or a field
// KEK rotation cannot start because the other one is changing the key
// material right now.
var errKeyRotationRunning = core.Errorf(core.ErrConflict,
	"another key rotation is changing the key material right now; start this one again when it has finished")

// lockKeyMaterial takes the key material for writing (RotateMaster and
// RotateKEK("field")) without waiting: another such rotation fails with
// errKeyRotationRunning, a backup's HoldKeyMaterial with errKeyMaterialHeld.
// keyRotMu makes the second case exact: once it is held, only a reader can
// hold keyMu.
func (s *Service) lockKeyMaterial() (unlock func(), err error) {
	if !s.keyRotMu.TryLock() {
		return nil, errKeyRotationRunning
	}
	if !s.keyMu.TryLock() {
		s.keyRotMu.Unlock()
		return nil, errKeyMaterialHeld
	}
	return func() {
		s.keyMu.Unlock()
		s.keyRotMu.Unlock()
	}, nil
}

// HoldKeyMaterial blocks changes to the on-disk key material — a master key
// rotation and RotateKEK("field"), which re-seals the key files under
// certs/ — until the returned function is called (calling it twice is
// harmless). It is what lets backup.create copy keys/master.key, certs/ and
// a database snapshot as one consistent unit: a rotation in between leaves
// a key file that does not belong to the archived database, which only a
// deep verification notices and which makes the restored server refuse to
// start. Rotations do not wait for it; they fail with core.ErrConflict.
func (s *Service) HoldKeyMaterial() func() {
	s.keyMu.RLock()
	var once sync.Once
	return func() { once.Do(s.keyMu.RUnlock) }
}

// ---------- master rotation ----------

// RotateMaster generates a new master key, writes keys/master.key.next,
// re-wraps every keyring row and updates meta.mk_id/mk_check in one
// transaction, then renames .next over master.key (DESIGN §7.6).
//
// Sealed mode re-seals MK2 under the unchanged passphrase-derived key and
// the recovery slot under the unchanged recovery hash, so the passphrase and
// the recovery key keep working. Both are known from the key file's escrow
// (see keyfile.go) or from the unlock itself. For the same reason a rotation
// alone does not cut off someone holding an older key file and its MK: its
// escrow yields both secrets, so after a suspected leak the passphrase must
// be changed (ChangePassphrase writes a fresh salt) and a new recovery key
// exported as well. Only for a key file without
// escrow (written by hand or by an older build) can they be unknown: then a
// sealed rotation fails with ErrPrecondition when the server was unlocked
// with the recovery key (change the passphrase first), and an unknown
// recovery hash invalidates the old recovery key (a new one must be
// exported; Status reports recovery_configured=false).
func (s *Service) RotateMaster(ctx context.Context) error {
	unlockKeys, err := s.lockKeyMaterial()
	if err != nil {
		return err
	}
	defer unlockKeys()
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	kf := s.currentFile()
	mk2 := crypt.RandomBytes(secretSize)
	defer crypt.Zero(mk2)
	mkID2 := ids.New(ids.PrefixMasterKey)
	nkf := &keyFile{V: fileVersion, MKID: mkID2, Mode: kf.Mode}
	recoveryDropped := false
	err = s.withMaterial(func(m *material) error {
		switch kf.Mode {
		case core.KeyModePlain:
			// The key itself is only written to .next (marshalWith).
		case core.KeyModeSealed:
			if m.passKey == nil {
				return core.Errorf(core.ErrPrecondition, "the server was unlocked with the recovery key: set a new passphrase first (the recovery key is accepted as the current passphrase)")
			}
			k := *kf.KDF
			nkf.KDF = &k
			box, err := sealBox(m.passKey.b, mk2, aadMK(mkID2))
			if err != nil {
				return err
			}
			nkf.Nonce, nkf.CT = box.Nonce, box.CT
			if err := nkf.setEscrow(mk2, escrowPass, m.passKey.b); err != nil {
				return err
			}
		}
		if kf.Recovery != nil {
			if m.recKey == nil {
				recoveryDropped = true
				return nil
			}
			box, err := sealBox(m.recKey.b, mk2, aadRecovery(mkID2))
			if err != nil {
				return err
			}
			nkf.Recovery = box
			return nkf.setEscrow(mk2, escrowRecovery, m.recKey.b)
		}
		return nil
	})
	if err != nil {
		return err
	}

	rows, err := loadKeyring(ctx, readerQ{s.env.DB})
	if err != nil {
		return err
	}
	rewrapped := make([][]byte, len(rows))
	err = s.withMK(func(mk []byte) error {
		a1, err := crypt.NewAEAD(crypt.CipherAES256GCM, mk)
		if err != nil {
			return err
		}
		a2, err := crypt.NewAEAD(crypt.CipherAES256GCM, mk2)
		if err != nil {
			return err
		}
		for i, r := range rows {
			aad := aadKEK(r.id, r.purpose)
			raw, err := crypt.Open(a1, r.wrapped, aad)
			if err != nil {
				return core.Wrap(core.ErrCorrupt, "keyring entry "+r.id+" failed authentication", err)
			}
			rewrapped[i] = crypt.Seal(a2, raw, aad)
			crypt.Zero(raw)
		}
		return nil
	})
	if err != nil {
		return err
	}
	check2 := mkCheck(mk2, mkID2)
	oldID := kf.MKID

	next := s.path + fileSuffixNx
	data := nkf.marshalWith(mk2)
	defer clear(data)
	if err := writeFileAtomic(next, data, 0o600); err != nil {
		return fmt.Errorf("keys: write %s: %w", next, err)
	}
	if err := hook("next-written"); err != nil {
		return err
	}
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		for i, r := range rows {
			res, err := tx.ExecContext(ctx, `UPDATE keyring SET wrapped = ?, mk_id = ? WHERE id = ? AND mk_id = ?`,
				rewrapped[i], mkID2, r.id, oldID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return core.Errorf(core.ErrConflict, "the keyring changed during the master key rotation")
			}
		}
		var left int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keyring WHERE mk_id <> ?`, mkID2).Scan(&left); err != nil {
			return err
		}
		if left != 0 {
			return core.Errorf(core.ErrConflict, "the keyring changed during the master key rotation")
		}
		if err := setMeta(ctx, tx, metaMKID, mkID2); err != nil {
			return err
		}
		return setMeta(ctx, tx, metaMKCheck, check2)
	})
	if err != nil {
		_ = os.Remove(next)
		_ = syncDir(filepath.Dir(next))
		return fmt.Errorf("keys: rotate master key: %w", err)
	}
	if err := hook("committed"); err != nil {
		return err
	}
	renameErr := os.Rename(next, s.path)
	if renameErr == nil {
		renameErr = syncDir(filepath.Dir(s.path))
	}
	// The database now belongs to MK2: switch even if the rename failed
	// (the next start completes it from master.key.next).
	s.mu.Lock()
	s.file = nkf
	if m := s.m; m != nil {
		old := m.mk
		m.mk = m.vault.put(mk2)
		m.vault.release(old)
		m.mkID = mkID2
	}
	s.mu.Unlock()
	s.audit(ctx, core.ActKeysRotate, core.OutcomeSuccess, map[string]any{
		"target": "master", "previous_mk_id": oldID, "recovery_invalidated": recoveryDropped,
	})
	s.publishState()
	if recoveryDropped {
		s.log.Warn("master key rotated; the previous recovery key no longer works: export a new one", "mk_id", mkID2)
	} else {
		s.log.Info("master key rotated", "mk_id", mkID2)
	}
	if renameErr != nil {
		return fmt.Errorf("keys: master key rotated but %s could not be replaced (it will be on the next start): %w", s.path, renameErr)
	}
	return nil
}

// ---------- KEK rotation ----------

// RotateKEK creates a new active KEK for purpose (blob|field), retires the
// previous one and re-wraps every DEK (blob) or re-seals every sealed column
// and key file (field) in batches of 500 rows per transaction. progress (may
// be nil) receives (done, total). It is resumable: every stored value names
// its KEK, and each run re-wraps everything not under the active KEK.
// Retired KEKs that nothing references any more and that were retired more
// than the grace period (15 min) ago are deleted at the end (a fresh one
// stays until the next rotation: a concurrent writer may still store a
// value sealed with it). Values that fail authentication are skipped,
// logged and reported as core.ErrCorrupt after the run.
func (s *Service) RotateKEK(ctx context.Context, purpose string, progress func(done, total int64)) error {
	if purpose != core.KEKBlob && purpose != core.KEKField {
		return core.Invalid("purpose", "purpose must be blob or field (the mac key only changes with a master key rotation)")
	}
	if progress == nil {
		progress = func(int64, int64) {}
	}
	s.rotMu.Lock()
	defer s.rotMu.Unlock()
	if purpose == core.KEKField {
		// The sealed key files under certs/ are re-sealed here, so they must
		// not be copied into a backup while the keyring rows that name their
		// KEK are already in its database snapshot (or the other way round).
		unlockKeys, err := s.lockKeyMaterial()
		if err != nil {
			return err
		}
		defer unlockKeys()
	}
	target, err := s.createKEK(ctx, purpose)
	if err != nil {
		return err
	}
	var st rewrapStats
	switch purpose {
	case core.KEKBlob:
		st, err = s.rewrapBlobs(ctx, target, progress)
	case core.KEKField:
		st, err = s.resealFields(ctx, target, progress)
	}
	details := map[string]any{"target": "kek", "purpose": purpose, "kek_id": target, "rewrapped": st.done, "failed": st.failed}
	if st.skipped > 0 {
		details["skipped"] = st.skipped
	}
	if err != nil {
		details["error"] = "interrupted"
		s.audit(ctx, core.ActKeysRotate, core.OutcomeFailure, details)
		return err
	}
	pruned, perr := s.pruneRetired(ctx, purpose)
	if perr != nil {
		// The rotation itself succeeded; the old keys simply stay. Record it
		// so an operator sees that the prune was skipped.
		s.log.Warn("pruning retired keys failed", "purpose", purpose, "err", perr)
		details["prune_error"] = perr.Error()
	}
	details["pruned"] = pruned
	if st.failed > 0 {
		s.audit(ctx, core.ActKeysRotate, core.OutcomeFailure, details)
		return core.Errorf(core.ErrCorrupt, "%d stored values failed authentication and were not re-wrapped (run keys verify)", st.failed)
	}
	s.audit(ctx, core.ActKeysRotate, core.OutcomeSuccess, details)
	s.log.Info("key encryption key rotated", "purpose", purpose, "kek_id", target, "rewrapped", st.done, "pruned", len(pruned))
	return nil
}

// rewrapStats counts what a rotation did: done (re-wrapped), failed (could
// not be opened) and skipped (changed by their owner meanwhile and left as
// they are; they still reference an older key, which pruneRetired sees).
type rewrapStats struct{ done, failed, skipped, total int64 }

// createKEK adds a new active KEK for purpose and retires the old one.
func (s *Service) createKEK(ctx context.Context, purpose string) (string, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return "", err
	}
	id := ids.New(ids.PrefixKEK)
	raw := crypt.RandomBytes(secretSize)
	defer crypt.Zero(raw)
	var wrapped []byte
	var mkID string
	if err := s.withMaterial(func(m *material) (err error) {
		mkID = m.mkID
		wrapped, err = wrapKEK(m.mk.b, id, purpose, raw)
		return err
	}); err != nil {
		return "", err
	}
	now := s.env.Now()
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE keyring SET state = 'retired', retired_at = ?
			WHERE purpose = ? AND state = 'active'`, db.Ms(now), purpose); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keyring (id, purpose, mk_id, wrapped, state, created_at)
			VALUES (?, ?, ?, ?, 'active', ?)`, id, purpose, mkID, wrapped, db.Ms(now))
		return err
	})
	if err != nil {
		return "", fmt.Errorf("keys: create %s key: %w", purpose, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.m; m != nil {
		t := now
		for _, k := range m.keks {
			if k.purpose == purpose && k.state == core.KEKActive {
				k.state, k.retiredAt = core.KEKRetired, &t
			}
		}
		if err := m.addKEK(id, purpose, core.KEKActive, raw, now, nil); err != nil {
			return "", err
		}
	}
	return id, nil
}

// withMaterial runs fn with the key material under the read lock.
func (s *Service) withMaterial(fn func(m *material) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.m == nil {
		return errLocked
	}
	return fn(s.m)
}

// rewrapBlobs re-wraps every DEK not under target.
func (s *Service) rewrapBlobs(ctx context.Context, target string, progress func(int64, int64)) (rewrapStats, error) {
	var st rewrapStats
	if err := s.env.DB.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE kek_id <> ?`, target).Scan(&st.total); err != nil {
		return st, err
	}
	progress(0, st.total)
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		var ok, bad int64
		var last string
		err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			ok, bad, last = 0, 0, ""
			type row struct {
				id, kek string
				wrapped []byte
			}
			rs, err := tx.QueryContext(ctx, `SELECT id, kek_id, wrapped_dek FROM blobs
				WHERE id > ? AND kek_id <> ? ORDER BY id LIMIT ?`, cursor, target, s.batchSize)
			if err != nil {
				return err
			}
			var batch []row
			for rs.Next() {
				var r row
				if err := rs.Scan(&r.id, &r.kek, &r.wrapped); err != nil {
					rs.Close()
					return err
				}
				batch = append(batch, r)
			}
			rs.Close()
			if err := rs.Err(); err != nil {
				return err
			}
			for _, r := range batch {
				last = r.id
				var w []byte
				err := s.withMaterial(func(m *material) error {
					k := m.keks[target]
					if k == nil {
						return errLocked
					}
					aad := []byte("fp-dek|" + r.id)
					dek, err := unwrapWith(m, r.kek, r.wrapped, aad)
					if err != nil {
						return err
					}
					w = crypt.Seal(k.aead, dek, aad)
					crypt.Zero(dek)
					return nil
				})
				if errors.Is(err, errLocked) {
					return err
				}
				if err != nil {
					bad++
					s.log.Error("cannot re-wrap blob key", "blob", r.id, "kek_id", r.kek, "err", err)
					continue
				}
				if _, err := tx.ExecContext(ctx, `UPDATE blobs SET kek_id = ?, wrapped_dek = ? WHERE id = ? AND kek_id = ?`,
					target, w, r.id, r.kek); err != nil {
					return err
				}
				ok++
			}
			return nil
		})
		if err != nil {
			return st, err
		}
		if last == "" {
			return st, nil
		}
		cursor = last
		st.done += ok
		st.failed += bad
		progress(st.done+st.failed, st.total)
	}
}

// resealFields re-seals every sealed column value and key file not under
// target.
func (s *Service) resealFields(ctx context.Context, target string, progress func(int64, int64)) (rewrapStats, error) {
	var st rewrapStats
	for _, c := range sealedColumns {
		cond, cargs, skip := c.scope()
		if skip {
			continue
		}
		var n int64
		args := append([]any{len(c.prefix("")), c.prefix(""), len(c.prefix(target)), c.prefix(target)}, cargs...)
		if err := s.env.DB.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s
			WHERE substr(%s, 1, ?) = ? AND substr(%s, 1, ?) <> ?%s`, c.table, c.col, c.col, cond), args...).Scan(&n); err != nil {
			return st, err
		}
		st.total += n
	}
	files, err := s.sealedFiles()
	if err != nil {
		return st, err
	}
	for _, f := range files {
		if f.kekID != target {
			st.total++
		}
	}
	progress(0, st.total)
	settingsChanged := false
	for _, c := range sealedColumns {
		n, err := s.resealColumn(ctx, c, target, &st, progress)
		if n > 0 && c.table == "settings" {
			settingsChanged = true
		}
		if err != nil {
			return st, err
		}
	}
	if settingsChanged && s.env.Bus != nil {
		// Make the settings store reload its snapshot (empty key list: the
		// values themselves did not change).
		s.env.Bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{}}})
	}
	for _, f := range files {
		if f.kekID == target {
			continue
		}
		if err := ctx.Err(); err != nil {
			return st, err
		}
		switch err := s.resealFile(f, target); {
		case err == nil:
			st.done++
		case errors.Is(err, errFileChanged):
			// Neither re-wrapped nor failed: the file was rewritten by its
			// owner and still names a KEK of its own.
			st.skipped++
		case errors.Is(err, errLocked):
			return st, err
		default:
			st.failed++
			s.log.Error("cannot re-seal key file", "file", f.path, "err", err)
		}
		progress(st.done+st.failed+st.skipped, st.total)
	}
	return st, nil
}

// resealColumn re-seals one column in keyset-paged batches; it returns the
// number of rows changed.
func (s *Service) resealColumn(ctx context.Context, c sealedColumn, target string, st *rewrapStats, progress func(int64, int64)) (int64, error) {
	cond, cargs, skip := c.scope()
	if skip {
		return 0, nil
	}
	sel := fmt.Sprintf(`SELECT %[1]s, %[2]s FROM %[3]s
		WHERE %[1]s > ? AND substr(%[2]s, 1, ?) = ? AND substr(%[2]s, 1, ?) <> ?%[4]s
		ORDER BY %[1]s LIMIT ?`, c.pk, c.col, c.table, cond)
	upd := fmt.Sprintf(`UPDATE %[3]s SET %[2]s = ? WHERE %[1]s = ? AND %[2]s = ?`, c.pk, c.col, c.table)
	anyP, tgtP := c.prefix(""), c.prefix(target)
	var changed int64
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		var ok, bad int64
		var last string
		err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			ok, bad, last = 0, 0, ""
			args := append([]any{cursor, len(anyP), anyP, len(tgtP), tgtP}, cargs...)
			rs, err := tx.QueryContext(ctx, sel, append(args, s.batchSize)...)
			if err != nil {
				return err
			}
			var keys, vals []string
			for rs.Next() {
				var k, v string
				if err := rs.Scan(&k, &v); err != nil {
					rs.Close()
					return err
				}
				keys, vals = append(keys, k), append(vals, v)
			}
			rs.Close()
			if err := rs.Err(); err != nil {
				return err
			}
			for i, k := range keys {
				last = k
				nv, err := s.resealValue(c, k, vals[i], target)
				if errors.Is(err, errLocked) {
					return err
				}
				if err != nil {
					bad++
					s.log.Error("cannot re-seal value", "table", c.table, "row", k, "err", err)
					continue
				}
				if _, err := tx.ExecContext(ctx, upd, nv, k, vals[i]); err != nil {
					return err
				}
				ok++
			}
			return nil
		})
		if err != nil {
			return changed, err
		}
		if last == "" {
			return changed, nil
		}
		cursor = last
		changed += ok
		st.done += ok
		st.failed += bad
		progress(st.done+st.failed, st.total)
	}
}

// resealValue opens a stored value of column c and seals it under target.
func (s *Service) resealValue(c sealedColumn, pk, stored, target string) (string, error) {
	sealed := stored
	if c.json {
		if err := json.Unmarshal([]byte(stored), &sealed); err != nil {
			return "", core.Wrap(core.ErrCorrupt, "malformed sealed setting", err)
		}
	}
	aad := c.aadPrefix + pk
	var out string
	err := s.withMaterial(func(m *material) error {
		k := m.keks[target]
		if k == nil {
			return errLocked
		}
		pt, err := openFieldWith(m, aad, sealed)
		if err != nil {
			return err
		}
		out = sealFieldWith(k, aad, pt)
		crypt.Zero(pt)
		return nil
	})
	if err != nil {
		return "", err
	}
	if c.json {
		b, _ := json.Marshal(out)
		out = string(b)
	}
	return out, nil
}

// sealedFile is a key file sealed with the field KEK (certs/**/*.enc; AAD
// "file|<path relative to HOME without .enc>").
type sealedFile struct {
	path, aad, kekID string
	content          []byte
}

// sealedFiles lists the sealed key files under certs/. It fails closed:
// this list is the only reference count for the field KEKs (pruneRetired)
// and the only reseal list (resealFields), so a file that cannot be
// enumerated or read must be an error, never a missing reference —
// otherwise the KEK it still needs is deleted under it and the key is
// crypto-shredded. Only two cases are tolerated, because they provably hold
// no reference: certs/ does not exist, and an entry that disappeared while
// walking. The walk does not follow symbolic links, so a symlinked certs/,
// a symlinked directory under it or a symlinked *.enc file is an error too
// (package certs reads and writes through such links, the walk would not
// see what they hide); symlinks to other files and dangling ones are no
// reference.
func (s *Service) sealedFiles() ([]sealedFile, error) {
	root := s.env.Home.CertsDir()
	if fi, err := os.Lstat(root); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("keys: %s is a symbolic link; the sealed key files must be in a real directory (replace the link with the directory itself or a bind mount)", root)
	}
	var out []sealedFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if p == root {
					return fs.SkipAll
				}
				return nil // removed while walking: it holds no reference
			}
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			st, err := os.Stat(p)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				return nil // dangling: it holds no reference
			case err != nil:
				return err
			case st.IsDir() || strings.HasSuffix(d.Name(), ".enc"):
				return fmt.Errorf("%s is a symbolic link; the sealed key files behind it cannot be tracked (replace the link with what it points to)", p)
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".enc") {
			return nil
		}
		rel, err := filepath.Rel(s.env.Home.Dir(), p)
		if err != nil {
			return err
		}
		b, err := readLimited(p, maxSealedFile)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		id, _, perr := parseSealed(string(bytes.TrimSpace(b)))
		if perr != nil {
			// Not a sealed value: it names no KEK, so it is no reference.
			s.log.Warn("sealed key file does not hold a sealed value", "file", p)
			return nil
		}
		out = append(out, sealedFile{path: p, aad: "file|" + filepath.ToSlash(strings.TrimSuffix(rel, ".enc")), kekID: id, content: b})
		return nil
	})
	if err != nil {
		// Never hand back a truncated list beside an error.
		return nil, fmt.Errorf("keys: list sealed key files under %s: %w", root, err)
	}
	return out, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file too large")
	}
	return b, nil
}

// errFileChanged reports that a sealed key file was written by someone else
// between enumeration and the replacing rename, so it was left alone.
var errFileChanged = errors.New("keys: key file changed during rotation")

// LockKeyFiles serialises writes of the sealed key files under certs/ with
// a field KEK rotation, which re-seals them. A writer (package certs) calls
// it before SealField and holds it until the file is written, renamed or
// removed; the returned func releases it (calling it twice is harmless).
// It is held only for the duration of one file write, never across a
// rotation, so certificate changes do not wait for a rotation to finish.
func (s *Service) LockKeyFiles() func() {
	s.fileMu.Lock()
	var once sync.Once
	return func() { once.Do(s.fileMu.Unlock) }
}

// beforeResealRename, when set by tests, runs in resealFile under fileMu
// between the changed-file check and the rename.
var beforeResealRename func(path string)

// resealFile re-seals one key file under target, replacing it atomically
// unless it changed meanwhile (errFileChanged). The check and the rename
// run under fileMu (LockKeyFiles), so a key file its owner writes in
// between is never overwritten with the previous key.
func (s *Service) resealFile(f sealedFile, target string) error {
	var out string
	err := s.withMaterial(func(m *material) error {
		k := m.keks[target]
		if k == nil {
			return errLocked
		}
		pt, err := openFieldWith(m, f.aad, string(bytes.TrimSpace(f.content)))
		if err != nil {
			return err
		}
		out = sealFieldWith(k, f.aad, pt)
		crypt.Zero(pt)
		return nil
	})
	if err != nil {
		return err
	}
	tmp := f.path + fileSuffixTm
	_ = os.Remove(tmp)
	if err := writeFileSync(tmp, []byte(out+"\n"), 0o600); err != nil {
		return err
	}
	if err := s.replaceUnchanged(f, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(f.path))
}

// replaceUnchanged renames tmp over f.path unless the file no longer holds
// f.content (errFileChanged), all under fileMu.
func (s *Service) replaceUnchanged(f sealedFile, tmp string) error {
	release := s.LockKeyFiles()
	defer release()
	cur, err := readLimited(f.path, maxSealedFile)
	if err != nil {
		return err
	}
	if !bytes.Equal(cur, f.content) {
		s.log.Info("key file changed during rotation; left as is", "file", f.path)
		// The file still names its old KEK, so it must not be counted as
		// re-wrapped (pruneRetired re-enumerates and keeps that KEK).
		return errFileChanged
	}
	if beforeResealRename != nil {
		beforeResealRename(f.path)
	}
	return os.Rename(tmp, f.path)
}

// writeFileSync creates path exclusively, writes data and fsyncs it.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(perm)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// ---------- pruning ----------

// pruneRetired deletes retired KEKs of purpose that were retired more than
// retiredGrace ago and that nothing references any more.
func (s *Service) pruneRetired(ctx context.Context, purpose string) ([]string, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	cutoff := db.Ms(s.env.Now().Add(-s.retiredGrace))
	rs, err := s.env.DB.Query(ctx, `SELECT id FROM keyring WHERE purpose = ? AND state = 'retired' AND retired_at <= ? ORDER BY id`, purpose, cutoff)
	if err != nil {
		return nil, err
	}
	var cands []string
	for rs.Next() {
		var id string
		if err := rs.Scan(&id); err != nil {
			rs.Close()
			return nil, err
		}
		cands = append(cands, id)
	}
	rs.Close()
	if err := rs.Err(); err != nil || len(cands) == 0 {
		return nil, err
	}
	fileRefs := map[string]int64{}
	if purpose == core.KEKField {
		files, err := s.sealedFiles()
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			fileRefs[f.kekID]++
		}
	}
	var deleted []string
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		deleted = deleted[:0]
		for _, id := range cands {
			n, err := kekRefs(ctx, tx, purpose, id)
			if err != nil {
				return err
			}
			if n+fileRefs[id] > 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM keyring WHERE id = ? AND state = 'retired'`, id); err != nil {
				return err
			}
			deleted = append(deleted, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if m := s.m; m != nil {
		for _, id := range deleted {
			if k := m.keks[id]; k != nil {
				m.vault.release(k.key)
				delete(m.keks, id)
			}
		}
	}
	s.mu.Unlock()
	return deleted, nil
}

// kekRefs counts the database rows that reference KEK id (files excluded).
func kekRefs(ctx context.Context, q querier, purpose, id string) (int64, error) {
	switch purpose {
	case core.KEKBlob:
		var n int64
		err := q.QueryRowContext(ctx, `SELECT count(*) FROM blobs WHERE kek_id = ?`, id).Scan(&n)
		return n, err
	case core.KEKField:
		var total int64
		for _, c := range sealedColumns {
			cond, cargs, skip := c.scope()
			if skip {
				continue
			}
			p := c.prefix(id)
			var n int64
			if err := q.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE substr(%s, 1, ?) = ?%s`, c.table, c.col, cond),
				append([]any{len(p), p}, cargs...)...).Scan(&n); err != nil {
				return 0, err
			}
			total += n
		}
		return total, nil
	}
	return 0, nil
}

// fieldRefCounts counts sealed values per KEK id across all sealed columns.
func fieldRefCounts(ctx context.Context, q querier) (map[string]int64, error) {
	out := map[string]int64{}
	for _, c := range sealedColumns {
		cond, cargs, skip := c.scope()
		if skip {
			continue
		}
		p := c.prefix("")
		start := len(p) + 1 // 1-based position of the KEK id
		query := fmt.Sprintf(`SELECT substr(%[1]s, %[2]d, instr(substr(%[1]s, %[2]d), ':') - 1) AS k, count(*)
			FROM %[3]s WHERE substr(%[1]s, 1, ?) = ?%[4]s GROUP BY k`, c.col, start, c.table, cond)
		rs, err := q.QueryContext(ctx, query, append([]any{len(p), p}, cargs...)...)
		if err != nil {
			return nil, err
		}
		for rs.Next() {
			var k string
			var n int64
			if err := rs.Scan(&k, &n); err != nil {
				rs.Close()
				return nil, err
			}
			out[k] += n
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// blobRefCounts counts blobs per KEK id.
func blobRefCounts(ctx context.Context, q querier) (map[string]int64, error) {
	rs, err := q.QueryContext(ctx, `SELECT kek_id, count(*) FROM blobs GROUP BY kek_id`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string]int64{}
	for rs.Next() {
		var k string
		var n int64
		if err := rs.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rs.Err()
}

// kekInfos lists the keyring with reference counts.
func (s *Service) kekInfos(ctx context.Context) ([]core.KEKInfo, error) {
	files, err := s.sealedFiles()
	if err != nil {
		return nil, err
	}
	return s.kekInfosWith(ctx, files)
}

// kekInfosWith lists the keyring with reference counts, counting files as
// the sealed key files the caller already enumerated. Verify uses it to
// report a failed enumeration as a problem instead of failing outright;
// every other caller goes through kekInfos, which fails closed.
func (s *Service) kekInfosWith(ctx context.Context, files []sealedFile) ([]core.KEKInfo, error) {
	q := readerQ{s.env.DB}
	rows, err := loadKeyring(ctx, q)
	if err != nil {
		return nil, err
	}
	brefs, err := blobRefCounts(ctx, q)
	if err != nil {
		return nil, err
	}
	frefs, err := fieldRefCounts(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		frefs[f.kekID]++
	}
	out := make([]core.KEKInfo, 0, len(rows))
	for _, r := range rows {
		info := core.KEKInfo{ID: r.id, Purpose: r.purpose, State: r.state, CreatedAt: db.FromMs(r.createdAt), RetiredAt: db.FromNullMs(r.retiredAt)}
		switch r.purpose {
		case core.KEKBlob:
			info.Refs = brefs[r.id]
		case core.KEKField:
			info.Refs = frefs[r.id]
		}
		out = append(out, info)
	}
	return out, nil
}

// PruneRetired deletes the retired KEKs (blob and field) that nothing
// references and that were retired more than the grace period ago. It
// returns the deleted KEK ids. RotateKEK calls it automatically.
func (s *Service) PruneRetired(ctx context.Context) ([]string, error) {
	var all []string
	for _, p := range []string{core.KEKBlob, core.KEKField} {
		d, err := s.pruneRetired(ctx, p)
		if err != nil {
			return all, err
		}
		all = append(all, d...)
	}
	return all, nil
}
