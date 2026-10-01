package keys

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// meta keys (DESIGN §6/§7.2).
const (
	metaMKID    = "mk_id"
	metaMKCheck = "mk_check" // hex HMAC-SHA256(MK, "fp-mk-check|"+mk_id)
)

// purposes lists the KEK purposes created by Init.
var purposes = []string{core.KEKBlob, core.KEKField, core.KEKMAC}

// maxMACCache bounds the number of cached MAC subkeys (purposes are code
// constants; anything beyond is derived per call).
const maxMACCache = 64

func aadKEK(id, purpose string) []byte { return []byte("fp-kek|" + id + "|" + purpose) }

// mkCheck computes meta.mk_check for mk.
func mkCheck(mk []byte, mkID string) string {
	return hex.EncodeToString(crypt.HMACRaw(mk, []byte("fp-mk-check|"+mkID)))
}

// kek is one unwrapped keyring entry.
type kek struct {
	id, purpose, state string
	key                *secret
	aead               cipher.AEAD // AES-256-GCM under key
	createdAt          time.Time
	retiredAt          *time.Time
}

// material is the key material held while unlocked. The maps are guarded
// by Service.mu (read lock for use, write lock for changes); the MAC subkey
// cache has its own mutex because it is filled under the read lock.
type material struct {
	vault  *vault
	mk     *secret
	mkID   string
	keks   map[string]*kek
	active map[string]*kek // purpose → active KEK

	macMu   sync.Mutex
	macKeys map[string]*secret

	passKey *secret // argon2id(passphrase) of the current sealed file, when known
	recKey  *secret // SHA-256(recovery key), when known
}

func newMaterial() *material {
	return &material{vault: newVault(), keks: map[string]*kek{}, active: map[string]*kek{}, macKeys: map[string]*secret{}}
}

// destroy zeroes all key material.
func (m *material) destroy() {
	if m == nil {
		return
	}
	for _, k := range m.keks {
		k.aead = nil
	}
	m.vault.destroy()
}

// addKEK stores an unwrapped KEK (raw is copied into the vault; the caller
// zeroes raw).
func (m *material) addKEK(id, purpose, state string, raw []byte, created time.Time, retired *time.Time) error {
	a, err := crypt.NewAEAD(crypt.CipherAES256GCM, raw)
	if err != nil {
		return err
	}
	k := &kek{id: id, purpose: purpose, state: state, key: m.vault.put(raw), aead: a, createdAt: created, retiredAt: retired}
	m.keks[id] = k
	if state == core.KEKActive {
		m.active[purpose] = k
	}
	return nil
}

// macKey returns the HKDF subkey for purpose (cached). The caller holds
// Service.mu for reading.
func (m *material) macKey(purpose string) []byte {
	m.macMu.Lock()
	defer m.macMu.Unlock()
	if s := m.macKeys[purpose]; s != nil {
		return s.b
	}
	k := m.active[core.KEKMAC]
	if k == nil {
		return nil
	}
	sub, err := crypt.HKDF(k.key.b, nil, "fp-mac|"+purpose, secretSize)
	if err != nil {
		return nil
	}
	if len(m.macKeys) >= maxMACCache {
		return sub // uncached (heap)
	}
	s := m.vault.put(sub)
	crypt.Zero(sub)
	m.macKeys[purpose] = s
	return s.b
}

// ---------- database helpers ----------

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// readerQ adapts the db reader pool to querier.
type readerQ struct{ d *db.DB }

func (r readerQ) QueryRowContext(ctx context.Context, q string, a ...any) *sql.Row {
	return r.d.QueryRow(ctx, q, a...)
}
func (r readerQ) QueryContext(ctx context.Context, q string, a ...any) (*sql.Rows, error) {
	return r.d.Query(ctx, q, a...)
}

func getMeta(ctx context.Context, q querier, key string) (string, bool, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if db.IsNoRows(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func setMeta(ctx context.Context, tx *sql.Tx, key, value string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// keyringRow is one row of the keyring table.
type keyringRow struct {
	id, purpose, mkID, state string
	wrapped                  []byte
	createdAt                int64
	retiredAt                sql.NullInt64
}

func loadKeyring(ctx context.Context, q querier) ([]keyringRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, purpose, mk_id, wrapped, state, created_at, retired_at
		FROM keyring ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyringRow
	for rows.Next() {
		var r keyringRow
		if err := rows.Scan(&r.id, &r.purpose, &r.mkID, &r.wrapped, &r.state, &r.createdAt, &r.retiredAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func countKeyring(ctx context.Context, q querier) (int64, error) {
	var n int64
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM keyring`).Scan(&n)
	return n, err
}

// wrapKEK seals a KEK under the master key.
func wrapKEK(mk []byte, id, purpose string, raw []byte) ([]byte, error) {
	a, err := crypt.NewAEAD(crypt.CipherAES256GCM, mk)
	if err != nil {
		return nil, err
	}
	return crypt.Seal(a, raw, aadKEK(id, purpose)), nil
}

// buildMaterial verifies mk against meta.mk_check and unwraps the whole
// keyring. mk is copied (the caller zeroes its copy).
func buildMaterial(ctx context.Context, q querier, mk []byte, mkID, check string) (*material, error) {
	if len(mk) != secretSize {
		return nil, core.Wrap(core.ErrCorrupt, "invalid master key", nil)
	}
	got := mkCheck(mk, mkID)
	if !ids.Equal(got, check) {
		return nil, core.Wrap(core.ErrCorrupt, "the master key does not belong to this database (mk_check mismatch)", nil)
	}
	rows, err := loadKeyring(ctx, q)
	if err != nil {
		return nil, err
	}
	m := newMaterial()
	m.mk = m.vault.put(mk)
	m.mkID = mkID
	mkAEAD, err := crypt.NewAEAD(crypt.CipherAES256GCM, mk)
	if err != nil {
		m.destroy()
		return nil, err
	}
	for _, r := range rows {
		if r.mkID != mkID {
			m.destroy()
			return nil, core.Wrap(core.ErrCorrupt, fmt.Sprintf("keyring entry %s is wrapped by another master key", r.id), nil)
		}
		raw, err := crypt.Open(mkAEAD, r.wrapped, aadKEK(r.id, r.purpose))
		if err != nil || len(raw) != secretSize {
			m.destroy()
			return nil, core.Wrap(core.ErrCorrupt, fmt.Sprintf("keyring entry %s failed authentication", r.id), err)
		}
		if r.state == core.KEKActive && m.active[r.purpose] != nil {
			crypt.Zero(raw)
			m.destroy()
			return nil, core.Wrap(core.ErrCorrupt, "keyring has two active keys for purpose "+r.purpose, nil)
		}
		err = m.addKEK(r.id, r.purpose, r.state, raw, db.FromMs(r.createdAt), db.FromNullMs(r.retiredAt))
		crypt.Zero(raw)
		if err != nil {
			m.destroy()
			return nil, err
		}
	}
	for _, p := range purposes {
		if m.active[p] == nil {
			m.destroy()
			return nil, core.Wrap(core.ErrCorrupt, "keyring has no active key for purpose "+p, nil)
		}
	}
	return m, nil
}

// errLocked is returned by operations that need the keys.
var errLocked = core.ErrKeysLocked
