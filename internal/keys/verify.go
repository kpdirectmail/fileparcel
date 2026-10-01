package keys

import (
	"context"
	"fmt"
	"os"
	"slices"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// VerifyReport is the result of Verify. The KEK list (with reference counts)
// is also in core.KeyStatus.KEKs; a retired KEK with Refs == 0 is
// unreferenced and is deleted by the next rotation.
type VerifyReport struct {
	OK    bool          `json:"ok"`
	State core.KeyState `json:"state"`
	Mode  string        `json:"mode"`
	MKID  string        `json:"mk_id"`
	// MKCheck is true when meta.mk_check matches the loaded master key.
	MKCheck bool           `json:"mk_check"`
	KEKs    []core.KEKInfo `json:"keks"`
	// Retired lists retired KEKs that are still referenced.
	Retired []string `json:"retired,omitempty"`
	// Unreferenced lists retired KEKs nothing references any more.
	Unreferenced []string `json:"unreferenced,omitempty"`
	// Problems describes every failed check (empty when OK).
	Problems []string `json:"problems,omitempty"`
}

// Verify checks the key hierarchy: the key file mode, meta.mk_check, that
// every keyring entry authenticates under the master key, one active KEK per
// purpose, and that every stored value names a known KEK. It needs the keys
// unlocked (ErrKeysLocked otherwise). It is an in-process consistency check
// (the tests run it after every rotation scenario); the CLI "keys verify"
// does not call it but checks the core.KeyStatus of GET /admin/keys: one
// active KEK per purpose, no retired KEK still referenced and, sealed, a
// recovery key. Unlock itself already refuses a keyring entry that fails
// authentication, a meta.mk_check mismatch and a purpose without exactly
// one active KEK (buildMaterial).
func (s *Service) Verify(ctx context.Context) (*VerifyReport, error) {
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	rep := &VerifyReport{State: s.State(), Mode: s.mode()}
	problem := func(f string, a ...any) { rep.Problems = append(rep.Problems, fmt.Sprintf(f, a...)) }

	if st, err := os.Stat(s.path); err != nil {
		problem("key file: %v", err)
	} else if st.Mode().Perm()&0o077 != 0 {
		problem("key file %s has mode %s (want 0600)", s.path, st.Mode().Perm())
	}
	q := readerQ{s.env.DB}
	metaID, _, err := getMeta(ctx, q, metaMKID)
	if err != nil {
		return nil, err
	}
	check, _, err := getMeta(ctx, q, metaMKCheck)
	if err != nil {
		return nil, err
	}
	rows, err := loadKeyring(ctx, q)
	if err != nil {
		return nil, err
	}
	err = s.withMaterial(func(m *material) error {
		rep.MKID = m.mkID
		if metaID != m.mkID {
			problem("meta.mk_id %s does not match the loaded master key %s", metaID, m.mkID)
		}
		rep.MKCheck = mkCheck(m.mk.b, m.mkID) == check
		if !rep.MKCheck {
			problem("meta.mk_check does not match the master key")
		}
		a, err := crypt.NewAEAD(crypt.CipherAES256GCM, m.mk.b)
		if err != nil {
			return err
		}
		active := map[string]int{}
		for _, r := range rows {
			if r.mkID != m.mkID {
				problem("keyring entry %s is wrapped by master key %s", r.id, r.mkID)
			}
			raw, err := crypt.Open(a, r.wrapped, aadKEK(r.id, r.purpose))
			if err != nil {
				problem("keyring entry %s (%s) fails authentication", r.id, r.purpose)
			}
			crypt.Zero(raw)
			if r.state == core.KEKActive {
				active[r.purpose]++
			}
		}
		for _, p := range purposes {
			if active[p] != 1 {
				problem("%d active keys for purpose %s (want 1)", active[p], p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Enumerate the sealed key files once. A failure is reported (ok=false)
	// rather than returned, so the report still covers everything else —
	// but the file reference counts below are then incomplete, which is
	// exactly why pruneRetired refuses to run at all in that case.
	files, ferr := s.sealedFiles()
	if ferr != nil {
		problem("cannot enumerate the sealed key files under certs/: %v", ferr)
		files = nil
	}
	infos, err := s.kekInfosWith(ctx, files)
	if err != nil {
		return nil, err
	}
	rep.KEKs = infos
	known := map[string]string{}
	for _, k := range infos {
		known[k.ID] = k.Purpose
		if k.State == core.KEKRetired {
			// With an incomplete file enumeration Refs is understated, so
			// nothing may be called unreferenced.
			if k.Refs == 0 && ferr == nil {
				rep.Unreferenced = append(rep.Unreferenced, k.ID)
			} else {
				rep.Retired = append(rep.Retired, k.ID)
			}
		}
	}
	frefs, err := fieldRefCounts(ctx, q)
	if err != nil {
		return nil, err
	}
	for id, n := range frefs {
		if known[id] != core.KEKField {
			problem("%d sealed values reference unknown key %q", n, id)
		}
	}
	for _, f := range files {
		if known[f.kekID] != core.KEKField {
			problem("key file %s is sealed with unknown key %q", f.path, f.kekID)
		}
	}
	slices.Sort(rep.Problems)
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}
