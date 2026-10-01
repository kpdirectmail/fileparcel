package backup

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"fileparcel/internal/core"
)

// blobHoldingKeys is fakeKeys plus the blob hold of *keys.Service
// (HoldBlobs), which pauses data re-encryption while it is held.
type blobHoldingKeys struct {
	*fakeKeys
	holds atomic.Int32 // holds currently open
	taken atomic.Int32 // holds taken so far
}

func (k *blobHoldingKeys) HoldBlobs() func() {
	k.holds.Add(1)
	k.taken.Add(1)
	var once sync.Once
	return func() { once.Do(func() { k.holds.Add(-1) }) }
}

// TestFullBackupHoldsTheBlobs: data re-encryption (keys.reencrypt) deletes
// the old blob of every file it re-encrypts, so a full backup must hold the
// blobs from before its database snapshot — whose blob list it copies —
// until the last blob is in the archive; otherwise the archive silently
// misses those files and still passes deep verification. A metadata backup
// copies no blobs and takes no hold.
func TestFullBackupHoldsTheBlobs(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.seedData(2)
	bk := &blobHoldingKeys{fakeKeys: te.env.Keys.(*fakeKeys)}
	te.env.Keys = bk
	plan := testPlan(t, te)
	atSnapshot, atBlobs := int32(-1), int32(-1)
	h := hookHandle{fn: func(note string) {
		switch {
		case note == "snapshotting the database":
			atSnapshot = bk.holds.Load()
		case strings.HasSuffix(note, " files"):
			atBlobs = bk.holds.Load()
		}
	}}
	if _, err := te.svc.writeArchive(ctx, probeHeader(t, te, plan, core.BackupFull), "blobs.fpbak", plan, h); err != nil {
		t.Fatal(err)
	}
	if atSnapshot != 1 || atBlobs != 1 {
		t.Fatalf("blobs not held from the snapshot through the blob phase (at snapshot %d, at blobs %d)", atSnapshot, atBlobs)
	}
	if n := bk.holds.Load(); n != 0 {
		t.Fatalf("%d blob holds still open after the archive was written", n)
	}
	taken := bk.taken.Load()
	if _, err := te.svc.writeArchive(ctx, probeHeader(t, te, plan, core.BackupMetadata), "meta.fpbak", plan, hookHandle{fn: func(string) {}}); err != nil {
		t.Fatal(err)
	}
	if bk.taken.Load() != taken {
		t.Fatal("a metadata backup held the blobs")
	}
}
