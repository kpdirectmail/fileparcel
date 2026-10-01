package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// backup.copy_to must lie outside the FileParcel home: a "copy" into the
// backups folder is the backup itself, and one elsewhere in the home is
// lost with it. The Backups page / CLI (SetConfig) and a system backup with
// copy_to refuse it; a value stored before (or through the generic settings
// route) makes the copy step fail instead of pretending there is a copy.
func TestCopyToOutsideHome(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	c, err := te.svc.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(te.h.Dir(), link); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{te.h.Dir(), te.h.BackupsDir(), te.h.Path("data", "new"), filepath.Join(link, "backups"), link} {
		cfg := *c
		cfg.CopyTo = dir
		err := te.svc.SetConfig(ctx, te.admin(), cfg)
		if ce := core.AsError(err); !isCode(err, core.ErrInvalid) || ce.Field != "copy_to" {
			t.Errorf("copy_to %s: %v", dir, err)
		}
		if _, err := te.svc.Create(ctx, core.SystemPrincipal(core.ViaSocket), core.BackupInput{Scope: core.BackupMetadata, CopyTo: dir}); !isCode(err, core.ErrInvalid) {
			t.Errorf("system backup with copy_to %s: %v", dir, err)
		}
	}
	cfg := *c
	cfg.CopyTo = outside
	if err := te.svc.SetConfig(ctx, te.admin(), cfg); err != nil {
		t.Fatalf("copy_to outside: %v", err)
	}
	// A value already stored inside the home: the copy step refuses it.
	src := filepath.Join(t.TempDir(), "src.fpbak")
	mustWrite(t, src, []byte("backup-bytes"))
	if _, err := te.svc.copyTo(ctx, src, te.h.BackupsDir(), "x.fpbak"); err == nil ||
		!strings.Contains(err.Error(), "inside the FileParcel directory") {
		t.Fatalf("copy into the backups folder: %v", err)
	}
	if dst, err := te.svc.copyTo(ctx, src, outside, "x.fpbak"); err != nil || dst != filepath.Join(outside, "x.fpbak") {
		t.Fatalf("copy outside: %s %v", dst, err)
	}
}
