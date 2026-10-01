package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// "backup verify --deep" of a backup whose master key is sealed decrypted no
// file at all but printed "deep-verified successfully"; the notes of the
// result were never shown. And a failed verification printed the backup's
// error column, which can hold a failed copy to backup.copy_to instead of
// the verification's reason.
func TestBackupVerifyReportsNotesAndReason(t *testing.T) {
	f := newFakeAPI(t)
	bid := ids.New(ids.PrefixBackup)
	ok, failed := true, false
	b := core.Backup{ID: bid, Scope: core.BackupFull, State: core.BackupReady, FileName: "fp.fpbak",
		Trigger: core.TriggerManual, CreatedAt: time.Now(), VerifyOK: &ok}
	var jobID string
	f.handle("POST", "/api/v1/admin/backups/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, core.JobRef{JobID: jobID})
	})
	f.handle("GET", "/api/v1/admin/backups/{id}", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, b) })

	const note = "file contents were not decrypted: the backup's master key is sealed with a passphrase"
	jobID = f.addJob(core.JobBackupVerify, map[string]any{"backup_id": bid, "ok": true, "deep": true, "blobs": 3,
		"blobs_verified": 0, "notes": []string{note}}, core.JobSucceeded)
	res := f.run(t, "", "backup", "verify", bid, "--deep")
	if res.code != 0 || !strings.Contains(res.stderr, "not decrypted") {
		t.Fatalf("the note of a sealed deep verification is not shown: %+v", res)
	}
	if strings.Contains(res.stdout+res.stderr, "deep-verified") {
		t.Fatalf("a deep verification that decrypted nothing is reported as deep-verified: %+v", res)
	}

	jobID = f.addJob(core.JobBackupVerify, map[string]any{"backup_id": bid, "ok": true, "deep": true, "blobs": 3,
		"blobs_verified": 3}, core.JobSucceeded)
	if res := f.run(t, "", "backup", "verify", bid, "--deep"); res.code != 0 || !strings.Contains(res.stdout+res.stderr, "deep-verified") {
		t.Fatalf("deep verification: %+v", res)
	}

	b.VerifyOK = &failed
	b.Error = "copy to /mnt/nas failed: no such file or directory; verification failed: the backup archive is damaged or truncated"
	jobID = f.addJob(core.JobBackupVerify, map[string]any{"backup_id": bid, "ok": false,
		"error": "the backup archive is damaged or truncated"}, core.JobFailed)
	res = f.run(t, "", "backup", "verify", bid)
	if res.code == 0 || !strings.Contains(res.stderr, "FAILED verification: the backup archive is damaged or truncated") ||
		strings.Contains(res.stderr, "/mnt/nas") {
		t.Fatalf("failed verification: %+v", res)
	}
}
