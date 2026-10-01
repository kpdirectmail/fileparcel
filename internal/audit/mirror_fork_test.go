package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"fileparcel/internal/core"
)

// mirrorSeqs returns the seq numbers of the records in the JSONL file at path.
func mirrorSeqs(t *testing.T, path string) []int64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []int64
	for _, line := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		var rec core.AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out = append(out, rec.Seq)
	}
	return out
}

// After a restore the database's audit log is back at the backup's last
// entry, but logs/audit.jsonl is not restored: the mirror moves the file
// aside instead of appending entries that reuse its seq numbers.
func TestMirrorJSONLAfterRewind(t *testing.T) {
	te := newTestEnv(t, true)
	te.settings.set(SettingMirrorJSONL, true)
	te.record(t, 5, core.ActFileUpload)
	te.svc.signal()
	waitFor(t, "mirror", func() bool { v, _ := te.meta(t, metaMirrorSeq); return v == "5" })
	if err := te.svc.Close(); err != nil {
		t.Fatal(err)
	}
	// The "backup" was taken at seq 3 with the mirror at 2.
	te.exec(t, `DELETE FROM audit_log WHERE seq > 3`)
	te.exec(t, `UPDATE sqlite_sequence SET seq = 3 WHERE name = 'audit_log'`)
	te.exec(t, `UPDATE meta SET value = '2' WHERE key = ?`, metaMirrorSeq)

	svc2, err := New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	te.svc = svc2
	te.record(t, 2, core.ActFileDownload)
	svc2.signal()
	waitFor(t, "mirror after the rewind", func() bool { v, _ := te.meta(t, metaMirrorSeq); return v == "5" })

	logs := te.env.Home.LogsDir()
	aside, err := filepath.Glob(filepath.Join(logs, mirrorFileName+".pre-restore-*"))
	if err != nil || len(aside) != 1 {
		t.Fatalf("set-aside files %v %v", aside, err)
	}
	if got := mirrorSeqs(t, aside[0]); len(got) != 5 || got[4] != 5 {
		t.Fatalf("old mirror %v", got)
	}
	got := mirrorSeqs(t, filepath.Join(logs, mirrorFileName))
	want := []int64{3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("new mirror %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("new mirror %v, want %v", got, want)
		}
	}
}

// A mirror that is simply behind or ahead of the saved position (a crash
// between the write and saving the position), or whose last record was
// pruned by retention, is no fork: the file stays.
func TestMirrorJSONLNoFalseFork(t *testing.T) {
	te := newTestEnv(t, true)
	te.settings.set(SettingMirrorJSONL, true)
	te.record(t, 3, core.ActFileUpload)
	te.svc.signal()
	waitFor(t, "mirror", func() bool { v, _ := te.meta(t, metaMirrorSeq); return v == "3" })
	if err := te.svc.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(te.env.Home.LogsDir(), mirrorFileName)
	// Pruned: the file's last record (seq 3) is gone from the table, newer
	// rows exist.
	svc2, err := New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	te.svc = svc2
	te.settings.set(SettingMirrorJSONL, false)
	te.record(t, 2, core.ActFileDownload)
	if err := svc2.Close(); err != nil {
		t.Fatal(err)
	}
	te.exec(t, `DELETE FROM audit_log WHERE seq <= 3`)
	te.settings.set(SettingMirrorJSONL, true)
	svc3, err := New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	defer svc3.Close()
	svc3.Record(context.Background(), core.AuditEntry{Action: core.ActSystemStart})
	waitFor(t, "resume", func() bool { v, _ := te.meta(t, metaMirrorSeq); return v == strconv.Itoa(6) })
	if aside, _ := filepath.Glob(path + ".pre-restore-*"); len(aside) != 0 {
		t.Fatalf("moved aside although nothing was rewound: %v", aside)
	}
	if got := mirrorSeqs(t, path); len(got) != 6 || got[5] != 6 {
		t.Fatalf("mirror %v", got)
	}
}
