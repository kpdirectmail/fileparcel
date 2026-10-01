package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// "backup identity show" lists every key backups are encrypted to: with
// backup.recipients emptied it printed no recipient (and --json
// {"recipients": []}) although every backup is encrypted to the server's own
// key, the stored identity's public key.
func TestBackupIdentityShowIncludesServerKey(t *testing.T) {
	f := newFakeAPI(t)
	cfg := core.BackupConfig{Encryption: core.BackupX25519, Recipients: []string{}, HasIdentity: true, IdentityRecipient: "age1own"}
	f.handle("GET", "/api/v1/admin/backups/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, cfg) })

	res := f.run(t, "", "backup", "identity", "show")
	if res.code != 0 || !strings.Contains(res.stdout, "Recipient:") || !strings.Contains(res.stdout, "age1own  (the server's own backup key)") {
		t.Fatalf("empty list: %+v", res)
	}
	res = f.run(t, "", "--json", "backup", "identity", "show")
	var out struct {
		Recipients           []string `json:"recipients"`
		ConfiguredRecipients []string `json:"configured_recipients"`
		IdentityRecipient    string   `json:"identity_recipient"`
	}
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &out) != nil || len(out.Recipients) != 1 || out.Recipients[0] != "age1own" ||
		out.ConfiguredRecipients == nil || len(out.ConfiguredRecipients) != 0 || out.IdentityRecipient != "age1own" {
		t.Fatalf("--json: %+v", res)
	}

	// Listed once when backup.recipients already holds it.
	cfg.Recipients = []string{"age1own", "age1other"}
	res = f.run(t, "", "backup", "identity", "show")
	if res.code != 0 || strings.Count(res.stdout, "age1own") != 1 || !strings.Contains(res.stdout, "age1other") {
		t.Fatalf("listed key: %+v", res)
	}
	// "backup config show" names it too.
	if res = f.run(t, "", "backup", "config", "show"); res.code != 0 || !strings.Contains(res.stdout, "Server's own key") {
		t.Fatalf("config show: %+v", res)
	}
}

// The output-only identity_recipient is never sent back on PUT.
func TestPutBackupConfigDropsIdentityRecipient(t *testing.T) {
	f := newFakeAPI(t)
	cfg := core.BackupConfig{Enabled: true, ScheduleMeta: "0 3 * * *", Encryption: core.BackupX25519, HasIdentity: true, IdentityRecipient: "age1own"}
	f.handle("GET", "/api/v1/admin/backups/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, cfg) })
	f.handle("PUT", "/api/v1/admin/backups/config", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if res := f.run(t, "", "backup", "schedule", "disable"); res.code != 0 {
		t.Fatalf("schedule disable: %+v", res)
	}
	body := string(f.body("PUT /api/v1/admin/backups/config"))
	if body == "" || strings.Contains(body, "identity_recipient") || strings.Contains(body, "has_identity") {
		t.Fatalf("PUT body: %s", body)
	}
}
