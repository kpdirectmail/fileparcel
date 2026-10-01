package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// "config test-email" sends POST /admin/settings/email/test (nothing on the
// command line called it) and shows the mail server's refusal.
func TestConfigTestEmail(t *testing.T) {
	f := newFakeAPI(t)
	fail := false
	f.handle("POST", "/api/v1/admin/settings/email/test", func(w http.ResponseWriter, r *http.Request) {
		if fail {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"code": "unavailable",
				"message": "smtp: 535 authentication failed"}})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	res := f.run(t, "", "config", "test-email", "--to", "admin@example.org")
	var in core.EmailTestInput
	if err := json.Unmarshal(f.body("POST /api/v1/admin/settings/email/test"), &in); err != nil || in.To != "admin@example.org" ||
		res.code != 0 || !strings.Contains(res.stdout+res.stderr, "test e-mail sent to admin@example.org") {
		t.Fatalf("send: %+v (body %+v, %v)", res, in, err)
	}
	fail = true
	if res = f.run(t, "", "config", "test-email", "--to", "admin@example.org"); res.code == 0 || !strings.Contains(res.stderr, "535 authentication failed") {
		t.Fatalf("refused: %+v", res)
	}
	if res = f.run(t, "", "config", "test-email"); res.code != ExitUsage || !strings.Contains(res.stderr, "--to is required") {
		t.Fatalf("without --to: %+v", res)
	}
}
