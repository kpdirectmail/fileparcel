package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/tslocal"
)

// TestDoctorFunnelWired runs the local doctor of a stopped server whose
// Funnel was turned on while it was stopped: the row comes from the real
// tsingress.OfflineFindings, which reads FileParcel's marker.
func TestDoctorFunnelWired(t *testing.T) {
	lcIsolateHost(t)
	// A socket that does not exist: tailscaled is never reached.
	t.Setenv(tslocal.EnvSocket, filepath.Join(t.TempDir(), "no-tailscaled.sock"))
	h := lcBareHome(t)
	marker := `{"version":1,"state":"pending","entries":[{"kind":"funnel","host_port":"node.tail.ts.net:443","port":443,"funnel":true}]}`
	if err := os.MkdirAll(h.ServiceDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.ServiceDir(), "tailscale.json"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ := lcDoctorJSON(t, h)
	var got *lcCheck
	for i := range rep.Checks {
		if rep.Checks[i].ID == "network.funnel" {
			got = &rep.Checks[i]
		}
	}
	if got == nil || got.Status != lcInfo || got.Name != "Tailscale Funnel" ||
		!strings.Contains(got.Message, "https://node.tail.ts.net/") || !strings.Contains(got.Message, "when the server starts") {
		t.Fatalf("Funnel row: %+v\nall: %+v", got, rep.Checks)
	}
}
