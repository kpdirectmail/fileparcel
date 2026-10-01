package opsapi

import (
	"testing"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/mw"
)

// maintSettings answers maintenance.enabled (the only key checkMaintenance reads).
type maintSettings struct {
	core.Settings
	on bool
}

func (s maintSettings) Bool(key string) bool { return key == mw.KeyMaintenanceEnabled && s.on }

// TestDoctorMaintenance: maintenance mode is a warning while it is on (the
// dashboard and `fileparcel doctor` show it), and no check at all while off.
func TestDoctorMaintenance(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	if got := checkMaintenance(te.d); len(got) != 0 {
		t.Fatalf("without settings: %+v", got)
	}
	te.d.Settings = maintSettings{}
	if got := checkMaintenance(te.d); len(got) != 0 {
		t.Fatalf("off: %+v", got)
	}
	te.d.Settings = maintSettings{on: true}
	got := checkMaintenance(te.d)
	if len(got) != 1 || got[0].ID != "maintenance" || got[0].Status != CheckWarn || got[0].Link != "/admin/settings/general" || got[0].Hint == "" {
		t.Fatalf("on: %+v", got)
	}
}

// TestSystemReportsMaintenance: GET /admin/system carries maintenance while
// it is on (what `fileparcel status` prints), and leaves it out while off.
func TestSystemReportsMaintenance(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	get := func() map[string]any {
		t.Helper()
		var m map[string]any
		r := te.do("GET", "/admin/system", "admin", nil)
		r.json(t, &m)
		if r.code != 200 {
			t.Fatalf("system %d %s", r.code, r.body)
		}
		return m
	}
	if _, ok := get()["maintenance"]; ok {
		t.Fatal("maintenance reported without settings")
	}
	te.d.Settings = maintSettings{}
	if _, ok := get()["maintenance"]; ok {
		t.Fatal("maintenance reported while off")
	}
	te.d.Settings = maintSettings{on: true}
	if v := get()["maintenance"]; v != true {
		t.Fatalf("maintenance = %v while on", v)
	}
}
