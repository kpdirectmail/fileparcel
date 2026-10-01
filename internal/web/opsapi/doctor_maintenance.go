package opsapi

import (
	"fileparcel/internal/app"
	"fileparcel/internal/web/mw"
)

// checkMaintenance reports maintenance mode while it is on (DESIGN §20):
// administrators keep working during it and would otherwise easily forget
// to switch it off — the dashboard's health list and `fileparcel doctor`
// (which includes these checks) say so. Nothing while it is off.
func checkMaintenance(d *app.Deps) []DoctorCheck {
	if !mw.MaintenanceOn(d) {
		return nil
	}
	return []DoctorCheck{{ID: "maintenance", Name: "Maintenance mode", Status: CheckWarn,
		Message: "On: only administrators and roles that operate the server can use FileParcel; everyone else gets the maintenance notice",
		Hint:    "Turn it off under Settings → General, or with \"fileparcel maintenance off\", when the work is done.",
		Link:    "/admin/settings/general"}}
}
