package pages

import (
	"fileparcel/internal/app"
	"fileparcel/internal/web/mw"
)

// maintenanceFeatures adds maintenance: whether maintenance mode is on
// (maintenance.enabled, DESIGN §20). Members are kept out by mw.Maintenance
// anyway; the flag is for the people who keep working during it —
// administrators and holders of "Operate the server" get a banner with the
// way to turn it off, and the sign-in page says it before anyone types a
// password.
func maintenanceFeatures(d *app.Deps, f map[string]bool) {
	f["maintenance"] = mw.MaintenanceOn(d)
}
