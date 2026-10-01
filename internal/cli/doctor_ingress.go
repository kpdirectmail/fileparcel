package cli

// The Tailscale Funnel and Serve rows of the local "fileparcel doctor" while
// the server is stopped (plan R29). While it runs, the server's own doctor
// reports them (network.funnel, network.serve, …) with the other server
// checks.

import (
	"context"

	"fileparcel/internal/home"
)

// ingressFinding is one Funnel/Serve fact of the local doctor: the fields
// of tsingress.OfflineFinding (package D), which converts to it directly.
type ingressFinding struct {
	ID      string // "network.funnel" | "network.serve" | "network.funnel_bypass" | "tailscale.key_expiry"
	Status  string // ok | info | warn | fail
	Message string
	Hint    string
}

// offlineIngressFindings reads the Funnel/Serve facts of a stopped server:
// FileParcel's marker <HOME>/service/tailscale.json and, when it answers,
// tailscaled (read only), never the database.
//
// Wired to tsingress.OfflineFindings (plan R29) in doctor_ingress_wire.go;
// a variable so tests can replace it.
var offlineIngressFindings func(ctx context.Context, h *home.Home) []ingressFinding

// ingressFindingNames are the row names of the known finding ids.
var ingressFindingNames = map[string]string{
	"network.funnel":        "Tailscale Funnel",
	"network.serve":         "Tailscale Serve",
	"network.funnel_bypass": "Tailscale forwarding around FileParcel",
	"tailscale.key_expiry":  "Tailscale key expiry",
}

// checkIngressOffline adds the Funnel/Serve rows of a stopped server.
func (d *lcDoctor) checkIngressOffline(ctx context.Context) {
	if offlineIngressFindings == nil {
		return
	}
	for _, f := range offlineIngressFindings(ctx, d.h) {
		name := ingressFindingNames[f.ID]
		if name == "" {
			name = f.ID
		}
		d.add(lcCheck{ID: f.ID, Name: name, Status: f.Status, Message: f.Message, Hint: f.Hint})
	}
}
