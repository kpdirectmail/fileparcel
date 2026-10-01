package cli

// The local doctor's Funnel/Serve rows come from package tsingress (plan
// R29): it reads FileParcel's marker and, when it answers, tailscaled (read
// only), never the database.

import (
	"context"

	"fileparcel/internal/home"
	"fileparcel/internal/tsingress"
)

func init() {
	offlineIngressFindings = func(ctx context.Context, h *home.Home) []ingressFinding {
		var out []ingressFinding
		for _, f := range tsingress.OfflineFindings(ctx, h, nil) {
			out = append(out, ingressFinding(f))
		}
		return out
	}
}
