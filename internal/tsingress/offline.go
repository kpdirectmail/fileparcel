package tsingress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/tslocal"
)

// OfflineFinding is one Funnel/Serve fact the local "fileparcel doctor"
// shows while the server is stopped.
type OfflineFinding struct {
	ID      string // "network.funnel" | "network.serve" | "network.funnel_bypass" | "tailscale.key_expiry"
	Status  string // ok | info | warn | fail
	Message string
	Hint    string
}

// Offline finding IDs.
const (
	FindingFunnel    = "network.funnel"
	FindingServe     = "network.serve"
	FindingBypass    = "network.funnel_bypass"
	FindingKeyExpiry = "tailscale.key_expiry"
)

// OfflineFindings reads <HOME>/service/tailscale.json and, when it answers,
// tailscaled (read only) — never the database (the server, which owns it,
// is stopped). It returns nil when the marker does not exist and no
// foreign serve entry targets FileParcel's main port or admin socket. ts
// nil means tslocal.Default().
func OfflineFindings(ctx context.Context, h *home.Home, ts *tslocal.Client) []OfflineFinding {
	if h == nil {
		return nil
	}
	if ts == nil {
		ts = tslocal.Default()
	}
	var out []OfflineFinding
	m, merr := loadMarkerOf(h)
	if merr != nil {
		out = append(out, OfflineFinding{ID: FindingFunnel, Status: "warn",
			Message: "FileParcel's Tailscale marker cannot be read: " + merr.Error(),
			Hint:    "Start the server and check the Network page; Re-apply rewrites it."})
	}
	var st *tslocal.Status
	var sc *tslocal.ServeConfig
	var tsErr error
	if ts.Installed() {
		if st, tsErr = ts.Status(ctx); tsErr == nil {
			sc, tsErr = ts.ServeConfig(ctx)
		}
	}

	// Foreign entries that bypass FileParcel's access policy.
	if sc != nil {
		own := ownershipFor(h, m)
		mains := []int{defaultMainPort}
		if c, err := config.Load(h); err == nil && c.Server.HTTPSPort > 0 {
			mains = []int{c.Server.HTTPSPort}
		}
		v := &tsView{st: st, sc: sc}
		local := offlineLocal(v)
		for _, e := range sc.Entries() {
			if !e.Foreground && e.Service == "" && e.Mount == "/" && own.owned(e.Proxy) {
				continue
			}
			if entryBypass(e, mains, h.Socket(), local) {
				where := e.HostPort
				if where == "" {
					where = "port " + strconv.Itoa(e.Port)
				}
				out = append(out, OfflineFinding{ID: FindingBypass, Status: "fail",
					Message: "Tailscale forwards " + where + " directly to FileParcel (" + e.Target() + "): every visitor " +
						"would appear as one address; FileParcel refuses these requests",
					Hint: "Remove it (" + tslocal.OffCommand(e.Port, false) + " on the machine that runs it), then " +
						"use fileparcel network funnel enable."})
			}
		}
	}
	if m == nil {
		return out
	}

	for _, e := range m.Entries {
		out = append(out, offlineEntry(e, m, sc, tsErr))
	}
	if st != nil && st.Self != nil && st.Self.KeyExpiry != nil && len(m.Entries) > 0 &&
		st.Self.KeyExpiry.Before(time.Now().Add(keyExpiryWarn)) {
		out = append(out, OfflineFinding{ID: FindingKeyExpiry, Status: "warn",
			Message: "The Tailscale key of this device expires on " + st.Self.KeyExpiry.UTC().Format("2006-01-02") +
				"; Funnel and Serve stop working then",
			Hint: "Disable key expiry for this machine in the Tailscale admin console."})
	}
	return out
}

// offlineEntry describes one marker entry while the server is stopped.
func offlineEntry(e markerEntry, m *marker, sc *tslocal.ServeConfig, tsErr error) OfflineFinding {
	id, label := FindingFunnel, "Tailscale Funnel"
	if e.Kind == core.IngressServe {
		id, label = FindingServe, "Tailscale Serve"
	}
	url := hostURL(strings.ToLower(strings.TrimSuffix(e.HostPort, ":"+strconv.Itoa(e.Port))), e.Port) + "/"
	f := OfflineFinding{ID: id, Status: "info"}
	switch {
	case m.State == markerPending:
		f.Message = label + " is turned on; FileParcel publishes it at " + url + " when the server starts"
	case m.State == markerSuspended:
		f.Message = label + " is turned on; FileParcel removed its entry when it stopped (local TCP connection) " +
			"and adds it again when the server starts"
	case sc == nil:
		f.Message = label + " publishes FileParcel at " + url + " (tailscaled could not be asked"
		if tsErr != nil {
			f.Message += ": " + tsErr.Error()
		}
		f.Message += ")"
	default:
		cur, _ := sc.Proxy(e.HostPort, e.Port)
		switch {
		case cur != e.Proxy || sc.FunnelOn(e.HostPort) != e.Funnel:
			f.Status = "warn"
			f.Message = "Tailscale no longer has FileParcel's " + label + " entry for " + url + " (changed outside FileParcel)"
			f.Hint = "Start the server and Re-apply on the Network page, or run fileparcel network " +
				map[bool]string{true: "funnel", false: "tailscale-serve"}[e.Kind == core.IngressFunnel] + " reapply."
		case backendOf(e.Proxy) == BackendTCP:
			f.Status = "warn"
			f.Message = label + "'s entry points at " + strings.TrimPrefix(e.Proxy, "http://") + ", which any local " +
				"program could take while FileParcel is stopped (it was not stopped cleanly)"
			f.Hint = "Start the server, or remove the entry: " + tslocal.OffCommand(e.Port, false)
		default:
			f.Message = label + " publishes FileParcel at " + url + "; visitors get an error page until the server starts"
		}
	}
	return f
}

// offlineLocal is localHost without the network service.
func offlineLocal(v *tsView) func(string) bool {
	s := &Service{}
	f := s.localHost(v)
	return func(host string) bool {
		if f(host) {
			return true
		}
		ip, err := netip.ParseAddr(strings.TrimSuffix(host, "."))
		return err == nil && hasLocalAddr(ip)
	}
}

// HasMarker reports whether FileParcel recorded Tailscale entries for this
// home (uninstall lists the removal step then).
func HasMarker(h *home.Home) bool {
	m, err := loadMarkerOf(h)
	return err != nil || (m != nil && len(m.Entries) > 0)
}

// RemoveMarked removes FileParcel's entries of this home from tailscaled
// (uninstall; the server is stopped) and deletes the marker. A failure
// names the commands that remove them by hand. ts nil means
// tslocal.Default().
func RemoveMarked(ctx context.Context, h *home.Home, ts *tslocal.Client) error {
	if ts == nil {
		ts = tslocal.Default()
	}
	m, err := readMarker(h)
	if err != nil {
		return err
	}
	if m == nil {
		return nil
	}
	if foreignMarker(h, m) {
		// A copied home: the entries belong to the installation it was
		// copied from, which still exists.
		return writeMarker(h, nil)
	}
	if _, err := removeOwned(ctx, ts, ownershipFor(h, m)); err != nil {
		return err
	}
	return writeMarker(h, nil)
}

// removeMarked removes the entries of own (Detach of the TCP backend).
func (s *Service) removeMarked(ctx context.Context, own ownership) error {
	_, err := removeOwned(ctx, s.ts, own)
	s.invalidateView()
	return err
}

// removeOwned removes every entry of own from tailscaled's serve
// configuration and reports what it removed. With the CLI transport each
// entry is removed with `tailscale serve --yes --https=<port>
// --set-path=/ off`. The error names the commands to run by hand.
func removeOwned(ctx context.Context, ts *tslocal.Client, own ownership) ([]ownedEntry, error) {
	var removed []ownedEntry
	for attempt := 0; attempt < 3; attempt++ {
		sc, err := ts.ServeConfig(ctx)
		if err != nil {
			return nil, removeError(nil, err)
		}
		entries := own.entries(sc)
		if len(entries) == 0 {
			return removed, nil
		}
		if ts.Transport() == "cli" {
			for _, e := range entries {
				if err := ts.ServeOffCLI(ctx, e.port); err != nil {
					return removed, removeError(entries, err)
				}
				removed = append(removed, e)
			}
			return removed, nil
		}
		work := sc.Clone()
		for _, e := range entries {
			work.RemoveEntry(e.hostPort, e.port, own.owned)
		}
		err = ts.SetServeConfig(ctx, work)
		if errors.Is(err, tslocal.ErrETagMismatch) {
			continue
		}
		if err != nil {
			return nil, removeError(entries, err)
		}
		return entries, nil
	}
	return nil, removeError(nil, tslocal.ErrETagMismatch)
}

// removeError explains a failed removal with the commands to run by hand.
func removeError(entries []ownedEntry, err error) error {
	sudo := errors.Is(err, tslocal.ErrUnixForbidden)
	var cmds []string
	for _, e := range entries {
		if c := tslocal.OffCommand(e.port, sudo); !slices.Contains(cmds, c) {
			cmds = append(cmds, c)
		}
	}
	if len(cmds) == 0 {
		return fmt.Errorf("could not remove FileParcel's Tailscale entries: %w", err)
	}
	return fmt.Errorf("could not remove FileParcel's Tailscale entries (run %s): %w", strings.Join(cmds, " and "), err)
}
