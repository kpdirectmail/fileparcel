package tsingress

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"fileparcel/internal/home"
)

// The marker <HOME>/service/tailscale.json records what FileParcel wrote to
// tailscaled's serve configuration (DESIGN §10.6). It is not in the
// database, so a restored backup carries only the settings and never
// publishes by itself. Uninstall, the offline doctor, the start of the
// server (Attach) and a rename of the node use it.
//
// It names the home that wrote it. A copied home (cp -a, to try an upgrade
// or a test instance next to the live one) carries the file too: while the
// home it names still exists, the marker belongs to that installation and
// the copy ignores it, so the copy never takes over, re-points or removes
// the live install's entries. A moved home (the named home is gone) adopts
// it.

// markerVersion is the format version of the marker.
const markerVersion = 1

// Marker states.
const (
	// markerPending: wanted, not yet written to tailscaled (enabled while
	// the server was stopped); written when the server starts.
	markerPending = "pending"
	// markerApplied: written to tailscaled.
	markerApplied = "applied"
	// markerSuspended: the TCP-backend entries were removed on a clean
	// stop; written again when the server starts.
	markerSuspended = "suspended"
)

// maxMarker bounds the marker file read.
const maxMarker = 64 << 10

// marker is the content of the marker file.
type marker struct {
	Version   int           `json:"version"`
	Home      string        `json:"home,omitempty"` // the home that wrote it ("" in markers of early v4 builds)
	NodeID    string        `json:"node_id,omitempty"`
	DNSName   string        `json:"dns_name,omitempty"` // HostPort name (tslocal.Status.HostPortName)
	Backend   string        `json:"backend,omitempty"`  // unix|tcp
	State     string        `json:"state"`
	Entries   []markerEntry `json:"entries"`
	AppliedAt *time.Time    `json:"applied_at,omitempty"`
}

// markerEntry is one serve-config entry FileParcel owns.
type markerEntry struct {
	Kind     string `json:"kind"` // funnel|serve
	HostPort string `json:"host_port"`
	Port     int    `json:"port"`
	Proxy    string `json:"proxy,omitempty"` // "" while pending with a TCP port not chosen yet
	Funnel   bool   `json:"funnel"`
}

// markerPath returns <HOME>/service/tailscale.json.
func markerPath(h *home.Home) string { return filepath.Join(h.ServiceDir(), "tailscale.json") }

// entry returns the entry of kind (nil when none).
func (m *marker) entry(kind string) *markerEntry {
	if m == nil {
		return nil
	}
	for i := range m.Entries {
		if m.Entries[i].Kind == kind {
			return &m.Entries[i]
		}
	}
	return nil
}

// entries returns the marker's entries (nil for no marker).
func (m *marker) entries() []markerEntry {
	if m == nil {
		return nil
	}
	return m.Entries
}

// waiting reports whether the marker asks the next start to write its
// entries (pending, or suspended by a clean stop of the TCP backend).
func (m *marker) waiting() bool {
	return m != nil && (m.State == markerPending || m.State == markerSuspended)
}

// readMarker reads the marker (nil, nil when there is none).
func readMarker(h *home.Home) (*marker, error) {
	if h == nil {
		return nil, nil
	}
	f, err := os.Open(markerPath(h))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxMarker+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMarker {
		return nil, fmt.Errorf("%s: larger than %d bytes", markerPath(h), maxMarker)
	}
	var m marker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", markerPath(h), err)
	}
	if m.Version != markerVersion {
		return nil, fmt.Errorf("%s: unknown version %d", markerPath(h), m.Version)
	}
	return &m, nil
}

// loadMarkerOf reads h's marker and drops one another installation wrote
// (foreignMarker): nil, nil then, as without a marker.
func loadMarkerOf(h *home.Home) (*marker, error) {
	m, err := readMarker(h)
	if err != nil || m == nil || !foreignMarker(h, m) {
		return m, err
	}
	return nil, nil
}

// foreignMarker reports whether m was written by another installation that
// still exists: a copied home's marker. The marker of a moved home (the home
// it names is gone) and one without a home belong to h.
func foreignMarker(h *home.Home, m *marker) bool {
	return m != nil && m.Home != "" && !sameDir(m.Home, h.Dir()) && !homeGone(m.Home)
}

// homeGone reports whether no installation lives in dir any more: its
// fileparcel.toml does not exist. A home this process may not look into
// counts as existing.
func homeGone(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, home.ConfigName))
	return errors.Is(err, fs.ErrNotExist)
}

// sameDir reports whether a and b name the same directory (also through a
// symlink).
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	x, err1 := os.Stat(a)
	y, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(x, y)
}

// writeMarker stores m atomically with mode 0600, or removes the file when
// m has no entries.
func writeMarker(h *home.Home, m *marker) error {
	if h == nil {
		return nil
	}
	path := markerPath(h)
	if m == nil || len(m.Entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	m.Version, m.Home = markerVersion, h.Dir()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), home.ModeService); err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), home.ModeSecret)
}

// writeFileAtomic writes data to path via a temporary file in the same
// directory, fsync and rename.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
