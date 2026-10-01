package svc

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Linger (systemd-logind): without it a user's services stop at logout and
// do not start at boot (DESIGN §18.2). The installer enables it for
// start-at-boot user services and records whether it did, so uninstall only
// disables linger it enabled itself.

// LingerEnabled reports whether linger is on for the host's user
// (/var/lib/systemd/linger/<user> exists).
func LingerEnabled(h *Host) bool {
	if h.User == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(h.Paths.LingerDir, h.User))
	return err == nil
}

// EnableLinger turns linger on with `loginctl enable-linger <user>`.
// changed reports whether it was off before (i.e. we enabled it).
func EnableLinger(ctx context.Context, h *Host) (changed bool, err error) {
	if h.User == "" {
		return false, errors.New("svc: unknown user name")
	}
	if LingerEnabled(h) {
		return false, nil
	}
	if _, err := h.run(ctx, nil, "loginctl", "enable-linger", h.User); err != nil {
		return false, err
	}
	return true, nil
}

// DisableLinger turns linger off with `loginctl disable-linger <user>`.
func DisableLinger(ctx context.Context, h *Host) error {
	if h.User == "" {
		return errors.New("svc: unknown user name")
	}
	if !LingerEnabled(h) {
		return nil
	}
	_, err := h.run(ctx, nil, "loginctl", "disable-linger", h.User)
	return err
}

// OtherUserUnitsEnabled lists user units other than FileParcel that the user
// enabled in their own unit directory (~/.config/systemd/user/*.wants/, as
// the user manager sees it: Host.userUnitDir). Linger must stay on while
// any exist. Globally preset units (e.g. pipewire) do not need linger and
// are not counted.
func OtherUserUnitsEnabled(h *Host) []string {
	var out []string
	dir := h.userUnitDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".wants") {
			continue
		}
		wants, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, w := range wants {
			if w.Name() == UnitName || seen[w.Name()] {
				continue
			}
			if w.Type()&fs.ModeSymlink == 0 && !w.Type().IsRegular() {
				continue
			}
			seen[w.Name()] = true
			out = append(out, w.Name())
		}
	}
	return out
}
