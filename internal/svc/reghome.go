package svc

import (
	"os"
	"path/filepath"

	"fileparcel/internal/home"
)

// RegisteredHome returns the spelling of h's directory that the service
// registration and the command link of an installed home use. The installer
// records HOME as it was given (filepath.Abs, no symlink resolution) and
// writes that path into the unit or plist (--home "<HOME>"), the link target
// and installed.json; the ownership checks compare those paths as strings.
// The same home is often reached by another path later: the physical one
// that home.Resolve (through the command link) and uninstall.sh find, e.g.
// /var/opt/fileparcel for /opt/fileparcel on ostree systems where /opt links
// to var/opt. A manager built for that spelling would take the home's own
// service for another home's (ErrNotOurs) and leave it registered.
//
// So when rec names the same directory as h by another absolute path, that
// recorded path is returned; otherwise h.Dir(). Callers use it only to build
// the service manager and to recognise the command link; the home's files
// are always handled through h.
func RegisteredHome(h *home.Home, rec *Installed) string {
	dir := h.Dir()
	if rec == nil || rec.Home == "" || !filepath.IsAbs(rec.Home) {
		return dir
	}
	recorded := filepath.Clean(rec.Home)
	if recorded == dir {
		return dir
	}
	a, err := os.Stat(recorded)
	if err != nil {
		return dir
	}
	b, err := os.Stat(dir)
	if err != nil || !os.SameFile(a, b) {
		return dir
	}
	return recorded
}
