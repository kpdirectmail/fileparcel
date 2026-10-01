package webassets

import (
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// TestManifestDisplay: the installed app opens as a plain standalone window
// (DESIGN §13.7). "window-controls-overlay" in display_override would let the
// user hide the title bar, after which the OS window buttons sit over the top
// bar's actions and nothing can drag the window: that mode needs
// env(titlebar-area-*) padding and an app-region: drag area in the CSS, which
// the shell does not have.
func TestManifestDisplay(t *testing.T) {
	raw, err := fs.ReadFile(FS, "static/manifest.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Display         string   `json:"display"`
		DisplayOverride []string `json:"display_override"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Display != "standalone" {
		t.Errorf("display %q, want standalone", m.Display)
	}
	if !slices.Contains(m.DisplayOverride, "window-controls-overlay") {
		return
	}
	var css strings.Builder
	err = fs.WalkDir(FS, "static/css", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".css") {
			return err
		}
		b, err := fs.ReadFile(FS, path)
		css.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := css.String(); !strings.Contains(s, "titlebar-area") || !strings.Contains(s, "app-region") {
		t.Error("manifest opts into window-controls-overlay, but no stylesheet lays out the title bar area (env(titlebar-area-*), app-region: drag)")
	}
}
