package pages

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"fileparcel/internal/app"
	"fileparcel/internal/web/static"
)

// Cache policies of the root files.
const (
	cacheRevalidate = "no-cache"              // /sw.js, /theme.css, /manifest.webmanifest: always revalidated (ETag)
	cacheDay        = "public, max-age=86400" // /favicon.ico
	maxShortName    = 12                      // manifest short_name length (launcher labels)
	manifestFile    = "manifest.webmanifest"  // under web/static
	swFile          = "sw.js"                 // under web/static
	defaultCSS      = "/* FileParcel theme: default colours (ui.accent_color unchanged). */\n"
)

// genCache memoises a generated root file per input key (the relevant
// settings), so settings changes take effect immediately while repeated
// requests reuse the compressed entry.
type genCache struct {
	mu    sync.Mutex
	key   string
	entry *static.Entry
}

func (c *genCache) get(key string, build func() *static.Entry) *static.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entry == nil || c.key != key {
		c.entry, c.key = build(), key
	}
	return c.entry
}

var (
	themeCache    genCache
	manifestCache genCache
)

// accentColor returns the configured accent (normalised "#rrggbb") and
// whether it differs from the default.
func accentColor(d *app.Deps) (RGB, bool) {
	def, _ := ParseHexColor(DefaultAccentColor)
	if !hasEnv(d) || d.Settings == nil {
		return def, false
	}
	c, err := ParseHexColor(d.Settings.String(KeyAccentColor))
	if err != nil {
		return def, false
	}
	return c, c != def
}

// themeCSS serves /theme.css: the design defaults when ui.accent_color is
// unchanged, otherwise ThemeCSS(accent).
func themeCSS(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, custom := accentColor(d)
		key := "default"
		if custom {
			key = c.Hex()
		}
		e := themeCache.get(key, func() *static.Entry {
			css := defaultCSS
			if custom {
				css = ThemeCSS(c)
			}
			return static.NewEntry("theme.css", []byte(css), "")
		})
		static.Serve(w, r, e, cacheRevalidate)
	}
}

// serviceWorker serves /sw.js from the root scope with the build hash
// substituted; it is revalidated on every load so upgrades roll out.
func serviceWorker(w http.ResponseWriter, r *http.Request) {
	e, ok := static.Templated(swFile)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Service-Worker-Allowed", "/")
	static.Serve(w, r, e, cacheRevalidate)
}

// manifest serves /manifest.webmanifest with the asset base substituted and
// name/short_name/theme_color taken from ui.instance_name and
// ui.accent_color.
func manifest(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		inst := instanceName(d)
		c, custom := accentColor(d)
		key := inst + "\x00" + c.Hex()
		e := manifestCache.get(key, func() *static.Entry {
			base, ok := static.Templated(manifestFile)
			if !ok {
				return nil
			}
			return static.NewEntry(manifestFile, BuildManifest(base.Data, inst, c, custom), "")
		})
		if e == nil {
			http.NotFound(w, r)
			return
		}
		static.Serve(w, r, e, cacheRevalidate)
	}
}

// BuildManifest rewrites a web manifest: name and short_name become the
// instance name (short_name truncated to 12 characters for launcher labels)
// and, when setTheme is set, theme_color becomes the accent. Invalid JSON is
// returned unchanged.
func BuildManifest(src []byte, instance string, accent RGB, setTheme bool) []byte {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return src
	}
	if instance != "" {
		m["name"] = instance
		short := instance
		if utf8.RuneCountInString(short) > maxShortName {
			short = strings.TrimSpace(string([]rune(short)[:maxShortName]))
		}
		m["short_name"] = short
	}
	if setTheme {
		m["theme_color"] = accent.Hex()
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return src
	}
	return append(out, '\n')
}

// favicon serves /favicon.ico: the app logo (PNG where available, which
// every browser accepts at that path; the SVG logo otherwise).
func favicon(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{"icons/app-192.png", "icons/logo.svg"} {
		if e, ok := static.Lookup(name); ok {
			static.Serve(w, r, e, cacheDay)
			return
		}
	}
	http.NotFound(w, r)
}
