// Package webassets embeds the FileParcel web UI (static assets and HTML templates).
package webassets

import "embed"

// FS holds web/static/** and web/templates/**.
//
//go:embed all:static all:templates
var FS embed.FS
