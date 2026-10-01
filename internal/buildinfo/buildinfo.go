// Package buildinfo exposes the version metadata stamped into the binary at
// link time:
//
//	go build -ldflags "-X fileparcel/internal/buildinfo.Version=v7 \
//	  -X fileparcel/internal/buildinfo.Commit=abc1234def56 \
//	  -X fileparcel/internal/buildinfo.Date=2026-09-19T10:00:00Z"
//
// When the variables are not stamped (plain `go build` / `go run`), Get falls
// back to the VCS information recorded by the Go toolchain, if any.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Link-time variables (set with -ldflags -X). Keep them plain strings.
var (
	// Version is the release name, e.g. "v7". "dev" for unreleased builds.
	Version = "dev"
	// Commit is the (abbreviated) git commit the binary was built from.
	Commit = ""
	// Date is the commit/build date (ISO 8601 / RFC 3339).
	Date = ""
)

// Info is the build metadata of the running binary. Its JSON form is part of
// the API (`GET /api/v1/admin/system`, `fileparcel version --json`).
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

var (
	once sync.Once
	info Info
)

// Get returns the build metadata (computed once).
func Get() Info {
	once.Do(func() {
		info = Info{
			Version:   Version,
			Commit:    Commit,
			Date:      Date,
			GoVersion: runtime.Version(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		}
		if info.Version == "" {
			info.Version = "dev"
		}
		if info.Commit == "" || info.Date == "" {
			if bi, ok := debug.ReadBuildInfo(); ok {
				modified := false
				for _, s := range bi.Settings {
					switch s.Key {
					case "vcs.revision":
						if info.Commit == "" {
							info.Commit = s.Value
						}
					case "vcs.time":
						if info.Date == "" {
							info.Date = s.Value
						}
					case "vcs.modified":
						modified = s.Value == "true"
					}
				}
				if modified && info.Commit != "" && !strings.HasSuffix(info.Commit, "-dirty") {
					info.Commit += "-dirty"
				}
			}
		}
		if len(info.Commit) > 12 && !strings.HasSuffix(info.Commit, "-dirty") {
			info.Commit = info.Commit[:12]
		}
		if info.Commit == "" {
			info.Commit = "unknown"
		}
	})
	return info
}

// String renders the info as written to <HOME>/VERSION, e.g.
// "v7 abc1234def56 2026-09-19". The date is shortened to YYYY-MM-DD.
func (i Info) String() string {
	d := i.Date
	if len(d) >= 10 {
		d = d[:10]
	}
	if d == "" {
		d = "unknown-date"
	}
	return fmt.Sprintf("%s %s %s", i.Version, i.Commit, d)
}

// String is shorthand for Get().String().
func String() string { return Get().String() }
