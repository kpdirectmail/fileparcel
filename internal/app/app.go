// Package app defines Deps, the bag of services handed to every HTTP package
// (web/*) and the CLI, and the run Mode. It imports only core and ratelimit.
package app

import (
	"fileparcel/internal/core"
	"fileparcel/internal/ratelimit"
)

// Mode says how the process uses the services.
type Mode int

const (
	// ModeNetwork is `serve`: listeners, background jobs, mDNS.
	ModeNetwork Mode = iota
	// ModeSocket is reserved (unused; socket clients talk to a ModeNetwork server).
	ModeSocket
	// ModeOffline is the in-process CLI when no server runs: no listeners, no
	// jobs runner, no mDNS; certificates are only loaded.
	ModeOffline
)

// String returns "network", "socket" or "offline".
func (m Mode) String() string {
	switch m {
	case ModeNetwork:
		return "network"
	case ModeSocket:
		return "socket"
	case ModeOffline:
		return "offline"
	}
	return "unknown"
}

// Deps holds every service (DESIGN §5.2). The embedded Env gives Home,
// Config, DB, Log, Clock, Bus, Build, Keys, Settings and Audit.
type Deps struct {
	*core.Env
	Mode Mode

	Auth    core.Auth
	Users   core.Users
	Files   core.Files
	Uploads core.Uploads
	Shares  core.Shares
	Blobs   core.BlobStore
	Jobs    core.Jobs
	Backups core.Backups
	Certs   core.Certs
	Network core.Network
	MDNS    core.MDNS
	Notify  core.Notify
	Limiter *ratelimit.Registry
	// Ingress is Tailscale Funnel/Serve (nil until package tsingress is
	// wired; every user nil-checks it).
	Ingress core.Ingress
}
