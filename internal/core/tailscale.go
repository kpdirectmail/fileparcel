package core

import "runtime"

// TailscaleSockets returns the tailscaled LocalAPI socket locations, in the
// order they are tried. Tailscale detection (netinfo, DESIGN §10.1) and the
// Tailscale certificate fetch (certs, §10.4) share this list, so a
// certificate the admin page offers can also be fetched.
func TailscaleSockets() []string {
	if runtime.GOOS == "darwin" {
		return []string{"/var/run/tailscaled.socket", "/var/run/tailscale/tailscaled.sock"}
	}
	return []string{"/var/run/tailscale/tailscaled.sock", "/run/tailscale/tailscaled.sock"}
}

// TailscaleCLIs returns the tailscale CLI candidates, the fallback when no
// LocalAPI socket answers (see TailscaleSockets). A launchd service's PATH
// (/usr/bin:/bin:/usr/sbin:/sbin) includes neither Homebrew nor the macOS
// app bundle, hence their absolute paths.
func TailscaleCLIs() []string {
	c := []string{"tailscale"}
	if runtime.GOOS == "darwin" {
		c = append(c, "/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale",
			"/Applications/Tailscale.app/Contents/MacOS/Tailscale")
	}
	return c
}
