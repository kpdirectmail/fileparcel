//go:build !linux

package netinfo

// isWireless is Linux-only (sysfs); elsewhere the name heuristic of classify
// (wl*) applies and darwin Wi-Fi (en0) is reported as lan (DESIGN §10.1).
func isWireless(string) bool { return false }

// sysfsInfo is Linux-only: other systems classify by name, address and the
// default route.
func sysfsInfo(string) (devType string, isTun bool, master string) { return "", false, "" }
