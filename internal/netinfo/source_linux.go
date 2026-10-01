package netinfo

import (
	"os"
	"path/filepath"
)

// isWireless reports whether the Linux interface is an 802.11 device
// (/sys/class/net/<name>/wireless or …/phy80211 exists).
func isWireless(name string) bool {
	if !safeIfName(name) {
		return false
	}
	for _, sub := range []string{"wireless", "phy80211"} {
		if _, err := os.Stat("/sys/class/net/" + name + "/" + sub); err == nil {
			return true
		}
	}
	return false
}

// sysfsInfo reads the classification signals sysfs has for an interface
// (DESIGN §10.1): DEVTYPE= of …/uevent ("wireguard", "ovpn-dco", "bridge",
// "wlan", …), whether it is a TUN/TAP device (…/tun_flags exists) and the
// bridge or bond it is a port of (basename of the …/master link).
func sysfsInfo(name string) (devType string, isTun bool, master string) {
	if !safeIfName(name) {
		return "", false, ""
	}
	dir := "/sys/class/net/" + name
	if b, err := os.ReadFile(dir + "/uevent"); err == nil && len(b) <= 64<<10 {
		devType = ueventDevType(b)
	}
	if _, err := os.Stat(dir + "/tun_flags"); err == nil {
		isTun = true
	}
	if l, err := os.Readlink(dir + "/master"); err == nil {
		master = filepath.Base(l)
	}
	return devType, isTun, master
}
