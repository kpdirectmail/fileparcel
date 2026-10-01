//go:build !darwin

package netinfo

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// systemResponderHost asks avahi-daemon (system D-Bus) for the host name it
// publishes (Server.GetHostNameFqdn). "" when Avahi is not running.
func systemResponderHost(ctx context.Context) string {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return ""
	}
	defer conn.Close()
	var owned bool
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, "org.freedesktop.Avahi").Store(&owned); err != nil || !owned {
		return ""
	}
	var fqdn string
	if err := conn.Object("org.freedesktop.Avahi", "/").CallWithContext(ctx, "org.freedesktop.Avahi.Server.GetHostNameFqdn", 0).Store(&fqdn); err != nil {
		return ""
	}
	return fqdn
}
