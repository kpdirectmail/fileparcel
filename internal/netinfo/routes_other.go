//go:build !linux && !darwin

package netinfo

import (
	"context"
	"errors"
)

// systemDefaultRouteIfaces is implemented on Linux and macOS only; elsewhere
// no generic tunnel is recognised as an exit VPN by its default route.
func systemDefaultRouteIfaces(context.Context) (map[int]bool, error) {
	return nil, errors.ErrUnsupported
}
