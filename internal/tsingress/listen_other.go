//go:build !linux

package tsingress

import "net/netip"

// listeningOn is not implemented outside Linux (port.shadow is skipped).
func listeningOn(int) ([]netip.AddrPort, bool) { return nil, false }
