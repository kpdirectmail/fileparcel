package netinfo

import "net/netip"

// IsLocal implements core.Network: whether ip is an address of a local
// interface of any kind, up or down (loopback always is). It reads the last
// interface snapshot without locking and never enumerates: before the
// first snapshot only loopback counts. Used to recognise unconfigured local
// reverse proxies and Tailscale entries that point back at this machine.
func (s *Service) IsLocal(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	sn := s.snap.Load()
	if sn == nil {
		return false
	}
	for _, ni := range sn.ifaces {
		for _, p := range ni.Addrs {
			if p.Addr().Unmap().WithZone("") == ip {
				return true
			}
		}
	}
	return false
}
