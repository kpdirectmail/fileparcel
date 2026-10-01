package mdns

import (
	"context"
	"fmt"
	"net"
)

// detectBackend implements mdns.mode "auto" (DESIGN §10.5): Avahi when the
// system bus has an owner for org.freedesktop.Avahi, dns-sd on macOS,
// otherwise the builtin responder.
func (s *Service) detectBackend(ctx context.Context) string {
	if s.goos == "darwin" {
		return BackendDNSSD
	}
	if avahiAvailable(ctx) {
		return BackendAvahi
	}
	return BackendBuiltin
}

// systemBackend constructs the real backend of kind.
func (s *Service) systemBackend(kind string, emit func(backendEvent)) (backend, error) {
	switch kind {
	case BackendAvahi:
		return newAvahiBackend(s.log, emit), nil
	case BackendDNSSD:
		return newDNSSDBackend(s.log, emit), nil
	case BackendBuiltin:
		return newBuiltinBackend(s.log, emit), nil
	}
	return nil, fmt.Errorf("unknown mDNS backend %q", kind)
}

// indexOf returns the OS interface index of name (0 when unknown).
func indexOf(name string) int {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return ifc.Index
}
