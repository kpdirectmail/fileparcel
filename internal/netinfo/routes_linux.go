package netinfo

import (
	"context"
	"encoding/binary"
	"syscall"
)

// systemDefaultRouteIfaces reads the policy rules and routes of both
// families over rtnetlink (syscall.NetlinkRIB; x/sys has no dump helper)
// and returns the interfaces that carry the effective default route
// (DESIGN §10.1). A family whose dump fails (IPv6 disabled) is skipped;
// the error is returned only when neither family could be read.
func systemDefaultRouteIfaces(ctx context.Context) (map[int]bool, error) {
	var dumps [][2][]byte
	var firstErr error
	for _, fam := range []int{syscall.AF_INET, syscall.AF_INET6} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rules, err := syscall.NetlinkRIB(syscall.RTM_GETRULE, fam)
		if err == nil {
			var routes []byte
			routes, err = syscall.NetlinkRIB(syscall.RTM_GETROUTE, fam)
			if err == nil {
				dumps = append(dumps, [2][]byte{rules, routes})
				continue
			}
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if len(dumps) == 0 {
		return nil, firstErr
	}
	return linuxDefaultRouteIfaces(binary.NativeEndian, dumps...)
}
