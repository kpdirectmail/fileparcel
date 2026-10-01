//go:build !unix

package uploads

import "errors"

// diskFree is not implemented on this platform; the free-space check is skipped.
func diskFree(string) (free, total uint64, err error) {
	return 0, 0, errors.New("uploads: free-space check not supported on this platform")
}
