//go:build !unix

package svc

import (
	"fmt"
	"runtime"
)

// chownTree is ChownTree, which needs the descriptor-relative calls of Unix.
func chownTree(root string, self bool, uid, gid int, skip []string) error {
	return fmt.Errorf("svc: changing the owner of %s is not supported on %s", root, runtime.GOOS)
}
