//go:build !unix

package installer

import (
	"context"
	"errors"
)

// processIsFileParcel cannot tell on this platform.
func processIsFileParcel(int) bool { return false }

// terminateProcess is not supported on this platform.
func terminateProcess(context.Context, int, func() bool) error {
	return errors.New("stopping a process is not supported on this platform")
}
