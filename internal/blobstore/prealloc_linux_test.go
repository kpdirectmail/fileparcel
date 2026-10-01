//go:build linux

package blobstore

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"fileparcel/internal/core"
)

// TestFallocFallback pins which fallocate failures fall back to a sparse
// Truncate: only "not supported", never a full disk or an exhausted quota
// (the reservation is what refuses an upload that cannot fit up front).
func TestFallocFallback(t *testing.T) {
	errTrunc := errors.New("truncated")
	for _, c := range []struct {
		name      string
		err       error
		want      error
		truncated bool
	}{
		{"success", nil, nil, false},
		{"ENOSPC", os.NewSyscallError("fallocate", syscall.ENOSPC), syscall.ENOSPC, false},
		{"EDQUOT", syscall.EDQUOT, syscall.EDQUOT, false},
		{"EOPNOTSUPP", syscall.EOPNOTSUPP, errTrunc, true},
		{"ENOSYS", syscall.ENOSYS, errTrunc, true},
	} {
		truncated := false
		err := fallocFallback(c.err, func() error { truncated = true; return errTrunc })
		if truncated != c.truncated {
			t.Errorf("%s: truncate called = %v, want %v", c.name, truncated, c.truncated)
		}
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if c.name == "EDQUOT" && !isErr(diskErr(err), core.ErrQuota) {
			t.Errorf("EDQUOT from fallocate must map to 507: %v", diskErr(err))
		}
	}
}
