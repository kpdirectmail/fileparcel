package uploads

import (
	"errors"
	"testing"

	"fileparcel/internal/core"
)

// The uploader name a file-request visitor types is shown to the owner
// (access log, audit log, notifications): text-direction overrides are
// refused as in file names; the implicit marks stay allowed.
func TestCleanUploaderRefusesBidiControls(t *testing.T) {
	for _, bad := range []string{"a\u202eb", "Eve\u2066x\u2069", "a\u0007b"} {
		if _, err := cleanUploader(bad); !errors.Is(err, core.ErrInvalid) || core.AsError(err).Field != "uploader" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, ok := range []string{"", "Eve", "  Zoë  ", "\u200fשרה"} {
		if _, err := cleanUploader(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}
