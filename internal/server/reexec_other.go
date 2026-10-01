//go:build !unix

package server

import "errors"

// ReExec is not supported on this platform; the caller exits with
// ExitRestart instead.
func ReExec() error { return errors.New("re-exec is not supported on this platform") }
