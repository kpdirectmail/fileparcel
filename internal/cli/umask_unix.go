//go:build unix

package cli

import "golang.org/x/sys/unix"

func setUmask() { unix.Umask(0o077) }
