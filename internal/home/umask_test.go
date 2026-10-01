//go:build unix

package home

import "golang.org/x/sys/unix"

func umask(m int) int { return unix.Umask(m) }
