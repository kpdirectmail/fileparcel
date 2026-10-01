//go:build !unix

package home

import "errors"

// Lock is not supported on this platform (FileParcel targets Linux and macOS).
func (h *Home) Lock() (unlock func(), err error) {
	return nil, errors.New("home: locking is only supported on Linux and macOS")
}
