//go:build unix

package uploads

import "golang.org/x/sys/unix"

// diskFree returns the bytes available to unprivileged users and the total
// size of the file system containing path.
func diskFree(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:unconvert // Bsize's type differs between platforms
	return uint64(st.Bavail) * bs, uint64(st.Blocks) * bs, nil
}
