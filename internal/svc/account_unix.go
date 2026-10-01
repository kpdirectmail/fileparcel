//go:build unix

package svc

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// chownTree is ChownTree; self says whether root itself is changed too.
func chownTree(root string, self bool, uid, gid int, skip []string) error {
	top, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	w := &chownWalker{uid: uid, gid: gid, skip: map[fileID]bool{}}
	for _, s := range skip {
		var st unix.Stat_t
		if unix.Lstat(s, &st) == nil {
			w.skip[idOf(&st)] = true
		}
	}
	f, st, err := w.open(unix.AT_FDCWD, top, top, unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer f.Close()
	if w.skip[idOf(st)] {
		return nil
	}
	if self && !w.owned(st) {
		if err := fchown(f, uid, gid); err != nil {
			return err
		}
	}
	return w.dir(f, top)
}

// fileID identifies a file (device and inode).
type fileID struct{ dev, ino uint64 }

func idOf(st *unix.Stat_t) fileID { return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)} }

// chownWalker walks a tree through directory descriptors (see ChownTree).
type chownWalker struct {
	uid, gid int
	skip     map[fileID]bool
}

func (w *chownWalker) owned(st *unix.Stat_t) bool {
	return int(st.Uid) == w.uid && int(st.Gid) == w.gid
}

// open opens name in the directory dirfd (p is its path, for errors and
// tests) without following a symlink, and returns it with its fstat.
func (w *chownWalker) open(dirfd int, name, p string, flags int) (*os.File, *unix.Stat_t, error) {
	fd, err := unix.Openat(dirfd, name, flags|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, nil, &fs.PathError{Op: "fstat", Path: p, Err: err}
	}
	return f, &st, nil
}

// replaced reports an open error meaning the entry is gone, or was replaced
// by a symlink (O_NOFOLLOW: ELOOP, EMLINK on FreeBSD), a file where a
// directory was listed, or a socket, since it was listed.
func replaced(err error) bool {
	for _, e := range []error{unix.ENOENT, unix.ELOOP, unix.EMLINK, unix.ENOTDIR, unix.ENXIO} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// dir changes everything in the open directory f (at p).
func (w *chownWalker) dir(f *os.File, p string) error {
	names, err := f.Readdirnames(-1)
	if err != nil {
		return err
	}
	sort.Strings(names)
	dirfd := int(f.Fd())
	for _, name := range names {
		if err := w.entry(dirfd, name, filepath.Join(p, name)); err != nil {
			return err
		}
	}
	return nil
}

// entry changes name in the directory dirfd (at p), and the tree below it
// when it is a directory. Everything is decided on the opened file's own
// fstat, whatever the entry was when it was listed.
func (w *chownWalker) entry(dirfd int, name, p string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return &fs.PathError{Op: "lstat", Path: p, Err: err}
	}
	var flags int
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		flags = unix.O_DIRECTORY
	case unix.S_IFREG:
		if w.owned(&st) {
			return nil
		}
		flags = unix.O_NONBLOCK // a FIFO swapped in must not block the open
	default:
		return nil // symlinks, sockets, FIFOs, devices
	}
	if chownVisit != nil {
		chownVisit(p)
	}
	f, fst, err := w.open(dirfd, name, p, flags)
	if err != nil {
		if replaced(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	if w.skip[idOf(fst)] {
		return nil
	}
	switch fst.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if !w.owned(fst) {
			if err := fchown(f, w.uid, w.gid); err != nil {
				return err
			}
		}
		return w.dir(f, p)
	case unix.S_IFREG:
		if w.owned(fst) || (fst.Nlink > 1 && int(fst.Uid) != w.uid) {
			return nil
		}
		return fchown(f, w.uid, w.gid)
	}
	return nil
}
