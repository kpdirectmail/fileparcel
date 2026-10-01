//go:build linux

package backup

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// lockHolders returns the PIDs holding a flock on path, from /proc/locks.
// ok is false when that cannot be determined.
func lockHolders(path string) (pids []int, ok bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return nil, false
	}
	dev := fmt.Sprintf("%02x:%02x:%d", unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino)
	f, err := os.Open("/proc/locks")
	if err != nil {
		return nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "1: FLOCK  ADVISORY  WRITE 5010 00:42:134 0 EOF" (blocked waiters have "->").
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || fields[1] != "FLOCK" {
			continue
		}
		if fields[5] != dev {
			continue
		}
		pid, err := strconv.Atoi(fields[4])
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, sc.Err() == nil
}
