//go:build unix

package shieldconfig

import (
	"errors"
	"os"
	"syscall"
)

// PublicWebMarked says whether the marker exists. Absent is false; present must be a regular file of `owner`'s that
// nobody may write, and anything else is an error (the caller fails closed).
func PublicWebMarked(path string, owner int) (bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || !ok || int(sys.Uid) != owner || st.Mode().Perm()&0o222 != 0 {
		return false, errors.New("the public web marker is not a read-only file of the monitor's")
	}
	return true, nil
}
