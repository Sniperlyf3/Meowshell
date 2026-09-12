//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

func validateNativeExecutable(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	euid := uint32(os.Geteuid())
	if st.Uid != euid && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not current uid %d or root", path, st.Uid, euid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group/other", path)
	}
	return nil
}
