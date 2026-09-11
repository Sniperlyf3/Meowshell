//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

func validateKnownHostsDir(path string) error {
	return validateKnownHostsPath(path, true)
}

func validateKnownHostsFile(path string) error {
	return validateKnownHostsPath(path, false)
}

func validateKnownHostsPath(path string, wantDir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("checking known_hosts security for %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing insecure known_hosts path %s: symbolic links are not allowed", path)
	}
	if wantDir != fi.IsDir() {
		kind := "file"
		if wantDir {
			kind = "directory"
		}
		return fmt.Errorf("refusing insecure known_hosts path %s: expected a %s", path, kind)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("refusing insecure known_hosts path %s: permissions %04o allow group/other access", path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checking known_hosts ownership for %s: unsupported stat data", path)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing insecure known_hosts path %s: owned by uid %d, current uid is %d", path, st.Uid, os.Geteuid())
	}
	return nil
}
