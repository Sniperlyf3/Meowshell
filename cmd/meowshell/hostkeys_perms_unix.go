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
	// Only group/other WRITE access is actually a tampering risk (someone
	// else replacing or editing the file/directory contents) -- matching
	// OpenSSH's own StrictModes checks on ~/.ssh, which reject group/other
	// write, not mere readability. Rejecting any group/other bit at all
	// (0o077) was stricter than that: it also rejected merely-readable
	// directories, which are completely ordinary (many systems' $HOME, and
	// notably testing.T.TempDir() itself, which os/testing creates at 0755)
	// and pose no tampering risk on their own.
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing insecure known_hosts path %s: permissions %04o allow group/other write access", path, fi.Mode().Perm())
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
