//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// withRestrictedUmask tightens the umask for the duration of fn, so a
// freshly created Unix domain socket file never briefly exists at default
// (umask-derived) permissions before being explicitly chmod'd afterward.
// Go's own docs note Umask is a process-wide attribute, so a concurrent,
// unrelated file creation elsewhere in the process during this narrow
// window could observe the tightened mask too -- accepted here since the
// window is a single net.Listen syscall and the caller's own Chmod still
// runs as a backstop regardless.
func withRestrictedUmask(fn func() error) error {
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return fn()
}


func validateSocketParent(path string) error {
	parent := filepath.Dir(path)
	absParent, err := filepath.Abs(parent)
	if err != nil {
		return fmt.Errorf("resolving socket parent %s: %w", parent, err)
	}
	resolved, err := filepath.EvalSymlinks(absParent)
	if err != nil {
		return fmt.Errorf("resolving socket parent %s: %w", absParent, err)
	}
	if filepath.Clean(resolved) != filepath.Clean(absParent) {
		return fmt.Errorf("refusing insecure socket parent %s: symbolic-link components are not allowed", absParent)
	}

	fi, err := os.Lstat(absParent)
	if err != nil {
		return fmt.Errorf("checking socket parent %s: %w", absParent, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("refusing insecure socket parent %s: not a directory", absParent)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checking socket parent ownership for %s: unsupported stat data", absParent)
	}
	euid := uint32(os.Geteuid())
	ownerOK := st.Uid == euid
	rootOwnedSticky := st.Uid == 0 && fi.Mode()&os.ModeSticky != 0
	if !ownerOK && !rootOwnedSticky {
		return fmt.Errorf("refusing insecure socket parent %s: owned by uid %d, current uid is %d", absParent, st.Uid, euid)
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("refusing insecure socket parent %s: group/other-writable without the sticky bit", absParent)
	}
	return nil
}
