//go:build unix

package main

import "syscall"

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
