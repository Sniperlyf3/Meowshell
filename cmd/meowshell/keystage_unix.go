//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// stagedKey holds the descriptor the staged key lives on. It is a package
// variable so the *os.File is never garbage collected: os.File has a
// finalizer that closes the descriptor, which would pull the key out from
// under tailcat before it reads it.
var stagedKey *os.File

// stageKey writes the key where tailcat can read it without it ever
// existing under a name.
//
// The bytes go into a temp file that is unlinked immediately, so the only
// remaining reference is the open descriptor. serve execs tailcat rather
// than forking it, so the process keeps its PID and the descriptor path
// still resolves in the new image. tailcat accepts it because it treats any
// --key containing a slash as a path and simply reads it.
func stageKey(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, "meowshell-key-*")
	if err != nil {
		return "", fmt.Errorf("staging key: %w", err)
	}
	// Unlink before writing: from here on nothing can open it by name.
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return "", fmt.Errorf("unlinking staged key: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", fmt.Errorf("writing staged key: %w", err)
	}
	// Go opens files close-on-exec; this descriptor has to survive the exec.
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_SETFD, 0); errno != 0 {
		f.Close()
		return "", fmt.Errorf("clearing close-on-exec on staged key: %w", errno)
	}

	stagedKey = f
	return fdPath(f.Fd()), nil
}

// fdPath names an open descriptor as a path the child can open.
func fdPath(fd uintptr) string {
	if runtimeGOOS == "linux" || runtimeGOOS == "android" {
		return fmt.Sprintf("/proc/self/fd/%d", fd)
	}
	return fmt.Sprintf("/dev/fd/%d", fd) // darwin, and BSDs with fdescfs
}

// cleanupStagedKey is a no-op here: the file was unlinked at creation, so it
// disappears when the process exits.
func cleanupStagedKey() {}
