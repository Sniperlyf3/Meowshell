package main

import (
	"fmt"
	"os"
	"syscall"
)

var stagedKey *os.File

func stageKey(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, "meowshell-key-*")
	if err != nil {
		return "", fmt.Errorf("staging key: %w", err)
	}

	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return "", fmt.Errorf("unlinking staged key: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", fmt.Errorf("writing staged key: %w", err)
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_SETFD, 0); errno != 0 {
		f.Close()
		return "", fmt.Errorf("clearing close-on-exec on staged key: %w", errno)
	}

	stagedKey = f
	return fdPath(f.Fd()), nil
}

func fdPath(fd uintptr) string {
	if runtimeGOOS == "linux" || runtimeGOOS == "android" {
		return fmt.Sprintf("/proc/self/fd/%d", fd)
	}
	return fmt.Sprintf("/dev/fd/%d", fd)
}

func cleanupStagedKey() {}
