//go:build unix

package main

import (
	"fmt"
	"io"
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
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return "", fmt.Errorf("rewinding staged key: %w", err)
	}

	// Tailcat's patched --key=- reads the JSON from stdin. Keep the anonymous
	// file CLOEXEC here; runTailcat duplicates it onto fd 0 immediately before
	// exec. That avoids leaving a private-key descriptor >= 3 inheritable by
	// Tailcat's later ssh/exec children.
	stagedKey = f
	return "-", nil
}

func prepareStagedKeyStdin() error {
	if stagedKey == nil {
		return nil
	}
	f := stagedKey
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewinding staged key for tailcat stdin: %w", err)
	}

	fd := int(f.Fd())
	if fd != int(os.Stdin.Fd()) {
		if err := syscall.Dup2(fd, int(os.Stdin.Fd())); err != nil {
			return fmt.Errorf("placing staged key on stdin: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("closing staged key descriptor: %w", err)
		}
	}
	// dup2 clears FD_CLOEXEC on the destination, but if CreateTemp happened to
	// allocate fd 0 because the caller started with stdin closed, clear it
	// explicitly so --key=- still works after exec.
	if _, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL,
		os.Stdin.Fd(),
		syscall.F_SETFD,
		0,
	); errno != 0 {
		return fmt.Errorf("making staged key stdin inheritable: %w", errno)
	}
	stagedKey = nil
	return nil
}

func cleanupStagedKey() {
	if stagedKey != nil {
		_ = stagedKey.Close()
		stagedKey = nil
	}
}
