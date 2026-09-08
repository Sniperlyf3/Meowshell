package main

import (
	"fmt"
	"os"
	"sync"
)

var (
	stagedKeyMu   sync.Mutex
	stagedKeyPath string
)

// stageKey writes the key to a file for tailcat to read.
//
// Windows has neither unlink-while-open nor a path for an inherited
// descriptor, so unlike Unix the key does briefly exist as a named file. It
// is created with an exclusive handle in a per-user temp directory; see
// runTailcat for when it gets removed.
func stageKey(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, "meowshell-key-*")
	if err != nil {
		return "", fmt.Errorf("staging key: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("writing staged key: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("closing staged key: %w", err)
	}
	stagedKeyMu.Lock()
	stagedKeyPath = f.Name()
	stagedKeyMu.Unlock()
	return f.Name(), nil
}

// cleanupStagedKey removes the staged key file, if any. It is safe to call
// more than once, and safe to call concurrently with itself: runTailcat
// calls it both from a timer and after the child exits, and only the first
// call is expected to find anything to remove.
func cleanupStagedKey() {
	stagedKeyMu.Lock()
	path := stagedKeyPath
	stagedKeyPath = ""
	stagedKeyMu.Unlock()
	if path != "" {
		os.Remove(path)
	}
}
