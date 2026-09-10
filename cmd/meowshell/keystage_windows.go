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

func cleanupStagedKey() {
	stagedKeyMu.Lock()
	path := stagedKeyPath
	stagedKeyPath = ""
	stagedKeyMu.Unlock()
	if path != "" {
		os.Remove(path)
	}
}
