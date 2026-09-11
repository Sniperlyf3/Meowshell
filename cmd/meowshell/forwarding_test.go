package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestListenUnixRefusesToRemoveNonSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not supported on Windows")
	}
	path := filepath.Join(t.TempDir(), "important")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(path); err == nil || !strings.Contains(err.Error(), "refusing to remove non-socket") {
		t.Fatalf("listenUnix over a regular file = %v, want refusal", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
	if string(got) != "keep me" {
		t.Fatalf("regular file changed to %q", got)
	}
}
