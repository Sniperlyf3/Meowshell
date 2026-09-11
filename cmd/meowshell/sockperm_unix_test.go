//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWithRestrictedUmaskTightensDuringAndRestoresAfter is a regression
// test for the fix to listenUnix's permission window: net.Listen creates
// the socket file at default (umask-derived) permissions, and only an
// explicit Chmod afterward restricted it -- a brief window in which
// another local user could connect before access narrowed to the owner.
// withRestrictedUmask closes that window by tightening the umask for the
// duration of the Listen call itself, so the file is 0600 from the moment
// it's created. Probes the umask in effect by the standard
// set-then-immediately-restore idiom (syscall.Umask has no separate "get").
func TestWithRestrictedUmaskTightensDuringAndRestoresAfter(t *testing.T) {
	const startingUmask = 0o022
	original := syscall.Umask(startingUmask)
	t.Cleanup(func() { syscall.Umask(original) })

	var observedDuring int
	if err := withRestrictedUmask(func() error {
		before := syscall.Umask(startingUmask)
		syscall.Umask(before)
		observedDuring = before
		return nil
	}); err != nil {
		t.Fatalf("withRestrictedUmask: %v", err)
	}
	if observedDuring != 0o177 {
		t.Errorf("umask during fn = %#o, want %#o (so a freshly created socket file is 0600 from the start, not just after a later Chmod)", observedDuring, 0o177)
	}

	after := syscall.Umask(startingUmask)
	syscall.Umask(after)
	if after != startingUmask {
		t.Errorf("umask after withRestrictedUmask returned = %#o, want it restored to %#o", after, startingUmask)
	}
}

// TestListenUnixSocketIsNeverWiderThanOwnerPermissions is a basic end-state
// sanity check, not a regression test on its own (the final Chmod already
// guaranteed this before the withRestrictedUmask fix too -- it's the
// transient window during creation that changed, which
// TestWithRestrictedUmaskTightensDuringAndRestoresAfter above actually
// covers): the resulting socket file's mode must be 0600 once listenUnix
// returns, regardless of the process's ambient umask when it was called.
func TestListenUnixSocketIsNeverWiderThanOwnerPermissions(t *testing.T) {
	original := syscall.Umask(0o022) // a permissive starting umask, deliberately
	t.Cleanup(func() { syscall.Umask(original) })

	path := filepath.Join(t.TempDir(), "test.sock")
	ln, err := listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("socket file permissions = %#o, want %#o", got, 0o600)
	}
}
