//go:build unix

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestStageKeyUsesStdinHandoffWithoutInheritableExtraFD(t *testing.T) {
	cleanupStagedKey()
	t.Cleanup(cleanupStagedKey)

	arg, err := stageKey(t.TempDir(), []byte(`{"Private":"test-private-key"}`))
	if err != nil {
		t.Fatal(err)
	}
	if arg != "-" {
		t.Fatalf("stageKey argument = %q, want stdin marker '-'", arg)
	}
	if stagedKey == nil {
		t.Fatal("stageKey did not retain the anonymous staging descriptor")
	}
	if _, err := os.Stat(stagedKey.Name()); !os.IsNotExist(err) {
		t.Fatalf("anonymous staging file still has a filesystem name: %v", err)
	}

	flags, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL,
		stagedKey.Fd(),
		syscall.F_GETFD,
		0,
	)
	if errno != 0 {
		t.Fatalf("F_GETFD: %v", errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("staged key descriptor is inheritable before runTailcat prepares stdin")
	}
}
