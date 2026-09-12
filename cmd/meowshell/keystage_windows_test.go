//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsStageKeyNeverCreatesCredentialFile is a regression test for the
// old named-temp-file handoff. stageKey must keep --key-stdin material only in
// memory and return tailcat's stdin sentinel, so a crash cannot strand private
// key JSON on disk and no timing-based deletion window exists.
func TestWindowsStageKeyNeverCreatesCredentialFile(t *testing.T) {
	dir := t.TempDir()
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte(`{"Private":"sensitive-test-key"}`)
	arg, err := stageKey(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupStagedKey()
	if arg != "-" {
		t.Fatalf("stageKey argument = %q, want stdin sentinel %q", arg, "-")
	}

	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("stageKey created a filesystem entry in %s: before=%v after=%v", filepath.Clean(dir), before, after)
	}

	got := takeStagedKey()
	if !bytes.Equal(got, secret) {
		t.Fatalf("staged key bytes = %q, want original secret", got)
	}
	zeroBytes(got)
}
