//go:build unix

package main

import "testing"

// TestShimDetectionAcceptsAnyFlag exercises shim_unix.go's isShimInvocation,
// which detects argv[0]-as-login-shell re-execution -- a purely Unix
// mechanism (execve/argv[0] conventions) that shim_windows.go correctly
// stubs out to always-false, since there is no Windows equivalent to test.
func TestShimDetectionAcceptsAnyFlag(t *testing.T) {
	for _, args := range [][]string{{"-l"}, {"-c", "echo hi"}, {"--login"}, {"-lc", "x"}} {
		if !isShimInvocation(args) {
			t.Errorf("isShimInvocation(%q) = false, want true", args)
		}
	}
	for _, args := range [][]string{{}, {"serve"}, {"connect", "tc..."}, {"env"}, {"-h"}, {"--help"}} {
		if isShimInvocation(args) {
			t.Errorf("isShimInvocation(%q) = true, want false", args)
		}
	}
}
