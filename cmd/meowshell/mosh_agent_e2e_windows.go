//go:build windows

package main

import "os"

// killMoshServerProcess exists only so mosh_agent_e2e_test.go builds under
// `go vet ./...` on Windows too (windows-e2e runs vet on every package, not
// just the ones with a Windows-relevant test). TestMoshAgentEndToEnd, the
// only caller, never actually reaches this: requireMoshServerBinary skips it
// first, since there is no real mosh-server to bootstrap against on Windows.
// syscall.Kill/SIGTERM don't exist on this platform, so this uses the
// portable os.Process.Kill instead -- fine for dead code that must still
// type-check, wrong for the Unix path where a clean SIGTERM matters (see
// mosh_agent_e2e_unix.go).
func killMoshServerProcess(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		p.Kill()
	}
}
