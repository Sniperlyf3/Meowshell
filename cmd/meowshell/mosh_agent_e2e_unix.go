//go:build unix

package main

import "syscall"

// killMoshServerProcess reaps the real mosh-server TestMoshAgentEndToEnd
// starts over its SSH bootstrap session. mosh-server daemonizes and detaches
// from that session (that's the whole point of Mosh's roaming), so nothing
// else terms it, and unlike an in-process fake there's no defer that cleans
// it up for free; skipping this leaks a UDP-listening process per run.
// SIGTERM, not Kill: mosh-server exits cleanly on SIGTERM, and disorderly
// process teardown is exactly what unrelated stray procs downstream test
// runs would rather not deal with.
func killMoshServerProcess(pid int) {
	syscall.Kill(pid, syscall.SIGTERM)
}
