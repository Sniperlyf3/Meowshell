//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// runTailcat replaces this process with tailcat, so the caller keeps the
// same PID: whoever launched meowshell holds a handle to the server itself,
// with no supervising process in between.
func runTailcat(bin string, argv, environ []string) error {
	// PR_SET_PDEATHSIG asks the kernel to SIGKILL this process when its
	// parent dies, and survives the exec below since tailcat carries no
	// setuid/setgid bit or file capabilities. Without it, a parent that
	// dies without stopping the server first -- a crash, an OOM kill, a
	// force-stop -- leaves tailcat running as an orphan with no one left
	// to enforce a caller's lifetime deadline. Best-effort: a restricted
	// environment that refuses this still gets a working session, just
	// without the crash backstop.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0); errno != 0 {
		fmt.Fprintf(os.Stderr, "# warning: could not arm the parent-death signal: %v\n", errno)
	}
	return syscall.Exec(bin, argv, environ)
}
