package main

import (
	"fmt"
	"os"
	"syscall"
)

func runTailcat(bin string, argv, environ []string) error {

	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0); errno != 0 {
		fmt.Fprintf(os.Stderr, "# warning: could not arm the parent-death signal: %v\n", errno)
	}
	return syscall.Exec(bin, argv, environ)
}
