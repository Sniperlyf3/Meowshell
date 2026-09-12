//go:build unix

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const managedParentPIDEnv = "MEOWSHELL_MANAGED_PARENT_PID"

func runTailcat(bin string, argv, environ []string) error {
	// Linux PR_SET_PDEATHSIG is tied to the specific parent thread/task that
	// created this process, not to the parent process as a whole. That is a
	// good crash backstop for ordinary native CLI launches, but it is unsafe
	// for children created by a managed thread pool: the spawning worker
	// thread can disappear while the host process remains perfectly healthy,
	// causing a spurious SIGKILL. Managed launches pass the host process PID
	// and the patched tailcat binary watches that process directly instead.
	if shouldArmParentDeathSignal(environ, os.Getppid()) {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0); errno != 0 {
			fmt.Fprintf(os.Stderr, "# warning: could not arm the parent-death signal: %v\n", errno)
		}
	}
	return syscall.Exec(bin, argv, environ)
}

func shouldArmParentDeathSignal(environ []string, parentPID int) bool {
	prefix := managedParentPIDEnv + "="
	for _, entry := range environ {
		if !strings.HasPrefix(entry, prefix) {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimPrefix(entry, prefix))
		if err != nil {
			return true
		}
		return pid != parentPID
	}
	return true
}
