//go:build unix

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

const managedParentPIDEnv = "MEOWSHELL_MANAGED_PARENT_PID"

var managedHostPID = consumeManagedHostPID()

// consumeManagedHostPID deliberately removes the marker from Meowshell's
// process environment as soon as the process starts. Long-lived commands such
// as "agent" spawn their own Tailcat subprocesses; those descendants are not
// direct children of the managed .NET host and must never inherit a marker
// that would make the Tailcat watchdog mistake the agent for a dead host.
//
// Exec-replacement commands (serve/forward/socks) re-add the marker explicitly
// in runTailcat below because the exec preserves this process PID and its
// direct parent really is the .NET host.
func consumeManagedHostPID() int {
	raw := os.Getenv(managedParentPIDEnv)
	if raw == "" {
		return 0
	}
	_ = os.Unsetenv(managedParentPIDEnv)
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

func runTailcat(bin string, argv, environ []string) error {
	if managedHostPID > 0 {
		if managedHostPID != os.Getppid() {
			return fmt.Errorf("managed parent process %d is no longer this process's parent", managedHostPID)
		}
		environ = setEnv(environ, [][2]string{{managedParentPIDEnv, strconv.Itoa(managedHostPID)}})
		return syscall.Exec(bin, argv, environ)
	}

	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0); errno != 0 {
		fmt.Fprintf(os.Stderr, "# warning: could not arm the parent-death signal: %v\n", errno)
	}
	return syscall.Exec(bin, argv, environ)
}
