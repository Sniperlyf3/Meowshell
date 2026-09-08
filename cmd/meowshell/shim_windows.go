package main

import "errors"

// shimSupported is false on Windows: tailcat builds the session's
// environment by inheriting the server's wholesale and chooses PowerShell
// from the registry, never consulting $SHELL. There is no broken PATH to
// repair and no way to interpose, so meowshell is a launcher only.
const shimSupported = false

func isShimInvocation([]string) bool { return false }

func runAsShell([]string) error {
	return errors.New("meowshell is not used as a shell on Windows")
}
