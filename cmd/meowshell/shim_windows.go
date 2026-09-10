package main

import "errors"

const shimSupported = false

func isShimInvocation([]string) bool { return false }

func runAsShell([]string) error {
	return errors.New("meowshell is not used as a shell on Windows")
}
