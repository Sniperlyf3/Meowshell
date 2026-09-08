//go:build unix

package main

import "syscall"

// runTailcat replaces this process with tailcat, so the caller keeps the
// same PID: whoever launched meowshell holds a handle to the server itself,
// with no supervising process in between.
func runTailcat(bin string, argv, environ []string) error {
	return syscall.Exec(bin, argv, environ)
}
