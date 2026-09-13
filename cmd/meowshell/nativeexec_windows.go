//go:build windows

package main

import "os"

func validateNativeExecutable(path string, _ os.FileInfo) error {
	// The known_hosts Windows validator already enforces exactly the trust
	// properties an executable needs here: real file (not a reparse point),
	// trusted owner SID, and no write-capable ACE for an untrusted principal.
	return validateKnownHostsPathWindows(path, false)
}
