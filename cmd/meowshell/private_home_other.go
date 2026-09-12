//go:build !unix

package main

import "os"

func ensurePrivateRuntimeDir(path string) error {
	return os.MkdirAll(path, 0o700)
}
