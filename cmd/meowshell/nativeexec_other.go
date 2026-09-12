//go:build !unix && !windows

package main

import "os"

func validateNativeExecutable(string, os.FileInfo) error { return nil }
