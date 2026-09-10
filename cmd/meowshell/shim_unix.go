//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const shimSupported = true

func isShimInvocation(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "-h", "--help":
		return false
	}
	return strings.HasPrefix(args[0], "-")
}

func runAsShell(args []string) error {
	env := newResolver().Resolve()

	os.Setenv("PATH", env.Path)
	os.Setenv("SHELL", env.Shell)
	if os.Getenv("TERM") == "" {
		os.Setenv("TERM", env.Term)
	}
	if os.Getenv("LANG") == "" {
		os.Setenv("LANG", env.Lang)
	}
	if os.Getenv("HOME") == "" {
		os.Setenv("HOME", env.Home)
	}
	if os.Getenv("TMPDIR") == "" && runtimeGOOS == "android" {
		if tmp := filepath.Join(env.Home, "tmp"); os.MkdirAll(tmp, 0o700) == nil {
			os.Setenv("TMPDIR", tmp)
		}
	}

	return syscall.Exec(env.Shell, append([]string{env.Shell}, args...), os.Environ())
}
