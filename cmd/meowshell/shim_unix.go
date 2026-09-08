//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// shimSupported reports whether tailcat can be made to run meowshell as the
// session's login shell. On Unix it reads $SHELL; on Windows it picks
// PowerShell itself and inherits the environment wholesale, so there is
// nothing for a shim to fix.
const shimSupported = true

// isShimInvocation reports whether these arguments come from tailcat
// starting the session's login shell rather than from a person.
//
// tailcat runs "$SHELL -l", or "$SHELL -c <command>" for a remote command.
// Any flag-like first argument counts: were tailcat to use a different flag,
// treating it as a subcommand would hand the session usage text instead of a
// shell.
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

// runAsShell is the shell shim. tailcat hands the session a fixed
// environment (SHELL, USER, HOME, PATH, plus TERM/LANG/LC_* from the
// client), so this is the only place PATH can be corrected before the real
// shell starts.
func runAsShell(args []string) error {
	env := newResolver().Resolve()

	os.Setenv("PATH", env.Path)
	os.Setenv("SHELL", env.Shell) // the real shell, not meowshell
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

	// Pass the arguments through so the real shell still does its own login
	// processing and sources the user's rc files.
	return syscall.Exec(env.Shell, append([]string{env.Shell}, args...), os.Environ())
}
