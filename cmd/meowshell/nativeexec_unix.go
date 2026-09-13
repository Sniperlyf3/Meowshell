//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validateNativeExecutable(path string, fi os.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group/other", path)
	}
	if err := validateNativeExecutableDir(filepath.Dir(path)); err != nil {
		return err
	}
	if runtimeGOOS == "android" {
		// Android extracts an app's native libraries from its own signed,
		// verified APK into nativeLibraryDir, a directory only the system
		// installer can write to; the extracted files come back owned by
		// the installer (system), never by the running app's own per-app
		// uid or root. The group/other-write check above already covers
		// the property that matters -- nothing but the trusted installer
		// can modify the file -- so an owner-identity match isn't
		// meaningful here the way it is on a general-purpose Unix host.
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	euid := uint32(os.Geteuid())
	if st.Uid != euid && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not current uid %d or root", path, st.Uid, euid)
	}
	return nil
}

func validateNativeExecutableDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("checking native executable directory %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("refusing native executable directory %s: expected a real directory", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing native executable directory %s: writable by group/other", path)
	}
	if runtimeGOOS == "android" {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of native executable directory %s", path)
	}
	euid := uint32(os.Geteuid())
	if st.Uid != euid && st.Uid != 0 {
		return fmt.Errorf("native executable directory %s is owned by uid %d, not current uid %d or root", path, st.Uid, euid)
	}
	return nil
}
