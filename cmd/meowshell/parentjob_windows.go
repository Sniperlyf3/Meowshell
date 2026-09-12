//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const parentJobEnv = "MEOWSHELL_PARENT_JOB"

var openJobObjectW = windows.NewLazySystemDLL("kernel32.dll").NewProc("OpenJobObjectW")

func joinParentJobFromEnv() error {
	name := os.Getenv(parentJobEnv)
	if name == "" {
		return nil
	}
	_ = os.Unsetenv(parentJobEnv)

	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("invalid parent job name: %w", err)
	}
	const jobObjectAssignProcess = 0x0001
	h, _, callErr := openJobObjectW.Call(
		uintptr(jobObjectAssignProcess),
		0,
		uintptr(unsafe.Pointer(namep)),
	)
	if h == 0 {
		return fmt.Errorf("opening parent Windows Job Object %q: %w", name, callErr)
	}
	job := windows.Handle(h)
	defer windows.CloseHandle(job)

	process, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("getting current process handle: %w", err)
	}
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("joining parent Windows Job Object %q: %w", name, err)
	}
	return nil
}
