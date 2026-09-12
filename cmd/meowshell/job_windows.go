//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// killOnCloseJob owns a Windows Job Object configured so every process in the
// job is terminated when the last handle to the job is closed. runTailcat keeps
// this handle for exactly as long as the child lives; if meowshell itself is
// killed/crashes, Windows closes the handle for us and tears the child down.
type killOnCloseJob struct {
	handle windows.Handle
}

func createKillOnCloseJob(name string) (*killOnCloseJob, error) {
	var namep *uint16
	var err error
	if name != "" {
		namep, err = windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, fmt.Errorf("encoding job object name: %w", err)
		}
	}
	job, err := windows.CreateJobObject(nil, namep)
	if err != nil {
		return nil, fmt.Errorf("creating tailcat job object: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("configuring tailcat job object: %w", err)
	}
	return &killOnCloseJob{handle: job}, nil
}

func newKillOnCloseJob(pid int) (*killOnCloseJob, error) {
	j, err := createKillOnCloseJob("")
	if err != nil {
		return nil, err
	}

	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(pid),
	)
	if err != nil {
		j.Close()
		return nil, fmt.Errorf("opening tailcat process for job assignment: %w", err)
	}
	defer windows.CloseHandle(process)

	if err := windows.AssignProcessToJobObject(j.handle, process); err != nil {
		j.Close()
		return nil, fmt.Errorf("assigning tailcat process to job object: %w", err)
	}
	return j, nil
}

func (j *killOnCloseJob) Close() error {
	if j == nil || j.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(j.handle)
	j.handle = 0
	return err
}
