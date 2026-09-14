//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
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

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

func (j *killOnCloseJob) ensureAssigned(pid int) error {
	const processQueryLimitedInformation = 0x1000
	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|processQueryLimitedInformation,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("opening Tailcat process for job assignment: %w", err)
	}
	defer windows.CloseHandle(process)

	contains := func() (bool, error) {
		var result uint32
		r1, _, callErr := isProcessInJob.Call(
			uintptr(process),
			uintptr(j.handle),
			uintptr(unsafe.Pointer(&result)),
		)
		if r1 == 0 {
			return false, callErr
		}
		return result != 0, nil
	}

	// The shipped Tailcat self-joins this already-created job at the very
	// beginning of main, before it can launch descendants. Give that race-free
	// path a brief chance to complete first. A caller-supplied older Tailcat
	// will never join, so after this bounded grace period we fall back to the
	// previous parent-side assignment rather than dropping containment.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if inJob, err := contains(); err != nil {
			return fmt.Errorf("checking Tailcat Job Object membership: %w", err)
		} else if inJob {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := windows.AssignProcessToJobObject(j.handle, process); err != nil {
		// The child can still self-join between our final membership check and
		// assignment. Re-check before treating the assignment error as fatal.
		if inJob, checkErr := contains(); checkErr == nil && inJob {
			return nil
		}
		return fmt.Errorf("assigning Tailcat process to Job Object: %w", err)
	}
	return nil
}

func newNamedKillOnCloseJob() (*killOnCloseJob, string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", fmt.Errorf("generating Windows Job Object name: %w", err)
	}
	name := "Local\\Meowshell-" + hex.EncodeToString(nonce[:])
	job, err := createKillOnCloseJob(name)
	if err != nil {
		return nil, "", err
	}
	return job, name, nil
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
	if err := j.ensureAssigned(pid); err != nil {
		j.Close()
		return nil, err
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
