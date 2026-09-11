//go:build windows

package main

import (
	"os/exec"
	"testing"
	"time"
)

// TestKillOnCloseJobTerminatesChild is a regression test for Windows orphaned
// tailcat processes. Before runTailcat owned its child with a Job Object,
// force-terminating meowshell could leave the long-lived tailcat child behind.
// Closing a JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE job must terminate its member.
func TestKillOnCloseJobTerminatesChild(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "ping 127.0.0.1 -n 30 > nul")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	job, err := newKillOnCloseJob(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := job.Close(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("child exited successfully; want Job Object closure to terminate it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child remained alive after kill-on-close Job Object was closed")
	}
}
