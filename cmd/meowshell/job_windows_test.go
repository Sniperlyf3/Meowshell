//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
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

// TestParentJobSelfJoinClosesStartupRace verifies the child-side half of the
// pre-start job protocol. The parent creates the named kill-on-close job before
// Process.Start; the child opens and joins that exact job from its environment
// before it can launch descendants. Closing the parent's only job handle must
// then terminate the child.
func TestParentJobSelfJoinClosesStartupRace(t *testing.T) {
	if os.Getenv("MEOWSHELL_TEST_JOB_CHILD") == "1" {
		if err := joinParentJobFromEnv(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println("joined")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}

	name := fmt.Sprintf("Local\\Meowshell-test-%d", time.Now().UnixNano())
	job, err := createKillOnCloseJob(name)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestParentJobSelfJoinClosesStartupRace$")
	cmd.Env = append(os.Environ(),
		"MEOWSHELL_TEST_JOB_CHILD=1",
		parentJobEnv+"="+name,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		job.Close()
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		job.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		job.Close()
		t.Fatalf("waiting for child self-join: %v", err)
	}
	if strings.TrimSpace(line) != "joined" {
		job.Close()
		t.Fatalf("child startup signal = %q, want joined", line)
	}

	if err := job.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("child exited successfully; want closing the parent job to terminate it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("self-joined child survived parent Job Object closure")
	}
}
