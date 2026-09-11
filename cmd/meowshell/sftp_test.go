package main

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDialSSHClientHonorsContextDuringHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()
	dial := dialer(func(context.Context) (net.Conn, error) { return client, nil })
	_, err := dialSSHClient(ctx, dial, "unresponsive.example:22", "user", ssh.InsecureIgnoreHostKey(), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialSSHClient error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("handshake cancellation took %s, want under 1s", elapsed)
	}
}

// TestPipeConnCloseDoesNotHangForever is a regression test: pipeConn.Close
// used to wait on cmd.Wait() unconditionally, with nothing bounding how long
// that could take. A subprocess that neither reads its closed stdin nor
// writes to its closed stdout (like "sleep") doesn't notice either closure
// and keeps running, so Close() -- invoked from dialSSHClient's
// context.AfterFunc when a handshake context expires -- could block forever
// instead of honoring the timeout the caller thought it had.
func TestPipeConnCloseDoesNotHangForever(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep subprocess fixture is Unix-only")
	}

	cmd := exec.Command("sleep", "100")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	c := &pipeConn{cmd: cmd, stdout: stdout, stdin: stdin}

	done := make(chan error, 1)
	go func() { done <- c.Close() }()

	select {
	case <-done:
	case <-time.After(pipeConnCloseGrace + 5*time.Second):
		t.Fatalf("Close() did not return within its %s grace period plus slack; it's hanging in cmd.Wait()", pipeConnCloseGrace)
	}
}
