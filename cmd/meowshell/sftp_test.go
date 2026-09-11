package main

import (
	"context"
	"errors"
	"net"
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
