package main

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"runtime"
	"slices"
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

// TestModernSSHAlgorithmsExcludesKnownInsecureOnes is the N11 regression:
// without an explicit Config/HostKeyAlgorithms, golang.org/x/crypto/ssh
// falls back to its own default lists, which still include algorithms the
// same package's own InsecureAlgorithms() names -- SHA-1 key exchange, a
// 96-bit truncated HMAC, and DSA/ssh-rsa (SHA-1) host keys -- for
// compatibility with very old servers. dialSSHClient must restrict
// negotiation to SupportedAlgorithms() instead, so a server offering only
// those legacy algorithms fails the handshake rather than silently
// downgrading to them.
func TestModernSSHAlgorithmsExcludesKnownInsecureOnes(t *testing.T) {
	cryptoConfig, hostKeyAlgos := modernSSHAlgorithms()
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()

	for _, tt := range []struct {
		name string
		got  []string
		want []string
	}{
		{"KeyExchanges", cryptoConfig.KeyExchanges, supported.KeyExchanges},
		{"Ciphers", cryptoConfig.Ciphers, supported.Ciphers},
		{"MACs", cryptoConfig.MACs, supported.MACs},
		{"HostKeyAlgorithms", hostKeyAlgos, supported.HostKeys},
	} {
		if !slices.Equal(tt.got, tt.want) {
			t.Errorf("%s = %q, want ssh.SupportedAlgorithms()'s %q", tt.name, tt.got, tt.want)
		}
	}

	for _, tt := range []struct {
		name string
		got  []string
		bad  []string
	}{
		{"KeyExchanges", cryptoConfig.KeyExchanges, insecure.KeyExchanges},
		{"Ciphers", cryptoConfig.Ciphers, insecure.Ciphers},
		{"MACs", cryptoConfig.MACs, insecure.MACs},
		{"HostKeyAlgorithms", hostKeyAlgos, insecure.HostKeys},
	} {
		for _, bad := range tt.bad {
			if slices.Contains(tt.got, bad) {
				t.Errorf("%s unexpectedly includes insecure algorithm %q", tt.name, bad)
			}
		}
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
