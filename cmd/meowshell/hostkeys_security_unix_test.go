//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTCPHostKeyCallbackRejectsInsecureKnownHostsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := tcpHostKeyCallback(filepath.Join(dir, "known_hosts"), func(string, net.Addr, ssh.PublicKey) (bool, error) {
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("tcpHostKeyCallback error = %v, want insecure-permissions rejection", err)
	}
}

func TestTCPHostKeyCallbackRejectsInsecureKnownHostsFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := tcpHostKeyCallback(path, func(string, net.Addr, ssh.PublicKey) (bool, error) {
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("tcpHostKeyCallback error = %v, want insecure-permissions rejection", err)
	}
}

func TestTCPHostKeyCallbackRejectsSymlinkedKnownHostsFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	_, err := tcpHostKeyCallback(path, func(string, net.Addr, ssh.PublicKey) (bool, error) {
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "symbolic") {
		t.Fatalf("tcpHostKeyCallback error = %v, want symlink rejection", err)
	}
}
