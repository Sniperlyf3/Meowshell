package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestConcurrentTOFUAcceptsOnlyOneHostKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")

	mkKey := func() ssh.PublicKey {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return signer.PublicKey()
	}
	key1, key2 := mkKey(), mkKey()

	// Build both callbacks before either one records a key so they both begin
	// with the same empty known_hosts snapshot, reproducing the original race.
	cb1, err := tcpHostKeyCallback(path, func(string, net.Addr, ssh.PublicKey) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	cb2, err := tcpHostKeyCallback(path, func(string, net.Addr, ssh.PublicKey) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}

	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	go func() {
		defer wg.Done()
		<-start
		results <- cb1("example.test:22", remote, key1)
	}()
	go func() {
		defer wg.Done()
		<-start
		results <- cb2("example.test:22", remote, key2)
	}()
	close(start)
	wg.Wait()
	close(results)

	var success, changed int
	for err := range results {
		if err == nil {
			success++
			continue
		}
		var hk *hostKeyChangedError
		if errors.As(err, &hk) {
			changed++
			continue
		}
		t.Fatalf("concurrent TOFU returned unexpected error: %v", err)
	}
	if success != 1 || changed != 1 {
		t.Fatalf("concurrent TOFU results: success=%d changed=%d, want 1 and 1", success, changed)
	}
}
