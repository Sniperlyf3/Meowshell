package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func startAuthTestSSHServer(t *testing.T, configure func(cfg *ssh.ServerConfig)) (addr string, hostKey ssh.Signer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{}
	configure(cfg)
	cfg.AddHostKey(signer)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSSHConn(conn, cfg, echoCommandHandler)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), signer
}

func newTestKeyPair(t *testing.T) (privatePEM []byte, public ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes, sshPub
}

func acceptHostKeyPrompt(t *testing.T, stdin *os.File, out *bufio.Reader) {
	t.Helper()
	f := mustReadFrame(t, out)
	msg := decodeControl(t, f)
	if msg.Msg != "prompt_request" || msg.PromptKind != "host_key" {
		t.Fatalf("message = %+v, want a host_key prompt_request", msg)
	}
	send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Accept: true})
}

func TestAgentPasswordAuth(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	addr, _ := startAuthTestSSHServer(t, func(cfg *ssh.ServerConfig) {
		cfg.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == "correct-horse" {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		}
	})
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	t.Run("correct password authenticates", func(t *testing.T) {
		cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
		defer stopAgent(t, cmd, stdin)

		acceptHostKeyPrompt(t, stdin, out)

		f := mustReadFrame(t, out)
		msg := decodeControl(t, f)
		if msg.Msg != "prompt_request" || msg.PromptKind != "password" {
			t.Fatalf("message = %+v, want a password prompt_request", msg)
		}
		send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Answer: "correct-horse"})

		expectConnected(t, out)
	})

	t.Run("wrong password is refused as a typed auth failure", func(t *testing.T) {
		cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
		defer stopAgent(t, cmd, stdin)

		f := mustReadFrame(t, out)
		msg := decodeControl(t, f)
		if msg.Msg != "prompt_request" || msg.PromptKind != "password" {
			t.Fatalf("message = %+v, want a password prompt_request", msg)
		}
		send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Answer: "wrong"})

		f = mustReadFrame(t, out)
		msg = decodeControl(t, f)
		if msg.Msg != "error" || msg.Code != errAuthFailed {
			t.Fatalf("message = %+v, want an error with code %q", msg, errAuthFailed)
		}
	})
}

func TestAgentSuppliedPrivateKeyAuth(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")
	privatePEM, publicKey := newTestKeyPair(t)

	addr, _ := startAuthTestSSHServer(t, func(cfg *ssh.ServerConfig) {
		cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), publicKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown public key")
		}
	})
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	t.Run("the matching key authenticates without any prompt beyond TOFU", func(t *testing.T) {
		cmd, stdin, out := startAgentConfigured(t, meowshellBin, knownHosts, "testuser@"+addr,
			controlMessage{Msg: "configure", Keys: [][]byte{privatePEM}})
		defer stopAgent(t, cmd, stdin)

		acceptHostKeyPrompt(t, stdin, out)
		expectConnected(t, out)
	})

	t.Run("a non-matching key is refused", func(t *testing.T) {
		wrongPEM, _ := newTestKeyPair(t)
		cmd, stdin, out := startAgentConfigured(t, meowshellBin, knownHosts, "testuser@"+addr,
			controlMessage{Msg: "configure", Keys: [][]byte{wrongPEM}})
		defer stopAgent(t, cmd, stdin)

		f := mustReadFrame(t, out)
		msg := decodeControl(t, f)
		if msg.Msg != "error" || msg.Code != errAuthFailed {
			t.Fatalf("message = %+v, want an error with code %q", msg, errAuthFailed)
		}
	})
}
