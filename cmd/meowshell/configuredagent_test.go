package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSignerAgentListsAndSignsWithConfiguredKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	forwarded := &signerAgent{signers: []ssh.Signer{signer}}
	keys, err := forwarded.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Format != ssh.KeyAlgoED25519 {
		t.Fatalf("unexpected forwarded keys: %#v", keys)
	}

	data := []byte("meowshell configured agent forwarding")
	sig, err := forwarded.Sign(signer.PublicKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("forwarded signature did not verify: %v", err)
	}
}

func TestSignerAgentHonorsRsaSha2Flags(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	forwarded := &signerAgent{signers: []ssh.Signer{signer}}
	data := []byte("rsa-sha2-forwarding")
	sig, err := forwarded.SignWithFlags(signer.PublicKey(), data, agent.SignatureFlagRsaSha512)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("signature format = %q, want %q", sig.Format, ssh.KeyAlgoRSASHA512)
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("forwarded RSA signature did not verify: %v", err)
	}
}

func TestSignerAgentIsReadOnly(t *testing.T) {
	forwarded := &signerAgent{}
	if err := forwarded.RemoveAll(); err == nil {
		t.Fatal("RemoveAll unexpectedly succeeded")
	}
	if err := forwarded.Lock([]byte("nope")); err == nil {
		t.Fatal("Lock unexpectedly succeeded")
	}
	if err := forwarded.Unlock([]byte("nope")); err == nil {
		t.Fatal("Unlock unexpectedly succeeded")
	}
}

func TestConfiguredForwardAgentGetsPrivateSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("configured forwarding uses an abstract Unix socket")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	session := &agentSession{}
	if err := session.startConfiguredForwardAgent([]ssh.Signer{signer}); err != nil {
		t.Fatal(err)
	}
	if session.agentForwardSock == "" || session.agentForwardSock[0] != '@' {
		t.Fatalf("configured forward socket = %q, want abstract Unix socket", session.agentForwardSock)
	}
}
