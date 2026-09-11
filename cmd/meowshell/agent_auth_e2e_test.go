package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

// driveKeystoreAuth answers the agent's prompts the way the app holding a
// Keystore key would: trust-on-first-use for the host key, and a real signature
// for each sign request, computed under the algorithm the agent asked for. It
// returns the algorithms it was asked for, in order, and the first message that
// was not a prompt it could answer.
func driveKeystoreAuth(t *testing.T, stdin *os.File, out *bufio.Reader, signer ssh.AlgorithmSigner) (algorithms []string, final controlMessage) {
	t.Helper()
	for {
		msg := decodeControl(t, mustReadFrame(t, out))
		switch {
		case msg.Msg == "prompt_request" && msg.PromptKind == "host_key":
			send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Accept: true})
		case msg.Msg == "prompt_request" && msg.PromptKind == "sign":
			algorithms = append(algorithms, msg.Algorithm)
			sig, err := signer.SignWithAlgorithm(rand.Reader, msg.SignData, msg.Algorithm)
			if err != nil {
				t.Fatalf("signing under %q: %v", msg.Algorithm, err)
			}
			send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Signature: sig.Blob})
		default:
			return algorithms, msg
		}
	}
}

func TestAgentKeystoreKeyAuth(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	// An RSA key is the case the key-type-as-signature-algorithm shortcut got
	// wrong: ssh-rsa means SHA-1, which every current server refuses. The server
	// here accepts only the RFC 8332 algorithms, so this fails outright unless
	// the negotiated algorithm reaches the signing callback.
	t.Run("an RSA keystore key authenticates against a server that refuses SHA-1", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		algSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			t.Fatal("an RSA signer from x/crypto is not an AlgorithmSigner")
		}

		addr, _ := startAuthTestSSHServer(t, func(cfg *ssh.ServerConfig) {
			cfg.PublicKeyAuthAlgorithms = []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
			cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
					return nil, nil
				}
				return nil, errors.New("unknown public key")
			}
		})

		cmd, stdin, out := startAgentConfigured(t, meowshellBin, filepath.Join(t.TempDir(), "known_hosts"), "testuser@"+addr,
			controlMessage{
				Msg:                "configure",
				KeystoreKeyIDs:     []string{"keystore-rsa"},
				KeystorePublicKeys: [][]byte{signer.PublicKey().Marshal()},
			})
		defer stopAgent(t, cmd, stdin)

		algorithms, msg := driveKeystoreAuth(t, stdin, out, algSigner)
		if msg.Msg != "connected" {
			t.Fatalf("message = %+v, want connected", msg)
		}
		if len(algorithms) == 0 {
			t.Fatal("the agent authenticated without ever asking the keystore to sign")
		}
		for _, algorithm := range algorithms {
			if algorithm != ssh.KeyAlgoRSASHA256 && algorithm != ssh.KeyAlgoRSASHA512 {
				t.Errorf("sign request algorithm = %q, want one the server accepts", algorithm)
			}
		}
	})

	// ECDSA is the case that already worked, because its key type and its
	// signature algorithm are the same string. It must keep working.
	t.Run("an ECDSA keystore key still authenticates", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		algSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			t.Fatal("an ECDSA signer from x/crypto is not an AlgorithmSigner")
		}

		addr, _ := startAuthTestSSHServer(t, func(cfg *ssh.ServerConfig) {
			cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
					return nil, nil
				}
				return nil, errors.New("unknown public key")
			}
		})

		cmd, stdin, out := startAgentConfigured(t, meowshellBin, filepath.Join(t.TempDir(), "known_hosts"), "testuser@"+addr,
			controlMessage{
				Msg:                "configure",
				KeystoreKeyIDs:     []string{"keystore-ecdsa"},
				KeystorePublicKeys: [][]byte{signer.PublicKey().Marshal()},
			})
		defer stopAgent(t, cmd, stdin)

		algorithms, msg := driveKeystoreAuth(t, stdin, out, algSigner)
		if msg.Msg != "connected" {
			t.Fatalf("message = %+v, want connected", msg)
		}
		for _, algorithm := range algorithms {
			if algorithm != ssh.KeyAlgoECDSA256 {
				t.Errorf("sign request algorithm = %q, want %q", algorithm, ssh.KeyAlgoECDSA256)
			}
		}
	})
}
