package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// signerAgent exposes the signers supplied through the Meowshell configure
// frame as a read-only SSH agent. This is intentionally narrower than a normal
// ssh-agent: a remote host that receives agent forwarding may ask these keys to
// sign, but can never add, remove, lock, or otherwise mutate the client's key
// material.
type signerAgent struct {
	signers []ssh.Signer
}

var _ agent.ExtendedAgent = (*signerAgent)(nil)

func (a *signerAgent) List() ([]*agent.Key, error) {
	keys := make([]*agent.Key, 0, len(a.signers))
	for _, signer := range a.signers {
		pub := signer.PublicKey()
		keys = append(keys, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: "meowshell",
		})
	}
	return keys, nil
}

func (a *signerAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	signer, err := a.findSigner(key)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand.Reader, data)
}

func (a *signerAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	signer, err := a.findSigner(key)
	if err != nil {
		return nil, err
	}

	algorithm := ""
	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		algorithm = ssh.KeyAlgoRSASHA512
	case flags&agent.SignatureFlagRsaSha256 != 0:
		algorithm = ssh.KeyAlgoRSASHA256
	}
	if algorithm == "" {
		return signer.Sign(rand.Reader, data)
	}
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("key %q cannot sign with requested algorithm %q", key.Type(), algorithm)
	}
	return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
}

func (a *signerAgent) Signers() ([]ssh.Signer, error) {
	return append([]ssh.Signer(nil), a.signers...), nil
}

func (a *signerAgent) Add(agent.AddedKey) error                  { return errReadOnlyForwardAgent }
func (a *signerAgent) Remove(ssh.PublicKey) error                { return errReadOnlyForwardAgent }
func (a *signerAgent) RemoveAll() error                          { return errReadOnlyForwardAgent }
func (a *signerAgent) Lock([]byte) error                         { return errReadOnlyForwardAgent }
func (a *signerAgent) Unlock([]byte) error                       { return errReadOnlyForwardAgent }
func (a *signerAgent) Extension(string, []byte) ([]byte, error)   { return nil, agent.ErrExtensionUnsupported }

var errReadOnlyForwardAgent = errors.New("forwarded Meowshell agent is read-only")

func (a *signerAgent) findSigner(key ssh.PublicKey) (ssh.Signer, error) {
	wanted := key.Marshal()
	for _, signer := range a.signers {
		if bytes.Equal(signer.PublicKey().Marshal(), wanted) {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("requested key %q is not available", key.Type())
}

// startConfiguredForwardAgent serves configured in-memory/keystore signers on
// an unguessable Linux abstract Unix socket. agent.ForwardToRemote can then use
// exactly the same forwarding path it already uses for SSH_AUTH_SOCK, while the
// actual private material remains in memory (or in Android Keystore).
//
// Abstract Unix sockets have no filesystem entry to clean up and disappear
// automatically with the process. Windows keeps the existing SSH_AUTH_SOCK
// forwarding path; configured-only forwarding is not created there because the
// Go Windows runtime does not provide this Unix-socket transport.
func (a *agentSession) startConfiguredForwardAgent(signers []ssh.Signer) error {
	if len(signers) == 0 || a.agentForwardSock != "" {
		return nil
	}
	if runtime.GOOS == "windows" {
		return nil
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generating forwarded-agent socket name: %w", err)
	}
	name := "@meowshell-agent-" + hex.EncodeToString(nonce[:])
	listener, err := net.Listen("unix", name)
	if err != nil {
		return fmt.Errorf("listening for configured agent forwarding: %w", err)
	}

	forwarded := &signerAgent{signers: append([]ssh.Signer(nil), signers...)}
	a.agentForwardSock = name
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = agent.ServeAgent(forwarded, conn)
			}()
		}
	}()
	return nil
}
