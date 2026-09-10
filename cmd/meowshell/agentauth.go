package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// buildAuthMethods turns a configure message into the ordered
// []ssh.AuthMethod dialSSHClient offers: every public-key-capable signer
// (the local ssh-agent, keys supplied over the control channel, and
// Keystore-backed keys) combined into one ssh.PublicKeys method, so
// golang.org/x/crypto/ssh tries each in turn within a single auth round,
// then keyboard-interactive, then password -- the package's own
// partial-success negotiation handles the rest. Against tailcat's own
// service this is mostly unused machinery (it only ever asks for
// public-key or nothing at all -- see hostkeys.go's tailcat comment for
// the same point about host keys) but it's what makes a general TCP SSH
// host, or a tailcat --ssh-authorized-keys service from an Android app
// with no ssh-agent, actually reachable.
func (a *agentSession) buildAuthMethods(cfg controlMessage) ([]ssh.AuthMethod, error) {
	var signers []ssh.Signer

	if !cfg.DisableAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if conn, err := net.Dial("unix", sock); err == nil {
				if s, err := agent.NewClient(conn).Signers(); err == nil {
					signers = append(signers, s...)
				}
				a.agentForwardSock = sock
			}
		}
	}

	for i, keyBytes := range cfg.Keys {
		signer, err := a.parseKeyMaybePrompting(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing supplied key %d: %w", i, err)
		}
		if i < len(cfg.Certificates) && len(cfg.Certificates[i]) > 0 {
			pub, err := ssh.ParsePublicKey(cfg.Certificates[i])
			if err != nil {
				return nil, fmt.Errorf("parsing supplied certificate %d: %w", i, err)
			}
			cert, ok := pub.(*ssh.Certificate)
			if !ok {
				return nil, fmt.Errorf("supplied certificate %d is not an SSH certificate", i)
			}
			if signer, err = ssh.NewCertSigner(cert, signer); err != nil {
				return nil, fmt.Errorf("pairing certificate %d with its key: %w", i, err)
			}
		}
		signers = append(signers, signer)
	}

	for i, keyID := range cfg.KeystoreKeyIDs {
		if i >= len(cfg.KeystorePublicKeys) {
			return nil, fmt.Errorf("keystore key %q has no matching public key", keyID)
		}
		pub, err := ssh.ParsePublicKey(cfg.KeystorePublicKeys[i])
		if err != nil {
			return nil, fmt.Errorf("parsing keystore public key %q: %w", keyID, err)
		}
		signers = append(signers, &keystoreSigner{session: a, keyID: keyID, pub: pub})
	}

	var methods []ssh.AuthMethod
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	methods = append(methods,
		ssh.KeyboardInteractive(a.keyboardInteractive),
		ssh.PasswordCallback(a.promptPassword),
	)
	return methods, nil
}

// parseKeyMaybePrompting parses a private key blob, round-tripping a
// passphrase prompt (up to a few attempts, the same allowance a real ssh
// client gives a typo'd passphrase) when the key turns out to be
// encrypted. keyBytes are never written to disk anywhere in this path --
// they arrive over the control channel and live only in process memory.
func (a *agentSession) parseKeyMaybePrompting(keyBytes []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, err
	}
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, perr := a.prompt(controlMessage{PromptKind: "passphrase"})
		if perr != nil {
			return nil, perr
		}
		if resp.Cancelled {
			return nil, fmt.Errorf("passphrase prompt cancelled")
		}
		if signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(resp.Answer)); err == nil {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("could not decrypt key after %d attempts: %w", maxAttempts, err)
}

// promptPassword is an ssh.PasswordCallback: one prompt, one answer.
func (a *agentSession) promptPassword() (string, error) {
	resp, err := a.prompt(controlMessage{PromptKind: "password"})
	if err != nil {
		return "", err
	}
	if resp.Cancelled {
		return "", fmt.Errorf("password prompt cancelled")
	}
	return resp.Answer, nil
}

// keyboardInteractive is an ssh.KeyboardInteractiveChallenge: the actual
// OTP/PAM path for a general SSH host (tailcat's own service never sends
// this challenge -- confirmed against its server source, see hostkeys.go
// and the project plan -- but the plumbing is shared and harmless against
// it). May be invoked more than once per connection attempt; each call is
// its own prompt round trip.
func (a *agentSession) keyboardInteractive(name, instruction string, questions []string, echos []bool) ([]string, error) {
	resp, err := a.prompt(controlMessage{
		PromptKind:  "keyboard_interactive",
		Remote:      name,
		Instruction: instruction,
		Questions:   questions,
		Echos:       echos,
	})
	if err != nil {
		return nil, err
	}
	if resp.Cancelled {
		return nil, fmt.Errorf("keyboard-interactive prompt cancelled")
	}
	return resp.Answers, nil
}

// keystoreSigner is an ssh.Signer backed entirely by a client-side
// callback: the private key never reaches this process at all, only its
// public half (supplied in the configure message) and, per signature, a
// blob signed elsewhere -- Android Keystore hardware being the motivating
// case. Sign blocks on the same prompt round trip host-key/password/etc.
// prompts use, just carrying binary key material instead of typed text.
//
// This implements the plain ssh.Signer interface rather than
// AlgorithmSigner, so it always signs with the key's default algorithm
// (fine for ed25519/ecdsa, which only have one); an RSA Keystore key
// talking to a server that insists on rsa-sha2-256/512 specifically would
// need AlgorithmSigner support this pass doesn't add.
type keystoreSigner struct {
	session *agentSession
	keyID   string
	pub     ssh.PublicKey
}

func (s *keystoreSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *keystoreSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	resp, err := s.session.prompt(controlMessage{
		PromptKind: "sign",
		KeyID:      s.keyID,
		Algorithm:  s.pub.Type(),
		SignData:   data,
	})
	if err != nil {
		return nil, err
	}
	if resp.Cancelled || len(resp.Signature) == 0 {
		return nil, fmt.Errorf("keystore signing for key %q was refused", s.keyID)
	}
	return &ssh.Signature{Format: s.pub.Type(), Blob: resp.Signature}, nil
}
