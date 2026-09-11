package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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

// keystoreSigner signs with a key the client holds and never discloses --
// Android's hardware-backed Keystore being the motivating case. It is a
// MultiAlgorithmSigner rather than a plain Signer: without Algorithms() the ssh
// package can only ever offer the key's own type, which for RSA means the SHA-1
// ssh-rsa form that servers have rejected by default since OpenSSH 8.8.
type keystoreSigner struct {
	session *agentSession
	keyID   string
	pub     ssh.PublicKey
}

var _ ssh.MultiAlgorithmSigner = (*keystoreSigner)(nil)

// keystoreSignError is a failure to get a signature out of a keystore-held key:
// the client refused, or asked for an algorithm the key cannot produce. Either
// way the connection ends up unauthenticated, so classifyConnectError reports
// it as an auth failure rather than as something unknown.
type keystoreSignError struct{ msg string }

func (e *keystoreSignError) Error() string { return e.msg }

func (s *keystoreSigner) PublicKey() ssh.PublicKey { return s.pub }

// Algorithms reports the signature algorithms this key can produce, in
// preference order. A keystore key is a single key of a single type, so the
// list is derived from the public key rather than being a free choice: the
// hardware holds one key, and no amount of negotiation can make it produce a
// signature of another key's type.
func (s *keystoreSigner) Algorithms() []string {
	switch s.pub.Type() {
	case ssh.KeyAlgoRSA:
		// SHA-2 first. ssh-rsa means SHA-1 and is retained only for servers
		// predating RFC 8332; OpenSSH has refused it by default since 8.8.
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	default:
		return []string{s.pub.Type()}
	}
}

// SignWithAlgorithm signs under the algorithm the handshake negotiated rather
// than assuming the key's own type. For RSA the two differ, and the difference
// is which digest the signature commits to.
func (s *keystoreSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	algorithms := s.Algorithms()
	if algorithm == "" {
		algorithm = algorithms[0]
	}
	// Reject before prompting, so a misconfigured client does not surface as a
	// biometric prompt the user satisfies only to have the signature refused.
	if !slices.Contains(algorithms, algorithm) {
		return nil, &keystoreSignError{fmt.Sprintf("keystore key %q cannot sign with %q", s.keyID, algorithm)}
	}

	resp, err := s.session.prompt(controlMessage{
		PromptKind: "sign",
		KeyID:      s.keyID,
		Algorithm:  algorithm,
		SignData:   data,
	})
	if err != nil {
		return nil, err
	}
	if resp.Cancelled || len(resp.Signature) == 0 {
		return nil, &keystoreSignError{fmt.Sprintf("keystore signing for key %q was refused", s.keyID)}
	}
	// The format must name the negotiated algorithm: a signature computed over
	// SHA-512 but labelled ssh-rsa fails verification.
	return &ssh.Signature{Format: algorithm, Blob: resp.Signature}, nil
}

// Sign keeps the plain ssh.Signer contract working, at the key's preferred
// algorithm.
func (s *keystoreSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}
