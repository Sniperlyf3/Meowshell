package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// tailcatHostKeyCallback is the tailcat-transport HostKeyCallback: always
// insecure-ignore, and correctly so, not a gap to "fix" later -- a tailcat
// address's embedded node key is what WireGuard already authenticates the
// peer with, so there is no separate host identity left for an SSH host key
// to vouch for on top of it. Real verification (tcpHostKeyCallback below)
// only has meaning once the transport is raw TCP, with no such peer
// authentication underneath it.
func tailcatHostKeyCallback() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey()
}

// hostKeyChangedError distinguishes "the host key changed" (a possible
// MITM, never auto-prompted-past) from "the host key is merely unknown" (a
// normal first connection, fine to prompt for). Both start life as a
// *knownhosts.KeyError from the same callback; only this wrapping on the
// "Want non-empty" case carries that distinction out to the caller, which
// maps it to the errHostKeyChanged typed error code.
type hostKeyChangedError struct {
	hostname string
	err      error
}

func (e *hostKeyChangedError) Error() string {
	return fmt.Sprintf("host key for %s has changed: %v", e.hostname, e.err)
}
func (e *hostKeyChangedError) Unwrap() error { return e.err }

// hostKeyPrompter asks whether to trust a host key the local known_hosts
// store has no entry for yet (TOFU), returning the caller's decision. The
// agent's implementation round-trips this over the control protocol as a
// prompt_request/prompt_response pair (see agent.go's promptHostKey).
type hostKeyPrompter func(hostname string, remote net.Addr, key ssh.PublicKey) (accept bool, err error)

// tcpHostKeyCallback builds a real ssh.HostKeyCallback for TCP transport,
// backed by a known_hosts file in the standard OpenSSH line format
// (golang.org/x/crypto/ssh/knownhosts) rather than a meowshell-specific one
// -- interoperable, and inspectable/editable with ordinary tools. An
// unknown key calls prompt and, if accepted, is appended to the file; a
// key that contradicts an existing entry is never offered to prompt at
// all -- it comes back as *hostKeyChangedError, a hard stop.
func tcpHostKeyCallback(knownHostsPath string, prompt hostKeyPrompter) (ssh.HostKeyCallback, error) {
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		return nil, fmt.Errorf("creating known_hosts directory: %w", err)
	}
	f, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating known_hosts file: %w", err)
	}
	f.Close()

	verify, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("loading known_hosts: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err // some other failure (a malformed store, an I/O error): not ours to prompt past
		}
		if len(keyErr.Want) > 0 {
			return &hostKeyChangedError{hostname: hostname, err: keyErr}
		}

		accept, perr := prompt(hostname, remote, key)
		if perr != nil {
			return perr
		}
		if !accept {
			return fmt.Errorf("host key for %s rejected", hostname)
		}
		return appendKnownHost(knownHostsPath, hostname, key)
	}, nil
}

func appendKnownHost(knownHostsPath, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("recording accepted host key: %w", err)
	}
	defer f.Close()
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	if _, err := fmt.Fprintln(f, line); err != nil {
		return fmt.Errorf("recording accepted host key: %w", err)
	}
	return nil
}

// fingerprintSHA256 formats key the way OpenSSH itself does (ssh-keygen -lf,
// a modern sshd's login log), so a fingerprint shown to a user matches what
// they'd see confirming the same key anywhere else.
func fingerprintSHA256(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
