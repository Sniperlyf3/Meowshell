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

func tailcatHostKeyCallback() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey()
}

type hostKeyChangedError struct {
	hostname string
	err      error
}

func (e *hostKeyChangedError) Error() string {
	return fmt.Sprintf("host key for %s has changed: %v", e.hostname, e.err)
}
func (e *hostKeyChangedError) Unwrap() error { return e.err }

type hostKeyPrompter func(hostname string, remote net.Addr, key ssh.PublicKey) (accept bool, err error)

func tcpHostKeyCallback(knownHostsPath string, prompt hostKeyPrompter) (ssh.HostKeyCallback, error) {
	dir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating known_hosts directory: %w", err)
	}
	if err := validateKnownHostsDir(dir); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(knownHostsPath); err == nil {
		if err := validateKnownHostsFile(knownHostsPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("checking known_hosts file: %w", err)
	}
	f, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating known_hosts file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("closing known_hosts file: %w", err)
	}
	if err := validateKnownHostsFile(knownHostsPath); err != nil {
		return nil, err
	}

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
			return err
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

		// Another connection may have completed TOFU while this prompt was
		// visible. Serialize the final re-check + append across processes and
		// reload known_hosts under the lock. If a different key won the race,
		// fail closed instead of appending a second trusted key for the host.
		unlock, lerr := lockKnownHosts(knownHostsPath)
		if lerr != nil {
			return lerr
		}
		defer unlock()

		freshVerify, lerr := knownhosts.New(knownHostsPath)
		if lerr != nil {
			return fmt.Errorf("reloading known_hosts: %w", lerr)
		}
		lerr = freshVerify(hostname, remote, key)
		if lerr == nil {
			return nil
		}
		var freshKeyErr *knownhosts.KeyError
		if !errors.As(lerr, &freshKeyErr) {
			return lerr
		}
		if len(freshKeyErr.Want) > 0 {
			return &hostKeyChangedError{hostname: hostname, err: freshKeyErr}
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

func fingerprintSHA256(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
