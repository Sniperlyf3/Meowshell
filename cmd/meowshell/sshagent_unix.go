//go:build unix

package main

import (
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// sshAgentAuthMethods returns an SSH public-key auth method backed by the
// local ssh-agent (via $SSH_AUTH_SOCK), for a server that requires public-key
// auth -- an "ssh" service configured with --ssh-authorized-keys, as opposed
// to a "no-auth-ssh" one, which accepts SSH's "none" method (always tried
// first, before anything in ClientConfig.Auth) on tailcat's own WireGuard-peer
// trust alone. Returns nil if no agent is running: the handshake still
// succeeds against a no-auth-ssh service either way, and simply has no
// public key to offer if the server asks for one.
func sshAgentAuthMethods() []ssh.AuthMethod {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil
	}
	return []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(conn).Signers)}
}
