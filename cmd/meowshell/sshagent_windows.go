//go:build windows

package main

import "golang.org/x/crypto/ssh"

// sshAgentAuthMethods: no Windows ssh-agent (named pipe) support yet. A
// no-auth-ssh service still works fine without it -- SSH's "none" method is
// always tried first, before anything here -- but an "ssh" service requiring
// --ssh-authorized-keys has no public key to offer on Windows until this
// grows one.
func sshAgentAuthMethods() []ssh.AuthMethod { return nil }
