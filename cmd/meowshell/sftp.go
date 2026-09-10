package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func tailcatClientArgv(key, derpMapURL string, verbose bool, addr, port string) []string {
	var argv []string
	if key != "" {
		argv = append(argv, "--key="+key)
	}
	if derpMapURL != "" {
		argv = append(argv, "--derpmap-url="+derpMapURL)
	}
	if verbose {
		argv = append(argv, "--verbose")
	}
	return append(argv, addr, port)
}

type pipeConn struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stdin  io.WriteCloser
}

func (c *pipeConn) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *pipeConn) Write(p []byte) (int, error) { return c.stdin.Write(p) }

func (c *pipeConn) Close() error {
	c.stdin.Close()
	c.stdout.Close()
	err := c.cmd.Wait()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil
	}
	return err
}

func (c *pipeConn) LocalAddr() net.Addr             { return pipeAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr            { return pipeAddr{} }
func (c *pipeConn) SetDeadline(time.Time) error     { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error {
	return nil
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "tailcat" }
func (pipeAddr) String() string  { return "tailcat" }

func dialSSHClient(ctx context.Context, dial dialer, remoteAddr, user string, hostKeyCallback ssh.HostKeyCallback, auth []ssh.AuthMethod) (*ssh.Client, error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, remoteAddr, &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: hostKeyCallback,
		Auth:            auth,
		Timeout:         sshHandshakeTimeout,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

const sshHandshakeTimeout = 20 * time.Second

func tailcatSSHDialer(tailcatBin string, argv []string) (dialer, string, ssh.HostKeyCallback) {
	return tailcatDialer(tailcatBin, argv), "tailcat", tailcatHostKeyCallback()
}

func dialSFTP(tailcatBin string, argv []string) (*sftp.Client, io.Closer, error) {
	dial, remoteAddr, hkCallback := tailcatSSHDialer(tailcatBin, argv)
	sc, err := dialSSHClient(context.Background(), dial, remoteAddr, "", hkCallback, sshAgentAuthMethods())
	if err != nil {
		return nil, nil, err
	}
	sf, err := sftp.NewClient(sc)
	if err != nil {
		sc.Close()
		return nil, nil, fmt.Errorf("opening SFTP session: %w", err)
	}
	return sf, closerFunc(func() error {
		sf.Close()
		return sc.Close()
	}), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func splitRemoteArg(arg string) (host, path string, ok bool) {
	i := strings.Index(arg, ":")
	if i <= 1 {
		return "", "", false
	}
	if strings.ContainsAny(arg[:i], `/\`) {
		return "", "", false
	}
	return arg[:i], arg[i+1:], true
}
