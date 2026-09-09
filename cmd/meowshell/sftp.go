package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// tailcatClientArgv builds the argv for tailcat's own bare client mode
// ("tailcat [flags] <addr> <port>"), the same netcat-over-tailcat bridge
// OpenSSH's ProxyCommand drives for tailcat's own ssh/cp subcommands --
// just built as a real argv slice here instead of a shell-quoted string,
// since dialSFTP execs it directly rather than handing it to a shell.
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

// pipeConn adapts a child process's stdin/stdout to net.Conn, the shape
// golang.org/x/crypto/ssh needs to drive a handshake. Deadlines are
// unsupported (no-ops): the child process enforces its own timeouts (the
// meow ping's fixed 10s handshake deadline among them), and the pipe has no
// deeper OS-level timeout mechanism to hook into.
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
	// Closing stdin/stdout above makes tailcat exit on its own; that shows
	// up here as a plain nonzero exit, not a real failure to report.
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

// dialSSHClient starts tailcat's own bare client mode as a subprocess (argv
// from tailcatClientArgv) and speaks SSH directly over its stdin/stdout --
// no system ssh binary involved, which is what makes this work in an
// Android app sandbox (and piped into from anywhere else with no real
// terminal attached at all). The server accepts the SSH "none" auth method
// unconditionally: tailcat's own WireGuard peer handshake, keyed by the
// address, already established who is connecting, the same trust tailcat's
// own native "ls" subcommand relies on. Closing the returned client also
// tears down the subprocess.
func dialSSHClient(tailcatBin string, argv []string) (*ssh.Client, error) {
	cmd := exec.Command(tailcatBin, argv...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	conn := &pipeConn{cmd: cmd, stdout: stdout, stdin: stdin}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "tailcat", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// dialSFTP is dialSSHClient plus opening the SFTP subsystem on top.
func dialSFTP(tailcatBin string, argv []string) (*sftp.Client, io.Closer, error) {
	sc, err := dialSSHClient(tailcatBin, argv)
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

// splitRemoteArg splits an scp-style remote argument "host:path", where
// host is a tailcat address or a DNS name with a "tailcat=" TXT record. ok
// reports whether arg is remote: it has a colon that isn't preceded by a
// path separator, and the part before the colon is longer than one
// character (so a Windows drive path like "C:\foo" stays local). Mirrors
// tailcat's own cp.go splitRemoteArg exactly, so the same address syntax
// works identically whether cp runs through tailcat or through meowshell.
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
