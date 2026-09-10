package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// dialer opens the net.Conn a *ssh.Client handshake runs over -- the one
// seam tailcat and raw TCP transport share (see dialSSHClient in sftp.go).
// A dialer owns the lifetime of whatever it returns: closing the *ssh.Client
// built on top closes the net.Conn, which for the tailcat dialer also tears
// down the subprocess underneath it (pipeConn.Close waits for it to exit).
type dialer func(ctx context.Context) (net.Conn, error)

// tailcatDialer runs tailcat's own bare client mode as a subprocess (argv
// from tailcatClientArgv) and adapts its stdin/stdout to net.Conn via
// pipeConn -- what makes this whole seam work inside an Android app sandbox
// in the first place: no raw socket of its own, just a child process's
// pipes. Deliberately plain exec.Command, not CommandContext: ctx here only
// ever bounds how long the dial itself may take (see dialSSHClient), and
// must not reach into the subprocess's lifetime once dialing succeeds --
// the subprocess IS the connection for as long as the connection lives.
func tailcatDialer(tailcatBin string, argv []string) dialer {
	return func(ctx context.Context) (net.Conn, error) {
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
		return &pipeConn{cmd: cmd, stdout: stdout, stdin: stdin}, nil
	}
}

const tcpDialTimeout = 15 * time.Second

// tcpDialer dials hostPort directly over TCP, for a destination that isn't
// a tailcat address (a bastion, a plain VPS). Unlike the tailcat dialer,
// there is no WireGuard-authenticated peer on the other end, so whatever
// calls dialSSHClient with this must also pass a real HostKeyCallback --
// never ssh.InsecureIgnoreHostKey, which is only correct for tailcat's own
// transport (see hostkeys.go).
func tcpDialer(hostPort string) dialer {
	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: tcpDialTimeout}
		return d.DialContext(ctx, "tcp", hostPort)
	}
}

// jumpDialer dials hostPort through an already-established SSH client
// (client.Dial), for each hop of a --jump chain after the first: the prior
// hop's own SSH connection carries the TCP stream to the next hop, rather
// than this process opening a second direct connection to it. via must
// outlive the returned dialer's use -- the caller keeps every hop's
// *ssh.Client alive for the life of the overall connection, closing them in
// reverse order when it ends.
func jumpDialer(via jumpClient, hostPort string) dialer {
	return func(ctx context.Context) (net.Conn, error) {
		return via.Dial("tcp", hostPort)
	}
}

// jumpClient is the one *ssh.Client method jumpDialer needs, broken out so
// tests can fake it without a real SSH server to dial through.
type jumpClient interface {
	Dial(network, addr string) (net.Conn, error)
}

// splitUserHost splits a "[user@]host[:port]" destination, defaulting port
// when host doesn't already carry one. host may be a bracketed IPv6
// literal ("[::1]:2222" or "[::1]").
func splitUserHost(dest, defaultPort string) (user, hostPort string) {
	if at := strings.LastIndex(dest, "@"); at >= 0 {
		user, dest = dest[:at], dest[at+1:]
	}
	if _, _, err := net.SplitHostPort(dest); err == nil {
		return user, dest
	}
	// dest carries no port. JoinHostPort re-brackets a literal that
	// contains ":" on its own, so a bracketed literal's brackets need
	// stripping first or it comes out double-bracketed ("[[::1]]:22").
	host := strings.TrimSuffix(strings.TrimPrefix(dest, "["), "]")
	return user, net.JoinHostPort(host, defaultPort)
}

// proxyDialer wraps hostPort's dial to go through an upstream SOCKS5 or
// HTTP CONNECT proxy (proxyURL: "socks5://[user:pass@]host:port" or
// "http://[user:pass@]host:port"), for a corporate network whose only path
// out is through one. Only meaningful for the first hop: --jump hops after
// it go through jumpDialer instead (an already-established SSH client's
// own Dial, which needs no further proxying to reach the network beyond
// it), and tailcat transport does not do a raw internet TCP dial of its
// own in the first place.
func proxyDialer(proxyURL, hostPort string) (dialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid --proxy %q: %w", proxyURL, err)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		d, err := proxy.SOCKS5("tcp", u.Host, proxyAuthFromURL(u), proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("configuring SOCKS5 proxy %q: %w", proxyURL, err)
		}
		return func(ctx context.Context) (net.Conn, error) {
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, "tcp", hostPort)
			}
			return d.Dial("tcp", hostPort)
		}, nil
	case "http", "https":
		return func(ctx context.Context) (net.Conn, error) {
			return dialHTTPConnectProxy(ctx, u, hostPort)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported --proxy scheme %q (want socks5 or http)", u.Scheme)
	}
}

func proxyAuthFromURL(u *url.URL) *proxy.Auth {
	if u.User == nil {
		return nil
	}
	pass, _ := u.User.Password()
	return &proxy.Auth{User: u.User.Username(), Password: pass}
}

// dialHTTPConnectProxy speaks the one HTTP request this needs by hand
// (net/http has no client-side CONNECT tunneling helper of its own): send
// CONNECT hostPort, read back the proxy's response line, and hand the raw
// TCP connection on once it answers 200 -- from that point on it's a plain
// byte pipe to hostPort, exactly like any other dialer here. The response
// is read through a bufio.Reader wrapped back into the returned conn
// (bufConn below): on a fast local proxy, the tunnel's first bytes can
// already be sitting in the same TCP segment as the status line, and a
// bufio.Reader that read them off the wire while parsing the response
// would otherwise strand them -- invisible to a caller reading conn
// directly afterwards.
func dialHTTPConnectProxy(ctx context.Context, proxyURL *url.URL, hostPort string) (net.Conn, error) {
	d := net.Dialer{Timeout: tcpDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}
	var authHeader string
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + pass))
		authHeader = "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", hostPort, hostPort, authHeader); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("HTTP CONNECT proxy %s refused: %s", proxyURL.Host, resp.Status)
	}
	return &bufConn{Conn: conn, r: br}, nil
}

// bufConn is a net.Conn whose Read is satisfied from r first -- see
// dialHTTPConnectProxy above for why that matters here.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// looksLikeTailcatAddress reports whether dest is syntactically a tailcat
// address: tailcat's own parseWire requires a "tc" prefix followed by
// base64.RawURLEncoding, and checking exactly that (without also pulling in
// the CBOR decode that only tailcat itself needs to actually use one) is
// enough to tell a tailcat address apart from a "[user@]host[:port]" TCP
// destination -- the base64url alphabet contains neither "@", ":", nor the
// "." a bare hostname or dotted IPv4 address needs.
func looksLikeTailcatAddress(dest string) bool {
	rest, ok := strings.CutPrefix(dest, "tc")
	if !ok || rest == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}
