package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type dialer func(ctx context.Context) (net.Conn, error)

func tailcatDialer(tailcatBin string, argv []string) dialer {
	return func(ctx context.Context) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The context only bounds dialing; it does not own the connection after
		// this function returns. In particular, dialSSHClient cancels its
		// handshake context after a successful handshake. CommandContext would
		// then kill the tailcat process backing the live SSH connection.
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

func tcpDialer(hostPort string) dialer {
	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: tcpDialTimeout}
		return d.DialContext(ctx, "tcp", hostPort)
	}
}

func jumpDialer(via jumpClient, hostPort string) dialer {
	return func(ctx context.Context) (net.Conn, error) {
		// via.Dial (an *ssh.Client's channel-opening Dial) takes no context,
		// so a hostile or unresponsive jump host can otherwise hang this
		// past the handshake timeout dialSSHClient thinks it's enforcing.
		// Run it in the background and honor ctx ourselves; if it does
		// eventually complete after we've given up, close the orphaned
		// connection instead of leaking it.
		type result struct {
			conn net.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			conn, err := via.Dial("tcp", hostPort)
			ch <- result{conn, err}
		}()
		select {
		case res := <-ch:
			return res.conn, res.err
		case <-ctx.Done():
			go func() {
				if res := <-ch; res.conn != nil {
					res.conn.Close()
				}
			}()
			return nil, ctx.Err()
		}
	}
}

type jumpClient interface {
	Dial(network, addr string) (net.Conn, error)
}

func splitUserHost(dest, defaultPort string) (username, hostPort string) {
	if at := strings.LastIndex(dest, "@"); at >= 0 {
		username, dest = dest[:at], dest[at+1:]
	} else if u, err := user.Current(); err == nil {
		// Matches ordinary `ssh host` behavior: no user@ prefix means the
		// local OS user, not an empty SSH username. If the lookup itself
		// fails (e.g. no /etc/passwd entry for the running UID, as can
		// happen in a minimal container), fall back to the previous
		// behavior of leaving it empty rather than failing the connection
		// outright.
		username = u.Username
	}
	if _, _, err := net.SplitHostPort(dest); err == nil {
		return username, dest
	}

	host := strings.TrimSuffix(strings.TrimPrefix(dest, "["), "]")
	return username, net.JoinHostPort(host, defaultPort)
}

func proxyDialer(proxyURL, hostPort string) (dialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		// url.ParseError includes the original URL, which can contain a proxy
		// password. Do not copy it into diagnostics.
		return nil, fmt.Errorf("invalid --proxy URL")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("invalid --proxy URL: missing host")
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		d, err := proxy.SOCKS5("tcp", u.Host, proxyAuthFromURL(u), proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("configuring SOCKS5 proxy %q: %w", u.Redacted(), err)
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

func dialHTTPConnectProxy(ctx context.Context, proxyURL *url.URL, hostPort string) (net.Conn, error) {
	d := net.Dialer{Timeout: tcpDialTimeout}
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	var conn net.Conn
	var err error
	if proxyURL.Scheme == "https" {
		tlsDialer := tls.Dialer{NetDialer: &d}
		conn, err = tlsDialer.DialContext(ctx, "tcp", proxyAddr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", proxyAddr)
	}
	if err != nil {
		return nil, err
	}
	stopCancellation := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopCancellation()
	var authHeader string
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + pass))
		authHeader = "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", hostPort, hostPort, authHeader); err != nil {
		conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("HTTP CONNECT proxy %s refused: %s", proxyURL.Host, resp.Status)
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return &bufConn{Conn: conn, r: br}, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

var lookupAgentTXT = net.DefaultResolver.LookupTXT

func resolveAgentDestination(ctx context.Context, dest string, allowTXT bool) (string, bool, error) {
	if looksLikeTailcatAddress(dest) {
		return dest, true, nil
	}
	// user@host, explicit host:port, and IP literals are unambiguously ordinary
	// SSH destinations. A bare DNS name is the only form that can also stand
	// for Tailcat's documented "tailcat=tc..." TXT indirection.
	if strings.Contains(dest, "@") {
		return dest, false, nil
	}
	if _, _, err := net.SplitHostPort(dest); err == nil {
		return dest, false, nil
	}
	if net.ParseIP(strings.Trim(dest, "[]")) != nil {
		return dest, false, nil
	}
	// A bare hostname otherwise means ordinary SSH, verified against
	// known_hosts with TOFU. The TXT indirection below hands trust to a
	// completely different mechanism instead -- tailcat's own client
	// authentication, with no known_hosts involved at all -- on the say-so
	// of whoever controls DNS for that name. That is a meaningfully weaker
	// (or at least different) trust boundary than the one a bare hostname
	// otherwise implies, so it only applies when the caller has explicitly
	// asked for it; the default leaves a bare hostname as ordinary SSH,
	// even if a "tailcat=" TXT record happens to exist for it.
	if !allowTXT {
		return dest, false, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txts, err := lookupAgentTXT(lookupCtx, strings.TrimSuffix(dest, "."))
	if err != nil {
		// A missing/unresolvable TXT record does not make a normal SSH hostname
		// invalid; its A/AAAA lookup belongs to the regular TCP dial path.
		return dest, false, nil
	}
	for _, txt := range txts {
		if value, ok := strings.CutPrefix(txt, "tailcat="); ok {
			value = strings.TrimSpace(value)
			if !looksLikeTailcatAddress(value) {
				return "", false, fmt.Errorf("DNS name %q has an invalid tailcat TXT address", dest)
			}
			return value, true, nil
		}
	}
	return dest, false, nil
}

func looksLikeTailcatAddress(dest string) bool {
	rest, ok := strings.CutPrefix(dest, "tc")
	if !ok || rest == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}
