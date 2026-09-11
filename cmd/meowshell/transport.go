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
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type dialer func(ctx context.Context) (net.Conn, error)

func tailcatDialer(tailcatBin string, argv []string) dialer {
	return func(ctx context.Context) (net.Conn, error) {
		cmd := exec.CommandContext(ctx, tailcatBin, argv...)
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
		return via.Dial("tcp", hostPort)
	}
}

type jumpClient interface {
	Dial(network, addr string) (net.Conn, error)
}

func splitUserHost(dest, defaultPort string) (user, hostPort string) {
	if at := strings.LastIndex(dest, "@"); at >= 0 {
		user, dest = dest[:at], dest[at+1:]
	}
	if _, _, err := net.SplitHostPort(dest); err == nil {
		return user, dest
	}

	host := strings.TrimSuffix(strings.TrimPrefix(dest, "["), "]")
	return user, net.JoinHostPort(host, defaultPort)
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

func looksLikeTailcatAddress(dest string) bool {
	rest, ok := strings.CutPrefix(dest, "tc")
	if !ok || rest == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}
