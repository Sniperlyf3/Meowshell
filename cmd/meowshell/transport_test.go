package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLooksLikeTailcatAddress(t *testing.T) {
	cases := []struct {
		dest string
		want bool
	}{
		// A real address as tailcat itself would publish one (captured
		// from a local test server run), not a hand-truncated fake --
		// base64.RawURLEncoding is picky about length, so this needs to
		// be a genuine, complete encoding to prove the happy path.
		{"tcpGFwWCCCAiC8CWRmU8Bh0If_O_VgzekQvOSa1sJo-6FEOuZSXGFrWCCOgRnXVZlBMOhYT2IA-bDVKrvHkvoCwZSFA5ZtmwzpJmFxWCC1_Zamsrq9_iP73WYNbE6NfssVj2moLObKm-IqlLlHzGFygaFhToGmYWhhVGE0aTEyNy4wLjAuMWE2ZG5vbmVhcxmlQ2FkGaPRYXj1", true},
		{"tc", false},                     // no payload at all
		{"tcp://example.com", false},      // "://" is not valid base64url
		{"example.com:2222", false},       // a plain TCP host:port
		{"user@example.com", false},       // a plain TCP user@host
		{"10.0.0.1:22", false},            // a bare IPv4:port
		{"tailscale-node.example", false}, // a bare hostname, no "tc" prefix
	}
	for _, c := range cases {
		if got := looksLikeTailcatAddress(c.dest); got != c.want {
			t.Errorf("looksLikeTailcatAddress(%q) = %v, want %v", c.dest, got, c.want)
		}
	}
}

func TestSplitUserHost(t *testing.T) {
	cases := []struct {
		dest           string
		wantUser, want string
	}{
		{"example.com", "", "example.com:22"},
		{"example.com:2222", "", "example.com:2222"},
		{"alice@example.com", "alice", "example.com:22"},
		{"alice@example.com:2222", "alice", "example.com:2222"},
		{"[::1]", "", "[::1]:22"},
		{"[::1]:2222", "", "[::1]:2222"},
		{"alice@[::1]:2222", "alice", "[::1]:2222"},
	}
	for _, c := range cases {
		user, hostPort := splitUserHost(c.dest, "22")
		if user != c.wantUser || hostPort != c.want {
			t.Errorf("splitUserHost(%q) = (%q, %q), want (%q, %q)", c.dest, user, hostPort, c.wantUser, c.want)
		}
	}
}

// TestDialHTTPConnectProxy drives dialHTTPConnectProxy against a minimal
// fake HTTP CONNECT proxy, proving --proxy=http://... actually tunnels
// bytes rather than just parsing a URL.
func TestDialHTTPConnectProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const backendReply = "hello through the tunnel"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil || req.Method != "CONNECT" {
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// From here on, the proxy is just a pipe: write something only the
		// far end of the tunnel could have -- the test can't easily stand
		// up a real second hop, so this stands in for it directly.
		conn.Write([]byte(backendReply))
	}()

	proxyURL := mustParseURL(t, "http://"+ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialHTTPConnectProxy(ctx, proxyURL, "backend.example:22")
	if err != nil {
		t.Fatalf("dialHTTPConnectProxy: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, len(backendReply))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("reading through the tunnel: %v", err)
	}
	if string(buf) != backendReply {
		t.Errorf("got %q through the tunnel, want %q", buf, backendReply)
	}
}

func TestDialHTTPConnectProxyRejectsNon200(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		http.ReadRequest(bufio.NewReader(conn))
		fmt.Fprintf(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
	}()

	proxyURL := mustParseURL(t, "http://"+ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialHTTPConnectProxy(ctx, proxyURL, "backend.example:22"); err == nil {
		t.Fatal("dialHTTPConnectProxy against a 407 response did not error")
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
