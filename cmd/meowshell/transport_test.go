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
		{"tcpGFwWCCCAiC8CWRmU8Bh0If_O_VgzekQvOSa1sJo-6FEOuZSXGFrWCCOgRnXVZlBMOhYT2IA-bDVKrvHkvoCwZSFA5ZtmwzpJmFxWCC1_Zamsrq9_iP73WYNbE6NfssVj2moLObKm-IqlLlHzGFygaFhToGmYWhhVGE0aTEyNy4wLjAuMWE2ZG5vbmVhcxmlQ2FkGaPRYXj1", true},
		{"tc", false},
		{"tcp://example.com", false},
		{"example.com:2222", false},
		{"user@example.com", false},
		{"10.0.0.1:22", false},
		{"tailscale-node.example", false},
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
