package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTailcatDialerContextDoesNotOwnReturnedConnection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cat subprocess fixture is Unix-only")
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn, err := tailcatDialer("cat", nil)(ctx)
	if err != nil {
		t.Fatalf("tailcatDialer: %v", err)
	}
	defer conn.Close()

	// A dial context governs creation of a connection, not the lifetime of a
	// successfully returned connection. dialSSHClient cancels the context it
	// passes here as soon as the SSH handshake completes.
	cancel()
	const message = "still connected\n"
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatalf("write after dial context cancellation: %v", err)
	}
	buf := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read after dial context cancellation: %v", err)
	}
	if got := string(buf); got != message {
		t.Fatalf("echo = %q, want %q", got, message)
	}
}

func TestTailcatDialerRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := tailcatDialer("command-must-not-be-started", nil)(ctx)
	if conn != nil {
		conn.Close()
		t.Fatal("tailcatDialer returned a connection for a canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("tailcatDialer error = %v, want context canceled", err)
	}
}

// blockingJumpClient's Dial never returns until unblocked, standing in for
// a hostile or unresponsive jump host during TestJumpDialerRespectsContext.
type blockingJumpClient struct {
	unblock chan struct{}
}

func (b *blockingJumpClient) Dial(network, addr string) (net.Conn, error) {
	<-b.unblock
	return nil, errors.New("dial finished after being unblocked, too late to matter")
}

// TestJumpDialerRespectsContext is a regression test: jumpDialer's returned
// func used to ignore the context entirely and call via.Dial directly, which
// takes no context of its own -- so a hostile or unresponsive jump host
// could hang a connection attempt indefinitely, well past the handshake
// timeout dialSSHClient thinks it's enforcing.
func TestJumpDialerRespectsContext(t *testing.T) {
	unblock := make(chan struct{})
	t.Cleanup(func() { close(unblock) })

	dial := jumpDialer(&blockingJumpClient{unblock: unblock}, "host:22")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()
	conn, err := dial(ctx)
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("jumpDialer error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("jumpDialer blocked for %s past its context deadline, want it to return promptly", elapsed)
	}
}

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

// TestSplitUserHost is also a regression test: an address with no user@
// prefix used to always produce an empty SSH username, diverging from
// ordinary `ssh host` behavior (which defaults to the local OS user). Cases
// with no @ now expect the local user, looked up the same way the fix does,
// so the test doesn't hardcode a value tied to whoever runs it.
func TestSplitUserHost(t *testing.T) {
	localUser := ""
	if u, err := user.Current(); err == nil {
		localUser = u.Username
	}
	cases := []struct {
		dest           string
		wantUser, want string
	}{
		{"example.com", localUser, "example.com:22"},
		{"example.com:2222", localUser, "example.com:2222"},
		{"alice@example.com", "alice", "example.com:22"},
		{"alice@example.com:2222", "alice", "example.com:2222"},
		{"[::1]", localUser, "[::1]:22"},
		{"[::1]:2222", localUser, "[::1]:2222"},
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

func TestDialHTTPConnectProxyHonorsCancellationAfterDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		io.Copy(io.Discard, conn)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	proxyURL := mustParseURL(t, "http://"+ln.Addr().String())
	done := make(chan error, 1)
	go func() {
		_, err := dialHTTPConnectProxy(ctx, proxyURL, "backend.example:22")
		done <- err
	}()
	<-accepted
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dialHTTPConnectProxy cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt the proxy response read")
	}
}

func TestProxyDialerDoesNotExposeMalformedURLPassword(t *testing.T) {
	const secret = "super-secret-password"
	_, err := proxyDialer("http://user:"+secret+"%zz@example.com", "backend.example:22")
	if err == nil {
		t.Fatal("proxyDialer accepted a malformed URL")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("proxy parse error exposed the password: %v", err)
	}
}

func TestDialHTTPSConnectProxyUsesTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	firstByte := make(chan byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var b [1]byte
		if _, err := conn.Read(b[:]); err == nil {
			firstByte <- b[0]
		}
	}()

	proxyURL := mustParseURL(t, "https://"+ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialHTTPConnectProxy(ctx, proxyURL, "backend.example:22"); err == nil {
		t.Fatal("dialHTTPConnectProxy against a non-TLS HTTPS proxy did not error")
	}
	select {
	case got := <-firstByte:
		if got != 0x16 { // TLS handshake record.
			t.Fatalf("first HTTPS proxy byte = %#x, want TLS handshake %#x", got, byte(0x16))
		}
	case <-ctx.Done():
		t.Fatal("HTTPS proxy did not receive a connection")
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

func TestResolveAgentDestinationFromTailcatTXT(t *testing.T) {
	old := lookupAgentTXT
	lookupAgentTXT = func(ctx context.Context, name string) ([]string, error) {
		if name != "device.example.com" {
			t.Fatalf("TXT lookup name = %q", name)
		}
		return []string{"other=value", "tailcat=tcQUJDRA"}, nil
	}
	t.Cleanup(func() { lookupAgentTXT = old })

	got, isTailcat, err := resolveAgentDestination(context.Background(), "device.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if !isTailcat || got != "tcQUJDRA" {
		t.Fatalf("resolveAgentDestination = (%q, %v), want (%q, true)", got, isTailcat, "tcQUJDRA")
	}
}

// TestResolveAgentDestinationTXTLookupIsOptIn is the security-relevant
// regression: without allowTXT, a bare hostname must be left as an ordinary
// SSH destination -- verified via known_hosts' TOFU -- even when a valid
// "tailcat=" TXT record exists for it. Without this, anyone able to publish
// a TXT record for a hostname (DNS being far easier to tamper with or
// misconfigure than a host's own SSH key) could silently redirect trust from
// known_hosts to Tailcat's own, unrelated authentication for any hostname a
// caller ever typed, with no indication anything unusual happened.
func TestResolveAgentDestinationTXTLookupIsOptIn(t *testing.T) {
	old := lookupAgentTXT
	lookupAgentTXT = func(context.Context, string) ([]string, error) {
		t.Fatal("TXT record looked up despite allowTXT=false")
		return nil, nil
	}
	t.Cleanup(func() { lookupAgentTXT = old })

	got, isTailcat, err := resolveAgentDestination(context.Background(), "device.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if isTailcat || got != "device.example.com" {
		t.Fatalf("resolveAgentDestination = (%q, %v), want ordinary SSH host, no TXT lookup", got, isTailcat)
	}
}

func TestResolveAgentDestinationLeavesOrdinarySSHHostAlone(t *testing.T) {
	old := lookupAgentTXT
	lookupAgentTXT = func(context.Context, string) ([]string, error) {
		return []string{"unrelated=value"}, nil
	}
	t.Cleanup(func() { lookupAgentTXT = old })

	got, isTailcat, err := resolveAgentDestination(context.Background(), "ssh.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if isTailcat || got != "ssh.example.com" {
		t.Fatalf("resolveAgentDestination = (%q, %v), want ordinary SSH host", got, isTailcat)
	}
}

func TestResolveAgentDestinationRejectsMalformedTailcatTXT(t *testing.T) {
	old := lookupAgentTXT
	lookupAgentTXT = func(context.Context, string) ([]string, error) {
		return []string{"tailcat=tcnot-valid!"}, nil
	}
	t.Cleanup(func() { lookupAgentTXT = old })

	if _, _, err := resolveAgentDestination(context.Background(), "device.example.com", true); err == nil {
		t.Fatal("malformed tailcat TXT record was accepted")
	}

func TestProxyDialerRejectsCredentialsOverPlainHTTP(t *testing.T) {
	_, err := proxyDialer("http://user:secret@127.0.0.1:8080", "backend.example:22")
	if err == nil {
		t.Fatal("proxyDialer accepted credentials over plaintext HTTP")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("proxy rejection exposed password: %v", err)
	}
}

}
