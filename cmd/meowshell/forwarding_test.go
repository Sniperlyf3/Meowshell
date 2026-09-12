package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDialWithTimeoutDoesNotHangForever is a regression test: forward_remote
// (and forward_local/forward_socks against a plain SSH destination, via
// forwardClient) used to dial their target with no timeout at all
// (net.Dial / *ssh.Client.Dial, neither of which has one built in), so an
// unresponsive target (a firewall silently dropping SYNs) could hang the
// dial indefinitely.
func TestDialWithTimeoutDoesNotHangForever(t *testing.T) {
	unblock := make(chan struct{})
	t.Cleanup(func() { close(unblock) })
	blockingDial := func(network, addr string) (net.Conn, error) {
		<-unblock
		return nil, fmt.Errorf("dial finished after being unblocked, too late to matter")
	}

	started := time.Now()
	conn, err := dialWithTimeout(blockingDial, "tcp", "unresponsive.example:1234", 50*time.Millisecond)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("dialWithTimeout returned no error for a dial that never completed")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("dialWithTimeout blocked for %s past its timeout, want it to return promptly", elapsed)
	}
}

func TestListenUnixRefusesToRemoveNonSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not supported on Windows")
	}
	path := filepath.Join(t.TempDir(), "important")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(path); err == nil || !strings.Contains(err.Error(), "refusing to remove non-socket") {
		t.Fatalf("listenUnix over a regular file = %v, want refusal", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
	if string(got) != "keep me" {
		t.Fatalf("regular file changed to %q", got)
	}
}

// TestProxyForwardedConnPropagatesHalfClose is a regression test: a client
// that finishes sending and half-closes its write side (not the whole
// connection) must still be able to receive a response the backend sends
// afterward. proxyForwardedConn used to tear down both connections outright
// the instant either direction's io.Copy saw EOF -- correct for a client
// that hangs up entirely, wrong for one that legitimately calls
// CloseWrite() and then waits for a reply.
func TestProxyForwardedConnPropagatesHalfClose(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()

	const request = "request-from-client"
	// Large enough that a connection torn down early would visibly truncate
	// it, rather than the test getting lucky with a response that fits in
	// one TCP segment either way.
	response := bytes.Repeat([]byte("response-data-"), 8192)

	backendDone := make(chan error, 1)
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()
		// io.ReadAll blocks until EOF -- the client's CloseWrite, not the
		// whole connection closing -- then this can still write back.
		got, err := io.ReadAll(conn)
		if err != nil {
			backendDone <- err
			return
		}
		if string(got) != request {
			backendDone <- fmt.Errorf("backend received %q, want %q", got, request)
			return
		}
		_, err = conn.Write(response)
		backendDone <- err
	}()

	forwardLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer forwardLn.Close()
	go func() {
		conn, err := forwardLn.Accept()
		if err != nil {
			return
		}
		proxyForwardedConn(conn, func() (net.Conn, error) {
			return net.Dial("tcp", backendLn.Addr().String())
		})
	}()

	client, err := net.Dial("tcp", forwardLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("client received %d bytes, want the full %d-byte response "+
			"(half-close was not propagated -- the connection was torn down early)", len(got), len(response))
	}

	select {
	case err := <-backendDone:
		if err != nil {
			t.Fatalf("backend goroutine: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend goroutine did not finish")
	}
}

// fakeSOCKSDialer never actually dials -- the SOCKS5 tests below exercise
// only the handshake, which fails (or times out) before any CONNECT target
// would be dialed.
type fakeSOCKSDialer struct{}

func (fakeSOCKSDialer) Dial(network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("fakeSOCKSDialer: unexpected dial to %s", addr)
}

// TestServeSOCKS5RejectsNoAuthWhenNotOffered is a regression test for RFC
// 1928 section 3.1: the server's method-selection reply must name a method
// the client actually offered. serveSOCKS5 used to select "no authentication
// required" (0x00) whenever the listener itself required no auth,
// regardless of whether the client's greeting ever listed that method.
func TestServeSOCKS5RejectsNoAuthWhenNotOffered(t *testing.T) {
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
		serveSOCKS5(conn, fakeSOCKSDialer{}, "", "") // no auth required
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting offering only username/password (0x02) -- never 0x00 ("no
	// authentication required").
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("method-selection reply = % x, want 05 ff (no acceptable methods) -- "+
			"the server must never select a method the client didn't offer", reply)
	}
}

// TestAcceptForwardedConnsLimitsConcurrency is a regression test for N14:
// openLocalForward/openRemoteForward/openSOCKSForward used to spawn an
// unbounded goroutine per accepted connection, so a forward under heavy (or
// hostile) load could pile up unlimited goroutines, file descriptors, and
// dial attempts. Drives more connections than the configured limit and
// checks both that the limit is actually enforced while connections are
// held open, and that every connection still eventually gets served once
// slots free up (the limit throttles, it doesn't drop).
func TestAcceptForwardedConnsLimitsConcurrency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const maxConnections = 3
	const totalConns = 8

	var mu sync.Mutex
	cur, peak := 0, 0
	release := make(chan struct{})
	handled := make(chan struct{}, totalConns)

	acceptForwardedConns(ln, maxConnections, func(conn net.Conn) {
		defer conn.Close()
		mu.Lock()
		cur++
		if cur > peak {
			peak = cur
		}
		mu.Unlock()

		<-release

		mu.Lock()
		cur--
		mu.Unlock()
		handled <- struct{}{}
	})

	var dialWG sync.WaitGroup
	for i := 0; i < totalConns; i++ {
		dialWG.Add(1)
		go func() {
			defer dialWG.Done()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		reached := cur == maxConnections
		mu.Unlock()
		if reached {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	gotCur := cur
	mu.Unlock()
	if gotCur != maxConnections {
		t.Fatalf("in-flight handlers = %d, want exactly %d (the configured limit) with %d connections pending",
			gotCur, maxConnections, totalConns)
	}

	close(release)
	for i := 0; i < totalConns; i++ {
		select {
		case <-handled:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d connections were ever handled -- the limit must throttle, not drop", i, totalConns)
		}
	}

	mu.Lock()
	gotPeak := peak
	mu.Unlock()
	if gotPeak > maxConnections {
		t.Fatalf("peak concurrent handlers = %d, want at most %d", gotPeak, maxConnections)
	}

	dialWG.Wait()
}

// TestAcceptForwardedConnsZeroMeansUnlimited is the flip side of the above:
// the zero value (what every message from a client that predates this field
// deserializes to) must not throttle at all, preserving prior behavior.
func TestAcceptForwardedConnsZeroMeansUnlimited(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const totalConns = 20
	var mu sync.Mutex
	cur, peak := 0, 0
	release := make(chan struct{})
	handled := make(chan struct{}, totalConns)

	acceptForwardedConns(ln, 0, func(conn net.Conn) {
		defer conn.Close()
		mu.Lock()
		cur++
		if cur > peak {
			peak = cur
		}
		mu.Unlock()
		<-release
		handled <- struct{}{}
	})

	var dialWG sync.WaitGroup
	for i := 0; i < totalConns; i++ {
		dialWG.Add(1)
		go func() {
			defer dialWG.Done()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		reached := cur == totalConns
		mu.Unlock()
		if reached {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	gotCur := cur
	mu.Unlock()
	if gotCur != totalConns {
		t.Fatalf("in-flight handlers = %d, want all %d accepted at once with maxConnections=0 (unlimited)", gotCur, totalConns)
	}

	close(release)
	for i := 0; i < totalConns; i++ {
		<-handled
	}
	dialWG.Wait()
}

// TestServeSOCKS5EnforcesHandshakeDeadline is a regression test: a client
// that opens the connection and then sends nothing must not hold it (and a
// goroutine) open indefinitely -- serveSOCKS5 used to perform every
// handshake read with no deadline at all, which only stayed a local
// resource concern for as long as these listeners were loopback-only.
func TestServeSOCKS5EnforcesHandshakeDeadline(t *testing.T) {
	old := socksHandshakeTimeout
	socksHandshakeTimeout = 200 * time.Millisecond
	defer func() { socksHandshakeTimeout = old }()

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
		serveSOCKS5(conn, fakeSOCKSDialer{}, "", "")
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send nothing. The server must give up and close its side well within
	// a couple of handshake-timeout windows, not hang forever.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err != io.EOF {
		t.Fatalf("read = (%d, %v), want (0, io.EOF): the server should have closed its side after the handshake deadline", n, err)
	}
}

func TestOpenForwardChannelRejectsExcessiveMaxConnectionsBeforeBinding(t *testing.T) {
	var out bytes.Buffer
	session := newAgentSession(nil, &out)
	session.openForwardChannel(controlMessage{
		Msg: "open_channel", Kind: "forward_local", RequestID: "too-many",
		ListenAddr: "127.0.0.1:0", RemoteAddr: "127.0.0.1:80",
		MaxConnections: maxForwardConnections + 1,
	})

	msgs := readControlFrames(t, &out)
	if len(msgs) != 1 || msgs[0].RequestID != "too-many" || msgs[0].Code != errProtocolError {
		t.Fatalf("excessive max_connections response = %+v, want one protocol error", msgs)
	}
}
