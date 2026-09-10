package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAgentRejectsNonLoopbackBindByDefault proves the fix for the
// unrestricted-bind finding: a forward_local asking to listen on a
// non-loopback address is refused unless AllowNonLoopbackBind is set.
func TestAgentRejectsNonLoopbackBindByDefault(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	addr, _, _ := startTestSSHServer(t, echoCommandHandler)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	t.Run("0.0.0.0 is refused by default", func(t *testing.T) {
		cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
		defer stopAgent(t, cmd, stdin)
		acceptHostKeyPrompt(t, stdin, out)
		expectConnected(t, out)

		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "forward_local", ListenAddr: "0.0.0.0:0", RemoteAddr: "127.0.0.1:1"})
		f := mustReadFrame(t, out)
		msg := decodeControl(t, f)
		if msg.Msg != "error" {
			t.Fatalf("binding 0.0.0.0 without opt-in = %+v, want an error", msg)
		}
	})

	t.Run("0.0.0.0 succeeds with AllowNonLoopbackBind", func(t *testing.T) {
		cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
		defer stopAgent(t, cmd, stdin)
		// known_hosts already trusts this server from the first subtest,
		// so no host-key prompt this time -- but "connected" still comes
		// first, same as any other fresh connection.
		expectConnected(t, out)

		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "forward_local", ListenAddr: "0.0.0.0:0", RemoteAddr: "127.0.0.1:1", AllowNonLoopbackBind: true})
		f := mustReadFrame(t, out)
		msg := decodeControl(t, f)
		if msg.Msg != "channel_opened" {
			t.Fatalf("binding 0.0.0.0 with opt-in = %+v, want channel_opened", msg)
		}
	})

	t.Run("127.0.0.1 and localhost succeed without opt-in", func(t *testing.T) {
		for _, listenAddr := range []string{"127.0.0.1:0", "localhost:0"} {
			cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
			expectConnected(t, out)
			send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "forward_local", ListenAddr: listenAddr, RemoteAddr: "127.0.0.1:1"})
			f := mustReadFrame(t, out)
			msg := decodeControl(t, f)
			if msg.Msg != "channel_opened" {
				t.Errorf("binding %s without opt-in = %+v, want channel_opened", listenAddr, msg)
			}
			stopAgent(t, cmd, stdin)
		}
	})
}

// TestAgentUnixSocketForward proves the UDS fix: a forward_local with
// listen_network "unix" listens on a filesystem-permission-protected
// socket, chmod'd 0600 regardless of umask, and actually relays bytes.
func TestAgentUnixSocketForward(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("unix domain sockets aren't this test's concern on Windows")
	}
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	const reply = "hello over a unix socket forward"
	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, reply)
	}()

	addr, _, _ := startTestSSHServer(t, echoCommandHandler)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer stopAgent(t, cmd, stdin)
	acceptHostKeyPrompt(t, stdin, out)
	expectConnected(t, out)

	socketPath := filepath.Join(t.TempDir(), "forward.sock")
	send(t, stdin, 0, controlMessage{
		Msg: "open_channel", Kind: "forward_local",
		ListenNetwork: "unix", ListenAddr: socketPath,
		RemoteAddr: backendLn.Addr().String(),
	})
	f := mustReadFrame(t, out)
	opened := decodeControl(t, f)
	if opened.Msg != "channel_opened" {
		t.Fatalf("open_channel(unix) = %+v", opened)
	}

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("socket permissions = %o, want 0600", got)
	}

	conn, err := net.DialTimeout("unix", socketPath, e2eDialTimeout)
	if err != nil {
		t.Fatalf("dialing the unix socket forward: %v", err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading through the forward: %v", err)
	}
	if string(got) != reply {
		t.Errorf("got %q through the unix socket forward, want %q", got, reply)
	}
}

// TestAgentSocksAuthToken proves the SOCKS5 auth fix: a proxy opened with
// SocksUsername/SocksPassword refuses a client presenting the wrong
// credentials (or none), and serves one presenting the right pair.
func TestAgentSocksAuthToken(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	const reply = "hello via authenticated socks"
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, reply)
			}()
		}
	}()

	addr, _, _ := startTestSSHServer(t, echoCommandHandler)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer stopAgent(t, cmd, stdin)
	acceptHostKeyPrompt(t, stdin, out)
	expectConnected(t, out)

	send(t, stdin, 0, controlMessage{
		Msg: "open_channel", Kind: "forward_socks", ListenAddr: "127.0.0.1:0",
		SocksUsername: "app", SocksPassword: "s3cret-token",
	})
	f := mustReadFrame(t, out)
	opened := decodeControl(t, f)
	if opened.Msg != "channel_opened" {
		t.Fatalf("open_channel(forward_socks) = %+v", opened)
	}

	t.Run("wrong credentials are refused", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", opened.BoundAddr, e2eDialTimeout)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := socks5Auth(conn, "app", "wrong-token"); err == nil {
			t.Error("wrong SOCKS credentials were accepted")
		}
	})

	t.Run("no credentials at all are refused", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", opened.BoundAddr, e2eDialTimeout)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		// Offer only "no auth"; the server requires user/pass and must
		// reject the method-selection outright (0xFF), not fall back.
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatal(err)
		}
		replyHdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, replyHdr); err != nil {
			t.Fatal(err)
		}
		if replyHdr[1] != 0xFF {
			t.Errorf("method selection reply = %v, want no acceptable method (0xFF)", replyHdr)
		}
	})

	t.Run("correct credentials reach the backend", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", opened.BoundAddr, e2eDialTimeout)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		got, err := socks5AuthAndConnect(conn, "app", "s3cret-token", backendLn.Addr().String())
		if err != nil {
			t.Fatalf("authenticated SOCKS5 CONNECT: %v", err)
		}
		if got != reply {
			t.Errorf("got %q, want %q", got, reply)
		}
	})
}

// TestAgentConfigureCarriesProxyURL proves the argv fix: the agent
// connects through a proxy configured via the "configure" message
// (never a CLI flag, so it never lands in this process's own argv/
// /proc/pid/cmdline) exactly as it did when --proxy was still a flag.
func TestAgentConfigureCarriesProxyURL(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")
	addr, _, _ := startTestSSHServer(t, echoCommandHandler)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	dialedThroughProxy := make(chan struct{}, 1)
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go serveHTTPConnectProxy(t, c, addr, dialedThroughProxy)
		}
	}()

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	proxyURL := "http://" + proxyLn.Addr().String()
	cmd, stdin, out := startAgentConfigured(t, meowshellBin, knownHosts, "testuser@"+addr,
		controlMessage{Msg: "configure", ProxyURL: proxyURL})
	defer stopAgent(t, cmd, stdin)
	acceptHostKeyPrompt(t, stdin, out)
	expectConnected(t, out)

	select {
	case <-dialedThroughProxy:
	default:
		t.Error("connection never went through the configured proxy")
	}
}

// serveHTTPConnectProxy answers exactly one CONNECT request by dialing
// wantTarget itself (ignoring whatever the client asked for, since this
// test only cares whether the agent used the proxy at all) and signals
// dialed once it has.
func serveHTTPConnectProxy(t *testing.T, conn net.Conn, wantTarget string, dialed chan<- struct{}) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	select {
	case dialed <- struct{}{}:
	default:
	}
	backend, err := net.DialTimeout("tcp", wantTarget, e2eDialTimeout)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer backend.Close()
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() { io.Copy(backend, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, backend); done <- struct{}{} }()
	<-done
}

const e2eDialTimeout = 5 * time.Second

// socks5Auth performs the greeting + username/password subnegotiation
// only, for a test that expects it to fail.
func socks5Auth(conn net.Conn, username, password string) (bool, error) {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return false, err
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodReply); err != nil {
		return false, err
	}
	if methodReply[1] != 0x02 {
		return false, fmt.Errorf("server didn't select username/password auth: %v", methodReply)
	}
	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return false, err
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		return false, err
	}
	if authReply[1] != 0x00 {
		return false, fmt.Errorf("authentication failed, status %d", authReply[1])
	}
	return true, nil
}

// socks5AuthAndConnect is socks5Auth plus a CONNECT request, returning
// whatever the far end sends back.
func socks5AuthAndConnect(conn net.Conn, username, password, target string) (string, error) {
	if ok, err := socks5Auth(conn, username, password); err != nil || !ok {
		return "", err
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return "", err
	}
	if respHdr[1] != 0x00 {
		return "", fmt.Errorf("SOCKS5 CONNECT failed, reply code %d", respHdr[1])
	}
	switch respHdr[3] {
	case 0x01:
		io.CopyN(io.Discard, conn, 4+2)
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		io.CopyN(io.Discard, conn, int64(lenBuf[0])+2)
	case 0x04:
		io.CopyN(io.Discard, conn, 16+2)
	}
	got, err := io.ReadAll(conn)
	return string(got), err
}
