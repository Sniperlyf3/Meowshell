package main

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestAgentLocalForwardEndToEnd drives "-L"-style forwarding: the agent
// listens locally and forwards each accepted connection through the SSH
// client to a target the test's own fake SSH server dials back out to.
func TestAgentLocalForwardEndToEnd(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	const backendReply = "hello from the forwarded backend"
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, backendReply)
			}()
		}
	}()

	addr, _, _ := startTestSSHServer(t, echoCommandHandler) // the SSH server whose Dial reaches backendLn
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer stopAgent(t, cmd, stdin)
	acceptHostKeyPrompt(t, stdin, out)
	expectConnected(t, out)

	send(t, stdin, 0, controlMessage{
		Msg: "open_channel", Kind: "forward_local",
		ListenAddr: "127.0.0.1:0", RemoteAddr: backendLn.Addr().String(),
	})
	f := mustReadFrame(t, out)
	opened := decodeControl(t, f)
	if opened.Msg != "channel_opened" || opened.BoundAddr == "" {
		t.Fatalf("channel_opened = %+v, want a non-empty BoundAddr", opened)
	}

	conn, err := net.DialTimeout("tcp", opened.BoundAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dialing the forwarded local listener: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading through the forward: %v", err)
	}
	if string(got) != backendReply {
		t.Errorf("got %q through the forward, want %q", got, backendReply)
	}
}

// TestAgentSOCKSForwardEndToEnd drives "-D": a SOCKS5 client (net.Dialer
// speaking the protocol by hand, since the standard library has no SOCKS5
// client of its own either) connects through the agent's SOCKS listener
// to a backend the SSH server's own Dial reaches.
func TestAgentSOCKSForwardEndToEnd(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	const backendReply = "hello via socks"
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, backendReply)
			}()
		}
	}()

	addr, _, _ := startTestSSHServer(t, echoCommandHandler)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer stopAgent(t, cmd, stdin)
	acceptHostKeyPrompt(t, stdin, out)
	expectConnected(t, out)

	send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "forward_socks", ListenAddr: "127.0.0.1:0"})
	f := mustReadFrame(t, out)
	opened := decodeControl(t, f)
	if opened.Msg != "channel_opened" || opened.BoundAddr == "" {
		t.Fatalf("channel_opened = %+v, want a non-empty BoundAddr", opened)
	}

	conn, err := net.DialTimeout("tcp", opened.BoundAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dialing the SOCKS listener: %v", err)
	}
	defer conn.Close()
	got, err := socks5Connect(conn, backendLn.Addr().String())
	if err != nil {
		t.Fatalf("SOCKS5 CONNECT: %v", err)
	}
	if got != backendReply {
		t.Errorf("got %q through SOCKS, want %q", got, backendReply)
	}
}

// socks5Connect speaks just enough SOCKS5 client-side to CONNECT to
// target through conn and read back whatever the far end sends.
func socks5Connect(conn net.Conn, target string) (string, error) {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return "", err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return "", fmt.Errorf("unexpected method-selection reply %v", reply)
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
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	return string(got), err
}
