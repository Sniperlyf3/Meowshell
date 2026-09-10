package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestAgentTCPEndToEnd drives "meowshell agent" against a real (if
// minimal) SSH server over plain TCP -- no tailcat involved at all -- to
// prove the general-SSH-host path: TCP dialing, TOFU host-key prompting
// round-tripped over the control channel, and the same known_hosts file
// trusting the same key silently on a second connection.
func TestAgentTCPEndToEnd(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	addr, hostKey1, stopServer1 := startTestSSHServer(t, echoCommandHandler)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	t.Run("first connection prompts for TOFU and the client accepts", func(t *testing.T) {
		cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
		defer stopAgent(t, cmd, stdin)

		f := mustReadFrame(t, out)
		msg := decodeControl(t, f)
		if msg.Msg != "prompt_request" || msg.PromptKind != "host_key" {
			t.Fatalf("first message = %+v, want a host_key prompt_request", msg)
		}
		wantFP := fingerprintSHA256(hostKey1.PublicKey())
		if msg.Fingerprint != wantFP {
			t.Errorf("prompted fingerprint = %q, want %q", msg.Fingerprint, wantFP)
		}
		send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Accept: true})

		expectConnected(t, out)

		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"ping"}})
		id := expectChannelOpened(t, out)
		got := readUntilExit(t, out, id)
		if !bytes.Contains(got, []byte("ping")) {
			t.Errorf("exec output = %q, want it to contain the echoed command", got)
		}
	})

	if _, err := os.Stat(knownHosts); err != nil {
		t.Fatalf("known_hosts was never written: %v", err)
	}

	t.Run("second connection reuses the trusted key without prompting", func(t *testing.T) {
		cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
		defer stopAgent(t, cmd, stdin)

		// No prompt this time: the very first message must be "connected".
		expectConnected(t, out)
	})

	t.Run("a changed host key is refused, never silently prompted past", func(t *testing.T) {
		port := addrPort(t, addr)
		stopServer1() // free the port before the second server rebinds it
		_, hostKey2, _ := startTestSSHServerOnPort(t, port, echoCommandHandler)
		if bytes.Equal(hostKey1.PublicKey().Marshal(), hostKey2.PublicKey().Marshal()) {
			t.Fatal("the second server's host key is identical to the first; the test proves nothing")
		}

		cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
		defer stopAgent(t, cmd, stdin)

		f := mustReadFrame(t, out)
		msg := decodeControl(t, f)
		if msg.Msg != "error" || msg.Code != errHostKeyChanged {
			t.Fatalf("connecting with a changed host key = %+v, want an error with code %q", msg, errHostKeyChanged)
		}
	})
}

func startAgent(t *testing.T, meowshellBin, knownHosts, dest string) (*exec.Cmd, *os.File, *bufio.Reader) {
	t.Helper()
	return startAgentConfigured(t, meowshellBin, knownHosts, dest, controlMessage{Msg: "configure"})
}

// startAgentConfigured is startAgent, sending configureMsg (which must set
// Msg: "configure") as the mandatory first message instead of an empty
// one -- for a test that needs to supply auth material (Keys,
// KeystoreKeyIDs, DisableAgent, ...).
func startAgentConfigured(t *testing.T, meowshellBin, knownHosts, dest string, configureMsg controlMessage) (*exec.Cmd, *os.File, *bufio.Reader) {
	t.Helper()
	cmd := exec.Command(meowshellBin, "agent", "--known-hosts="+knownHosts, dest)
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting meowshell agent: %v", err)
	}
	stdinR.Close()
	stdoutW.Close()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent stderr:\n%s", stderr.String())
		}
	})
	send(t, stdinW, 0, configureMsg)
	return cmd, stdinW, bufio.NewReader(stdoutR)
}

func stopAgent(t *testing.T, cmd *exec.Cmd, stdin *os.File) {
	t.Helper()
	stdin.Close()
	cmd.Wait()
}

func mustReadFrame(t *testing.T, r *bufio.Reader) frame {
	t.Helper()
	f, err := readFrameWithDeadline(t, r)
	if err != nil {
		t.Fatalf("reading a frame: %v", err)
	}
	return f
}

func decodeControl(t *testing.T, f frame) controlMessage {
	t.Helper()
	var msg controlMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		t.Fatalf("decoding control message: %v", err)
	}
	return msg
}

func addrPort(t *testing.T, hostPort string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// echoCommandHandler is a fake SSH server's exec handler: it writes the
// requested command line back to the channel and exits 0, just enough to
// prove a channel round trip happened without needing a real shell.
func echoCommandHandler(ch ssh.Channel, command string) {
	fmt.Fprintf(ch, "%s\n", command)
	ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
}

// startTestSSHServer starts a minimal SSH server on an OS-assigned port,
// accepting any client (NoClientAuth -- auth methods aren't this test's
// concern) and running handleExec for every "exec" request it receives.
// Returns the server's address, host key, and a stop function (also
// registered as t.Cleanup, but exposed for a test that needs the port
// freed before it ends, e.g. to rebind it for a "changed host key" case).
func startTestSSHServer(t *testing.T, handleExec func(ssh.Channel, string)) (addr string, key ssh.Signer, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	signer, stop := serveTestSSH(t, ln, handleExec)
	return "127.0.0.1:" + port, signer, stop
}

// startTestSSHServerOnPort is startTestSSHServer for a specific, already
// chosen port -- used to simulate a changed host key answering at the same
// address a prior test server used.
func startTestSSHServerOnPort(t *testing.T, port string, handleExec func(ssh.Channel, string)) (addr string, key ssh.Signer, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	signer, stop := serveTestSSH(t, ln, handleExec)
	return "127.0.0.1:" + port, signer, stop
}

func serveTestSSH(t *testing.T, ln net.Listener, handleExec func(ssh.Channel, string)) (ssh.Signer, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSSHConn(conn, config, handleExec)
		}
	}()
	stop := func() { ln.Close() }
	t.Cleanup(stop)
	return signer, stop
}

func serveTestSSHConn(conn net.Conn, config *ssh.ServerConfig, handleExec func(ssh.Channel, string)) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() == "direct-tcpip" {
			go serveTestSSHDirectTCPIP(newCh)
			continue
		}
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range requests {
				switch req.Type {
				case "exec":
					var payload struct{ Command string }
					ssh.Unmarshal(req.Payload, &payload)
					req.Reply(true, nil)
					handleExec(ch, payload.Command)
					return
				case "pty-req", "shell", "window-change":
					if req.WantReply {
						req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}()
	}
}

// serveTestSSHDirectTCPIP answers a "direct-tcpip" channel request --
// what ssh.Client.Dial sends server-side -- by dialing the requested
// address locally and piping bytes both ways, the same shape a real
// sshd's own forwarding support has. Without this, meowshell agent's own
// forward_local/forward_socks channels (which both go through
// client.Dial) have nothing on the server end to actually reach a
// backend through.
func serveTestSSHDirectTCPIP(newCh ssh.NewChannel) {
	var payload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &payload); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	target := net.JoinHostPort(payload.DestAddr, fmt.Sprint(payload.DestPort))
	remote, err := net.Dial("tcp", target)
	if err != nil {
		newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, requests, err := newCh.Accept()
	if err != nil {
		remote.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	proxyForwardedConn(ch, func() (net.Conn, error) { return remote, nil })
}
