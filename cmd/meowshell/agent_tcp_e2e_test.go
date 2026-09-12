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

		expectConnected(t, out)
	})

	t.Run("a changed host key is refused, never silently prompted past", func(t *testing.T) {
		port := addrPort(t, addr)
		stopServer1()
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

// TestOpenShellChannelReportsOpenFailureNotChannelOpenedThenError is a
// regression test: openShellChannel used to send channel_opened before
// calling session.Start/session.Shell, so a failure there produced a
// misleading channel_opened immediately followed by an error -- instead of
// a single, correctly-correlated open failure the caller never has to
// unwind a "successfully opened" channel for. A server that rejects the
// exec request lets the test trigger that failure deterministically.
func TestOpenShellChannelReportsOpenFailureNotChannelOpenedThenError(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")
	addr, stop := startTestSSHServerRejectingSessionStart(t)
	defer stop()
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer stopAgent(t, cmd, stdin)

	f := mustReadFrame(t, out)
	msg := decodeControl(t, f)
	if msg.Msg != "prompt_request" || msg.PromptKind != "host_key" {
		t.Fatalf("first message = %+v, want a host_key prompt_request", msg)
	}
	send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Accept: true})
	expectConnected(t, out)

	send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"anything"}, RequestID: "req1"})

	f = mustReadFrame(t, out)
	msg = decodeControl(t, f)
	if msg.Msg != "error" {
		t.Fatalf("open_channel against a server that rejects the exec request = %+v, want a single \"error\" (not a channel_opened)", msg)
	}
	if msg.RequestID != "req1" {
		t.Errorf("error RequestID = %q, want %q -- the open failure must correlate to the open_channel request, not arrive as a channel_opened followed by a separate error", msg.RequestID, "req1")
	}
}

// startTestSSHServerRejectingSessionStart accepts session channels but
// always rejects the "exec"/"shell" request that session.Start/session.Shell
// send to actually start the remote command -- deterministically forcing
// openShellChannel's post-open failure path without needing a flaky timing
// trick.
func startTestSSHServerRejectingSessionStart(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
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
							case "exec", "shell":
								if req.WantReply {
									req.Reply(false, nil)
								}
								return
							default:
								if req.WantReply {
									req.Reply(true, nil)
								}
							}
						}
					}()
				}
			}()
		}
	}()
	stop = func() { ln.Close() }
	t.Cleanup(stop)

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "127.0.0.1:" + port, stop
}

// TestOpenChannelDoesNotBlockOtherChannels is a regression test for N2:
// openChannel used to run inline in handleControl, called directly from
// serveFrames' sole frame-reading loop -- so a blocking SSH operation deep
// inside it (session.NewSession/RequestPty/Start/Shell, sftp.Stat/Open,
// client.Listen) stalled that one goroutine forever, and with it every other
// multiplexed channel: nothing else could be read off the wire at all, not
// another open_channel, not a resize, not a close_channel for a channel that
// opened fine moments earlier. The test server here accepts every SSH
// session channel-open normally, but for one specific exec command
// deliberately never replies to the "exec" request that session.Start sends
// -- identified by the command payload itself, since the server has no other
// way to correlate an SSH-level channel-open with this protocol's own
// RequestID. That command's channel is left permanently pending; a second,
// ordinary exec channel opened right after it must still succeed promptly
// rather than wait on the first.
func TestOpenChannelDoesNotBlockOtherChannels(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")
	const stuckCommand = "stuck"
	addr, stop := startTestSSHServerHangingOnExecCommand(t, stuckCommand)
	defer stop()
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	cmd, stdin, out := startAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer stopAgent(t, cmd, stdin)

	f := mustReadFrame(t, out)
	msg := decodeControl(t, f)
	if msg.Msg != "prompt_request" || msg.PromptKind != "host_key" {
		t.Fatalf("first message = %+v, want a host_key prompt_request", msg)
	}
	send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Accept: true})
	expectConnected(t, out)

	// session.Start(stuckCommand) blocks forever waiting for a reply to the
	// "exec" request it sends -- the test server never answers it. With the
	// bug, that alone would already be enough to freeze everything below.
	send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{stuckCommand}, RequestID: "hang"})

	send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"still works"}, RequestID: "req2"})
	id := expectChannelOpened(t, out)
	got := readUntilExit(t, out, id)
	if !bytes.Contains(got, []byte("still works")) {
		t.Errorf("second channel's output = %q, want it to contain the echoed command", got)
	}
}

// startTestSSHServerHangingOnExecCommand accepts every SSH session
// channel-open normally, but for an exec request whose command equals
// stuckCommand, deliberately never replies to it (leaving the client's
// session.Start blocked on that reply forever) -- simulating a slow or
// malicious SSH server that never finishes answering one specific request.
// Any other exec command is answered and completed normally. Correlating by
// the command payload (rather than which channel-open the server happens to
// see first) is deliberate: once multiple opens are genuinely concurrent
// (the very property this is testing), there is no guarantee about which of
// several SSH-level channel-opens reaches the server first.
func startTestSSHServerHangingOnExecCommand(t *testing.T, stuckCommand string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
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
								if payload.Command == stuckCommand {
									// Never Reply, and never return either:
									// returning would run the deferred
									// ch.Close() above, closing the SSH
									// channel out from under session.Start's
									// wait and unblocking it with an error
									// instead of actually hanging it -- the
									// opposite of what this is simulating.
									// Parking here keeps the channel open
									// with no reply ever sent, the same as a
									// server that never gets around to
									// answering it.
									select {}
								}
								req.Reply(true, nil)
								echoCommandHandler(ch, payload.Command)
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
			}()
		}
	}()
	stop = func() { ln.Close() }
	t.Cleanup(stop)

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "127.0.0.1:" + port, stop
}

func startAgent(t *testing.T, meowshellBin, knownHosts, dest string) (*exec.Cmd, *os.File, *bufio.Reader) {
	t.Helper()
	return startAgentConfigured(t, meowshellBin, knownHosts, dest, controlMessage{Msg: "configure"})
}

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

func echoCommandHandler(ch ssh.Channel, command string) {
	fmt.Fprintf(ch, "%s\n", command)
	ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
}

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
