package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	mosh "github.com/unixshells/mosh-go"
	"golang.org/x/crypto/ssh"
)

func TestMoshConnectPatternExtractsPortAndKey(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		wantPort string
		wantKey  string
	}{
		{
			name:     "real mosh-server 1.4 banner, with the SSH_CONNECTION warning ahead of it",
			output:   "Warning: SSH_CONNECTION not found; binding to any interface.\nMOSH CONNECT 60001 xcheUtOJ8jJPH6Abv1v2HQ\n\nmosh-server (mosh 1.4.0) [build mosh 1.4.0]\n[mosh-server detached, pid = 851]\n",
			wantPort: "60001",
			wantKey:  "xcheUtOJ8jJPH6Abv1v2HQ",
		},
		{
			name:     "no leading warning line",
			output:   "MOSH CONNECT 40000 AAAAAAAAAAAAAAAAAAAAAA==\n",
			wantPort: "40000",
			wantKey:  "AAAAAAAAAAAAAAAAAAAAAA==",
		},
		{
			name:     "CRLF line ending, as a real network read can deliver",
			output:   "MOSH CONNECT 12345 abcd1234\r\n",
			wantPort: "12345",
			wantKey:  "abcd1234",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			match := moshConnectPattern.FindSubmatch([]byte(c.output))
			if len(match) != 3 {
				t.Fatalf("FindSubmatch(%q) = %v, want a 3-element match", c.output, match)
			}
			if string(match[1]) != c.wantPort || string(match[2]) != c.wantKey {
				t.Errorf("FindSubmatch(%q) port/key = %q/%q, want %q/%q", c.output, match[1], match[2], c.wantPort, c.wantKey)
			}
		})
	}
}

// TestMoshConnectPatternRejectsUnanchoredOrMissingLine is a regression test
// for the anchoring itself: moshConnectPattern requires "MOSH CONNECT" to
// start a line (^ under (?m)), not merely appear as a substring. Without
// that anchor, arbitrary remote command output -- an error message that
// happens to quote or echo the string, or a message-of-the-day -- could be
// misread as a real connect line.
func TestMoshConnectPatternRejectsUnanchoredOrMissingLine(t *testing.T) {
	cases := []string{
		"bash: mosh-server: command not found\n",
		"",
		"the log says: MOSH CONNECT 1 aaaa\n",
		"MOSH CONNECT abc def\n", // port must be digits
	}
	for _, output := range cases {
		if match := moshConnectPattern.FindSubmatch([]byte(output)); match != nil {
			t.Errorf("FindSubmatch(%q) = %v, want no match", output, match)
		}
	}
}

func TestResolveMoshDestination(t *testing.T) {
	cases := []struct {
		name        string
		destination string
		sshPort     string
		want        string
		wantErr     bool
	}{
		{"bare IPv4 literal, port comes from sshPort", "127.0.0.1", "22", "127.0.0.1", false},
		{"IPv4 literal with its own port", "127.0.0.1:2222", "22", "127.0.0.1", false},
		{"user@ prefix is stripped before host parsing", "root@127.0.0.1:22", "22", "127.0.0.1", false},
		{"hostname resolving to an IPv4 address", "localhost", "22", "127.0.0.1", false},
		{"bracketed IPv6 literal is rejected: mosh-go's Dial only ever does udp4", "[::1]:22", "22", "", true},
		{"a hostname with no IPv4 address of any kind fails to resolve", "definitely-does-not-exist.invalid", "22", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveMoshDestination(c.destination, c.sshPort)
			if c.wantErr {
				if err == nil {
					t.Fatalf("resolveMoshDestination(%q, %q) = %q, <nil>, want an error", c.destination, c.sshPort, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveMoshDestination(%q, %q) = %v, want no error", c.destination, c.sshPort, err)
			}
			if got != c.want {
				t.Errorf("resolveMoshDestination(%q, %q) = %q, want %q", c.destination, c.sshPort, got, c.want)
			}
		})
	}
}

// TestMoshAgentRejectsTailcatAddress is a regression test: Mosh needs direct
// UDP reachability to the SSH bootstrap host, which a tailcat address
// (routed over DERP/WireGuard, no stable UDP endpoint a Mosh client can
// dial) cannot provide. moshAgentCmd must refuse one before it ever touches
// stdin/stdout, which this exercises directly -- no subprocess or framed
// protocol needed, since the check happens before newAgentSession is even
// created.
func TestMoshAgentRejectsTailcatAddress(t *testing.T) {
	// validTailcatAddress (transport_test.go) is a real, structurally valid
	// tailcat address: looksLikeTailcatAddress parses it with
	// tailcat.ParseAddr, so a made-up "tc..."-prefixed string won't do.
	if !looksLikeTailcatAddress(validTailcatAddress) {
		t.Fatalf("validTailcatAddress is no longer recognized as a tailcat address; the test proves nothing")
	}
	err := moshAgentCmd([]string{validTailcatAddress})
	if err == nil {
		t.Fatal("moshAgentCmd with a tailcat address = nil, want an error")
	}
	if got := err.Error(); got != "Mosh requires direct UDP reachability and cannot use a tailcat address" {
		t.Errorf("moshAgentCmd with a tailcat address = %q, want the direct-UDP-reachability message", got)
	}
}

func TestMoshAgentRequiresExactlyOneDestination(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"host1", "host2"},
	} {
		if err := moshAgentCmd(args); err == nil {
			t.Errorf("moshAgentCmd(%v) = nil, want an error for anything but exactly one destination", args)
		}
	}
}

// --- bootstrapMosh -----------------------------------------------------
//
// bootstrapMosh only needs an *ssh.Client with a working session, which an
// in-process fake SSH server (the same style agent_tcp_e2e_test.go's
// startTestSSHServer uses for the full agent) can provide directly, without
// spawning the compiled binary or touching the framed protocol at all.

func newTestSSHClientAndServer(t *testing.T, exec func(ssh.Channel, string)) *ssh.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
		conn, err := ln.Accept()
		if err != nil {
			return
		}
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
					if req.Type != "exec" {
						if req.WantReply {
							req.Reply(false, nil)
						}
						continue
					}
					var payload struct{ Command string }
					ssh.Unmarshal(req.Payload, &payload)
					req.Reply(true, nil)
					exec(ch, payload.Command)
					return
				}
			}()
		}
	}()

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dialing the fake SSH bootstrap server: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func agentWithSSHClient(client *ssh.Client) *agentSession {
	a := newAgentSession(nil, io.Discard)
	a.scPtr.Store(client)
	return a
}

func TestBootstrapMoshParsesTheConnectLine(t *testing.T) {
	client := newTestSSHClientAndServer(t, func(ch ssh.Channel, command string) {
		if command != "mosh-server new -s -c 256 -l LANG=C.UTF-8" {
			t.Errorf("bootstrapMosh ran %q, want the exact mosh-server invocation", command)
		}
		fmt.Fprint(ch, "Warning: SSH_CONNECTION not found; binding to any interface.\nMOSH CONNECT 60123 dGVzdGtleQ==\n\n[mosh-server detached, pid = 1]\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
	})

	port, key, err := bootstrapMosh(agentWithSSHClient(client))
	if err != nil {
		t.Fatalf("bootstrapMosh = %v, want success", err)
	}
	if port != 60123 {
		t.Errorf("bootstrapMosh port = %d, want 60123", port)
	}
	if key != "dGVzdGtleQ==" {
		t.Errorf("bootstrapMosh key = %q, want %q", key, "dGVzdGtleQ==")
	}
}

// TestBootstrapMoshFailsWithoutAConnectLine is a regression test: a remote
// exec that exits 0 but never prints "MOSH CONNECT ..." (mosh-server not
// installed and PATH silently falling through to something else, or a
// shell alias eating the output) must not be read as success with a zero
// port and an empty key -- that would make the agent proceed to
// mosh.Dial(host, 0, "") instead of failing where the real problem is.
func TestBootstrapMoshFailsWithoutAConnectLine(t *testing.T) {
	client := newTestSSHClientAndServer(t, func(ch ssh.Channel, _ string) {
		fmt.Fprint(ch, "mosh-server: command not found\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
	})

	_, _, err := bootstrapMosh(agentWithSSHClient(client))
	if err == nil {
		t.Fatal("bootstrapMosh with no MOSH CONNECT line in the output = nil, want an error")
	}
}

func TestBootstrapMoshSurfacesANonZeroExit(t *testing.T) {
	client := newTestSSHClientAndServer(t, func(ch ssh.Channel, _ string) {
		fmt.Fprint(ch, "mosh-server: command not found\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{127}))
	})

	_, _, err := bootstrapMosh(agentWithSSHClient(client))
	if err == nil {
		t.Fatal("bootstrapMosh against a failing remote command = nil, want an error")
	}
}

// TestBootstrapMoshRejectsOutOfRangePort is a regression test: the port
// bootstrapMosh hands back is parsed straight out of the remote's own text
// output and fed to strconv.Atoi with no range checking beyond what
// bootstrapMosh itself does -- a malicious or simply broken remote
// mosh-server could print a "port" outside 1-65535, and that must fail
// loudly rather than get truncated or wrapped into some other UDP port by
// the eventual net.Dial.
func TestBootstrapMoshRejectsOutOfRangePort(t *testing.T) {
	client := newTestSSHClientAndServer(t, func(ch ssh.Channel, _ string) {
		fmt.Fprint(ch, "MOSH CONNECT 99999999 dGVzdGtleQ==\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
	})

	_, _, err := bootstrapMosh(agentWithSSHClient(client))
	if err == nil {
		t.Fatal("bootstrapMosh with a MOSH CONNECT port outside 1-65535 = nil, want an error")
	}
}

func TestBootstrapMoshFailsWithoutAnSSHClient(t *testing.T) {
	_, _, err := bootstrapMosh(newAgentSession(nil, io.Discard))
	if err == nil {
		t.Fatal("bootstrapMosh with no SSH bootstrap connection = nil, want an error")
	}
}

// --- moshAgentRuntime ----------------------------------------------------

// TestMoshAgentRuntimeCloseIsIdempotentUnderConcurrency is a regression test
// for the sync.Once in moshAgentRuntime.close: it exists specifically
// because close is called from more than one place that can race in
// production (serveMoshFrames on close_channel, moshAgentCmd on every one
// of its error returns, and the frameErr/runtime.done select in
// moshAgentCmd's main line). A close that ran its body twice would double-
// close runtime.done, which panics, and could double-Close the same *mosh.
// Client. mosh.Dial to a loopback address needs no listener -- UDP dial
// never blocks on one being there -- so this needs no real mosh-server.
func TestMoshAgentRuntimeCloseIsIdempotentUnderConcurrency(t *testing.T) {
	client, err := mosh.Dial("127.0.0.1", 1, "AAAAAAAAAAAAAAAAAAAAAA==")
	if err != nil {
		t.Fatalf("mosh.Dial = %v", err)
	}
	runtime := newMoshAgentRuntime()
	runtime.setClient(client)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.close()
		}()
	}
	wg.Wait()

	select {
	case <-runtime.done:
	default:
		t.Error("runtime.done was not closed")
	}
}

// TestServeMoshFramesHandlesCloseChannelBeforeClientIsSet is a regression
// test: close_channel used to be handled in the same switch as "resize",
// gated behind "the Mosh client already exists" (see the comment on that
// check in mosh_agent.go). A close_channel frame arriving before setClient
// ever runs -- exactly the window a cancellation sent during the SSH
// bootstrap or the mosh-server dial lands in -- was silently dropped
// instead of ending the session, leaving serveMoshFrames blocked on the
// next readFrame.
func TestServeMoshFramesHandlesCloseChannelBeforeClientIsSet(t *testing.T) {
	inR, inW := io.Pipe()
	t.Cleanup(func() { inW.Close() })
	agent := newAgentSession(inR, io.Discard)
	runtime := newMoshAgentRuntime()
	// runtime.client is deliberately left nil throughout this test.

	done := make(chan error, 1)
	go func() { done <- serveMoshFrames(agent, runtime) }()

	body, err := json.Marshal(controlMessage{Msg: "close_channel"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(inW, frame{Type: frameTypeControl, ChannelID: 1, Payload: body}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveMoshFrames on close_channel with no Mosh client yet = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveMoshFrames did not return after close_channel arrived before the Mosh client was set")
	}

	select {
	case <-runtime.done:
	default:
		t.Error("runtime.done was not closed by close_channel")
	}
}

// TestServeMoshFramesDropsDataAndResizeWithNoClientYet is a companion to the
// close_channel regression above, pinning down that data and resize frames
// (unlike close_channel) are meant to be silently ignored -- not queued,
// not erroring the connection -- when they arrive before the Mosh client
// exists, since there is nothing yet to send them to.
func TestServeMoshFramesDropsDataAndResizeWithNoClientYet(t *testing.T) {
	inR, inW := io.Pipe()
	agent := newAgentSession(inR, io.Discard)
	runtime := newMoshAgentRuntime()

	done := make(chan error, 1)
	go func() { done <- serveMoshFrames(agent, runtime) }()

	if err := writeFrame(inW, frame{Type: frameTypeData, ChannelID: 1, Payload: []byte("keystrokes")}); err != nil {
		t.Fatal(err)
	}
	resizeBody, err := json.Marshal(controlMessage{Msg: "resize", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(inW, frame{Type: frameTypeControl, ChannelID: 1, Payload: resizeBody}); err != nil {
		t.Fatal(err)
	}

	// Now prove the loop is still alive and reading (neither frame crashed
	// or ended it) by closing the pipe and expecting a clean, non-error
	// return from the read failing, not from something above panicking.
	inW.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
			t.Fatalf("serveMoshFrames after data/resize with no client, then EOF = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveMoshFrames never returned after the pipe closed")
	}
}
