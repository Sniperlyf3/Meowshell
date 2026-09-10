package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestAgentEndToEnd drives "meowshell agent" as a real subprocess against a
// real tailcat server (hermetic: TS_DEBUG_TAILCAT_LOCAL_DERP replaces the
// public DERP/STUN infrastructure with an in-process one, so this needs no
// network access), speaking the framed control protocol exactly as
// dotnet/Meowshell's MeowshellAgentConnection eventually will. It proves
// the multiplexing daemon model end to end: one process, one handshake,
// two channels (an exec and a resized shell) opened on it in turn.
//
// Needs real tailcat/meowshell binaries built for this platform; skips
// itself when they aren't found rather than failing the whole package
// (dist/ is a local/CI build product, not checked in).
func TestAgentEndToEnd(t *testing.T) {
	tailcatBin := findE2EBinary(t, "TAILCAT", "tailcat_linux_amd64")
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("TS_DEBUG_TAILCAT_LOCAL_DERP", "1")

	addr := startE2EServer(t, tailcatBin, meowshellBin, home)

	cmd := exec.Command(meowshellBin, "agent", "--tailcat="+tailcatBin, addr)
	cmd.Env = append(os.Environ(), "TAILCAT_BIN="+tailcatBin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting meowshell agent: %v", err)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
		if t.Failed() {
			t.Logf("agent stderr:\n%s", stderr.String())
		}
	})

	out := bufio.NewReader(stdout)

	t.Run("exec channel runs a command and reports exit status", func(t *testing.T) {
		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"echo", "hello-from-agent-e2e"}})
		id := expectChannelOpened(t, out)

		got := readUntilExit(t, out, id)
		if !bytes.Contains(got, []byte("hello-from-agent-e2e")) {
			t.Errorf("exec output = %q, want it to contain the echoed marker", got)
		}
	})

	t.Run("exec channel with a nonzero exit reports it as a structured value", func(t *testing.T) {
		// Quoted, not bare: Command elements are joined with plain spaces
		// (agent.go documents this, matching connect.go and a real ssh
		// client), so "exit 42" must survive as one argument to sh -c.
		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"sh", "-c", "'exit 42'"}})
		id := expectChannelOpened(t, out)

		exitCode := readExitOnly(t, out, id)
		if exitCode != 42 {
			t.Errorf("exit code = %d, want 42", exitCode)
		}
	})

	t.Run("shell channel accepts input, resizes, and exits on stdin close", func(t *testing.T) {
		pty := true
		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "shell", Pty: &pty, Cols: 80, Rows: 24})
		id := expectChannelOpened(t, out)

		send(t, stdin, id, controlMessage{Msg: "resize", Cols: 120, Rows: 40})

		mustWriteFrame(t, stdin, frame{Type: frameTypeData, ChannelID: id, Payload: []byte("echo shell-marker-e2e\n")})

		got := readUntil(t, out, id, "shell-marker-e2e", 20*time.Second)
		if !bytes.Contains(got, []byte("shell-marker-e2e")) {
			t.Errorf("shell output = %q, want it to contain the echoed marker", got)
		}

		mustWriteFrame(t, stdin, frame{Type: frameTypeData, ChannelID: id, Payload: []byte("exit\n")})
		readUntilExit(t, out, id)
	})
}

// findE2EBinary locates a real binary for the e2e test to drive: an
// explicit env var override, falling back to dist/<name> relative to the
// repo root (build.sh's own output layout).
func findE2EBinary(t *testing.T, envVar, distName string) string {
	t.Helper()
	if p := os.Getenv(envVar); p != "" {
		return p
	}
	p := filepath.Join("..", "..", "dist", distName)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("no %s (looked for $%s and %s); build.sh must run first", distName, envVar, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// startE2EServer starts an unauthenticated meowshell server over a
// hermetic local DERP relay and returns the address it publishes, the same
// setup e2e/host-e2e.sh uses against real binaries.
func startE2EServer(t *testing.T, tailcatBin, meowshellBin, home string) string {
	t.Helper()
	addrFile := filepath.Join(home, "addr")
	cmd := exec.Command(meowshellBin, "serve", "--insecure-no-auth", "--tailcat="+tailcatBin)
	cmd.Env = append(os.Environ(),
		"TAILCAT_BIN="+tailcatBin,
		"TAILCAT_ADDR_FILE="+addrFile,
		"HOME="+home,
		"TS_DEBUG_TAILCAT_LOCAL_DERP=1",
	)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting meowshell serve: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("server log:\n%s", out.String())
		}
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(addrFile); err == nil && len(data) > 0 {
			return string(bytes.TrimSpace(data))
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server never published an address; log:\n%s", out.String())
	return ""
}

func send(t *testing.T, w io.Writer, channelID uint32, msg controlMessage) {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFrame(t, w, frame{Type: frameTypeControl, ChannelID: channelID, Payload: body})
}

func mustWriteFrame(t *testing.T, w io.Writer, f frame) {
	t.Helper()
	if err := writeFrame(w, f); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
}

// expectChannelOpened reads frames until channel_opened, failing the test
// on an error frame or a control message it didn't expect.
func expectChannelOpened(t *testing.T, r *bufio.Reader) uint32 {
	t.Helper()
	for {
		f, err := readFrameWithDeadline(t, r)
		if err != nil {
			t.Fatalf("reading channel_opened: %v", err)
		}
		if f.Type != frameTypeControl {
			continue
		}
		var msg controlMessage
		if err := json.Unmarshal(f.Payload, &msg); err != nil {
			t.Fatalf("decoding control message: %v", err)
		}
		switch msg.Msg {
		case "channel_opened":
			return f.ChannelID
		case "error":
			t.Fatalf("agent returned an error opening the channel: %s: %s", msg.Code, msg.Message)
		}
	}
}

// readUntilExit collects data frames for id until its exit_status arrives,
// returning the concatenated stdout+stderr bytes seen along the way.
func readUntilExit(t *testing.T, r *bufio.Reader, id uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	for {
		f, err := readFrameWithDeadline(t, r)
		if err != nil {
			t.Fatalf("reading channel %d: %v", id, err)
		}
		if f.ChannelID != id {
			continue
		}
		switch f.Type {
		case frameTypeData:
			buf.Write(f.Payload[1:]) // drop the stream tag
		case frameTypeControl:
			var msg controlMessage
			if err := json.Unmarshal(f.Payload, &msg); err != nil {
				t.Fatalf("decoding control message: %v", err)
			}
			switch msg.Msg {
			case "exit_status":
				return buf.Bytes()
			case "error":
				t.Fatalf("channel %d errored: %s: %s", id, msg.Code, msg.Message)
			}
		}
	}
}

// readExitOnly is readUntilExit's counterpart when only the exit code
// matters to the caller.
func readExitOnly(t *testing.T, r *bufio.Reader, id uint32) int {
	t.Helper()
	for {
		f, err := readFrameWithDeadline(t, r)
		if err != nil {
			t.Fatalf("reading channel %d: %v", id, err)
		}
		if f.ChannelID != id || f.Type != frameTypeControl {
			continue
		}
		var msg controlMessage
		if err := json.Unmarshal(f.Payload, &msg); err != nil {
			t.Fatalf("decoding control message: %v", err)
		}
		if msg.Msg == "exit_status" {
			return msg.ExitCode
		}
		if msg.Msg == "error" {
			t.Fatalf("channel %d errored: %s: %s", id, msg.Code, msg.Message)
		}
	}
}

// readUntil collects data frames for id until want appears in them or
// timeout elapses.
func readUntil(t *testing.T, r *bufio.Reader, id uint32, want string, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var buf bytes.Buffer
	for time.Now().Before(deadline) {
		f, err := readFrameWithDeadline(t, r)
		if err != nil {
			t.Fatalf("reading channel %d: %v", id, err)
		}
		if f.ChannelID != id || f.Type != frameTypeData {
			continue
		}
		buf.Write(f.Payload[1:])
		if bytes.Contains(buf.Bytes(), []byte(want)) {
			return buf.Bytes()
		}
	}
	t.Fatalf("timed out waiting for %q on channel %d; got %q", want, id, buf.Bytes())
	return nil
}

// readFrameWithDeadline wraps readFrame with an overall per-call budget, so
// a protocol bug hangs the one subtest that hit it instead of the whole
// test binary.
func readFrameWithDeadline(t *testing.T, r *bufio.Reader) (frame, error) {
	t.Helper()
	type result struct {
		f   frame
		err error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := readFrame(r)
		ch <- result{f, err}
	}()
	select {
	case res := <-ch:
		return res.f, res.err
	case <-time.After(30 * time.Second):
		return frame{}, fmt.Errorf("timed out reading a frame")
	}
}
