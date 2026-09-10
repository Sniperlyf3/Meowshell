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
	send(t, stdin, 0, controlMessage{Msg: "configure"})
	expectConnected(t, out)

	t.Run("exec channel runs a command and reports exit status", func(t *testing.T) {
		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"echo", "hello-from-agent-e2e"}})
		id := expectChannelOpened(t, out)

		got := readUntilExit(t, out, id)
		if !bytes.Contains(got, []byte("hello-from-agent-e2e")) {
			t.Errorf("exec output = %q, want it to contain the echoed marker", got)
		}
	})

	t.Run("exec channel with a nonzero exit reports it as a structured value", func(t *testing.T) {
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

func expectConnected(t *testing.T, r *bufio.Reader) {
	t.Helper()
	f, err := readFrameWithDeadline(t, r)
	if err != nil {
		t.Fatalf("reading the connection handshake: %v", err)
	}
	var msg controlMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		t.Fatalf("decoding the connection handshake: %v", err)
	}
	switch msg.Msg {
	case "connected":
		return
	case "error":
		t.Fatalf("agent failed to connect: %s: %s", msg.Code, msg.Message)
	default:
		t.Fatalf("unexpected first message %q, want \"connected\"", msg.Msg)
	}
}

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
			buf.Write(f.Payload[1:])
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
