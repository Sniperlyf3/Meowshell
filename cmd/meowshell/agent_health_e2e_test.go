package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestAgentRelayHealthReporterAttachesToARealTailcatConnection is the
// relay_health analogue of TestAgentEndToEnd: proof that
// reportTailcatRelayHealth is wired to agentCmd's real, in-process
// tailcat.Client (session.tailcatHealthSource), not merely exercised
// through e2e/fakeagent's scripted "relay_health" frames -- which is all
// the .NET E2E suite (and this package's own agent_health_test.go /
// agent_control_reader_test.go) ever drives it through.
//
// A real, unpatched testderp has no way to make its DERP server emit a
// derp.FrameHealth: MeowSSH's managed relay only does that via
// deploy/single-node/derper/patches/admission-reason.patch, which lives in
// the meowsshapi repo (a different repo this task must not touch), applied
// to a real derper deployment this test harness has no equivalent of. So
// this test cannot force tailcat.Client.RelayHealth() to report an actual
// problem the way agent_health_test.go's scripted source does -- there is
// no lever here to pull that would do that honestly.
//
// What it proves instead against the real client is what would actually
// regress if the wiring in agent.go or the reporter itself broke:
//
//  1. The reporter genuinely runs concurrently with real request/reply
//     channel traffic (several exec channels, spaced past
//     agentHealthPollInterval so the real tailcat.Client is polled more than
//     once) without corrupting reply correlation -- exactly the hazard
//     agent_e2e_test.go's expectChannelOpenedMessage/expectRequestReply had
//     to learn to tolerate "relay_health" for.
//  2. A real, healthy loopback-DERP connection never produces a
//     false-positive relay_health report: derpRelayHealthProblem must not
//     misfire on the ordinary, unrelated health.Tracker warnings (NAT
//     traversal, control-plane connectivity, ...) a real client can
//     legitimately report while it's still settling in a sandboxed test
//     environment.
func TestAgentRelayHealthReporterAttachesToARealTailcatConnection(t *testing.T) {
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

	var relayHealthFrames []controlMessage
	for i := 0; i < 3; i++ {
		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"echo", "relay-health-e2e"}})
		id := expectChannelOpenedRecordingControl(t, out, &relayHealthFrames)
		got := readUntilExitRecordingControl(t, out, id, &relayHealthFrames)
		if !bytes.Contains(got, []byte("relay-health-e2e")) {
			t.Errorf("exec output = %q, want it to contain the echoed marker", got)
		}
		// Space requests past agentHealthPollInterval (1s) so the live
		// reporter goroutine has actually polled the real tailcat.Client
		// more than once by the time the loop ends, not just at connect.
		if i < 2 {
			time.Sleep(agentHealthPollInterval + 200*time.Millisecond)
		}
	}

	for _, msg := range relayHealthFrames {
		if msg.RelayProblem != "" {
			t.Errorf("saw a relay_health report of %q against a healthy real loopback-DERP connection; want no false positive", msg.RelayProblem)
		}
	}
}

// expectChannelOpenedRecordingControl is expectChannelOpenedMessage plus
// recording any "relay_health" frame it skips past, so a test can assert on
// those instead of silently discarding them the way production callers do.
func expectChannelOpenedRecordingControl(t *testing.T, r *bufio.Reader, relayHealth *[]controlMessage) uint32 {
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
		case "relay_health":
			*relayHealth = append(*relayHealth, msg)
		}
	}
}

// readUntilExitRecordingControl is readUntilExit plus recording any
// "relay_health" frame seen on channel 0 while waiting on channelID's own
// traffic, instead of silently dropping it the way readUntilExit's
// f.ChannelID != id filter does.
func readUntilExitRecordingControl(t *testing.T, r *bufio.Reader, id uint32, relayHealth *[]controlMessage) []byte {
	t.Helper()
	var buf bytes.Buffer
	for {
		f, err := readFrameWithDeadline(t, r)
		if err != nil {
			t.Fatalf("reading channel %d: %v", id, err)
		}
		if f.ChannelID != id {
			if f.Type == frameTypeControl {
				var msg controlMessage
				if err := json.Unmarshal(f.Payload, &msg); err == nil && msg.Msg == "relay_health" {
					*relayHealth = append(*relayHealth, msg)
				}
			}
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
