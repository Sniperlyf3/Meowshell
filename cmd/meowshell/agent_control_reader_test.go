package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

// TestExpectChannelOpenedSkipsAnInterleavedRelayHealthMessage is a regression
// test for the exact failure mode this project's own history warns about:
// PR #52's E2E suite broke because a "path" reporter goroutine could write an
// unsolicited control message on the shared control stream between an
// open_channel request and its channel_opened reply, and a test helper that
// assumed "the next control frame is the reply I asked for" got the
// unsolicited one instead.
//
// reportTailcatRelayHealth follows the exact same "write an async control
// message on the shared stream" shape as reportTailcatPath, so adding it
// reintroduces that same hazard for any reader with that assumption unless
// every such reader also tolerates a "relay_health" frame turning up first.
// expectChannelOpened (used throughout this package's own E2E suite) already
// tolerates this by construction -- it loops until it sees "channel_opened"
// or "error", silently skipping anything else -- but that tolerance was
// written for "path", never exercised against "relay_health", and would
// silently stop being true the moment someone rewrites the loop into a
// single read. This test pins it directly, without needing the real
// tailcat/meowshell binaries agent_e2e_test.go's own tests require.
func TestExpectChannelOpenedSkipsAnInterleavedRelayHealthMessage(t *testing.T) {
	var buf bytes.Buffer
	mustEncode := func(channelID uint32, msg controlMessage) {
		body, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFrame(&buf, frame{Type: frameTypeControl, ChannelID: channelID, Payload: body}); err != nil {
			t.Fatal(err)
		}
	}

	// A relay_health notification lands on channel 0 (as agentCmd's
	// top-level reporter would send it) squarely between the request and
	// the reply expectChannelOpened is waiting for.
	mustEncode(0, controlMessage{Msg: "relay_health", RelayProblem: "MeowSSH managed relay: monthly usage allowance exceeded"})
	mustEncode(7, controlMessage{Msg: "channel_opened", RequestID: "req-1"})

	r := bufio.NewReader(&buf)
	gotID := expectChannelOpened(t, r)
	if gotID != 7 {
		t.Fatalf("expectChannelOpened returned channel %d, want 7 -- the interleaved relay_health frame broke reply correlation", gotID)
	}
}

// TestReadExitOnlySkipsAnInterleavedRelayHealthMessage covers the other
// production-shaped reader in this file's own suite: a channel-scoped read
// loop (readExitOnly, used the same way exit_status is awaited on a real
// shell/exec channel) must also not mistake an unrelated, channel-0
// "relay_health" frame for -- or be derailed by -- traffic on the channel it
// is actually waiting on.
func TestReadExitOnlySkipsAnInterleavedRelayHealthMessage(t *testing.T) {
	var buf bytes.Buffer
	mustEncode := func(channelID uint32, msg controlMessage) {
		body, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFrame(&buf, frame{Type: frameTypeControl, ChannelID: channelID, Payload: body}); err != nil {
			t.Fatal(err)
		}
	}

	mustEncode(0, controlMessage{Msg: "relay_health", RelayProblem: "MeowSSH managed relay: monthly usage allowance exceeded"})
	const exitCode = 3
	mustEncode(7, controlMessage{Msg: "exit_status", ExitCode: exitCode})

	r := bufio.NewReader(&buf)
	got := readExitOnly(t, r, 7)
	if got != exitCode {
		t.Fatalf("readExitOnly returned exit code %d, want %d -- the interleaved relay_health frame broke reply correlation", got, exitCode)
	}
}
