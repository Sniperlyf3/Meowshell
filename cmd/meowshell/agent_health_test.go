package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
)

// TestTailcatHealthSourceMirrorsTailcatPathSourceForALiveTailcatClient locks
// down the wiring agentCmd depends on but can't otherwise be unit-tested
// through (agentCmd itself is a CLI entrypoint reading os.Stdin, not
// something a test can call directly): tailcatHealthSource must return nil
// before a.tcClient exists (a TCP destination, or before connect() has run),
// and once set it must wrap the exact same *tailcat.Client connect() stored
// -- not a copy, and not always-nil -- the same contract tailcatPathSource
// already has for reportTailcatPath. A real agent E2E test can't catch a
// regression here on its own: TestAgentRelayHealthReporterAttachesToARealTailcatConnection
// proves the reporter is being polled against the real client (a mutation
// that made tailcat.Client.RelayHealth panic crashed that test), but proves
// nothing about the *source* were tailcatHealthSource itself to start
// returning nil unconditionally, since a real, healthy connection would look
// identical either way (no relay_health frame in both cases).
func TestTailcatHealthSourceMirrorsTailcatPathSourceForALiveTailcatClient(t *testing.T) {
	a := newAgentSession(nil, nil)
	if src := a.tailcatHealthSource(); src != nil {
		t.Fatalf("health source before a.tcClient is set = %#v, want nil", src)
	}

	tc := &tailcat.Client{Server: "tc-does-not-need-to-be-dialable-for-this-check"}
	a.tcMu.Lock()
	a.tcClient = tc
	a.tcMu.Unlock()

	src := a.tailcatHealthSource()
	if src == nil {
		t.Fatal("health source after a.tcClient is set = nil, want a source wrapping the live client")
	}
	if src.cl != tc {
		t.Fatal("health source wraps a different *tailcat.Client than session.tcClient -- relay health would be polled against the wrong connection")
	}
}

func TestHealthControlMessageFromStatusRoundTripsProblemText(t *testing.T) {
	msg := healthControlMessageFromStatus("MeowSSH managed relay: monthly usage allowance exceeded")
	if msg.Msg != "relay_health" {
		t.Fatalf("msg = %q, want relay_health", msg.Msg)
	}
	if msg.RelayProblem != "MeowSSH managed relay: monthly usage allowance exceeded" {
		t.Fatalf("relay problem = %q, want the exact managed-relay text", msg.RelayProblem)
	}
}

func TestHealthControlMessageFromStatusClearsWithEmptyProblem(t *testing.T) {
	msg := healthControlMessageFromStatus("")
	if msg.RelayProblem != "" {
		t.Fatalf("relay problem = %q, want empty for a healthy report", msg.RelayProblem)
	}
}

type scriptedHealthSource struct {
	mu     sync.Mutex
	states []scriptedHealthState
	next   int
}

type scriptedHealthState struct {
	problem string
	ok      bool
}

func (s *scriptedHealthSource) RelayHealth() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.states) {
		last := s.states[len(s.states)-1]
		return last.problem, last.ok
	}
	state := s.states[s.next]
	s.next++
	return state.problem, state.ok
}

func TestReportTailcatRelayHealthIgnoresUnknownAndEmitsOnlyChanges(t *testing.T) {
	source := &scriptedHealthSource{states: []scriptedHealthState{
		{}, // not started yet: skipped entirely, not reported as healthy
		{problem: "", ok: true},
		{problem: "", ok: true}, // unchanged: must not re-emit
		{problem: "MeowSSH managed relay: monthly usage allowance exceeded", ok: true},
		{problem: "MeowSSH managed relay: monthly usage allowance exceeded", ok: true}, // unchanged
		{problem: "", ok: true},                                                        // recovered
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var got []controlMessage

	reportTailcatRelayHealth(ctx, source, time.Millisecond, func(msg controlMessage) error {
		got = append(got, msg)
		if len(got) == 3 {
			cancel()
		}
		return nil
	})

	if len(got) != 3 {
		t.Fatalf("emitted %d messages, want 3 (healthy, problem, recovered); got %+v", len(got), got)
	}
	if got[0].RelayProblem != "" {
		t.Fatalf("first report = %q, want the initial healthy report (empty)", got[0].RelayProblem)
	}
	if got[1].RelayProblem != "MeowSSH managed relay: monthly usage allowance exceeded" {
		t.Fatalf("second report = %q, want the managed-relay quota text", got[1].RelayProblem)
	}
	if got[2].RelayProblem != "" {
		t.Fatalf("third report = %q, want empty once the relay recovers", got[2].RelayProblem)
	}
}
