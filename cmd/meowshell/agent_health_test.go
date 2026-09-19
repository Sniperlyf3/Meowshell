package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

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
