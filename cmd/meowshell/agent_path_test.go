package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestPathControlMessageFromStatusDoesNotMislabelPeerBytesAsRelayUsage(t *testing.T) {
	msg := pathControlMessageFromStatus(agentPathStatus{
		direct:      false,
		relayRegion: "ams",
		txBytes:     12345,
		rxBytes:     67890,
	})

	if msg.Msg != "path" {
		t.Fatalf("msg = %q, want path", msg.Msg)
	}
	if msg.Direct == nil || *msg.Direct {
		t.Fatalf("direct = %#v, want explicit false", msg.Direct)
	}
	if msg.Via != "ams" {
		t.Fatalf("via = %q, want ams", msg.Via)
	}
	if msg.RelayedBytesSent != 0 || msg.RelayedBytesRecv != 0 {
		t.Fatalf("relayed counters = (%d, %d), want zero because peer counters are total traffic",
			msg.RelayedBytesSent, msg.RelayedBytesRecv)
	}
}

func TestPathControlMessageFromStatusOmitsRelayForDirectPath(t *testing.T) {
	msg := pathControlMessageFromStatus(agentPathStatus{
		direct:      true,
		endpoint:    "203.0.113.7:41641",
		relayRegion: "ams",
	})

	if msg.Direct == nil || !*msg.Direct {
		t.Fatalf("direct = %#v, want explicit true", msg.Direct)
	}
	if msg.Via != "" {
		t.Fatalf("via = %q, want empty for a direct path", msg.Via)
	}
}

type scriptedPathSource struct {
	mu     sync.Mutex
	states []scriptedPathState
	next   int
}

type scriptedPathState struct {
	status agentPathStatus
	ok     bool
}

func (s *scriptedPathSource) PathStatus() (agentPathStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.states) {
		return s.states[len(s.states)-1].status, s.states[len(s.states)-1].ok
	}
	state := s.states[s.next]
	s.next++
	return state.status, state.ok
}

func TestReportTailcatPathIgnoresUnknownAndEmitsOnlyPathChanges(t *testing.T) {
	source := &scriptedPathSource{states: []scriptedPathState{
		{},
		{status: agentPathStatus{direct: false, relayRegion: "ams", txBytes: 10}, ok: true},
		{status: agentPathStatus{direct: false, relayRegion: "ams", txBytes: 20}, ok: true},
		{status: agentPathStatus{direct: true, endpoint: "203.0.113.7:41641", txBytes: 30}, ok: true},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var got []controlMessage

	reportTailcatPath(ctx, source, time.Millisecond, func(msg controlMessage) error {
		got = append(got, msg)
		if len(got) == 2 {
			cancel()
		}
		return nil
	})

	if len(got) != 2 {
		t.Fatalf("emitted %d messages, want 2", len(got))
	}
	if got[0].Direct == nil || *got[0].Direct || got[0].Via != "ams" {
		t.Fatalf("first path = direct %#v via %q, want relayed via ams", got[0].Direct, got[0].Via)
	}
	if got[1].Direct == nil || !*got[1].Direct || got[1].Via != "" {
		t.Fatalf("second path = direct %#v via %q, want direct with no relay", got[1].Direct, got[1].Via)
	}
}

type probingPathSource struct {
	mu     sync.Mutex
	direct bool
	probes int
}

func (s *probingPathSource) PathStatus() (agentPathStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return agentPathStatus{
		direct:      s.direct,
		relayRegion: "ci",
	}, true
}

func (s *probingPathSource) ProbePath(context.Context) (agentPathStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probes++
	s.direct = true
	return agentPathStatus{direct: true, endpoint: "203.0.113.7:41641"}, true
}

func TestReportTailcatPathProbesRelayedConnectionAndEmitsDirectUpgrade(t *testing.T) {
	source := &probingPathSource{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var got []controlMessage
	reportTailcatPath(ctx, source, time.Millisecond, func(msg controlMessage) error {
		got = append(got, msg)
		if len(got) == 2 {
			cancel()
		}
		return nil
	})

	if len(got) != 2 {
		t.Fatalf("got %d path updates, want 2", len(got))
	}
	if got[0].Direct == nil || *got[0].Direct || got[0].Via != "ci" {
		t.Fatalf("first update = %#v, want relayed via ci", got[0])
	}
	if got[1].Direct == nil || !*got[1].Direct || got[1].Via != "" {
		t.Fatalf("second update = %#v, want direct", got[1])
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.probes == 0 {
		t.Fatal("relayed path was never actively probed")
	}
}

type initiallyUnknownProbingPathSource struct {
	mu     sync.Mutex
	probes int
}

func (s *initiallyUnknownProbingPathSource) PathStatus() (agentPathStatus, bool) {
	return agentPathStatus{}, false
}

func (s *initiallyUnknownProbingPathSource) ProbePath(context.Context) (agentPathStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probes++
	return agentPathStatus{direct: true, endpoint: "127.0.0.1:41641"}, true
}

func TestReportTailcatPathProbesUnknownConnectionAndUsesLivePingResult(t *testing.T) {
	source := &initiallyUnknownProbingPathSource{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var got []controlMessage
	reportTailcatPath(ctx, source, time.Millisecond, func(msg controlMessage) error {
		got = append(got, msg)
		cancel()
		return nil
	})

	if len(got) != 1 {
		t.Fatalf("got %d path updates, want 1", len(got))
	}
	if got[0].Direct == nil || !*got[0].Direct || got[0].Via != "" {
		t.Fatalf("path update = %#v, want direct probe result", got[0])
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.probes == 0 {
		t.Fatal("unknown path was never actively probed")
	}
}
