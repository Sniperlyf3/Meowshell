package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
)

func TestPathControlMessageFromTailcatDoesNotMislabelPeerBytesAsRelayUsage(t *testing.T) {
	msg := pathControlMessageFromTailcat(tailcat.PathStatus{
		Direct:      false,
		RelayRegion: "ams",
		TxBytes:     12345,
		RxBytes:     67890,
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
		t.Fatalf("relayed counters = (%d, %d), want zero because PathStatus counters are total peer traffic",
			msg.RelayedBytesSent, msg.RelayedBytesRecv)
	}
}

func TestPathControlMessageFromTailcatOmitsRelayForDirectPath(t *testing.T) {
	msg := pathControlMessageFromTailcat(tailcat.PathStatus{
		Direct:      true,
		Endpoint:    "203.0.113.7:41641",
		RelayRegion: "ams",
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
	status tailcat.PathStatus
	ok     bool
}

func (s *scriptedPathSource) PathStatus() (tailcat.PathStatus, bool) {
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
		{status: tailcat.PathStatus{Direct: false, RelayRegion: "ams", TxBytes: 10}, ok: true},
		{status: tailcat.PathStatus{Direct: false, RelayRegion: "ams", TxBytes: 20}, ok: true},
		{status: tailcat.PathStatus{Direct: true, Endpoint: "203.0.113.7:41641", TxBytes: 30}, ok: true},
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
