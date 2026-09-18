package main

import (
	"context"
	"time"
)

const agentPathPollInterval = time.Second

type agentPathStatus struct {
	direct      bool
	endpoint    string
	relayRegion string
	txBytes     int64
	rxBytes     int64
}

type agentPathStatusSource interface {
	PathStatus() (agentPathStatus, bool)
}

type agentPathProber interface {
	ProbePath(context.Context) (agentPathStatus, bool)
}

type agentPathState struct {
	direct bool
	via    string
}

func pathControlMessageFromStatus(status agentPathStatus) controlMessage {
	direct := status.direct
	via := ""
	if !status.direct {
		via = status.relayRegion
	}

	// txBytes/rxBytes are total WireGuard peer counters. They are
	// intentionally not copied into relayed_bytes_*: doing so would bill or
	// display direct-path traffic as relay usage whenever a connection later
	// happened to be relayed.
	return controlMessage{
		Msg:    "path",
		Direct: &direct,
		Via:    via,
	}
}

func reportTailcatPath(
	ctx context.Context,
	source agentPathStatusSource,
	interval time.Duration,
	emit func(controlMessage) error,
) {
	if interval <= 0 {
		interval = agentPathPollInterval
	}

	var last agentPathState
	haveLast := false
	emitStatus := func(status agentPathStatus) bool {
		msg := pathControlMessageFromStatus(status)
		state := agentPathState{direct: *msg.Direct, via: msg.Via}
		if haveLast && state == last {
			return true
		}
		if err := emit(msg); err != nil {
			return false
		}
		last = state
		haveLast = true
		return true
	}
	poll := func() bool {
		status, ok := source.PathStatus()
		if ok {
			if !emitStatus(status) {
				return false
			}
			if status.direct {
				return true
			}
		}

		// Tailcat's DiscoPing actively nudges the call-me-maybe endpoint
		// exchange. Probe while the path is unknown as well as while it is
		// relayed: on a freshly started client Status can lag behind the live
		// magicsock route, and returning early here used to prevent the very
		// probe needed to establish a direct endpoint.
		if prober, hasProber := source.(agentPathProber); hasProber {
			probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			probed, probeOK := prober.ProbePath(probeCtx)
			cancel()
			if probeOK {
				return emitStatus(probed)
			}
		}
		return true
	}

	if !poll() {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !poll() {
				return
			}
		}
	}
}
