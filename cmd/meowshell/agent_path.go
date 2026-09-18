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
	ProbePath(context.Context) error
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
	poll := func() bool {
		status, ok := source.PathStatus()
		if !ok {
			return true
		}
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

		// Tailcat's DiscoPing actively nudges the call-me-maybe endpoint
		// exchange. A persistent SSH connection can otherwise remain on its
		// bootstrap DERP route for much longer than necessary when there is
		// little tunnel traffic. Probe only while relayed; failures are
		// diagnostic and never tear down the live SSH session.
		if !status.direct {
			if prober, ok := source.(agentPathProber); ok {
				probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_ = prober.ProbePath(probeCtx)
				cancel()
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
