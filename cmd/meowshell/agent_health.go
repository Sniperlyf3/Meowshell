package main

import (
	"context"
	"time"
)

const agentHealthPollInterval = time.Second

// agentHealthStatusSource is the live tailcat.Client's RelayHealth, factored
// out the same way agentPathStatusSource factors out PathStatus: so this
// reporter can be tested against a scripted fake instead of a real engine.
type agentHealthStatusSource interface {
	RelayHealth() (problem string, ok bool)
}

func healthControlMessageFromStatus(problem string) controlMessage {
	return controlMessage{Msg: "relay_health", RelayProblem: problem}
}

// reportTailcatRelayHealth polls source.RelayHealth and emits a "relay_health"
// control message on every observed change, mirroring reportTailcatPath's
// shape and its two whys: emit only when something has actually changed
// rather than that on every poll, and skip emitting anything at all before
// the client has started (an !ok read) rather than inventing a healthy
// default while we simply don't know yet.
func reportTailcatRelayHealth(
	ctx context.Context,
	source agentHealthStatusSource,
	interval time.Duration,
	emit func(controlMessage) error,
) {
	if interval <= 0 {
		interval = agentHealthPollInterval
	}

	var last string
	haveLast := false
	poll := func() bool {
		problem, ok := source.RelayHealth()
		if !ok {
			return true
		}
		if haveLast && problem == last {
			return true
		}
		if err := emit(healthControlMessageFromStatus(problem)); err != nil {
			return false
		}
		last = problem
		haveLast = true
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
