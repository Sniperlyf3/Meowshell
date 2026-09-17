package main

import (
	"context"
	"time"

	"github.com/tailscale/tailcat"
)

const agentPathPollInterval = time.Second

type tailcatPathStatusSource interface {
	PathStatus() (tailcat.PathStatus, bool)
}

type agentPathState struct {
	direct bool
	via    string
}

func pathControlMessageFromTailcat(status tailcat.PathStatus) controlMessage {
	direct := status.Direct
	via := ""
	if !status.Direct {
		via = status.RelayRegion
	}

	// PathStatus.TxBytes/RxBytes are total WireGuard peer counters. They are
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
	source tailcatPathStatusSource,
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
		msg := pathControlMessageFromTailcat(status)
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
