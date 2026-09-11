package main

import (
	"bytes"
	"testing"
)

// TestOpenChannelRejectsUnknownKind is a regression test: openChannel used
// to fall through to opening an interactive shell for any Kind it didn't
// recognize, silently doing the most privileged thing available instead of
// refusing what it doesn't understand -- so a protocol bug, version skew, or
// a typo in Kind would open a shell rather than fail closed.
func TestOpenChannelRejectsUnknownKind(t *testing.T) {
	session := newAgentSession(nil, &bytes.Buffer{})
	session.chans = make(map[uint32]*agentChannel)

	session.openChannel(controlMessage{Msg: "open_channel", Kind: "bogus-kind", RequestID: "r1"})

	out := session.out.(*bytes.Buffer)
	msgs := readControlFrames(t, out)
	if len(msgs) != 1 {
		t.Fatalf("control messages from openChannel with an unknown kind = %+v, want exactly one", msgs)
	}
	if msgs[0].Msg != "error" || msgs[0].Code != errProtocolError {
		t.Fatalf("openChannel with an unknown kind produced %+v, want a single \"error\" with code %q", msgs[0], errProtocolError)
	}
	if msgs[0].RequestID != "r1" {
		t.Fatalf("error RequestID = %q, want it correlated to the original request %q", msgs[0].RequestID, "r1")
	}
	if len(session.chans) != 0 {
		t.Fatalf("openChannel with an unknown kind registered %d channel(s); want none opened", len(session.chans))
	}
}
