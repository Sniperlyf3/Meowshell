package main

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"
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


type blockingWriteCloser struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingWriteCloser() *blockingWriteCloser {
	return &blockingWriteCloser{started: make(chan struct{}), release: make(chan struct{})}
}

func (w *blockingWriteCloser) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func (w *blockingWriteCloser) Close() error {
	select {
	case <-w.release:
	default:
		close(w.release)
	}
	return nil
}

// TestBlockedChannelWriteDoesNotBlockFrameReader is a regression test for a
// multiplexing-wide denial of service: handleData used to call the remote
// stdin/SFTP Write synchronously on serveFrames' sole goroutine. A remote
// command that stopped reading stdin could therefore block prompt responses,
// closes, and every unrelated channel on the same agent connection.
func TestBlockedChannelWriteDoesNotBlockFrameReader(t *testing.T) {
	var input bytes.Buffer
	if err := writeFrame(&input, frame{Type: frameTypeData, ChannelID: 1, Payload: []byte("blocked")}); err != nil {
		t.Fatal(err)
	}
	promptBody, err := json.Marshal(controlMessage{Msg: "prompt_response", RequestID: "p1", Answer: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&input, frame{Type: frameTypeControl, ChannelID: 0, Payload: promptBody}); err != nil {
		t.Fatal(err)
	}

	session := newAgentSession(&input, io.Discard)
	blocked := newBlockingWriteCloser()
	ch := &agentChannel{stdin: blocked}
	session.chans[1] = ch
	session.startChannelWriter(1, ch)

	prompt := make(chan controlMessage, 1)
	session.prompts["p1"] = prompt

	done := make(chan error, 1)
	go func() { done <- session.serveFrames() }()

	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("channel writer never reached the blocking remote Write")
	}

	select {
	case got := <-prompt:
		if got.Answer != "ok" {
			t.Fatalf("prompt response answer = %q, want %q", got.Answer, "ok")
		}
	case <-time.After(time.Second):
		t.Fatal("prompt_response was not processed while another channel's remote Write was blocked")
	}

	blocked.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveFrames returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveFrames did not finish after consuming its input")
	}
}
