// Command fakeagent stands in for "meowshell agent" in tests that need to
// control the timing of an open_channel response -- something no real
// destination lets a test dictate deterministically. It speaks just enough
// of the framed control protocol (see cmd/meowshell/protocol.go, which this
// intentionally does not import: it's a small, throwaway wire-compatible
// reimplementation, not a client of that package) to:
//
//  1. Reply "connected" to "configure" immediately, so a real
//     MeowshellAgentConnection.ConnectAsync completes normally.
//  2. On "open_channel", sleep for openDelay before replying
//     "channel_opened" (echoing the request's RequestID) -- giving a test a
//     reliable window to cancel the call before that response arrives,
//     instead of racing against however fast a real open happens to be.
//  3. If a "close_channel" later arrives for that channel ID, append a line
//     to its results file recording it, so a test can confirm the agent
//     actually closed the channel it created after the caller gave up on
//     it, rather than leaving it to leak for the life of the connection.
//
// No flags: MeowshellAgentConnection.ConnectAsync builds its own argv for
// the "meowshell agent" invocation and gives a caller no way to inject
// extra ones, so a test can't pass this program its own options that way.
// The results file path is instead derived from os.Args[0] -- the absolute
// path a test copies this binary to is already unique per test.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const frameHeaderLength = 5

const openDelay = 300 * time.Millisecond

type frame struct {
	Type      byte
	ChannelID uint32
	Payload   []byte
}

func writeFrame(w io.Writer, f frame) error {
	buf := make([]byte, 4+frameHeaderLength+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(frameHeaderLength+len(f.Payload)))
	buf[4] = f.Type
	binary.BigEndian.PutUint32(buf[5:9], f.ChannelID)
	copy(buf[9:], f.Payload)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) (frame, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return frame{}, err
	}
	return frame{Type: body[0], ChannelID: binary.BigEndian.Uint32(body[1:5]), Payload: body[5:]}, nil
}

type message struct {
	Msg       string `json:"msg"`
	RequestID string `json:"request_id,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Path      string `json:"path,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
}

func writeControl(w io.Writer, mu *sync.Mutex, channelID uint32, msg message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	return writeFrame(w, frame{ChannelID: channelID, Payload: body})
}

func writeData(w io.Writer, mu *sync.Mutex, channelID uint32, data []byte) error {
	payload := append([]byte{0}, data...)
	mu.Lock()
	defer mu.Unlock()
	return writeFrame(w, frame{Type: 1, ChannelID: channelID, Payload: payload})
}

func main() {
	var outMu sync.Mutex
	var nextID uint32

	results, err := os.OpenFile(os.Args[0]+".results", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fakeagent: opening results file: %v\n", err)
		os.Exit(1)
	}
	defer results.Close()

	// configure -> connected, matching a real agent's handshake closely
	// enough for MeowshellAgentConnection.ConnectAsync to complete.
	if _, err := readFrame(os.Stdin); err != nil {
		return
	}
	if err := writeControl(os.Stdout, &outMu, 0, message{Msg: "connected"}); err != nil {
		return
	}

	for {
		f, err := readFrame(os.Stdin)
		if err != nil {
			return
		}
		var msg message
		if err := json.Unmarshal(f.Payload, &msg); err != nil {
			continue
		}
		switch msg.Msg {
		case "open_channel":
			nextID++
			id := nextID
			go func(requestID, kind, path string, id uint32) {
				time.Sleep(openDelay)
				writeControl(os.Stdout, &outMu, id, message{Msg: "channel_opened", RequestID: requestID})
				if kind == "sftp_download" && path == "partial-then-error" {
					writeData(os.Stdout, &outMu, id, []byte("partial-new-data"))
					writeControl(os.Stdout, &outMu, id, message{Msg: "error", Code: "unknown", Message: "synthetic download failure"})
					return
				}
				// Only kinds that realistically finish on their own in the
				// real protocol get a following exit_status: a shell/exec
				// channel (waitChannel) and an sftp_upload (finalizeUpload).
				// Forwards never get one at all -- the agent sends nothing
				// back when a forward's listener closes (see closeChannel in
				// forwarding.go), so sending one here would be testing
				// against behavior the real agent doesn't have. sftp_download
				// is deliberately excluded too: some tests rely on a download
				// channel staying open with nothing ever arriving, to
				// exercise cancelling a transfer that would otherwise never
				// finish on its own.
				switch kind {
				case "", "shell", "exec", "sftp_upload":
					writeControl(os.Stdout, &outMu, id, message{Msg: "exit_status"})
				}
			}(msg.RequestID, msg.Kind, msg.Path, id)
		case "close_channel":
			fmt.Fprintf(results, "CLOSED %d\n", f.ChannelID)
			results.Sync()
		}
	}
}
