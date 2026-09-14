//go:build unix

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/creack/pty"
)

// local-agent is a private subprocess transport for callers that want a real
// local PTY without involving Tailcat, DERP, SSH, TCP, UDP, DNS, or any other
// network path. It deliberately speaks the same framed shell-channel subset as
// "meowshell agent", so higher layers can reuse their terminal plumbing while
// the transport remains entirely inside the process tree of the calling app.
func init() {
	if len(os.Args) < 2 || os.Args[1] != "local-agent" {
		return
	}
	startManagedParentWatchdog()
	if err := localAgentCmd(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "meowshell local-agent: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

type localAgentChannel struct {
	cmd       *exec.Cmd
	pty       *os.File
	closeOnce sync.Once
}

func (c *localAgentChannel) close() {
	c.closeOnce.Do(func() {
		_ = c.pty.Close()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
	})
}

type localAgentSession struct {
	in  io.Reader
	out io.Writer

	outMu sync.Mutex

	channelsMu sync.Mutex
	channels   map[uint32]*localAgentChannel
	nextID     atomic.Uint32
}

func localAgentCmd(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("local-agent takes no arguments")
	}
	return runLocalAgent(os.Stdin, os.Stdout)
}

func runLocalAgent(in io.Reader, out io.Writer) error {
	s := &localAgentSession{
		in:       in,
		out:      out,
		channels: make(map[uint32]*localAgentChannel),
	}
	defer s.closeAll()

	first, err := readFrame(in)
	if err != nil {
		return fmt.Errorf("reading configure: %w", err)
	}
	if first.Type != frameTypeControl || first.ChannelID != 0 {
		return fmt.Errorf("expected configure control frame on channel 0")
	}
	var cfg controlMessage
	if err := json.Unmarshal(first.Payload, &cfg); err != nil {
		return fmt.Errorf("decoding configure: %w", err)
	}
	if cfg.Msg != "configure" {
		return fmt.Errorf("expected configure as first message, got %q", cfg.Msg)
	}

	if err := s.writeControl(0, controlMessage{Msg: "connected"}); err != nil {
		return err
	}

	for {
		f, err := readFrame(in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading local-agent frame: %w", err)
		}

		switch f.Type {
		case frameTypeControl:
			s.handleControl(f.ChannelID, f.Payload)
		case frameTypeData:
			s.handleData(f.ChannelID, f.Payload)
		default:
			_ = s.writeError(f.ChannelID, errProtocolError, fmt.Errorf("unknown frame type %d", f.Type))
		}
	}
}

func (s *localAgentSession) handleControl(channelID uint32, payload []byte) {
	var msg controlMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		_ = s.writeError(channelID, errProtocolError, err)
		return
	}

	switch msg.Msg {
	case "open_channel":
		s.openChannel(msg)
	case "resize":
		s.resize(channelID, msg)
	case "close_channel":
		s.closeChannel(channelID)
	default:
		_ = s.writeError(channelID, errProtocolError, fmt.Errorf("local-agent does not support message %q", msg.Msg))
	}
}

func (s *localAgentSession) handleData(channelID uint32, payload []byte) {
	ch := s.channel(channelID)
	if ch == nil {
		return
	}
	if _, err := ch.pty.Write(payload); err != nil {
		_ = s.writeError(channelID, errConnectionLost, fmt.Errorf("writing local PTY: %w", err))
		s.removeChannel(channelID)
		ch.close()
	}
}

func (s *localAgentSession) openChannel(msg controlMessage) {
	if msg.Kind != "shell" && msg.Kind != "exec" {
		_ = s.writeOpenError(msg.RequestID, errProtocolError,
			fmt.Errorf("local-agent only supports shell and exec channels, got %q", msg.Kind))
		return
	}

	env := newResolver().Resolve()
	for _, warning := range env.Warnings {
		fmt.Fprintf(os.Stderr, "# warning: %s\n", warning)
	}
	if env.Shell == "" {
		_ = s.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("no local shell is available"))
		return
	}

	var cmd *exec.Cmd
	if msg.Kind == "exec" {
		cmd = exec.Command(env.Shell, "-c", strings.Join(msg.Command, " "))
	} else {
		cmd = exec.Command(env.Shell)
	}
	cmd.Dir = env.Home
	term := msg.Term
	if term == "" {
		term = "xterm-256color"
	}
	cmd.Env = setEnv(os.Environ(), [][2]string{
		{"HOME", env.Home},
		{"USER", env.User},
		{"PATH", env.Path},
		{"LANG", env.Lang},
		{"TERM", term},
	})

	cols, rows := msg.Cols, msg.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	if err != nil {
		_ = s.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("starting local PTY: %w", err))
		return
	}

	ch := &localAgentChannel{cmd: cmd, pty: ptmx}
	id, err := s.registerChannel(ch)
	if err != nil {
		ch.close()
		_ = s.writeOpenError(msg.RequestID, errUnknown, err)
		return
	}
	if err := s.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID}); err != nil {
		s.removeChannel(id)
		ch.close()
		return
	}

	go s.pumpAndWait(id, ch)
}

func (s *localAgentSession) pumpAndWait(id uint32, ch *localAgentChannel) {
	buf := make([]byte, 32*1024)
	for {
		n, err := ch.pty.Read(buf)
		if n > 0 {
			if werr := s.writeData(id, streamStdout, buf[:n]); werr != nil {
				s.removeChannel(id)
				ch.close()
				return
			}
		}
		if err != nil {
			break
		}
	}

	err := ch.cmd.Wait()
	exitCode := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		exitCode = 0
	case errors.As(err, &exitErr):
		exitCode = exitErr.ExitCode()
	default:
		_ = s.writeError(id, errConnectionLost, fmt.Errorf("waiting for local shell: %w", err))
		s.removeChannel(id)
		ch.close()
		return
	}
	_ = s.writeControl(id, controlMessage{Msg: "exit_status", ExitCode: exitCode})
	s.removeChannel(id)
	ch.close()
}

func (s *localAgentSession) resize(channelID uint32, msg controlMessage) {
	if msg.Cols <= 0 || msg.Rows <= 0 {
		_ = s.writeError(channelID, errProtocolError,
			fmt.Errorf("resize needs positive cols/rows, got %dx%d", msg.Cols, msg.Rows))
		return
	}
	ch := s.channel(channelID)
	if ch == nil {
		return
	}
	if err := pty.Setsize(ch.pty, &pty.Winsize{Rows: uint16(msg.Rows), Cols: uint16(msg.Cols)}); err != nil {
		_ = s.writeError(channelID, errUnknown, fmt.Errorf("resizing local PTY: %w", err))
	}
}

func (s *localAgentSession) closeChannel(channelID uint32) {
	ch := s.removeChannel(channelID)
	if ch == nil {
		return
	}
	ch.close()
}

func (s *localAgentSession) registerChannel(ch *localAgentChannel) (uint32, error) {
	s.channelsMu.Lock()
	defer s.channelsMu.Unlock()
	for attempts := uint64(0); attempts < uint64(^uint32(0)); attempts++ {
		id := s.nextID.Add(1)
		if id == 0 {
			continue
		}
		if _, exists := s.channels[id]; exists {
			continue
		}
		s.channels[id] = ch
		return id, nil
	}
	return 0, fmt.Errorf("no free channel IDs")
}

func (s *localAgentSession) channel(id uint32) *localAgentChannel {
	s.channelsMu.Lock()
	defer s.channelsMu.Unlock()
	return s.channels[id]
}

func (s *localAgentSession) removeChannel(id uint32) *localAgentChannel {
	s.channelsMu.Lock()
	defer s.channelsMu.Unlock()
	ch := s.channels[id]
	delete(s.channels, id)
	return ch
}

func (s *localAgentSession) closeAll() {
	s.channelsMu.Lock()
	channels := make([]*localAgentChannel, 0, len(s.channels))
	for id, ch := range s.channels {
		channels = append(channels, ch)
		delete(s.channels, id)
	}
	s.channelsMu.Unlock()
	for _, ch := range channels {
		ch.close()
	}
}

func (s *localAgentSession) writeControl(channelID uint32, msg controlMessage) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	return writeFrame(s.out, frame{Type: frameTypeControl, ChannelID: channelID, Payload: payload})
}

func (s *localAgentSession) writeData(channelID uint32, stream byte, data []byte) error {
	payload := make([]byte, 1+len(data))
	payload[0] = stream
	copy(payload[1:], data)
	s.outMu.Lock()
	defer s.outMu.Unlock()
	return writeFrame(s.out, frame{Type: frameTypeData, ChannelID: channelID, Payload: payload})
}

func (s *localAgentSession) writeError(channelID uint32, code errorCode, err error) error {
	return s.writeControl(channelID, controlMessage{Msg: "error", Code: code, Message: err.Error(), Terminal: &terminalTrue})
}

func (s *localAgentSession) writeOpenError(requestID string, code errorCode, err error) error {
	return s.writeControl(0, controlMessage{Msg: "error", RequestID: requestID, Code: code, Message: err.Error()})
}
