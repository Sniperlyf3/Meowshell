package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

const agentUsage = `meowshell agent -- a persistent, multiplexed SSH connection

USAGE
  meowshell agent [flags] <tc-addr>

Dials once and keeps the connection open, multiplexing shell and exec
channels over it via a framed control protocol on stdin/stdout (see
protocol.go) instead of the one-process-per-operation model "meowshell
connect"/"cp" use. Opening a shell and running a command against the same
host costs one login instead of two. Driven by dotnet/Meowshell's
MeowshellAgentConnection -- not meant to be typed at directly.

	meowshell agent <tc-addr>
`

// agentCmd implements "meowshell agent": see agentUsage.
func agentCmd(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	key := fs.String("key", "", "tailcat client key name or path")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	derpMapURL := fs.String("derpmap-url", "", "URL of the JSON DERP map to resolve a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url")
	verbose := fs.Bool("verbose", false, "passed to tailcat's own --verbose")
	port := fs.String("p", "22", "port number of the server's SSH service")
	fs.Usage = func() { fmt.Fprint(os.Stderr, agentUsage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("agent needs exactly one tailcat address")
	}
	addr := fs.Arg(0)

	bin, err := findTailcat(*tailcatBin)
	if err != nil {
		return err
	}
	sc, err := dialSSHClient(bin, tailcatClientArgv(*key, *derpMapURL, *verbose, addr, *port))
	if err != nil {
		return err
	}
	defer sc.Close()

	return newAgentSession(sc, os.Stdin, os.Stdout).run()
}

// agentChannel is one multiplexed shell or exec session, live on the
// shared *ssh.Client for as long as the remote command/shell runs.
type agentChannel struct {
	session *ssh.Session
	stdin   io.WriteCloser
	pty     bool
}

// agentSession serves the control protocol for one agent connection: reads
// frames from in, dispatches them against sc, and writes replies/channel
// data to out. Safe for its writeControl/writeData methods to be called
// from multiple goroutines at once (one per open channel's output pumps,
// plus the main read loop), which is why every write to out goes through
// outMu.
type agentSession struct {
	sc  *ssh.Client
	in  *bufio.Reader
	out io.Writer

	outMu sync.Mutex

	chansMu sync.Mutex
	chans   map[uint32]*agentChannel
	nextID  atomic.Uint32
}

func newAgentSession(sc *ssh.Client, in io.Reader, out io.Writer) *agentSession {
	return &agentSession{
		sc:    sc,
		in:    bufio.NewReader(in),
		out:   out,
		chans: make(map[uint32]*agentChannel),
	}
}

func (a *agentSession) writeControl(channelID uint32, msg controlMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	a.outMu.Lock()
	defer a.outMu.Unlock()
	return writeFrame(a.out, frame{Type: frameTypeControl, ChannelID: channelID, Payload: body})
}

func (a *agentSession) writeData(channelID uint32, stream byte, p []byte) error {
	payload := make([]byte, 1+len(p))
	payload[0] = stream
	copy(payload[1:], p)
	a.outMu.Lock()
	defer a.outMu.Unlock()
	return writeFrame(a.out, frame{Type: frameTypeData, ChannelID: channelID, Payload: payload})
}

func (a *agentSession) writeError(channelID uint32, code errorCode, err error) error {
	return a.writeControl(channelID, controlMessage{Msg: "error", Code: code, Message: err.Error()})
}

// run serves frames from a.in until the client closes its end (a clean
// shutdown, reported as nil) or a frame-level protocol error makes the
// stream unrecoverable.
func (a *agentSession) run() error {
	defer a.closeAllChannels()
	for {
		f, err := readFrame(a.in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading control frame: %w", err)
		}
		switch f.Type {
		case frameTypeControl:
			a.handleControl(f.ChannelID, f.Payload)
		case frameTypeData:
			a.handleData(f.ChannelID, f.Payload)
		default:
			a.writeError(f.ChannelID, errProtocolError, fmt.Errorf("unknown frame type %d", f.Type))
		}
	}
}

func (a *agentSession) handleControl(channelID uint32, payload []byte) {
	var msg controlMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		a.writeError(channelID, errProtocolError, err)
		return
	}
	switch msg.Msg {
	case "open_channel":
		a.openChannel(msg)
	case "resize":
		a.resize(channelID, msg)
	case "close_channel":
		a.closeChannel(channelID)
	default:
		a.writeError(channelID, errProtocolError, fmt.Errorf("unknown message %q", msg.Msg))
	}
}

// handleData writes an incoming data frame to the target channel's remote
// stdin. There is no stream tag to interpret here (unlike an outgoing data
// frame): everything the client sends is keystrokes/command input.
func (a *agentSession) handleData(channelID uint32, payload []byte) {
	ch := a.channel(channelID)
	if ch == nil {
		return // channel already closed; nothing left to write to
	}
	ch.stdin.Write(payload)
}

func (a *agentSession) channel(id uint32) *agentChannel {
	a.chansMu.Lock()
	defer a.chansMu.Unlock()
	return a.chans[id]
}

// openChannel opens a new SSH session on the shared client for a shell (no
// command) or exec (a command) request, wires its stdin/stdout/stderr into
// the framed protocol, and starts it running. wantPty mirrors connect.go's
// own default (a pseudo-terminal unless the request is a command that
// explicitly declined one).
func (a *agentSession) openChannel(msg controlMessage) {
	session, err := a.sc.NewSession()
	if err != nil {
		a.writeError(0, errUnknown, fmt.Errorf("opening session: %w", err))
		return
	}

	wantPty := msg.Kind == "shell"
	if msg.Pty != nil {
		wantPty = *msg.Pty
	}
	if wantPty {
		cols, rows := msg.Cols, msg.Rows
		if cols <= 0 {
			cols = 80
		}
		if rows <= 0 {
			rows = 24
		}
		term := msg.Term
		if term == "" {
			term = "xterm-256color"
		}
		if err := session.RequestPty(term, rows, cols, ssh.TerminalModes{}); err != nil {
			session.Close()
			a.writeError(0, errUnknown, fmt.Errorf("requesting a pseudo-terminal: %w", err))
			return
		}
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		a.writeError(0, errUnknown, fmt.Errorf("opening remote stdin: %w", err))
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		a.writeError(0, errUnknown, fmt.Errorf("opening remote stdout: %w", err))
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		session.Close()
		a.writeError(0, errUnknown, fmt.Errorf("opening remote stderr: %w", err))
		return
	}

	id := a.nextID.Add(1)
	ch := &agentChannel{session: session, stdin: stdin, pty: wantPty}
	a.chansMu.Lock()
	a.chans[id] = ch
	a.chansMu.Unlock()

	go a.pumpToClient(id, streamStdout, stdout)
	go a.pumpToClient(id, streamStderr, stderr)

	switch msg.Kind {
	case "exec":
		// Plain space-join, no quoting -- exactly what a real ssh client
		// sends too (connect.go documents this same choice in detail).
		err = session.Start(strings.Join(msg.Command, " "))
	default:
		err = session.Shell()
	}
	if err != nil {
		a.removeChannel(id)
		session.Close()
		a.writeError(0, errUnknown, fmt.Errorf("starting session: %w", err))
		return
	}

	if err := a.writeControl(id, controlMessage{Msg: "channel_opened"}); err != nil {
		a.removeChannel(id)
		session.Close()
		return
	}

	go a.waitChannel(id, ch)
}

// pumpToClient relays one of a channel's remote output streams to the
// client as data frames until the pipe closes (the session ending, or the
// channel being closed out from under it).
func (a *agentSession) pumpToClient(id uint32, stream byte, r io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := a.writeData(id, stream, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// waitChannel reports the channel's outcome as a typed exit_status once the
// remote session ends, replacing connect.go's os.Exit(status) (fine for a
// one-shot process, but this one serves many channels and must never exit
// the whole agent over one of them) with a structured field the client can
// inspect.
func (a *agentSession) waitChannel(id uint32, ch *agentChannel) {
	err := ch.session.Wait()
	exitCode := 0
	var exitErr *ssh.ExitError
	switch {
	case err == nil:
		exitCode = 0
	case errors.As(err, &exitErr):
		exitCode = exitErr.ExitStatus()
	default:
		a.writeError(id, errConnectionLost, err)
		a.removeChannel(id)
		return
	}
	a.writeControl(id, controlMessage{Msg: "exit_status", ExitCode: exitCode})
	a.removeChannel(id)
}

func (a *agentSession) resize(channelID uint32, msg controlMessage) {
	ch := a.channel(channelID)
	if ch == nil {
		return
	}
	if msg.Cols <= 0 || msg.Rows <= 0 {
		a.writeError(channelID, errProtocolError, fmt.Errorf("resize needs positive cols/rows, got %dx%d", msg.Cols, msg.Rows))
		return
	}
	if err := ch.session.WindowChange(msg.Rows, msg.Cols); err != nil {
		a.writeError(channelID, errUnknown, fmt.Errorf("resizing: %w", err))
	}
}

func (a *agentSession) closeChannel(channelID uint32) {
	if ch := a.removeChannel(channelID); ch != nil {
		ch.session.Close()
	}
}

func (a *agentSession) removeChannel(id uint32) *agentChannel {
	a.chansMu.Lock()
	defer a.chansMu.Unlock()
	ch := a.chans[id]
	delete(a.chans, id)
	return ch
}

func (a *agentSession) closeAllChannels() {
	a.chansMu.Lock()
	chans := a.chans
	a.chans = make(map[uint32]*agentChannel)
	a.chansMu.Unlock()
	for _, ch := range chans {
		ch.session.Close()
	}
}
