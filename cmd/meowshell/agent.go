package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

const agentUsage = `meowshell agent -- a persistent, multiplexed SSH connection

USAGE
  meowshell agent [flags] <destination>

Dials once and keeps the connection open, multiplexing shell and exec
channels over it via a framed control protocol on stdin/stdout (see
protocol.go) instead of the one-process-per-operation model "meowshell
connect"/"cp" use. Opening a shell and running a command against the same
host costs one login instead of two.

<destination> is a tailcat address (dialed through tailcat's own bare
client mode, same as "connect"/"cp") or a "[user@]host[:port]" TCP address
for a general (non-tailcat) SSH host, verified against a known_hosts file
(--known-hosts) with trust-on-first-use for a host seen for the first time.
--jump chains through one or more intermediate TCP hosts first, each
verified the same way, before reaching <destination>.

Driven by dotnet/Meowshell's MeowshellAgentConnection -- not meant to be
typed at directly.

	meowshell agent <tc-addr>
	meowshell agent user@bastion.example.com:2222
	meowshell agent --jump=user@bastion.example.com 10.0.0.5
`

// stringList collects a repeatable flag's values in the order given.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// agentCmd implements "meowshell agent": see agentUsage.
func agentCmd(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	key := fs.String("key", "", "tailcat client key name or path")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	derpMapURL := fs.String("derpmap-url", "", "URL of the JSON DERP map to resolve a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url")
	verbose := fs.Bool("verbose", false, "passed to tailcat's own --verbose")
	port := fs.String("p", "22", "port number of the destination's SSH service")
	knownHosts := fs.String("known-hosts", "", "known_hosts file for TCP-transport host-key verification (default: $HOME/.meowshell/known_hosts)")
	proxyURL := fs.String("proxy", "", "SOCKS5 or HTTP CONNECT proxy to reach the first TCP hop through, e.g. socks5://user:pass@proxy:1080")
	var jumps stringList
	fs.Var(&jumps, "jump", "an intermediate TCP SSH host to tunnel through first ([user@]host[:port]); repeatable, in order, closest-to-here first")
	fs.Usage = func() { fmt.Fprint(os.Stderr, agentUsage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("agent needs exactly one destination")
	}
	dest := fs.Arg(0)

	// The tailcat binary is only needed at all when the final hop is a
	// tailcat address -- --jump hops are always TCP (a bastion is a real
	// SSH host, not something reachable through tailcat's own transport).
	var bin string
	if looksLikeTailcatAddress(dest) {
		b, err := findTailcat(*tailcatBin)
		if err != nil {
			return err
		}
		bin = b
	}

	khPath := *knownHosts
	if khPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		khPath = filepath.Join(home, ".meowshell", "known_hosts")
	}

	session := newAgentSession(os.Stdin, os.Stdout)
	frameErrCh := make(chan error, 1)
	go func() { frameErrCh <- session.serveFrames() }()

	err := session.connect(context.Background(), connectOptions{
		destination:    dest,
		jumps:          jumps,
		tailcatBin:     bin,
		key:            *key,
		derpMapURL:     *derpMapURL,
		verbose:        *verbose,
		port:           *port,
		knownHostsPath: khPath,
		proxyURL:       *proxyURL,
	})
	if err != nil {
		session.writeError(0, classifyConnectError(err), err)
		return err
	}
	defer session.closeHops()

	if err := session.writeControl(0, controlMessage{Msg: "connected"}); err != nil {
		return err
	}
	return <-frameErrCh
}

// classifyConnectError maps a connection-establishment failure to the
// typed error code a client can branch on. Coarse today (string-matched
// auth failures included) -- the full typed-error surface lands with the
// rest of phase 3, but a connection failure is common enough (a wrong
// password, an unreachable host) to be worth classifying now rather than
// leaving every one of them as errUnknown.
func classifyConnectError(err error) errorCode {
	var hkChanged *hostKeyChangedError
	if errors.As(err, &hkChanged) {
		return errHostKeyChanged
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errTimeout
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errNetworkUnreachable
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return errAuthFailed
	}
	return errUnknown
}

// connectOptions is agentSession.connect's parameter set: everything about
// where to dial and how, gathered up so connect itself reads as the hop
// loop it actually is rather than a wall of individual arguments.
type connectOptions struct {
	destination    string
	jumps          []string
	tailcatBin     string
	key            string
	derpMapURL     string
	verbose        bool
	port           string
	knownHostsPath string
	proxyURL       string // SOCKS5 or HTTP CONNECT proxy for the first TCP hop only; see proxyDialer
}

// agentChannel is one multiplexed shell or exec session, live on the
// shared *ssh.Client for as long as the remote command/shell runs.
type agentChannel struct {
	session *ssh.Session
	stdin   io.WriteCloser
}

// agentSession serves the control protocol for one agent connection: reads
// frames from in, dispatches them, and writes replies/channel data to out.
// Every write to out goes through outMu, since channels' output pumps and
// the main read loop can all be writing concurrently.
//
// The SSH connection itself is built by connect, which runs on the same
// goroutine as agentCmd's caller while serveFrames already runs on its own
// -- necessarily concurrent, since a host-key or auth prompt raised deep
// inside connect's dial needs the very same stdin serveFrames is reading
// to receive its answer. scPtr is what makes that safe to publish across
// goroutines: nil until connect succeeds, then set once.
type agentSession struct {
	scPtr atomic.Pointer[ssh.Client]
	hops  []*ssh.Client // every hop's client, including the final one scPtr points at; closed in reverse on shutdown

	in  io.Reader
	out io.Writer

	outMu sync.Mutex

	chansMu sync.Mutex
	chans   map[uint32]*agentChannel
	nextID  atomic.Uint32

	promptsMu    sync.Mutex
	prompts      map[string]chan controlMessage
	nextPromptID atomic.Uint64
}

func newAgentSession(in io.Reader, out io.Writer) *agentSession {
	return &agentSession{
		in:      in,
		out:     out,
		chans:   make(map[uint32]*agentChannel),
		prompts: make(map[string]chan controlMessage),
	}
}

func (a *agentSession) client() *ssh.Client { return a.scPtr.Load() }

// connect dials destination (and any --jump hops before it), completing
// the SSH handshake for each hop in turn, and publishes the final client
// via scPtr once every hop succeeds. Only the last hop may be a tailcat
// address; --jump hops are always TCP, verified with a real host-key
// callback (see hostkeys.go) since there is no WireGuard-authenticated
// peer to lean on for them the way there is for tailcat's own transport.
func (a *agentSession) connect(ctx context.Context, opts connectOptions) error {
	hops := append(append([]string{}, opts.jumps...), opts.destination)
	var chain []*ssh.Client
	var current *ssh.Client

	for i, hop := range hops {
		last := i == len(hops)-1
		var dial dialer
		var hkCallback ssh.HostKeyCallback
		remoteAddr := "tailcat"
		user := ""

		if last && looksLikeTailcatAddress(hop) {
			dial = tailcatDialer(opts.tailcatBin, tailcatClientArgv(opts.key, opts.derpMapURL, opts.verbose, hop, opts.port))
			hkCallback = tailcatHostKeyCallback()
		} else {
			var hostPort string
			user, hostPort = splitUserHost(hop, opts.port)
			remoteAddr = hostPort
			switch {
			case current != nil:
				dial = jumpDialer(current, hostPort)
			case opts.proxyURL != "":
				pd, err := proxyDialer(opts.proxyURL, hostPort)
				if err != nil {
					closeClients(chain)
					return err
				}
				dial = pd
			default:
				dial = tcpDialer(hostPort)
			}
			cb, err := tcpHostKeyCallback(opts.knownHostsPath, a.promptHostKey)
			if err != nil {
				closeClients(chain)
				return err
			}
			hkCallback = cb
		}

		sc, err := dialSSHClient(ctx, dial, remoteAddr, user, hkCallback, sshAgentAuthMethods())
		if err != nil {
			closeClients(chain)
			return fmt.Errorf("connecting to %s: %w", hop, err)
		}
		chain = append(chain, sc)
		current = sc
	}

	a.hops = chain
	a.scPtr.Store(current)
	return nil
}

func closeClients(clients []*ssh.Client) {
	for i := len(clients) - 1; i >= 0; i-- {
		clients[i].Close()
	}
}

func (a *agentSession) closeHops() { closeClients(a.hops) }

// promptHostKey is the hostKeyPrompter connect passes to tcpHostKeyCallback:
// a TOFU decision round-tripped to the client over the control channel.
func (a *agentSession) promptHostKey(hostname string, remote net.Addr, key ssh.PublicKey) (bool, error) {
	resp, err := a.prompt(controlMessage{
		PromptKind:  "host_key",
		Remote:      hostname,
		Fingerprint: fingerprintSHA256(key),
	})
	if err != nil {
		return false, err
	}
	if resp.Cancelled {
		return false, fmt.Errorf("host key prompt for %s was cancelled", hostname)
	}
	return resp.Accept, nil
}

// prompt sends a prompt_request and blocks for the client's matching
// prompt_response, delivered by serveFrames (running concurrently on its
// own goroutine -- see the agentSession doc comment on why that matters).
func (a *agentSession) prompt(msg controlMessage) (controlMessage, error) {
	id := fmt.Sprintf("p%d", a.nextPromptID.Add(1))
	msg.Msg = "prompt_request"
	msg.RequestID = id

	ch := make(chan controlMessage, 1)
	a.promptsMu.Lock()
	a.prompts[id] = ch
	a.promptsMu.Unlock()
	defer func() {
		a.promptsMu.Lock()
		delete(a.prompts, id)
		a.promptsMu.Unlock()
	}()

	if err := a.writeControl(0, msg); err != nil {
		return controlMessage{}, err
	}
	resp, ok := <-ch
	if !ok {
		return controlMessage{}, fmt.Errorf("connection closed while waiting for a prompt response")
	}
	return resp, nil
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

// serveFrames reads frames from a.in until the client closes its end (a
// clean shutdown, reported as nil) or a frame-level protocol error makes
// the stream unrecoverable. Runs for the whole process lifetime, starting
// before connect even dials -- see the agentSession doc comment.
func (a *agentSession) serveFrames() error {
	defer a.closeAllChannels()
	defer a.closeAllPrompts()
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
	if msg.Msg == "prompt_response" {
		a.deliverPromptResponse(msg)
		return
	}
	if a.client() == nil {
		a.writeError(channelID, errProtocolError, fmt.Errorf("message %q sent before the connection was ready", msg.Msg))
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

func (a *agentSession) deliverPromptResponse(msg controlMessage) {
	a.promptsMu.Lock()
	ch := a.prompts[msg.RequestID]
	a.promptsMu.Unlock()
	if ch != nil {
		ch <- msg
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
	session, err := a.client().NewSession()
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
	ch := &agentChannel{session: session, stdin: stdin}
	a.chansMu.Lock()
	a.chans[id] = ch
	a.chansMu.Unlock()

	// channel_opened must reach the client before anything else naming this
	// id can: a fast remote command (nothing unusual -- a local test server
	// hits this every time on loopback) can produce output and even exit
	// before this function would otherwise get around to announcing the id
	// at all, so the client needs it in hand before Start/Shell runs, not
	// after -- otherwise pumpToClient below could write data (or
	// waitChannel an exit_status) for an id the client hasn't been told
	// about yet.
	if err := a.writeControl(id, controlMessage{Msg: "channel_opened"}); err != nil {
		a.removeChannel(id)
		session.Close()
		return
	}

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
		a.writeError(id, errUnknown, fmt.Errorf("starting session: %w", err))
		return
	}

	go a.pumpToClient(id, streamStdout, stdout)
	go a.pumpToClient(id, streamStderr, stderr)
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

func (a *agentSession) closeAllPrompts() {
	a.promptsMu.Lock()
	prompts := a.prompts
	a.prompts = make(map[string]chan controlMessage)
	a.promptsMu.Unlock()
	for _, ch := range prompts {
		close(ch)
	}
}
