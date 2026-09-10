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
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

	// The client's auth material (configure) has to be read synchronously,
	// before serveFrames starts consuming stdin on its own goroutine --
	// it's the one message with nowhere else to come from, since no
	// prompt has been raised yet for serveFrames' usual
	// prompt_response dispatch to deliver it through.
	cfg, err := session.readConfigure()
	if err != nil {
		session.writeError(0, errProtocolError, err)
		return err
	}
	auth, err := session.buildAuthMethods(cfg)
	if err != nil {
		session.writeError(0, errAuthFailed, err)
		return err
	}

	frameErrCh := make(chan error, 1)
	go func() { frameErrCh <- session.serveFrames() }()

	err = session.connect(context.Background(), connectOptions{
		destination:    dest,
		jumps:          jumps,
		tailcatBin:     bin,
		key:            *key,
		derpMapURL:     *derpMapURL,
		verbose:        *verbose,
		port:           *port,
		knownHostsPath: khPath,
		proxyURL:       *proxyURL,
		auth:           auth,
	})
	if err != nil {
		session.writeError(0, classifyConnectError(err), err)
		return err
	}
	defer session.closeHops()
	session.startKeepalive()

	if cfg.AgentForwarding && session.agentForwardSock != "" {
		if err := agent.ForwardToRemote(session.client(), session.agentForwardSock); err != nil {
			session.writeError(0, errUnknown, fmt.Errorf("setting up agent forwarding: %w", err))
		} else {
			session.agentForwardingReady = true
		}
	}

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
	proxyURL       string           // SOCKS5 or HTTP CONNECT proxy for the first TCP hop only; see proxyDialer
	auth           []ssh.AuthMethod // from buildAuthMethods; every hop dials with the same auth list
}

// agentChannel is one multiplexed shell/exec session, SFTP transfer, or
// port-forward listener, live for as long as its own operation runs.
// Exactly one of session, sftpFile, or listener is set, identifying which
// kind this is; the others are that kind's own extra state.
type agentChannel struct {
	// shell/exec
	session *ssh.Session
	stdin   io.WriteCloser

	// sftp_upload/sftp_download (agentsftp.go)
	sftpFile       *sftp.File
	ctx            context.Context
	cancel         context.CancelFunc
	isUpload       bool
	uploadPath     string
	uploadPreserve bool
	uploadMode     uint32
	uploadModTime  int64

	// forward_local/forward_remote/forward_socks (forwarding.go): closing
	// the listener stops accepting new forwarded connections; connections
	// already in flight finish or fail on their own.
	listener net.Listener
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

	sftpMu     sync.Mutex
	sftpClient *sftp.Client // lazily opened by sftpClientFor (agentsftp.go), shared across every ls/stat/.../upload/download

	promptsMu    sync.Mutex
	prompts      map[string]chan controlMessage
	nextPromptID atomic.Uint64

	// Auth-related state buildAuthMethods/agentCmd populate before connect
	// runs and later reads: agentForwardSock is the local ssh-agent socket
	// (if one was found and configure didn't disable it) ForwardToRemote
	// needs; agentForwardingReady is set once that forwarding is actually
	// wired up on the connected client, gating whether openChannel asks
	// for it per session.
	agentForwardSock     string
	agentForwardingReady bool
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

// readConfigure reads the client's mandatory first message, synchronously,
// before serveFrames starts consuming a.in on its own goroutine -- see the
// comment at its one call site in agentCmd for why that ordering matters.
func (a *agentSession) readConfigure() (controlMessage, error) {
	f, err := readFrame(a.in)
	if err != nil {
		return controlMessage{}, fmt.Errorf("reading configure: %w", err)
	}
	if f.Type != frameTypeControl {
		return controlMessage{}, fmt.Errorf("expected a configure control frame, got a data frame")
	}
	var msg controlMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		return controlMessage{}, fmt.Errorf("decoding configure: %w", err)
	}
	if msg.Msg != "configure" {
		return controlMessage{}, fmt.Errorf("expected %q as the first message, got %q", "configure", msg.Msg)
	}
	return msg, nil
}

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

		sc, err := dialSSHClient(ctx, dial, remoteAddr, user, hkCallback, opts.auth)
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

func (a *agentSession) closeHops() {
	if a.sftpClient != nil {
		a.sftpClient.Close()
	}
	closeClients(a.hops)
}

const (
	keepaliveInterval = 30 * time.Second
	keepaliveTimeout  = 15 * time.Second
)

// startKeepalive sends an OpenSSH-style keepalive request on an interval
// for as long as the connection lives, so a mobile carrier's NAT binding
// (or any other idle-connection timeout along the path) doesn't silently
// drop a connection nothing has sent traffic on in a while. A request that
// doesn't get answered within keepaliveTimeout is treated as a dead peer:
// reported to the client and the connection torn down, rather than left to
// hang indefinitely.
func (a *agentSession) startKeepalive() {
	go func() {
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for range ticker.C {
			client := a.client()
			if client == nil {
				return
			}
			result := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				result <- err
			}()
			select {
			case err := <-result:
				if err != nil {
					a.reportConnectionLost(fmt.Errorf("keepalive: %w", err))
					return
				}
			case <-time.After(keepaliveTimeout):
				a.reportConnectionLost(fmt.Errorf("keepalive: no response within %s", keepaliveTimeout))
				return
			}
		}
	}()
}

// reportConnectionLost tells the client the connection is dead and closes
// it, so anything still blocked on it (a channel read, a pending SFTP
// request) unblocks instead of hanging on a peer that will never answer.
func (a *agentSession) reportConnectionLost(err error) {
	a.writeError(0, errConnectionLost, err)
	if client := a.client(); client != nil {
		client.Close()
	}
}

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
	case "sftp_op":
		a.sftpOp(msg)
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

// handleData writes an incoming data frame to the target channel: a
// shell/exec channel's remote stdin, or an sftp_upload channel's remote
// file. There is no stream tag to interpret here (unlike an outgoing data
// frame): everything the client sends is keystrokes/command input or
// upload bytes, never something split across two streams.
func (a *agentSession) handleData(channelID uint32, payload []byte) {
	ch := a.channel(channelID)
	if ch == nil {
		return // channel already closed; nothing left to write to
	}
	switch {
	case ch.stdin != nil:
		ch.stdin.Write(payload)
	case ch.sftpFile != nil:
		if _, err := ch.sftpFile.Write(payload); err != nil {
			a.writeError(channelID, classifySFTPError(err), err)
		}
	}
}

func (a *agentSession) channel(id uint32) *agentChannel {
	a.chansMu.Lock()
	defer a.chansMu.Unlock()
	return a.chans[id]
}

// openChannel dispatches an open_channel request by kind: "shell"/"exec"
// here (an SSH session), "sftp_upload"/"sftp_download" to agentsftp.go,
// and "forward_local"/"forward_remote"/"forward_socks" to forwarding.go.
func (a *agentSession) openChannel(msg controlMessage) {
	switch msg.Kind {
	case "sftp_upload", "sftp_download":
		a.openSFTPChannel(msg)
		return
	case "forward_local", "forward_remote", "forward_socks":
		a.openForwardChannel(msg)
		return
	}
	a.openShellChannel(msg)
}

// openShellChannel opens a new SSH session on the shared client for a
// shell (no command) or exec (a command) request, wires its
// stdin/stdout/stderr into the framed protocol, and starts it running.
// wantPty mirrors connect.go's own default (a pseudo-terminal unless the
// request is a command that explicitly declined one).
func (a *agentSession) openShellChannel(msg controlMessage) {
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

	if a.agentForwardingReady {
		if err := agent.RequestAgentForwarding(session); err != nil {
			a.writeError(id, errUnknown, fmt.Errorf("requesting agent forwarding: %w", err))
		}
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

	// session.Wait (in waitChannel) is not synchronized with StdoutPipe/
	// StderrPipe's own internal buffering -- golang.org/x/crypto/ssh can
	// report the exit-status request before a pumpToClient goroutine has
	// been scheduled to drain the last of what's sitting in a pipe ahead
	// of it, which reordered exit_status before its own channel's last
	// data frame in practice (caught by a fake SSH server fast enough to
	// expose it: pumpSFTPDownload has no such race, since it IS the
	// reader driving its own completion signal). wg makes waitChannel
	// block until both pumps have reached EOF -- which, for a well-behaved
	// remote, only happens once the channel itself is done sending data --
	// before it ever calls Wait, so every data frame is written first.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.pumpToClient(id, streamStdout, stdout) }()
	go func() { defer wg.Done(); a.pumpToClient(id, streamStderr, stderr) }()
	go a.waitChannel(id, ch, &wg)
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
// inspect. Waits for wg (both output pumps having reached EOF) first -- see
// the ordering comment at this function's one call site.
func (a *agentSession) waitChannel(id uint32, ch *agentChannel, wg *sync.WaitGroup) {
	wg.Wait()
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
	if ch == nil || ch.session == nil {
		return // not a shell/exec channel (or already closed); resize is meaningless for the others
	}
	if msg.Cols <= 0 || msg.Rows <= 0 {
		a.writeError(channelID, errProtocolError, fmt.Errorf("resize needs positive cols/rows, got %dx%d", msg.Cols, msg.Rows))
		return
	}
	if err := ch.session.WindowChange(msg.Rows, msg.Cols); err != nil {
		a.writeError(channelID, errUnknown, fmt.Errorf("resizing: %w", err))
	}
}

// closeChannel ends channelID's operation, however that channel kind ends
// one: a shell/exec session simply closes; an sftp_upload finalizes (see
// finalizeUpload -- close_channel is its "no more bytes coming" signal,
// not just cleanup); an in-progress sftp_download's context is cancelled,
// letting pumpSFTPDownload report and clean up on its own; a forward's
// listener closes, ending new connections (ones already in flight finish
// or fail on their own).
func (a *agentSession) closeChannel(channelID uint32) {
	ch := a.removeChannel(channelID)
	if ch == nil {
		return
	}
	switch {
	case ch.session != nil:
		ch.session.Close()
	case ch.sftpFile != nil && ch.isUpload:
		a.finalizeUpload(channelID, ch)
	case ch.sftpFile != nil:
		if ch.cancel != nil {
			ch.cancel()
		}
	case ch.listener != nil:
		ch.listener.Close()
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
		switch {
		case ch.session != nil:
			ch.session.Close()
		case ch.sftpFile != nil:
			if ch.cancel != nil {
				ch.cancel()
			}
			ch.sftpFile.Close()
		case ch.listener != nil:
			ch.listener.Close()
		}
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
