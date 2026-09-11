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
	"github.com/tailscale/tailcat"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"tailscale.com/types/key"
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

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func agentCmd(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	key := fs.String("key", "", "tailcat client key name or path")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	derpMapURL := fs.String("derpmap-url", os.Getenv("TAILCAT_DERPMAP_URL"), "URL of the JSON DERP map to resolve a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url for the agent's own connection; also used directly by exit-node forwarding's in-process tailcat.Client, which spawns no subprocess and so cannot fall back to tailcat's own TAILCAT_DERPMAP_URL handling the way every other tailcat invocation here does")
	verbose := fs.Bool("verbose", false, "passed to tailcat's own --verbose")
	port := fs.String("p", "22", "port number of the destination's SSH service")
	knownHosts := fs.String("known-hosts", "", "known_hosts file for TCP-transport host-key verification (default: $HOME/.meowshell/known_hosts)")
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

	cfg, err := session.readConfigure()
	if err != nil {
		session.writeError(0, errProtocolError, err)
		return err
	}

	// serveFrames must be running before buildAuthMethods: an encrypted
	// supplied private key makes buildAuthMethods call session.prompt for
	// its passphrase, which blocks on a prompt_response that only
	// serveFrames (reading stdin) can ever deliver. Building auth methods
	// first, as this used to, deadlocks every encrypted-key connection --
	// the .NET side sends prompt_response, but nothing here is reading
	// stdin yet to receive it.
	frameErrCh := make(chan error, 1)
	go func() { frameErrCh <- session.serveFrames() }()

	auth, err := session.buildAuthMethods(cfg)
	if err != nil {
		session.writeError(0, errAuthFailed, err)
		return err
	}

	err = session.connect(context.Background(), connectOptions{
		destination:    dest,
		jumps:          jumps,
		tailcatBin:     bin,
		key:            *key,
		derpMapURL:     *derpMapURL,
		verbose:        *verbose,
		port:           *port,
		knownHostsPath: khPath,
		proxyURL:       cfg.ProxyURL,
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

func classifyConnectError(err error) errorCode {
	var hkChanged *hostKeyChangedError
	if errors.As(err, &hkChanged) {
		return errHostKeyChanged
	}
	var keystoreSign *keystoreSignError
	if errors.As(err, &keystoreSign) {
		return errAuthFailed
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

type connectOptions struct {
	destination    string
	jumps          []string
	tailcatBin     string
	key            string
	derpMapURL     string
	verbose        bool
	port           string
	knownHostsPath string
	proxyURL       string
	auth           []ssh.AuthMethod
}

type agentChannel struct {
	session *ssh.Session
	stdin   io.WriteCloser

	sftpFile       *sftp.File
	ctx            context.Context
	cancel         context.CancelFunc
	isUpload       bool
	uploadPath     string
	uploadPreserve bool
	uploadMode     uint32
	uploadModTime  int64
	// uploadErr, once set, is terminal: a write to sftpFile failed, so
	// finalizeUpload must report that failure instead of exit_status 0 --
	// closing the file cleanly afterward says nothing about the data
	// actually having landed, and further data frames must stop touching
	// the file at all.
	uploadErr error

	listener net.Listener
}

type agentSession struct {
	scPtr atomic.Pointer[ssh.Client]
	hops  []*ssh.Client

	in  io.Reader
	out io.Writer

	outMu sync.Mutex

	chansMu sync.Mutex
	chans   map[uint32]*agentChannel
	nextID  atomic.Uint32

	sftpMu     sync.Mutex
	sftpClient *sftp.Client

	promptsMu    sync.Mutex
	prompts      map[string]chan controlMessage
	nextPromptID atomic.Uint64

	agentForwardSock     string
	agentForwardingReady bool

	tcAddr       tailcat.Addr
	tcKey        key.NodePrivate
	tcDERPMapURL string

	tcMu     sync.Mutex
	tcClient *tailcat.Client
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

func (a *agentSession) forwardClient() interface {
	Dial(network, addr string) (net.Conn, error)
} {
	if a.tcAddr == "" {
		return a.client()
	}
	a.tcMu.Lock()
	defer a.tcMu.Unlock()
	if a.tcClient == nil {
		a.tcClient = &tailcat.Client{
			Server:     a.tcAddr,
			Key:        a.tcKey,
			DERPMapURL: a.tcDERPMapURL,
		}
	}
	return &tailcatForwardClient{cl: a.tcClient}
}

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
			tcKey, err := tailcatKeyFromName(opts.key)
			if err != nil {
				closeClients(chain)
				return fmt.Errorf("resolving --key %q for forwarding: %w", opts.key, err)
			}
			a.tcAddr = tailcat.Addr(hop)
			a.tcKey = tcKey
			a.tcDERPMapURL = opts.derpMapURL
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
	a.tcMu.Lock()
	if a.tcClient != nil {
		a.tcClient.Close()
	}
	a.tcMu.Unlock()
	closeClients(a.hops)
}

const (
	keepaliveInterval = 30 * time.Second
	keepaliveTimeout  = 15 * time.Second
)

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

func (a *agentSession) reportConnectionLost(err error) {
	a.writeError(0, errConnectionLost, err)
	if client := a.client(); client != nil {
		client.Close()
	}
}

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

// writeOpenError reports a failure to open a channel, before any channel ID
// exists to key it by -- correlated instead by the open_channel request's
// own RequestID, echoed back the same way channel_opened is (see
// openChannel and its handlers). The caller may already have stopped
// waiting on requestID by the time this arrives, in which case it's simply
// dropped: an open failure has nothing left to leak.
func (a *agentSession) writeOpenError(requestID string, code errorCode, err error) error {
	return a.writeControl(0, controlMessage{Msg: "error", RequestID: requestID, Code: code, Message: err.Error()})
}

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
	defer a.promptsMu.Unlock()
	ch := a.prompts[msg.RequestID]
	if ch != nil {
		// Ignore a duplicate response instead of blocking the only frame reader.
		// Holding promptsMu also prevents closeAllPrompts from closing ch between
		// the lookup and send.
		select {
		case ch <- msg:
		default:
		}
	}
}

func (a *agentSession) handleData(channelID uint32, payload []byte) {
	ch := a.channel(channelID)
	if ch == nil {
		return
	}
	switch {
	case ch.stdin != nil:
		// A failure here isn't reported as a channel error: the session's
		// own exit (session.Wait(), in waitChannel) is what determines the
		// channel's real outcome, and normally arrives on its own shortly
		// after stdin breaks. Logged rather than silently dropped so it's
		// at least visible in diagnostics if the exit itself is delayed or
		// doesn't explain what happened.
		if _, err := ch.stdin.Write(payload); err != nil {
			fmt.Fprintf(os.Stderr, "meowshell: writing to channel %d's remote stdin: %v\n", channelID, err)
		}
	case ch.sftpFile != nil && ch.isUpload:
		if ch.uploadErr != nil {
			// Already failed: don't keep writing to (or erroring about) a
			// file finalizeUpload is going to report as failed regardless.
			return
		}
		if _, err := ch.sftpFile.Write(payload); err != nil {
			ch.uploadErr = err
			a.writeError(channelID, classifySFTPError(err), err)
		}
	}
}

func (a *agentSession) channel(id uint32) *agentChannel {
	a.chansMu.Lock()
	defer a.chansMu.Unlock()
	return a.chans[id]
}

func (a *agentSession) openChannel(msg controlMessage) {
	switch msg.Kind {
	case "sftp_upload", "sftp_download":
		a.openSFTPChannel(msg)
	case "forward_local", "forward_remote", "forward_socks":
		a.openForwardChannel(msg)
	case "shell", "exec":
		a.openShellChannel(msg)
	default:
		// Fail closed: an unrecognized kind (a protocol bug, version skew,
		// or a typo) used to fall through to opening an interactive shell,
		// the same as a legitimate "shell" request -- silently doing the
		// most privileged thing available instead of refusing what it
		// doesn't understand.
		a.writeOpenError(msg.RequestID, errProtocolError, fmt.Errorf("unknown open_channel kind %q", msg.Kind))
	}
}

func (a *agentSession) openShellChannel(msg controlMessage) {
	session, err := a.client().NewSession()
	if err != nil {
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("opening session: %w", err))
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
			a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("requesting a pseudo-terminal: %w", err))
			return
		}
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("opening remote stdin: %w", err))
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("opening remote stdout: %w", err))
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		session.Close()
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("opening remote stderr: %w", err))
		return
	}

	id := a.nextID.Add(1)
	ch := &agentChannel{session: session, stdin: stdin}
	a.chansMu.Lock()
	a.chans[id] = ch
	a.chansMu.Unlock()

	// RequestAgentForwarding must happen before Start/Shell (the remote
	// shell only picks up forwarding if it's requested before the shell
	// process starts), but reporting its failure is deferred until after
	// channel_opened below -- it's non-fatal to the channel itself (the
	// shell/exec still works, just without forwarding), and channel_opened
	// no longer precedes Start/Shell, so there's no longer an already-open
	// channel to report it on until that's succeeded.
	var forwardingErr error
	if a.agentForwardingReady {
		forwardingErr = agent.RequestAgentForwarding(session)
	}

	switch msg.Kind {
	case "exec":

		err = session.Start(strings.Join(msg.Command, " "))
	default:
		err = session.Shell()
	}
	if err != nil {
		// Reported via writeOpenError (correlated by RequestID, not a
		// channel ID), not writeError: channel_opened is deliberately sent
		// only once Start/Shell has actually succeeded, so a caller never
		// sees a channel reported as open that immediately turns out not to
		// be -- a channel_opened-then-error sequence the caller would have
		// to specifically account for, versus a single, already-handled
		// open failure.
		a.removeChannel(id)
		session.Close()
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("starting session: %w", err))
		return
	}

	if err := a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID}); err != nil {
		a.removeChannel(id)
		session.Close()
		return
	}

	if forwardingErr != nil {
		a.writeError(id, errUnknown, fmt.Errorf("requesting agent forwarding: %w", forwardingErr))
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.pumpToClient(id, streamStdout, stdout) }()
	go func() { defer wg.Done(); a.pumpToClient(id, streamStderr, stderr) }()
	go a.waitChannel(id, ch, &wg)
}

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
