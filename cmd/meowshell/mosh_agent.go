package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	mosh "github.com/unixshells/mosh-go"
)

// mosh-agent is intentionally handled during package initialization rather
// than in main's human-facing command switch. It is a private, framed
// subprocess protocol used by the .NET client, just like "agent"; keeping the
// entry point here makes the Mosh transport self-contained and prevents its
// protocol-only command from becoming part of the user-facing CLI surface.
func init() {
	if len(os.Args) < 2 || os.Args[1] != "mosh-agent" {
		return
	}
	if err := moshAgentCmd(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "meowshell mosh-agent: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

var moshConnectPattern = regexp.MustCompile(`(?m)^MOSH CONNECT ([0-9]+) ([A-Za-z0-9+/=]+)\s*$`)

type moshAgentRuntime struct {
	mu     sync.RWMutex
	client *mosh.Client
	done   chan struct{}
	once   sync.Once
}

func newMoshAgentRuntime() *moshAgentRuntime {
	return &moshAgentRuntime{done: make(chan struct{})}
}

func (r *moshAgentRuntime) setClient(client *mosh.Client) {
	r.mu.Lock()
	r.client = client
	r.mu.Unlock()
}

func (r *moshAgentRuntime) getClient() *mosh.Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.client
}

func (r *moshAgentRuntime) close() {
	r.once.Do(func() {
		if client := r.getClient(); client != nil {
			client.Close()
		}
		close(r.done)
	})
}

func moshAgentCmd(args []string) error {
	fs := flag.NewFlagSet("mosh-agent", flag.ContinueOnError)
	port := fs.String("p", "22", "SSH bootstrap port")
	knownHosts := fs.String("known-hosts", "", "known_hosts file for the SSH bootstrap")
	proxyURL := fs.String("proxy", "", "SOCKS5 or HTTP CONNECT proxy for the SSH bootstrap")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("mosh-agent needs exactly one SSH destination")
	}
	destination := fs.Arg(0)
	if looksLikeTailcatAddress(destination) {
		return errors.New("Mosh requires direct UDP reachability and cannot use a tailcat address")
	}

	agent := newAgentSession(os.Stdin, os.Stdout)
	cfg, err := agent.readConfigure()
	if err != nil {
		return err
	}

	runtime := newMoshAgentRuntime()
	frameErr := make(chan error, 1)
	go func() { frameErr <- serveMoshFrames(agent, runtime) }()

	auth, err := agent.buildAuthMethods(cfg)
	if err != nil {
		runtime.close()
		return err
	}
	defer agent.closeAuthAgent()

	if err := agent.connect(context.Background(), connectOptions{
		destination:    destination,
		port:           *port,
		knownHostsPath: *knownHosts,
		proxyURL:       *proxyURL,
		auth:           auth,
	}); err != nil {
		runtime.close()
		agent.writeError(0, classifyConnectError(err), err)
		return err
	}

	moshPort, key, err := bootstrapMosh(agent)
	if err != nil {
		runtime.close()
		agent.closeHops()
		agent.writeError(0, errUnknown, err)
		return err
	}

	host, err := resolveMoshDestination(destination, *port)
	if err != nil {
		runtime.close()
		agent.closeHops()
		agent.writeError(0, errNetworkUnreachable, err)
		return err
	}
	client, err := mosh.Dial(host, moshPort, key)
	if err != nil {
		runtime.close()
		agent.closeHops()
		agent.writeError(0, errNetworkUnreachable, fmt.Errorf("dialing Mosh UDP endpoint: %w", err))
		return err
	}
	runtime.setClient(client)

	// SSH is only the authenticated bootstrap. Releasing it here is important:
	// the Mosh session must continue across SSH/TCP loss and network changes.
	agent.closeHops()
	if err := agent.writeControl(0, controlMessage{Msg: "connected"}); err != nil {
		runtime.close()
		return err
	}

	go pumpMoshOutput(agent, runtime)
	select {
	case err := <-frameErr:
		runtime.close()
		return err
	case <-runtime.done:
		return nil
	}
}

func bootstrapMosh(agent *agentSession) (int, string, error) {
	client := agent.client()
	if client == nil {
		return 0, "", errors.New("SSH bootstrap connection is unavailable")
	}
	session, err := client.NewSession()
	if err != nil {
		return 0, "", fmt.Errorf("opening Mosh bootstrap session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput("mosh-server new -s -c 256 -l LANG=C.UTF-8")
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return 0, "", fmt.Errorf("starting mosh-server: %s", message)
	}
	match := moshConnectPattern.FindSubmatch(output)
	if len(match) != 3 {
		return 0, "", errors.New("mosh-server did not return a MOSH CONNECT line; ensure mosh-server is installed and available on PATH")
	}
	moshPort, err := strconv.Atoi(string(match[1]))
	if err != nil || moshPort < 1 || moshPort > 65535 {
		return 0, "", fmt.Errorf("mosh-server returned invalid UDP port %q", match[1])
	}
	return moshPort, string(match[2]), nil
}

func resolveMoshDestination(destination, sshPort string) (string, error) {
	_, hostPort := splitUserHost(destination, sshPort)
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", fmt.Errorf("parsing Mosh destination: %w", err)
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", fmt.Errorf("Mosh client currently requires an IPv4 destination")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolving Mosh destination %q: %w", host, err)
	}
	for _, address := range addresses {
		if v4 := address.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("Mosh destination %q has no IPv4 address", host)
}

func serveMoshFrames(agent *agentSession, runtime *moshAgentRuntime) error {
	for {
		frame, err := readFrame(agent.in)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				runtime.close()
				return nil
			}
			runtime.close()
			return err
		}
		switch frame.Type {
		case frameTypeData:
			client := runtime.getClient()
			if client == nil {
				continue
			}
			client.Send(frame.Payload)
		case frameTypeControl:
			var msg controlMessage
			if err := jsonUnmarshalControl(frame.Payload, &msg); err != nil {
				return err
			}
			if msg.Msg == "prompt_response" {
				agent.deliverPromptResponse(msg)
				continue
			}
			// close_channel must end the session even if the Mosh client
			// doesn't exist yet: this frame is how DisposeAsync tells the
			// agent to stop, and it can arrive during the SSH bootstrap or
			// the mosh-server dial, before setClient has ever run. Gating
			// it behind "a client exists" (as it used to be, alongside
			// resize below) silently dropped a cancellation sent in that
			// window instead of ending the session -- serveMoshFrames just
			// kept reading, relying on the client's stdin eventually
			// closing some other way to notice at all.
			if msg.Msg == "close_channel" {
				runtime.close()
				return nil
			}
			client := runtime.getClient()
			if client == nil {
				continue
			}
			if msg.Msg == "resize" {
				if msg.Cols > 0 && msg.Rows > 0 && msg.Cols <= 65535 && msg.Rows <= 65535 {
					client.Resize(uint16(msg.Cols), uint16(msg.Rows))
				}
			}
		default:
			return fmt.Errorf("unknown Mosh frame type %d", frame.Type)
		}
	}
}

func jsonUnmarshalControl(payload []byte, msg *controlMessage) error {
	if err := json.Unmarshal(payload, msg); err != nil {
		return fmt.Errorf("decoding Mosh control frame: %w", err)
	}
	return nil
}

func pumpMoshOutput(agent *agentSession, runtime *moshAgentRuntime) {
	for {
		select {
		case <-runtime.done:
			return
		default:
		}
		client := runtime.getClient()
		if client == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		output := client.Recv(500 * time.Millisecond)
		if len(output) == 0 {
			continue
		}
		if err := agent.writeData(1, streamStdout, output); err != nil {
			runtime.close()
			return
		}
	}
}
