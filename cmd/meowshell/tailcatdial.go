package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

// tailcatForwardClient adapts a *tailcat.Client to the small Dial-shaped
// interface forwarding.go's openLocalForward/openSOCKSForward already take
// (the same one a.client(), the *ssh.Client, satisfies for a general SSH
// host) -- so forward_local/forward_socks can reuse that exact code
// unmodified against a tailcat destination too, dialing through tailcat's
// own client-side WireGuard connection instead of an SSH direct-tcpip
// channel, which tailcat's own embedded SSH service never implements (see
// forwarding.go's package doc comment). This mirrors what tailcat's own
// "forward"/"socks" subcommands do (cmd/tailcat/forward.go's
// forwardListener, cmd/tailcat/tailcat.go's dialSOCKSTarget) -- forwarding
// through a tailcat server was never an SSH feature there either.
type tailcatForwardClient struct {
	cl *tailcat.Client
}

// Dial implements forwarding.go's client interface. network is always
// "tcp" here (forward_local/forward_socks never ask for anything else,
// unlike tailcat's own SOCKS5 UDP ASSOCIATE support, which this doesn't
// need). addr is a "host:port": a target on the tailcat server's own
// loopback dials that port on the server itself (DialTCPPort), matching a
// bare-port mapping in "tailcat forward"'s own syntax; anything else is
// routed through the server acting as an exit node (DialTCP), matching a
// "local:remote-ip:remote-port" mapping there -- just always spelled as a
// full host:port here, since that's this protocol's own RemoteAddr/SOCKS
// CONNECT shape rather than a mapping string to parse.
func (c *tailcatForwardClient) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("tailcat forwarding only supports tcp, not %q", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid forward target %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid forward target port %q: %w", portStr, err)
	}
	ctx := context.Background()
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return c.cl.DialTCPPort(ctx, uint16(port))
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Prefer an IPv4 result, same as tailcat's own classifySOCKSAddr:
		// it rides the exit node's NAT64 mapping, and the server may not
		// have IPv6 connectivity of its own at all.
		ips, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if lookupErr != nil {
			return nil, fmt.Errorf("resolving forward target host %q: %w", host, lookupErr)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for forward target host %q", host)
		}
		ip = ips[0]
		for _, a := range ips {
			if a.Unmap().Is4() {
				ip = a
				break
			}
		}
	}
	return c.cl.DialTCP(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
}

// tailcatKeyFromName resolves a "--key" value the same way tailcat's own
// CLI does (cmd/tailcat's clientKey/keyPath -- not importable from here,
// since they live in a main package and this one needs its own copy): an
// empty or "new" value means a fresh ephemeral node identity; anything
// containing a path separator is a literal path to a key file; anything
// else is a name under tailcat's own on-disk key directory, what
// "tailcat genkey" itself writes to.
func tailcatKeyFromName(name string) (key.NodePrivate, error) {
	if name == "" || name == "new" {
		return key.NewNode(), nil
	}
	path := name
	if !strings.ContainsAny(name, `/\`) {
		confDir, err := os.UserConfigDir()
		if err != nil {
			return key.NodePrivate{}, err
		}
		path = filepath.Join(confDir, "tailcat", "keys", name+".private.json")
	}
	j, err := os.ReadFile(path)
	if err != nil {
		return key.NodePrivate{}, err
	}
	var conf tailcat.PrivateKey
	if err := json.Unmarshal(j, &conf); err != nil {
		return key.NodePrivate{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return conf.Private, nil
}
