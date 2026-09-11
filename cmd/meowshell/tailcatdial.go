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

type tailcatForwardClient struct {
	cl *tailcat.Client
}

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

	ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
	defer cancel()
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return c.cl.DialTCPPort(ctx, uint16(port))
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
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

func tailcatKeyFromName(name string) (key.NodePrivate, error) {
	if name == "" {
		// Mirrors tailcat's own clientKey(): an empty --key means "use the
		// saved client-default key if one exists, else a fresh ephemeral
		// one" -- not unconditionally a fresh ephemeral key. Diverging here
		// meant exit-node forwarding's in-process tailcat.Client could end
		// up using a different identity than the SSH transport subprocess
		// (which, unlike this function, already calls into tailcat's own
		// clientKey()), silently failing authorization against a
		// destination's --allow list that only names the saved
		// client-default key even though the SSH connection itself worked.
		confDir, err := os.UserConfigDir()
		if err != nil {
			return key.NodePrivate{}, err
		}
		if _, err := os.Stat(filepath.Join(confDir, "tailcat", "keys", "client-default.private.json")); err != nil {
			return key.NewNode(), nil
		}
		name = "client-default"
	} else if name == "new" {
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
