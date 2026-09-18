package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

type tailcatForwardClient struct {
	cl *tailcat.Client
}

func tailcatClientDialer(cl *tailcat.Client, port string) (dialer, error) {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, fmt.Errorf("invalid Tailcat SSH port %q", port)
	}
	return func(ctx context.Context) (net.Conn, error) {
		return cl.DialTCPPort(ctx, uint16(p))
	}, nil
}

func (c *tailcatForwardClient) PathStatus() (agentPathStatus, bool) {
	// PathStatus is a small API we add to the pinned Tailcat source in
	// build.sh. Normal vet/unit-test workflows intentionally compile against
	// the pristine upstream checkout before that patch is applied, so keep the
	// optional API behind reflection here. Release binaries are built only
	// after live-path-status.patch has been applied and therefore expose it.
	method := reflect.ValueOf(c.cl).MethodByName("PathStatus")
	if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 2 {
		return agentPathStatus{}, false
	}
	out := method.Call(nil)
	if out[1].Kind() != reflect.Bool || !out[1].Bool() {
		return agentPathStatus{}, false
	}
	return decodeTailcatPathStatus(out[0])
}

func decodeTailcatPathStatus(value reflect.Value) (agentPathStatus, bool) {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return agentPathStatus{}, false
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return agentPathStatus{}, false
	}

	direct := value.FieldByName("Direct")
	endpoint := value.FieldByName("Endpoint")
	relayRegion := value.FieldByName("RelayRegion")
	txBytes := value.FieldByName("TxBytes")
	rxBytes := value.FieldByName("RxBytes")
	if direct.Kind() != reflect.Bool ||
		endpoint.Kind() != reflect.String ||
		relayRegion.Kind() != reflect.String ||
		!isReflectInt(txBytes) ||
		!isReflectInt(rxBytes) {
		return agentPathStatus{}, false
	}

	return agentPathStatus{
		direct:      direct.Bool(),
		endpoint:    endpoint.String(),
		relayRegion: relayRegion.String(),
		txBytes:     txBytes.Int(),
		rxBytes:     rxBytes.Int(),
	}, true
}

func isReflectInt(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}

func (c *tailcatForwardClient) ProbePath(ctx context.Context) error {
	_, err := c.cl.DiscoPing(ctx)
	return err
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

const maxTailcatKeyJSON = 64 << 10

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
	f, err := os.Open(path)
	if err != nil {
		return key.NodePrivate{}, err
	}
	defer f.Close()
	j, err := io.ReadAll(io.LimitReader(f, maxTailcatKeyJSON+1))
	if err != nil {
		return key.NodePrivate{}, err
	}
	if len(j) > maxTailcatKeyJSON {
		return key.NodePrivate{}, fmt.Errorf("key file %s exceeds %d bytes", path, maxTailcatKeyJSON)
	}
	defer clear(j)
	var conf tailcat.PrivateKey
	if err := json.Unmarshal(j, &conf); err != nil {
		return key.NodePrivate{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return conf.Private, nil
}
