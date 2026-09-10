package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// openForwardChannel opens one of the three generic SSH forwarding modes,
// each as its own listener living inside this agent process for as long
// as its channel stays open (unlike a shell/exec/SFTP channel, none of
// these carry their own bytes over the framed protocol at all -- once a
// forwarded connection is accepted, its bytes flow directly between a
// local net.Conn and the SSH client's own Dial/Listen, entirely inside
// this process). Separate from tailcat's own "forward" subcommand
// (MeowshellPortForward), which tunnels through a tailcat *server*
// instead -- a different, still-valid use case this doesn't replace.
func (a *agentSession) openForwardChannel(msg controlMessage) {
	switch msg.Kind {
	case "forward_local":
		a.openLocalForward(msg)
	case "forward_remote":
		a.openRemoteForward(msg)
	case "forward_socks":
		a.openSOCKSForward(msg)
	default:
		a.writeError(0, errProtocolError, fmt.Errorf("unknown open_channel kind %q", msg.Kind))
	}
}

// openLocalForward implements "-L": the agent listens on ListenAddr, and
// forwards each accepted connection to RemoteAddr through the SSH client
// (client.Dial), the same as OpenSSH's -L.
func (a *agentSession) openLocalForward(msg controlMessage) {
	ln, err := net.Listen("tcp", msg.ListenAddr)
	if err != nil {
		a.writeError(0, errUnknown, fmt.Errorf("listening on %s: %w", msg.ListenAddr, err))
		return
	}
	client := a.client()
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", BoundAddr: ln.Addr().String()})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed (close_channel), or a real accept failure either way ends this forward
			}
			go proxyForwardedConn(conn, func() (net.Conn, error) {
				return client.Dial("tcp", msg.RemoteAddr)
			})
		}
	}()
}

// openRemoteForward implements "-R": the agent asks the remote server to
// listen on ListenAddr (client.Listen, SSH's tcpip-forward), and for each
// connection the remote side accepts, dials RemoteAddr locally -- a
// resource on this process's own machine, made reachable from the far
// end of the connection.
func (a *agentSession) openRemoteForward(msg controlMessage) {
	client := a.client()
	ln, err := client.Listen("tcp", msg.ListenAddr)
	if err != nil {
		a.writeError(0, errUnknown, fmt.Errorf("asking the remote to listen on %s: %w", msg.ListenAddr, err))
		return
	}
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", BoundAddr: ln.Addr().String()})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxyForwardedConn(conn, func() (net.Conn, error) {
				return net.Dial("tcp", msg.RemoteAddr)
			})
		}
	}()
}

// openSOCKSForward implements "-D": the agent runs a minimal SOCKS5
// server on ListenAddr (CONNECT only, no authentication -- this listener
// is local to the agent's own machine, the same trust boundary a real
// ssh -D's dynamic port already has), dialing each requested destination
// through the SSH client.
func (a *agentSession) openSOCKSForward(msg controlMessage) {
	ln, err := net.Listen("tcp", msg.ListenAddr)
	if err != nil {
		a.writeError(0, errUnknown, fmt.Errorf("listening on %s: %w", msg.ListenAddr, err))
		return
	}
	client := a.client()
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", BoundAddr: ln.Addr().String()})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(conn, client)
		}
	}()
}

// registerForward allocates a channel ID for a forward's listener,
// storing it as an agentChannel so close_channel can find and stop it the
// same way it closes any other channel kind.
func (a *agentSession) registerForward(ln net.Listener) uint32 {
	id := a.nextID.Add(1)
	a.chansMu.Lock()
	a.chans[id] = &agentChannel{listener: ln}
	a.chansMu.Unlock()
	return id
}

// proxyForwardedConn copies bytes in both directions between conn and
// whatever dial returns, closing both once either side is done -- the
// same shape ssh(1)'s own -L/-R handling uses internally. conn only needs
// to be an io.ReadWriteCloser (not the fuller net.Conn every caller here
// happens to have): an ssh.Channel satisfies it too, which is what a
// direct-tcpip channel on the *serving* end of a connection is (see the
// test helper that exercises this against a real one).
func proxyForwardedConn(conn io.ReadWriteCloser, dial func() (net.Conn, error)) {
	defer conn.Close()
	remote, err := dial()
	if err != nil {
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, remote); done <- struct{}{} }()
	<-done
}

// serveSOCKS5 speaks just enough of RFC 1928 to handle one CONNECT
// request with no authentication, then hands the connection to
// proxyForwardedConn like any other forwarded one. Anything else --
// BIND, UDP ASSOCIATE, an auth method this offers none of -- gets
// rejected; a SOCKS client asking for either is not this feature's
// use case (routing an app's outbound TCP through the SSH connection).
func serveSOCKS5(conn net.Conn, client interface {
	Dial(network, addr string) (net.Conn, error)
}) {
	defer func() {
		// A protocol violation or unsupported request closes conn without
		// forwarding it on; proxyForwardedConn (the success path) takes
		// over closing conn itself once control reaches it below.
		if r := recover(); r != nil {
			conn.Close()
		}
	}()

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x05 {
		conn.Close()
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		conn.Close()
		return
	}
	// 0x00 = no authentication required, the only method offered.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		conn.Close()
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		conn.Close()
		return
	}
	const cmdConnect = 0x01
	if req[0] != 0x05 || req[1] != cmdConnect {
		writeSOCKS5Reply(conn, 0x07) // command not supported
		conn.Close()
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			conn.Close()
			return
		}
		host = net.IP(addr).String()
	case 0x03: // domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return
		}
		name := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			conn.Close()
			return
		}
		host = string(name)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			conn.Close()
			return
		}
		host = net.IP(addr).String()
	default:
		writeSOCKS5Reply(conn, 0x08) // address type not supported
		conn.Close()
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		conn.Close()
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, fmt.Sprint(port))

	remote, err := client.Dial("tcp", target)
	if err != nil {
		writeSOCKS5Reply(conn, 0x05) // connection refused
		conn.Close()
		return
	}
	if err := writeSOCKS5Reply(conn, 0x00); err != nil { // succeeded
		conn.Close()
		remote.Close()
		return
	}
	proxyForwardedConn(conn, func() (net.Conn, error) { return remote, nil })
}

// writeSOCKS5Reply writes a reply with a fixed 0.0.0.0:0 bound address --
// this proxy never actually binds a local address on the target's behalf,
// and no SOCKS client this is meant to serve inspects that field.
func writeSOCKS5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
