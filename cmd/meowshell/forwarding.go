package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

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

func resolveLocalListener(msg controlMessage) (net.Listener, error) {
	switch msg.ListenNetwork {
	case "", "tcp":
		if !msg.AllowNonLoopbackBind && !isLoopbackListenAddr(msg.ListenAddr) {
			return nil, fmt.Errorf("refusing to bind %q: not a loopback address (set allow_non_loopback_bind to allow a wider bind deliberately)", msg.ListenAddr)
		}
		return net.Listen("tcp", msg.ListenAddr)
	case "unix":
		return listenUnix(msg.ListenAddr)
	default:
		return nil, fmt.Errorf("unknown listen_network %q (want \"tcp\" or \"unix\")", msg.ListenNetwork)
	}
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func listenUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("a unix listen_network needs a non-empty socket path")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale socket %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("restricting socket permissions: %w", err)
	}
	return ln, nil
}

func (a *agentSession) openLocalForward(msg controlMessage) {
	ln, err := resolveLocalListener(msg)
	if err != nil {
		a.writeError(0, errUnknown, err)
		return
	}
	client := a.forwardClient()
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", BoundAddr: ln.Addr().String()})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxyForwardedConn(conn, func() (net.Conn, error) {
				return client.Dial("tcp", msg.RemoteAddr)
			})
		}
	}()
}

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

func (a *agentSession) openSOCKSForward(msg controlMessage) {
	ln, err := resolveLocalListener(msg)
	if err != nil {
		a.writeError(0, errUnknown, err)
		return
	}
	client := a.forwardClient()
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", BoundAddr: ln.Addr().String()})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(conn, client, msg.SocksUsername, msg.SocksPassword)
		}
	}()
}

func (a *agentSession) registerForward(ln net.Listener) uint32 {
	id := a.nextID.Add(1)
	a.chansMu.Lock()
	a.chans[id] = &agentChannel{listener: ln}
	a.chansMu.Unlock()
	return id
}

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

func serveSOCKS5(conn net.Conn, client interface {
	Dial(network, addr string) (net.Conn, error)
}, username, password string) {
	defer func() {
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

	requireAuth := username != "" || password != ""
	const (
		methodNone      = 0x00
		methodUserPass  = 0x02
		methodNoneUsage = methodNone
	)
	selected := byte(methodNoneUsage)
	if requireAuth {
		if !containsByte(methods, methodUserPass) {
			conn.Write([]byte{0x05, 0xFF})
			conn.Close()
			return
		}
		selected = methodUserPass
	}
	if _, err := conn.Write([]byte{0x05, selected}); err != nil {
		conn.Close()
		return
	}
	if requireAuth && !authenticateSOCKS5(conn, username, password) {
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
		writeSOCKS5Reply(conn, 0x07)
		conn.Close()
		return
	}

	var host string
	switch req[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			conn.Close()
			return
		}
		host = net.IP(addr).String()
	case 0x03:
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
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			conn.Close()
			return
		}
		host = net.IP(addr).String()
	default:
		writeSOCKS5Reply(conn, 0x08)
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
		writeSOCKS5Reply(conn, 0x05)
		conn.Close()
		return
	}
	if err := writeSOCKS5Reply(conn, 0x00); err != nil {
		conn.Close()
		remote.Close()
		return
	}
	proxyForwardedConn(conn, func() (net.Conn, error) { return remote, nil })
}

func authenticateSOCKS5(conn net.Conn, wantUsername, wantPassword string) bool {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x01 {
		return false
	}
	uname := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return false
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return false
	}
	passwd := make([]byte, plenBuf[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return false
	}

	ok := subtle.ConstantTimeCompare(uname, []byte(wantUsername)) == 1 &&
		subtle.ConstantTimeCompare(passwd, []byte(wantPassword)) == 1
	status := byte(0x01)
	if ok {
		status = 0x00
	}
	if _, err := conn.Write([]byte{0x01, status}); err != nil {
		return false
	}
	return ok
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

func writeSOCKS5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
