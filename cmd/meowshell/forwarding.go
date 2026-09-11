package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
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
		a.writeOpenError(msg.RequestID, errProtocolError, fmt.Errorf("unknown open_channel kind %q", msg.Kind))
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
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove non-socket path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing stale socket %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("checking stale socket %s: %w", path, err)
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
		a.writeOpenError(msg.RequestID, errUnknown, err)
		return
	}
	client := a.forwardClient()
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID, BoundAddr: ln.Addr().String()})

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
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("asking the remote to listen on %s: %w", msg.ListenAddr, err))
		return
	}
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID, BoundAddr: ln.Addr().String()})

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
		a.writeOpenError(msg.RequestID, errUnknown, err)
		return
	}
	client := a.forwardClient()
	id := a.registerForward(ln)
	a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID, BoundAddr: ln.Addr().String()})

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

// halfCloser is implemented by *net.TCPConn and *net.UnixConn, the two
// concrete connection types actually passed as conn/remote here (accepted
// TCP/Unix forwards, and ssh.Client.Dial's own net.Conn). Where it's
// available, closing only the write half on EOF lets a client that has
// finished sending (an explicit CloseWrite, not just going idle) still
// receive a response the other side hasn't finished sending yet, instead of
// the whole connection dying the instant one direction goes quiet.
type halfCloser interface {
	CloseWrite() error
}

func proxyForwardedConn(conn io.ReadWriteCloser, dial func() (net.Conn, error)) {
	defer conn.Close()
	remote, err := dial()
	if err != nil {
		return
	}
	defer remote.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, conn)
		if hc, ok := remote.(halfCloser); ok {
			hc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, remote)
		if hc, ok := conn.(halfCloser); ok {
			hc.CloseWrite()
		}
	}()
	// Wait for both directions, not just the first to finish: with EOF
	// alone now only half-closing (above) instead of tearing down the
	// whole connection, returning early here would still cut off whichever
	// direction is still in flight via the deferred Close calls.
	wg.Wait()
}

// socksHandshakeTimeout bounds the unauthenticated SOCKS5 negotiation (the
// greeting, credentials, and CONNECT request) so a slow or silent client
// can't hold a goroutine and socket open indefinitely. Normally that's a
// self-inflicted local resource concern at worst -- these listeners default
// to loopback -- but OpenSocksForwardAsync/OpenSocksForwardOnUnixSocketAsync
// can opt into a wider bind (allowNonLoopbackBind), at which point it
// becomes remotely triggerable and matters for real. Reset once the tunnel
// is established: the data-relay phase that follows has no business timing
// out on its own. A var, not a const, so a test can shrink it rather than
// waiting out the real 30s to exercise the deadline.
var socksHandshakeTimeout = 30 * time.Second

func serveSOCKS5(conn net.Conn, client interface {
	Dial(network, addr string) (net.Conn, error)
}, username, password string) {
	defer func() {
		if r := recover(); r != nil {
			conn.Close()
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		conn.Close()
		return
	}

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
		methodNone         = 0x00
		methodUserPass     = 0x02
		methodNoAcceptable = 0xFF
	)
	var selected byte
	switch {
	case requireAuth && containsByte(methods, methodUserPass):
		selected = methodUserPass
	case !requireAuth && containsByte(methods, methodNone):
		selected = methodNone
	default:
		// Either the client didn't offer the one method this listener
		// actually supports (RFC 1928 3.1: the reply must be a method the
		// client offered, never one it didn't), or auth is required and it
		// offered something else entirely.
		conn.Write([]byte{0x05, methodNoAcceptable})
		conn.Close()
		return
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
	// The handshake is done; a long-lived data relay is the point from
	// here on, not something to time out on its own.
	if err := conn.SetDeadline(time.Time{}); err != nil {
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
