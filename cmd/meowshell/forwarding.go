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

const maxForwardConnections = 65_535

func (a *agentSession) openForwardChannel(msg controlMessage) {
	if msg.MaxConnections < 0 || msg.MaxConnections > maxForwardConnections {
		a.writeOpenError(msg.RequestID, errProtocolError,
			fmt.Errorf("max_connections must be between 0 (unlimited) and %d", maxForwardConnections))
		return
	}
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
	// net.Listen creates the socket file at default (umask-derived)
	// permissions; only the Chmod below narrows it to the owner. Without
	// withRestrictedUmask, that's a brief window in which another local
	// user could connect before access is restricted. Chmod still runs
	// unconditionally afterward as a backstop.
	var ln net.Listener
	err := withRestrictedUmask(func() error {
		var lnErr error
		ln, lnErr = net.Listen("unix", path)
		return lnErr
	})
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
	client, err := a.forwardClient()
	if err != nil {
		ln.Close()
		a.writeOpenError(msg.RequestID, errConnectionLost, err)
		return
	}
	id, err := a.registerForward(ln)
	if err != nil {
		ln.Close()
		a.writeOpenError(msg.RequestID, errUnknown, err)
		return
	}
	a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID, BoundAddr: ln.Addr().String()})

	acceptForwardedConns(ln, msg.MaxConnections, func(conn net.Conn) {
		proxyForwardedConn(conn, func() (net.Conn, error) {
			var abort func()
			if a.tcAddr == "" {
				// *ssh.Client.Dial has no cancellable request primitive. If a
				// remote SSH server stops answering forwarded-channel opens,
				// returning a timeout without closing the transport leaves the
				// dial goroutine blocked forever. Abort the SSH connection so
				// the request actually unwinds instead of becoming a leak.
				abort = func() {
					a.reportConnectionLost(fmt.Errorf("forward dial to %s timed out after %s", msg.RemoteAddr, tcpDialTimeout))
				}
			}
			return dialWithTimeout(client.Dial, "tcp", msg.RemoteAddr, tcpDialTimeout, abort)
		})
	})
}

func (a *agentSession) openRemoteForward(msg controlMessage) {
	client := a.client()
	if client == nil {
		a.writeOpenError(msg.RequestID, errConnectionLost, fmt.Errorf("SSH connection is no longer available"))
		return
	}
	ln, err := client.Listen("tcp", msg.ListenAddr)
	if err != nil {
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("asking the remote to listen on %s: %w", msg.ListenAddr, err))
		return
	}
	id, err := a.registerForward(ln)
	if err != nil {
		ln.Close()
		a.writeOpenError(msg.RequestID, errUnknown, err)
		return
	}
	a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID, BoundAddr: ln.Addr().String()})

	acceptForwardedConns(ln, msg.MaxConnections, func(conn net.Conn) {
		proxyForwardedConn(conn, func() (net.Conn, error) {
			d := net.Dialer{Timeout: tcpDialTimeout}
			return dialWithTimeout(d.Dial, "tcp", msg.RemoteAddr, tcpDialTimeout, nil)
		})
	})
}

func (a *agentSession) openSOCKSForward(msg controlMessage) {
	ln, err := resolveLocalListener(msg)
	if err != nil {
		a.writeOpenError(msg.RequestID, errUnknown, err)
		return
	}
	client, err := a.forwardClient()
	if err != nil {
		ln.Close()
		a.writeOpenError(msg.RequestID, errConnectionLost, err)
		return
	}
	id, err := a.registerForward(ln)
	if err != nil {
		ln.Close()
		a.writeOpenError(msg.RequestID, errUnknown, err)
		return
	}
	a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID, BoundAddr: ln.Addr().String()})

	acceptForwardedConns(ln, msg.MaxConnections, func(conn net.Conn) {
		var abort func()
		if a.tcAddr == "" {
			abort = func() {
				a.reportConnectionLost(fmt.Errorf("SOCKS forward dial timed out after %s", tcpDialTimeout))
			}
		}
		serveSOCKS5(conn, client, msg.SocksUsername, msg.SocksPassword, abort)
	})
}

// acceptForwardedConns runs ln's accept loop on its own goroutine, handing
// each accepted connection to handle on a further goroutine of its own so
// one slow connection can't hold up accepting the next. maxConnections, when
// positive, bounds how many of those handler goroutines may be in flight at
// once: the accept loop blocks acquiring a slot before calling Accept again,
// so once the limit is reached, further connections simply queue in the
// listen backlog (or get refused once that fills) instead of an unbounded
// number of goroutines, file descriptors, and dial attempts piling up for a
// single forward. Zero (the default) means unlimited, matching every
// forward's behavior before this limit existed.
func acceptForwardedConns(ln net.Listener, maxConnections int, handle func(net.Conn)) {
	var sem chan struct{}
	if maxConnections > 0 {
		sem = make(chan struct{}, maxConnections)
	}
	go func() {
		for {
			if sem != nil {
				sem <- struct{}{}
			}
			conn, err := ln.Accept()
			if err != nil {
				if sem != nil {
					<-sem
				}
				return
			}
			go func() {
				defer func() {
					if sem != nil {
						<-sem
					}
				}()
				handle(conn)
			}()
		}
	}()
}

// dialWithTimeout bounds a dial func that has no timeout of its own --
// *ssh.Client.Dial (used for forward_local/forward_socks against a plain
// SSH destination, via forwardClient) and net.Dial (used for
// forward_remote's target) both block indefinitely against an unresponsive
// target (e.g. a firewall silently dropping SYNs), unlike tailcat-backed
// forwarding, which already enforces tcpDialTimeout internally. If the dial
// does eventually complete after the timeout, the orphaned connection is
// closed rather than leaked.
func dialWithTimeout(dial func(network, addr string) (net.Conn, error), network, addr string, timeout time.Duration, onTimeout func()) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dial(network, addr)
		ch <- result{conn, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res.conn, res.err
	case <-timer.C:
		if onTimeout != nil {
			onTimeout()
		}
		// If the underlying dial eventually returns after the timeout, close
		// the late connection. For the plain-SSH case onTimeout closes the
		// transport, which also forces the otherwise-uncancellable Dial call
		// itself to unwind.
		go func() {
			if res := <-ch; res.conn != nil {
				res.conn.Close()
			}
		}()
		return nil, fmt.Errorf("dial %s %s: timed out after %s", network, addr, timeout)
	}
}

func (a *agentSession) registerForward(ln net.Listener) (uint32, error) {
	return a.registerChannel(&agentChannel{listener: ln})
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
}, username, password string, abortDialOnTimeout func()) {
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

	remote, err := dialWithTimeout(client.Dial, "tcp", target, tcpDialTimeout, abortDialOnTimeout)
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
