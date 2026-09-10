package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
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
//
// Only works against a general SSH host, not against tailcat's own
// embedded service: tailcat_ssh.go registers no "direct-tcpip" channel
// handler and no "tcpip-forward" request handler at all (confirmed
// against its source), so a tailcat server always refuses the channel
// forward_local/forward_socks need and the global request forward_remote
// needs -- this isn't a bug here to fix, tailcat's minimal SSH server
// simply never implemented forwarding. The listener itself still opens
// successfully either way (nothing about accepting a connection touches
// the remote yet); the failure lands per forwarded connection instead,
// silently closing it rather than reporting an error back over the
// control channel -- a known, minor gap (see proxyForwardedConn) rather
// than something a caller can currently distinguish from "the backend
// simply refused."
//
// forward_local and forward_socks create a *local* listener, which needs
// its own access control: see resolveLocalListener. forward_remote does
// not -- its "listener" is virtual, implemented entirely over the SSH
// wire protocol (client.Listen / tcpip-forward) with no local socket of
// any kind, so nothing else on this machine can reach it that way.
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

// resolveLocalListener builds the local listener a forward_local/
// forward_socks request asks for. Two shapes:
//
//   - ListenNetwork "unix": ListenAddr is a filesystem path. The
//     recommended choice -- a Unix socket is protected by ordinary file
//     permissions (restricted to 0600 here, regardless of umask), so only
//     this process's own user can connect to it. Critically, on Android
//     that means only *this app* can reach it: unlike a TCP socket on
//     127.0.0.1, which most platforms (Android included) let any other
//     local process connect to, a Unix socket under the app's own private
//     files directory is off-limits to every other app on the device.
//   - ListenNetwork "" or "tcp": ListenAddr is a "host:port". Restricted
//     to loopback (127.0.0.0/8, ::1, or "localhost") unless
//     AllowNonLoopbackBind is set, so a caller can't expose a forward or
//     SOCKS proxy to the whole LAN by accident -- opting into a wider
//     bind is a deliberate act, not a default.
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

// isLoopbackListenAddr reports whether addr ("host:port", or ":port" for
// an OS-assigned port on every interface) names only loopback interfaces.
// An empty host means "all interfaces" in net.Listen and is never
// loopback, matching that same meaning here.
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

// listenUnix binds a Unix domain socket at path, clearing a stale socket
// a crashed previous instance may have left behind first (a fresh Listen
// otherwise fails with "address already in use"), and restricting the
// resulting file to this process's own user -- a fresh AF_UNIX socket's
// permissions otherwise just follow the umask, which can be far more
// permissive than that. Go's net.UnixListener removes the socket file on
// Close on its own, so no matching cleanup is needed at that end.
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

// openLocalForward implements "-L": the agent listens (see
// resolveLocalListener), and forwards each accepted connection to
// RemoteAddr through the SSH client (client.Dial), the same as OpenSSH's
// -L.
func (a *agentSession) openLocalForward(msg controlMessage) {
	ln, err := resolveLocalListener(msg)
	if err != nil {
		a.writeError(0, errUnknown, err)
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
// end of the connection. No local listener of any kind is created here
// (see this file's top-level doc comment), so resolveLocalListener/UDS/
// loopback restriction don't apply.
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
// server on the listener resolveLocalListener builds, gated by
// SocksUsername/SocksPassword when either is set (RFC 1929), dialing each
// requested destination through the SSH client.
func (a *agentSession) openSOCKSForward(msg controlMessage) {
	ln, err := resolveLocalListener(msg)
	if err != nil {
		a.writeError(0, errUnknown, err)
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
			go serveSOCKS5(conn, client, msg.SocksUsername, msg.SocksPassword)
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
// request, then hands the connection to proxyForwardedConn like any other
// forwarded one. Anything else -- BIND, UDP ASSOCIATE -- gets rejected; a
// SOCKS client asking for either is not this feature's use case (routing
// an app's outbound TCP through the SSH connection). When username or
// password is non-empty, RFC 1929 username/password auth is required
// (the only method offered besides "none"); a client that doesn't
// support it, or doesn't present this exact pair, never reaches the
// CONNECT stage at all.
func serveSOCKS5(conn net.Conn, client interface {
	Dial(network, addr string) (net.Conn, error)
}, username, password string) {
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

	requireAuth := username != "" || password != ""
	const (
		methodNone      = 0x00
		methodUserPass  = 0x02
		methodNoneUsage = methodNone
	)
	selected := byte(methodNoneUsage)
	if requireAuth {
		if !containsByte(methods, methodUserPass) {
			conn.Write([]byte{0x05, 0xFF}) // no acceptable method
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

// authenticateSOCKS5 reads one RFC 1929 username/password negotiation
// message and replies with its status byte, reporting whether the
// presented credentials matched. Comparisons are constant-time so a
// client can't learn anything about a wrong token's length or contents
// from response timing.
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

// writeSOCKS5Reply writes a reply with a fixed 0.0.0.0:0 bound address --
// this proxy never actually binds a local address on the target's behalf,
// and no SOCKS client this is meant to serve inspects that field.
func writeSOCKS5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
