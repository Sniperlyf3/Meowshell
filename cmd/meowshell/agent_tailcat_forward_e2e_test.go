package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentForwardsThroughTailcatDestination(t *testing.T) {
	tailcatBin := findE2EBinary(t, "TAILCAT", "tailcat_linux_amd64")
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("TS_DEBUG_TAILCAT_LOCAL_DERP", "1")

	addr := startE2EServerWithExitNode(t, tailcatBin, meowshellBin, home)

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	const backendReply = "hello from the tailcat-forwarded backend"
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, backendReply)
			}()
		}
	}()
	_, backendPort, err := net.SplitHostPort(backendLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(meowshellBin, "agent", "--tailcat="+tailcatBin, addr)
	cmd.Env = append(os.Environ(), "TAILCAT_BIN="+tailcatBin, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting meowshell agent: %v", err)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
		if t.Failed() {
			t.Logf("agent stderr:\n%s", stderr.String())
		}
	})

	out := bufio.NewReader(stdout)
	send(t, stdin, 0, controlMessage{Msg: "configure"})
	expectConnected(t, out)

	t.Run("forward_local", func(t *testing.T) {
		send(t, stdin, 0, controlMessage{
			Msg: "open_channel", Kind: "forward_local",
			ListenAddr: "127.0.0.1:0", RemoteAddr: "localhost:" + backendPort,
		})
		f := mustReadFrame(t, out)
		opened := decodeControl(t, f)
		if opened.Msg != "channel_opened" || opened.BoundAddr == "" {
			t.Fatalf("channel_opened = %+v, want a non-empty BoundAddr", opened)
		}

		conn, err := net.DialTimeout("tcp", opened.BoundAddr, 10*time.Second)
		if err != nil {
			t.Fatalf("dialing the forwarded local listener: %v", err)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("reading through the forward: %v", err)
		}
		if string(got) != backendReply {
			t.Errorf("got %q through the tailcat-destination forward, want %q", got, backendReply)
		}
	})

	t.Run("forward_socks", func(t *testing.T) {
		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "forward_socks", ListenAddr: "127.0.0.1:0"})
		f := mustReadFrame(t, out)
		opened := decodeControl(t, f)
		if opened.Msg != "channel_opened" || opened.BoundAddr == "" {
			t.Fatalf("channel_opened = %+v, want a non-empty BoundAddr", opened)
		}

		conn, err := net.DialTimeout("tcp", opened.BoundAddr, 10*time.Second)
		if err != nil {
			t.Fatalf("dialing the SOCKS listener: %v", err)
		}
		defer conn.Close()
		got, err := socks5Connect(conn, "localhost:"+backendPort)
		if err != nil {
			t.Fatalf("SOCKS5 CONNECT: %v", err)
		}
		if got != backendReply {
			t.Errorf("got %q through SOCKS against a tailcat destination, want %q", got, backendReply)
		}
	})
}

func startE2EServerWithExitNode(t *testing.T, tailcatBin, meowshellBin, home string) string {
	t.Helper()
	addrFile := filepath.Join(home, "addr")
	cmd := exec.Command(meowshellBin, "serve", "--insecure-no-auth", "--exit-node", "--tailcat="+tailcatBin)
	cmd.Env = append(os.Environ(),
		"TAILCAT_BIN="+tailcatBin,
		"TAILCAT_ADDR_FILE="+addrFile,
		"HOME="+home,
		"TS_DEBUG_TAILCAT_LOCAL_DERP=1",
	)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tailcat serve: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("server log:\n%s", out.String())
		}
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(addrFile); err == nil && len(data) > 0 {
			return string(bytes.TrimSpace(data))
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server never published an address; log:\n%s", out.String())
	return ""
}
