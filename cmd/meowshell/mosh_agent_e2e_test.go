package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// These tests exercise the real "mosh-agent" subcommand end to end: a real
// SSH bootstrap (the same in-process fake server agent_tcp_e2e_test.go
// uses), a real system mosh-server for the bootstrap's exec command, and a
// real Mosh/UDP client dialing it -- the same three pieces production wires
// together, just all on loopback. They skip (via findE2EBinary) without a
// built dist/meowshell_linux_amd64, and skip outright if this host has no
// mosh-server on PATH: neither is optional stand-in behavior worth faking,
// since bootstrapMosh's whole job is parsing that program's real output.

func requireMoshServerBinary(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("mosh-server"); err != nil {
		t.Skip("no mosh-server on PATH; install the mosh package to run this test")
	}
}

var moshDetachedPIDPattern = regexp.MustCompile(`pid = (\d+)`)

// moshServerExecHandler answers the exact SSH exec bootstrapMosh sends by
// running the real, installed mosh-server and relaying its output and exit
// status back over the SSH channel -- exactly what a real sshd would do,
// just without the sandboxed environment actually being sshd. Any other
// command is rejected, matching a stricter real host that doesn't run
// arbitrary "unexpected command" sessions.
func moshServerExecHandler(pids chan<- int) func(ssh.Channel, string) {
	return func(ch ssh.Channel, command string) {
		if command != "mosh-server new -s -c 256 -l LANG=C.UTF-8" {
			fmt.Fprintf(ch, "unexpected command: %s\n", command)
			ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{1}))
			return
		}
		out, err := exec.Command("mosh-server", "new", "-s", "-c", "256", "-l", "LANG=C.UTF-8").CombinedOutput()
		ch.Write(out)
		var status uint32
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				status = uint32(exitErr.ExitCode())
			} else {
				status = 1
			}
		}
		if m := moshDetachedPIDPattern.FindSubmatch(out); len(m) == 2 {
			if pid, convErr := strconv.Atoi(string(m[1])); convErr == nil && pids != nil {
				pids <- pid
			}
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{status}))
	}
}

// moshServerNotInstalledExecHandler simulates a bootstrap host that has no
// mosh-server on PATH -- the single most likely real-world failure this
// whole feature has, since it depends on server-side software the SSH
// bootstrap host must provide and meowshell cannot install.
func moshServerNotInstalledExecHandler(ch ssh.Channel, command string) {
	fmt.Fprintf(ch, "bash: %s: command not found\n", command)
	ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{127}))
}

func startMoshAgent(t *testing.T, meowshellBin, knownHosts, dest string) (*exec.Cmd, *os.File, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(meowshellBin, "mosh-agent", "--known-hosts="+knownHosts, dest)
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting meowshell mosh-agent: %v", err)
	}
	stdinR.Close()
	stdoutW.Close()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("mosh-agent stderr:\n%s", stderr.String())
		}
	})
	send(t, stdinW, 0, controlMessage{Msg: "configure"})
	return cmd, stdinW, bufio.NewReader(stdoutR), &stderr
}

// acceptMoshHostKey answers the host_key prompt every TCP mosh-agent
// connection raises (bootstrapMosh reuses the same agent.connect/known_hosts
// path "agent" does -- see hostkeys.go) and returns the reader positioned
// right after it, ready for expectConnected.
func acceptMoshHostKey(t *testing.T, stdin *os.File, out *bufio.Reader) {
	t.Helper()
	f := mustReadFrame(t, out)
	msg := decodeControl(t, f)
	if msg.Msg != "prompt_request" || msg.PromptKind != "host_key" {
		t.Fatalf("first message from mosh-agent = %+v, want a host_key prompt_request", msg)
	}
	send(t, stdin, 0, controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Accept: true})
}

// TestMoshAgentEndToEnd drives the full Mosh transport for real: SSH
// bootstrap and host-key TOFU, a real mosh-server started over that SSH
// session, the handoff to Mosh/UDP, a resize, a roundtrip of real terminal
// I/O through the real shell mosh-server spawns, and a clean shutdown via
// close_channel -- the same close_channel path
// TestServeMoshFramesHandlesCloseChannelBeforeClientIsSet exercises directly,
// here proven from the outside through the compiled binary instead.
func TestMoshAgentEndToEnd(t *testing.T) {
	requireMoshServerBinary(t)
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	pids := make(chan int, 1)
	addr, _, stop := startTestSSHServer(t, moshServerExecHandler(pids))
	defer stop()
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	cmd, stdin, out, _ := startMoshAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer func() {
		stdin.Close()
		cmd.Wait()
	}()
	t.Cleanup(func() {
		select {
		case pid := <-pids:
			// The real mosh-server daemonizes and outlives the SSH exec
			// that started it (that's the whole point of "roaming"); a
			// test that starts one for real has to reap it itself, or
			// every run leaks a UDP-listening process.
			syscall.Kill(pid, syscall.SIGTERM)
		default:
		}
	})

	acceptMoshHostKey(t, stdin, out)
	expectConnected(t, out)

	// A resize before any data: must not crash or desync the framed
	// protocol (mutating the cols/rows bounds check in serveMoshFrames is
	// exactly what this would catch if it ever, say, started accepting
	// resize before checking for a client and panicked on a nil Resize).
	send(t, stdin, 1, controlMessage{Msg: "resize", Cols: 100, Rows: 30})

	// The command itself must not contain the marker text: a pty echoes
	// typed input back to the terminal before the shell ever runs it, so a
	// marker equal to (or contained in) the command line would appear from
	// local echo alone and prove nothing about the remote shell -- and by
	// extension the Mosh session -- actually having run it. Computing the
	// marker (an arithmetic result formatted into a distinct string) closes
	// that hole: it exists only in the command's real output.
	const marker = "mosh-e2e-result-987653"
	mustWriteFrame(t, stdin, frame{Type: frameTypeData, ChannelID: 1, Payload: []byte("printf 'mosh-e2e-result-%d\\n' $((987640+13))\n")})

	got := readUntil(t, out, 1, marker, 20*time.Second)
	if !bytes.Contains(got, []byte(marker)) {
		t.Errorf("Mosh terminal output = %q, want it to contain the computed marker from the remote shell's real output", got)
	}

	// close_channel must end the session promptly on its own, without
	// relying on stdin closing (that's the regression
	// TestServeMoshFramesHandlesCloseChannelBeforeClientIsSet targets at the
	// unit level -- this proves the same thing through the real binary).
	send(t, stdin, 1, controlMessage{Msg: "close_channel"})
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Errorf("mosh-agent after close_channel exited with %v, want a clean exit", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mosh-agent did not exit after close_channel; it must not require stdin to close as well")
	}
}

// TestMoshAgentSurfacesAMissingModshServer is a real-binary regression test
// for the single likeliest Mosh failure in the field: a bootstrap host with
// no mosh-server installed. bootstrapMosh's own error message names the
// fix ("ensure mosh-server is installed and available on PATH"); this
// confirms that message actually reaches the client as a structured "error"
// rather than the process just hanging or exiting silently.
func TestMoshAgentSurfacesAMissingMoshServer(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	addr, _, stop := startTestSSHServer(t, moshServerNotInstalledExecHandler)
	defer stop()
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	cmd, stdin, out, _ := startMoshAgent(t, meowshellBin, knownHosts, "testuser@"+addr)
	defer func() {
		stdin.Close()
		cmd.Wait()
	}()

	acceptMoshHostKey(t, stdin, out)

	f := mustReadFrame(t, out)
	msg := decodeControl(t, f)
	if msg.Msg != "error" || msg.Code != errUnknown {
		t.Fatalf("mosh-agent against a host with no mosh-server = %+v, want an \"error\" with code %q", msg, errUnknown)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case err := <-waitDone:
		if err == nil {
			t.Error("mosh-agent exited 0 after failing to bootstrap Mosh, want a non-zero exit")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mosh-agent did not exit after the bootstrap failure")
	}
}

// TestMoshAgentRejectsTailcatAddressAsARealProcess is the subprocess
// counterpart to TestMoshAgentRejectsTailcatAddress: it goes through
// init()'s os.Args dispatch and main's actual os.Exit(1), which the direct
// moshAgentCmd() call can't observe on its own.
func TestMoshAgentRejectsTailcatAddressAsARealProcess(t *testing.T) {
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	cmd := exec.Command(meowshellBin, "mosh-agent", validTailcatAddress)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("mosh-agent with a tailcat address exited 0, want a non-zero exit")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("cannot use a tailcat address")) {
		t.Errorf("mosh-agent stderr = %q, want it to explain the tailcat address is unsupported", stderr.String())
	}
}
