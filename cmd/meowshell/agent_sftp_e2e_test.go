package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestAgentSFTPEndToEnd drives meowshell agent's SFTP surface (verbs
// beyond meowshell cp's plain upload/download/ls) against a real tailcat
// server, over the local-DERP hermetic setup agent_e2e_test.go uses.
func TestAgentSFTPEndToEnd(t *testing.T) {
	tailcatBin := findE2EBinary(t, "TAILCAT", "tailcat_linux_amd64")
	meowshellBin := findE2EBinary(t, "MEOWSHELL", "meowshell_linux_amd64")

	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("TS_DEBUG_TAILCAT_LOCAL_DERP", "1")

	served := t.TempDir() // meowshell serve --files serves this directory
	addr := startE2EFilesServer(t, tailcatBin, meowshellBin, home, served)

	// startAgent (agent_tcp_e2e_test.go) doesn't set an explicit Env for
	// the subprocess, so it inherits the test process's own -- this is
	// what gets TAILCAT_BIN to it for a tailcat-address destination
	// (--known-hosts is harmless but unused on this path: tailcat
	// transport never builds a TCP host-key callback).
	t.Setenv("TAILCAT_BIN", tailcatBin)
	_, stdin, out := startAgent(t, meowshellBin, filepath.Join(t.TempDir(), "known_hosts"), addr)
	t.Cleanup(func() { stdin.Close() })
	expectConnected(t, out)

	t.Run("mkdir, then ls sees it", func(t *testing.T) {
		sftpOp(t, stdin, out, controlMessage{Op: "mkdir", Path: "adir"})
		resp := sftpOp(t, stdin, out, controlMessage{Op: "ls", Path: "."})
		if !hasEntry(resp.Entries, "adir", true) {
			t.Errorf("ls after mkdir = %+v, want a directory entry named \"adir\"", resp.Entries)
		}
	})

	t.Run("upload, stat, chmod, rename, download, remove", func(t *testing.T) {
		uploadContent := []byte("hello from the sftp e2e test\n")
		uploadViaAgent(t, stdin, out, "adir/file.txt", uploadContent, false, 0, 0)

		stat := sftpOp(t, stdin, out, controlMessage{Op: "stat", Path: "adir/file.txt"})
		if len(stat.Entries) != 1 || stat.Entries[0].Size != int64(len(uploadContent)) {
			t.Fatalf("stat = %+v, want one entry of size %d", stat.Entries, len(uploadContent))
		}

		sftpOp(t, stdin, out, controlMessage{Op: "chmod", Path: "adir/file.txt", Mode: 0o640})
		stat = sftpOp(t, stdin, out, controlMessage{Op: "stat", Path: "adir/file.txt"})
		if got := stat.Entries[0].Mode & 0o777; got != 0o640 {
			t.Errorf("mode after chmod = %o, want 0640", got)
		}

		sftpOp(t, stdin, out, controlMessage{Op: "rename", Path: "adir/file.txt", NewPath: "adir/renamed.txt"})

		got := downloadViaAgent(t, stdin, out, "adir/renamed.txt")
		if !bytes.Equal(got, uploadContent) {
			t.Errorf("downloaded content = %q, want %q", got, uploadContent)
		}

		sftpOp(t, stdin, out, controlMessage{Op: "remove", Path: "adir/renamed.txt"})
		if _, err := os.Stat(filepath.Join(served, "adir", "renamed.txt")); err == nil {
			t.Error("file still exists on disk after remove")
		}
	})

	t.Run("upload with preserve carries mode and mtime", func(t *testing.T) {
		mtime := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
		uploadViaAgent(t, stdin, out, "adir/preserved.txt", []byte("x"), true, 0o600, mtime.Unix())

		stat := sftpOp(t, stdin, out, controlMessage{Op: "stat", Path: "adir/preserved.txt"})
		if len(stat.Entries) != 1 {
			t.Fatalf("stat = %+v", stat.Entries)
		}
		if got := stat.Entries[0].Mode & 0o777; got != 0o600 {
			t.Errorf("preserved mode = %o, want 0600", got)
		}
		if got := stat.Entries[0].ModTime; got != mtime.Unix() {
			t.Errorf("preserved mtime = %d, want %d", got, mtime.Unix())
		}
	})

	t.Run("symlink and readlink", func(t *testing.T) {
		sftpOp(t, stdin, out, controlMessage{Op: "symlink", Path: "adir/link", Target: "preserved.txt"})
		resp := sftpOp(t, stdin, out, controlMessage{Op: "readlink", Path: "adir/link"})
		if resp.Target != "preserved.txt" {
			t.Errorf("readlink = %q, want %q", resp.Target, "preserved.txt")
		}
	})

	t.Run("realpath resolves relative to the served root", func(t *testing.T) {
		resp := sftpOp(t, stdin, out, controlMessage{Op: "realpath", Path: "adir/preserved.txt"})
		if resp.Path == "" || resp.Path == "adir/preserved.txt" {
			t.Errorf("realpath = %q, want an absolute path", resp.Path)
		}
	})

	t.Run("rmdir on a non-empty directory fails, then remove+rmdir succeeds", func(t *testing.T) {
		if err := trySFTPOp(t, stdin, out, controlMessage{Op: "rmdir", Path: "adir"}); err == "" {
			t.Error("rmdir on a non-empty directory did not error")
		}
		sftpOp(t, stdin, out, controlMessage{Op: "remove", Path: "adir/preserved.txt"})
		sftpOp(t, stdin, out, controlMessage{Op: "remove", Path: "adir/link"})
		sftpOp(t, stdin, out, controlMessage{Op: "rmdir", Path: "adir"})
	})

	t.Run("stat on a missing file is a typed not_found error", func(t *testing.T) {
		if err := trySFTPOp(t, stdin, out, controlMessage{Op: "stat", Path: "does-not-exist"}); err != errNotFound {
			t.Errorf("stat on a missing file: code = %v, want %v", err, errNotFound)
		}
	})

	t.Run("download reports progress and a real total size", func(t *testing.T) {
		payload := bytes.Repeat([]byte("0123456789"), 10_000) // 100KB, big enough to cross the progress interval at least once
		uploadViaAgent(t, stdin, out, "big.bin", payload, false, 0, 0)

		send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "sftp_download", Path: "big.bin"})
		f := mustReadFrame(t, out)
		opened := decodeControl(t, f)
		if opened.Msg != "channel_opened" || opened.Size != int64(len(payload)) {
			t.Fatalf("channel_opened = %+v, want Size %d", opened, len(payload))
		}
		id := f.ChannelID

		var got bytes.Buffer
		sawProgress := false
		for {
			f := mustReadFrame(t, out)
			if f.ChannelID != id {
				continue
			}
			if f.Type == frameTypeData {
				got.Write(f.Payload[1:])
				continue
			}
			msg := decodeControl(t, f)
			switch msg.Msg {
			case "progress":
				sawProgress = true
			case "exit_status":
				goto done
			case "error":
				t.Fatalf("download errored: %+v", msg)
			}
		}
	done:
		if !bytes.Equal(got.Bytes(), payload) {
			t.Errorf("downloaded %d bytes, want %d matching bytes", got.Len(), len(payload))
		}
		if !sawProgress {
			t.Error("never saw a progress message for a 100KB download")
		}
	})
}

func startE2EFilesServer(t *testing.T, tailcatBin, meowshellBin, home, served string) string {
	t.Helper()
	addrFile := filepath.Join(home, "addr")
	cmd := exec.Command(meowshellBin, "serve", "--insecure-no-auth", "--files="+served+":rw", "--tailcat="+tailcatBin)
	cmd.Env = append(os.Environ(),
		"TAILCAT_BIN="+tailcatBin,
		"TAILCAT_ADDR_FILE="+addrFile,
		"HOME="+home,
		"TS_DEBUG_TAILCAT_LOCAL_DERP=1",
	)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting meowshell serve: %v", err)
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

// sftpOp sends one sftp_op request and returns its sftp_result, failing
// the test on an error response.
func sftpOp(t *testing.T, stdin interface {
	Write([]byte) (int, error)
}, out *bufio.Reader, req controlMessage) controlMessage {
	t.Helper()
	req.Msg = "sftp_op"
	req.RequestID = fmt.Sprintf("op%d", time.Now().UnixNano())
	send(t, stdin, 0, req)
	f := mustReadFrame(t, out)
	msg := decodeControl(t, f)
	if msg.RequestID != req.RequestID {
		t.Fatalf("sftp_op %s: reply RequestID = %q, want %q (msg=%+v)", req.Op, msg.RequestID, req.RequestID, msg)
	}
	if msg.Msg == "error" {
		t.Fatalf("sftp_op %s %s failed: %s: %s", req.Op, req.Path, msg.Code, msg.Message)
	}
	return msg
}

// trySFTPOp is sftpOp for a call the test expects might fail: it returns
// the error code (or "" on success) instead of failing the test itself.
func trySFTPOp(t *testing.T, stdin interface {
	Write([]byte) (int, error)
}, out *bufio.Reader, req controlMessage) errorCode {
	t.Helper()
	req.Msg = "sftp_op"
	req.RequestID = fmt.Sprintf("op%d", time.Now().UnixNano())
	send(t, stdin, 0, req)
	f := mustReadFrame(t, out)
	msg := decodeControl(t, f)
	if msg.Msg == "error" {
		return msg.Code
	}
	return ""
}

func hasEntry(entries []sftpEntry, name string, isDir bool) bool {
	for _, e := range entries {
		if e.Name == name && e.IsDir == isDir {
			return true
		}
	}
	return false
}

func uploadViaAgent(t *testing.T, stdin interface {
	Write([]byte) (int, error)
}, out *bufio.Reader, path string, content []byte, preserve bool, mode uint32, modTime int64) {
	t.Helper()
	send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "sftp_upload", Path: path, Preserve: preserve, Mode: mode, ModTime: modTime})
	id := expectChannelOpened(t, out)
	mustWriteFrame(t, stdin, frame{Type: frameTypeData, ChannelID: id, Payload: content})
	send(t, stdin, id, controlMessage{Msg: "close_channel"})
	readUntilExit(t, out, id)
}

func downloadViaAgent(t *testing.T, stdin interface {
	Write([]byte) (int, error)
}, out *bufio.Reader, path string) []byte {
	t.Helper()
	send(t, stdin, 0, controlMessage{Msg: "open_channel", Kind: "sftp_download", Path: path})
	id := expectChannelOpened(t, out)
	return readUntilExit(t, out, id)
}
