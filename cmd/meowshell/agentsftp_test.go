package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// pipeRWC pairs a read pipe and a write pipe into one io.ReadWriteCloser, so
// an in-process sftp.Server/sftp.Client can talk to each other without any
// SSH connection or subprocess. Close closes both ends explicitly since
// embedding *io.PipeReader and *io.PipeWriter directly would leave Close
// ambiguous between the two.
type pipeRWC struct {
	*io.PipeReader
	*io.PipeWriter
}

func (p pipeRWC) Close() error {
	p.PipeReader.Close()
	return p.PipeWriter.Close()
}

// newInProcessSFTPClient wires an sftp.Client to a real sftp.Server rooted
// at a temp directory, connected by in-memory pipes -- no SSH, no
// subprocess. Returns the client (already installed as session.sftpClient),
// the server's root directory (for a test that needs to inspect the backing
// filesystem directly -- e.g. after severing the transport, when the client
// itself can no longer be used to check anything), and a breakTransport
// func that severs the client's write side, so a test can make the next
// client-initiated request fail deterministically, simulating a write (or
// any other) failure partway through a transfer.
func newInProcessSFTPClient(t *testing.T) (session *agentSession, client *sftp.Client, rootDir string, breakTransport func()) {
	t.Helper()
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()

	rootDir = t.TempDir()
	svr, err := sftp.NewServer(pipeRWC{serverRead, serverWrite}, sftp.WithServerWorkingDirectory(rootDir))
	if err != nil {
		t.Fatal(err)
	}
	go svr.Serve()

	client, err = sftp.NewClientPipe(clientRead, clientWrite)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The server side must close first: it unblocks the client's
		// background read loop (by closing serverWrite, which delivers EOF
		// to clientRead) that client.Close() otherwise waits on forever.
		svr.Close()
		client.Close()
	})

	session = newAgentSession(nil, &bytes.Buffer{})
	session.sftpClient = client
	session.chans = make(map[uint32]*agentChannel)

	return session, client, rootDir, func() { clientWrite.Close() }
}

func readControlFrames(t *testing.T, buf *bytes.Buffer) []controlMessage {
	t.Helper()
	r := bytes.NewReader(buf.Bytes())
	var msgs []controlMessage
	for {
		f, err := readFrame(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("readFrame: %v", err)
		}
		if f.Type != frameTypeControl {
			continue
		}
		var msg controlMessage
		if err := json.Unmarshal(f.Payload, &msg); err != nil {
			t.Fatalf("decoding control message: %v", err)
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

// TestHandleDataRecordsAWriteFailure checks the first half of the fix: a
// failed Write to an upload's file must be remembered on the channel (not
// just reported once and forgotten), so finalizeUpload can see it later.
func TestHandleDataRecordsAWriteFailure(t *testing.T) {
	session, client, _, breakTransport := newInProcessSFTPClient(t)

	f, err := client.Create("up.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const id = uint32(1)
	ch := &agentChannel{sftpFile: f, isUpload: true, uploadPath: "up.bin"}
	session.chans[id] = ch
	session.startChannelWriter(id, ch)

	// Sever the transport so the next client-initiated SFTP request (the
	// upcoming Write) fails deterministically, standing in for any real
	// write failure (disk full, quota, a server-side error) without relying
	// on OS-specific ways to actually trigger one.
	breakTransport()

	out := session.out.(*bytes.Buffer)
	session.handleData(id, []byte("this data will not make it"))

	deadline := time.Now().Add(time.Second)
	for ch.getUploadErr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ch.getUploadErr() == nil {
		t.Fatal("channel writer did not record the write failure on the channel (ch.uploadErr is nil)")
	}
	msgs := readControlFrames(t, out)
	if len(msgs) != 1 || msgs[0].Msg != "error" {
		t.Fatalf("control messages after the failed write = %+v, want exactly one \"error\"", msgs)
	}
}

// TestFinalizeUploadReportsRecordedWriteFailureNotSuccess is a regression
// test: finalizeUpload used to unconditionally send exit_status 0 once
// sftpFile.Close() succeeded, even when an earlier Write to that same file
// had already failed (ch.uploadErr set, per the handleData test above) --
// producing a contradictory error-then-success sequence for the same
// upload, and telling the caller data that never landed had. Sets
// uploadErr directly, with the transport otherwise left intact, so Close()
// itself genuinely succeeds here: this isolates finalizeUpload's own
// success-despite-a-prior-failure bug from whether Close() happens to fail
// too (which a broken-transport simulation can't rule out on its own).
func TestFinalizeUploadReportsRecordedWriteFailureNotSuccess(t *testing.T) {
	session, client, _, _ := newInProcessSFTPClient(t)

	f, err := client.Create("up2.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const id = uint32(1)
	ch := &agentChannel{
		sftpFile: f, isUpload: true, uploadPath: "up2.bin",
		uploadErr: fmt.Errorf("simulated write failure partway through the transfer"),
	}
	session.chans[id] = ch

	out := session.out.(*bytes.Buffer)
	session.finalizeUpload(id, ch)

	msgs := readControlFrames(t, out)
	if len(msgs) != 1 {
		t.Fatalf("control messages from finalizeUpload = %+v, want exactly one", msgs)
	}
	if msgs[0].Msg != "error" {
		t.Fatalf("finalizeUpload's outcome = %+v, want \"error\" (Close() succeeding must not paper over the earlier write failure)", msgs[0])
	}
}

// TestUploadFurtherDataAfterAFailureIsIgnored checks the other half of the
// same fix: once a write has failed, handleData must stop touching the file
// (and stop erroring about it again) instead of continuing to call Write on
// a file finalizeUpload is already going to report as failed.
func TestUploadFurtherDataAfterAFailureIsIgnored(t *testing.T) {
	session, client, _, breakTransport := newInProcessSFTPClient(t)

	f, err := client.Create("up2.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const id = uint32(1)
	ch := &agentChannel{sftpFile: f, isUpload: true, uploadPath: "up2.bin"}
	session.chans[id] = ch
	session.startChannelWriter(id, ch)

	breakTransport()

	out := session.out.(*bytes.Buffer)
	session.handleData(id, []byte("first chunk, fails"))
	deadline := time.Now().Add(time.Second)
	for ch.getUploadErr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ch.getUploadErr() == nil {
		t.Fatal("first upload write never failed")
	}
	firstErrCount := len(readControlFrames(t, out))

	// failChannelWrite removes the failed channel, so any later frame for the
	// stale ID is ignored by handleData instead of reaching the broken file.
	session.handleData(id, []byte("second chunk, must be ignored"))
	secondErrCount := len(readControlFrames(t, out))

	if secondErrCount != firstErrCount {
		t.Fatalf("a data frame after the channel's terminal write error produced %d more control message(s); want it silently ignored",
			secondErrCount-firstErrCount)
	}
}

func readRemoteFile(t *testing.T, client *sftp.Client, path string) []byte {
	t.Helper()
	f, err := client.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func openedChannelID(t *testing.T, out *bytes.Buffer) uint32 {
	t.Helper()
	f, err := readFrame(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var msg controlMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Msg != "channel_opened" {
		t.Fatalf("first control message = %+v, want channel_opened", msg)
	}
	return f.ChannelID
}

// TestSuccessfulUploadAtomicallyReplacesDestination verifies that upload data
// lands in a sibling staging file and the existing destination is replaced
// only at finalization via the server's POSIX rename extension.
//
// It waits for the exit_status control message before ever looking at the
// destination file's content, rather than polling the destination via a
// concurrent SFTP open/read/close in a loop: on Windows, a file opened
// without FILE_SHARE_DELETE (the default for both os.Open and the SFTP
// server's own file handles) blocks a concurrent rename-to-replace of that
// same path, so a concurrent reader would race the very rename this test is
// verifying and intermittently fail with "Access is denied" -- a race POSIX
// rename() doesn't have, since Unix lets a rename proceed under any open
// reader.
func TestSuccessfulUploadAtomicallyReplacesDestination(t *testing.T) {
	session, client, rootDir, _ := newInProcessSFTPClient(t)
	old, err := client.Create("atomic.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Write([]byte("old-good-data")); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	out := session.out.(*bytes.Buffer)
	session.openSFTPChannel(controlMessage{Kind: "sftp_upload", Path: "atomic.txt", RequestID: "u1"})
	id := openedChannelID(t, out)
	session.handleData(id, []byte("new-complete-data"))
	session.closeChannel(id, controlMessage{})

	deadline := time.Now().Add(2 * time.Second)
	var msgs []controlMessage
	for time.Now().Before(deadline) {
		msgs = readControlFrames(t, out)
		for _, msg := range msgs {
			if msg.Msg == "exit_status" {
				if msg.ExitCode != 0 {
					t.Fatalf("upload finished with exit code %d, messages = %+v", msg.ExitCode, msgs)
				}
				got, err := os.ReadFile(filepath.Join(rootDir, "atomic.txt"))
				if err != nil {
					t.Fatalf("reading committed destination: %v", err)
				}
				if string(got) != "new-complete-data" {
					t.Fatalf("destination after commit = %q, want %q", got, "new-complete-data")
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("upload never committed successfully; messages = %+v", msgs)
}

// TestCancelledUploadPreservesExistingDestination is the integrity regression:
// close_channel with Cancelled set must discard the staging file instead of
// finalizing a partial upload over a previously valid remote file.
func TestCancelledUploadPreservesExistingDestination(t *testing.T) {
	session, client, _, _ := newInProcessSFTPClient(t)
	old, err := client.Create("keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	out := session.out.(*bytes.Buffer)
	session.openSFTPChannel(controlMessage{Kind: "sftp_upload", Path: "keep.txt", RequestID: "u2"})
	id := openedChannelID(t, out)
	session.handleData(id, []byte("partial"))
	session.closeChannel(id, controlMessage{Cancelled: true})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if string(readRemoteFile(t, client, "keep.txt")) == "original" {
			entries, err := client.ReadDir(".")
			if err != nil {
				t.Fatal(err)
			}
			leftover := false
			for _, entry := range entries {
				if strings.Contains(entry.Name(), ".meowshell-upload-") {
					leftover = true
				}
			}
			if !leftover {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("cancelled upload changed destination or left staging file behind")
}
