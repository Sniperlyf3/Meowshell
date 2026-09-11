package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
// subprocess. Returns the client (already installed as session.sftpClient)
// and a breakTransport func that severs the client's write side, so a test
// can make the next client-initiated request fail deterministically,
// simulating a write (or any other) failure partway through a transfer.
func newInProcessSFTPClient(t *testing.T) (session *agentSession, client *sftp.Client, breakTransport func()) {
	t.Helper()
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()

	svr, err := sftp.NewServer(pipeRWC{serverRead, serverWrite}, sftp.WithServerWorkingDirectory(t.TempDir()))
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

	return session, client, func() { clientWrite.Close() }
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
	session, client, breakTransport := newInProcessSFTPClient(t)

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
	session, client, _ := newInProcessSFTPClient(t)

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
	session, client, breakTransport := newInProcessSFTPClient(t)

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
