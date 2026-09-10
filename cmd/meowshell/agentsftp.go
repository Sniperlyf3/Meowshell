package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pkg/sftp"
)

// sftpClientFor lazily opens the one *sftp.Client this connection shares
// across every ls/stat/mkdir/.../upload/download request -- pkg/sftp
// already multiplexes concurrent requests over its single SSH subsystem
// channel internally, so there is no need for more than one here.
func (a *agentSession) sftpClientFor() (*sftp.Client, error) {
	a.sftpMu.Lock()
	defer a.sftpMu.Unlock()
	if a.sftpClient != nil {
		return a.sftpClient, nil
	}
	sf, err := sftp.NewClient(a.client())
	if err != nil {
		return nil, fmt.Errorf("opening SFTP session: %w", err)
	}
	a.sftpClient = sf
	return sf, nil
}

// classifySFTPError maps an SFTP failure to a typed error code. pkg/sftp
// documents its client methods as returning errors satisfying the
// standard os.IsNotExist/os.IsPermission predicates for the common
// not-found/denied cases (wrapping the wire-level SSH_FX_* status), which
// is enough to cover what a caller is actually likely to branch on without
// this needing to unpack pkg/sftp's *sftp.StatusError codes by hand.
func classifySFTPError(err error) errorCode {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return errNotFound
	case errors.Is(err, os.ErrPermission):
		return errPermissionDenied
	default:
		return errUnknown
	}
}

// sftpOp answers one metadata request/response op -- see protocol.go's
// controlMessage doc for the field meanings and agentUsage-adjacent
// sftpUsage-style listing of supported Op values.
func (a *agentSession) sftpOp(msg controlMessage) {
	sf, err := a.sftpClientFor()
	if err != nil {
		a.writeControl(0, controlMessage{Msg: "error", RequestID: msg.RequestID, Code: errUnknown, Message: err.Error()})
		return
	}

	resp := controlMessage{Msg: "sftp_result", RequestID: msg.RequestID}
	switch msg.Op {
	case "ls":
		entries, lsErr := sf.ReadDir(msg.Path)
		if lsErr != nil {
			err = lsErr
			break
		}
		resp.Entries = make([]sftpEntry, len(entries))
		for i, fi := range entries {
			resp.Entries[i] = fileInfoToEntry(fi)
		}
	case "stat", "lstat":
		var fi os.FileInfo
		if msg.Op == "stat" {
			fi, err = sf.Stat(msg.Path)
		} else {
			fi, err = sf.Lstat(msg.Path)
		}
		if err == nil {
			resp.Entries = []sftpEntry{fileInfoToEntry(fi)}
		}
	case "mkdir":
		err = sf.Mkdir(msg.Path)
	case "mkdir_all":
		err = sf.MkdirAll(msg.Path)
	case "rmdir":
		err = sf.RemoveDirectory(msg.Path)
	case "remove":
		err = sf.Remove(msg.Path)
	case "rename":
		err = sf.Rename(msg.Path, msg.NewPath)
	case "chmod":
		err = sf.Chmod(msg.Path, os.FileMode(msg.Mode))
	case "chown":
		err = sf.Chown(msg.Path, msg.UID, msg.GID)
	case "symlink":
		err = sf.Symlink(msg.Target, msg.Path)
	case "readlink":
		resp.Target, err = sf.ReadLink(msg.Path)
	case "truncate":
		err = sf.Truncate(msg.Path, msg.Size)
	case "realpath":
		resp.Path, err = sf.RealPath(msg.Path)
	default:
		a.writeControl(0, controlMessage{Msg: "error", RequestID: msg.RequestID, Code: errProtocolError, Message: fmt.Sprintf("unknown sftp op %q", msg.Op)})
		return
	}
	if err != nil {
		a.writeControl(0, controlMessage{Msg: "error", RequestID: msg.RequestID, Code: classifySFTPError(err), Message: err.Error()})
		return
	}
	a.writeControl(0, resp)
}

func fileInfoToEntry(fi os.FileInfo) sftpEntry {
	return sftpEntry{
		Name:    fi.Name(),
		Size:    fi.Size(),
		Mode:    uint32(fi.Mode()),
		ModTime: fi.ModTime().Unix(),
		IsDir:   fi.IsDir(),
	}
}

// openSFTPChannel opens an upload or download channel: a file transfer,
// unlike sftpOp's fast metadata request/response, gets its own channel ID
// so its bytes can ride the same data-frame machinery shell/exec channels
// use, with progress and cancellation alongside.
func (a *agentSession) openSFTPChannel(msg controlMessage) {
	sf, err := a.sftpClientFor()
	if err != nil {
		a.writeError(0, errUnknown, fmt.Errorf("opening SFTP: %w", err))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())

	switch msg.Kind {
	case "sftp_upload":
		f, err := sf.Create(msg.Path)
		if err != nil {
			cancel()
			a.writeError(0, classifySFTPError(err), fmt.Errorf("creating %s: %w", msg.Path, err))
			return
		}
		id := a.nextID.Add(1)
		ch := &agentChannel{
			sftpFile: f, ctx: ctx, cancel: cancel, isUpload: true,
			uploadPath: msg.Path, uploadPreserve: msg.Preserve, uploadMode: msg.Mode, uploadModTime: msg.ModTime,
		}
		a.chansMu.Lock()
		a.chans[id] = ch
		a.chansMu.Unlock()
		a.writeControl(id, controlMessage{Msg: "channel_opened"})

	case "sftp_download":
		fi, err := sf.Stat(msg.Path)
		if err != nil {
			cancel()
			a.writeError(0, classifySFTPError(err), fmt.Errorf("stat %s: %w", msg.Path, err))
			return
		}
		f, err := sf.Open(msg.Path)
		if err != nil {
			cancel()
			a.writeError(0, classifySFTPError(err), fmt.Errorf("opening %s: %w", msg.Path, err))
			return
		}
		id := a.nextID.Add(1)
		ch := &agentChannel{sftpFile: f, ctx: ctx, cancel: cancel}
		a.chansMu.Lock()
		a.chans[id] = ch
		a.chansMu.Unlock()
		a.writeControl(id, controlMessage{Msg: "channel_opened", Size: fi.Size()})
		go a.pumpSFTPDownload(id, f, ctx)

	default:
		cancel()
		a.writeError(0, errProtocolError, fmt.Errorf("unknown open_channel kind %q", msg.Kind))
	}
}

// sftpProgressInterval throttles progress messages -- frequent enough for
// a UI progress bar to feel live, rare enough not to flood the control
// channel on a fast local transfer.
const sftpProgressInterval = 200 * time.Millisecond

// pumpSFTPDownload streams a remote file to the client as data frames,
// reporting progress and ending in exit_status (success) or error
// (cancelled, or a real read failure) -- the same three-way outcome
// waitChannel reports for a shell/exec channel, just driven by file reads
// instead of session.Wait.
func (a *agentSession) pumpSFTPDownload(id uint32, f *sftp.File, ctx context.Context) {
	defer f.Close()
	defer a.removeChannel(id)

	buf := make([]byte, 32*1024)
	var done int64
	lastProgress := time.Now()
	for {
		select {
		case <-ctx.Done():
			a.writeError(id, errCancelled, fmt.Errorf("download cancelled"))
			return
		default:
		}
		n, err := f.Read(buf)
		if n > 0 {
			if werr := a.writeData(id, streamStdout, buf[:n]); werr != nil {
				return
			}
			done += int64(n)
			if time.Since(lastProgress) >= sftpProgressInterval {
				a.writeControl(id, controlMessage{Msg: "progress", BytesDone: done})
				lastProgress = time.Now()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				a.writeControl(id, controlMessage{Msg: "progress", BytesDone: done})
				a.writeControl(id, controlMessage{Msg: "exit_status", ExitCode: 0})
			} else {
				a.writeError(id, classifySFTPError(err), err)
			}
			return
		}
	}
}

// finalizeUpload closes an sftp_upload channel's remote file and applies
// Preserve (mode + mtime) if requested, reporting the outcome as
// exit_status. close_channel is how the client signals "no more bytes
// coming" for an upload -- this is where a transfer is actually considered
// done, not just where its resources get cleaned up.
func (a *agentSession) finalizeUpload(channelID uint32, ch *agentChannel) {
	if ch.cancel != nil {
		defer ch.cancel()
	}
	if err := ch.sftpFile.Close(); err != nil {
		a.writeError(channelID, classifySFTPError(err), err)
		return
	}
	if ch.uploadPreserve {
		if sf, err := a.sftpClientFor(); err == nil {
			// Best-effort: neither failure should turn an upload that
			// otherwise completed into a reported failure, but the client
			// should still hear about it.
			if err := sf.Chmod(ch.uploadPath, os.FileMode(ch.uploadMode)); err != nil {
				a.writeError(channelID, errUnknown, fmt.Errorf("preserving mode: %w", err))
			}
			if ch.uploadModTime != 0 {
				mt := time.Unix(ch.uploadModTime, 0)
				if err := sf.Chtimes(ch.uploadPath, mt, mt); err != nil {
					a.writeError(channelID, errUnknown, fmt.Errorf("preserving mtime: %w", err))
				}
			}
		}
	}
	a.writeControl(channelID, controlMessage{Msg: "exit_status", ExitCode: 0})
}
