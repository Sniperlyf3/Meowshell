package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pkg/sftp"
)

func (a *agentSession) sftpClientFor() (*sftp.Client, error) {
	a.sftpMu.Lock()
	defer a.sftpMu.Unlock()
	if a.sftpClient != nil {
		return a.sftpClient, nil
	}
	client := a.client()
	if client == nil {
		return nil, fmt.Errorf("SSH connection is no longer available")
	}
	sf, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("opening SFTP session: %w", err)
	}
	a.sftpClient = sf
	return sf, nil
}

func (a *agentSession) resetSFTPClient(expected *sftp.Client) {
	a.sftpMu.Lock()
	sf := a.sftpClient
	if sf == nil || (expected != nil && sf != expected) {
		a.sftpMu.Unlock()
		return
	}
	a.sftpClient = nil
	a.sftpMu.Unlock()
	_ = sf.Close()
}

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

func (a *agentSession) sftpOp(msg controlMessage) {
	sf, err := a.sftpClientFor()
	if err != nil {
		a.writeControl(0, controlMessage{Msg: "error", RequestID: msg.RequestID, Code: errUnknown, Message: err.Error()})
		return
	}
	a.sftpOpWithClient(sf, msg)
}

func (a *agentSession) sftpOpWithClient(sf *sftp.Client, msg controlMessage) {
	var err error
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

func (a *agentSession) openSFTPChannel(msg controlMessage) {
	sf, err := a.sftpClientFor()
	if err != nil {
		a.writeOpenError(msg.RequestID, errUnknown, fmt.Errorf("opening SFTP: %w", err))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())

	switch msg.Kind {
	case "sftp_upload":
		f, tempPath, err := createUploadTemp(sf, msg.Path)
		if err != nil {
			cancel()
			a.writeOpenError(msg.RequestID, classifySFTPError(err), fmt.Errorf("creating upload staging file for %s: %w", msg.Path, err))
			return
		}
		ch := &agentChannel{
			sftpFile: f, sftpClose: f.Close, ctx: ctx, cancel: cancel, isUpload: true,
			uploadPath: msg.Path, uploadTempPath: tempPath,
			uploadPreserve: msg.Preserve, uploadMode: msg.Mode, uploadModTime: msg.ModTime,
		}
		id, err := a.registerChannel(ch)
		if err != nil {
			cancel()
			f.Close()
			a.writeOpenError(msg.RequestID, errUnknown, err)
			return
		}
		a.startChannelWriter(id, ch)
		a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID})

	case "sftp_download":
		fi, err := sf.Stat(msg.Path)
		if err != nil {
			cancel()
			a.writeOpenError(msg.RequestID, classifySFTPError(err), fmt.Errorf("stat %s: %w", msg.Path, err))
			return
		}
		f, err := sf.Open(msg.Path)
		if err != nil {
			cancel()
			a.writeOpenError(msg.RequestID, classifySFTPError(err), fmt.Errorf("opening %s: %w", msg.Path, err))
			return
		}
		ch := &agentChannel{sftpFile: f, sftpClose: f.Close, ctx: ctx, cancel: cancel}
		id, err := a.registerChannel(ch)
		if err != nil {
			cancel()
			f.Close()
			a.writeOpenError(msg.RequestID, errUnknown, err)
			return
		}
		a.writeControl(id, controlMessage{Msg: "channel_opened", RequestID: msg.RequestID, Size: fi.Size()})
		go a.pumpSFTPDownload(id, f, ctx)

	default:
		cancel()
		a.writeOpenError(msg.RequestID, errProtocolError, fmt.Errorf("unknown open_channel kind %q", msg.Kind))
	}
}

func createUploadTemp(sf *sftp.Client, finalPath string) (*sftp.File, string, error) {
	for i := 0; i < 8; i++ {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, "", err
		}
		tempPath := fmt.Sprintf("%s.meowshell-upload-%x", finalPath, nonce[:])
		f, err := sf.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err == nil {
			return f, tempPath, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("could not allocate a unique upload staging path")
}

func (a *agentSession) cleanupUploadTemp(ch *agentChannel) {
	if ch == nil || ch.uploadTempPath == "" {
		return
	}
	if sf, err := a.sftpClientFor(); err == nil {
		_ = sf.Remove(ch.uploadTempPath)
	}
}

func commitUpload(sf *sftp.Client, tempPath, finalPath string) error {
	if _, ok := sf.HasExtension("posix-rename@openssh.com"); ok {
		return sf.PosixRename(tempPath, finalPath)
	}
	if _, err := sf.Lstat(finalPath); err == nil {
		return fmt.Errorf("server does not support atomic replacement of existing files")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return sf.Rename(tempPath, finalPath)
}

const sftpProgressInterval = 200 * time.Millisecond

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

func (a *agentSession) finalizeUpload(channelID uint32, ch *agentChannel) {
	if ch.cancel != nil {
		defer ch.cancel()
	}
	closeErr := ch.sftpFile.Close()
	if uploadErr := ch.getUploadErr(); uploadErr != nil {
		a.cleanupUploadTemp(ch)
		a.writeError(channelID, classifySFTPError(uploadErr), uploadErr)
		return
	}
	if closeErr != nil {
		a.cleanupUploadTemp(ch)
		a.writeError(channelID, classifySFTPError(closeErr), closeErr)
		return
	}

	sf, err := a.sftpClientFor()
	if err != nil {
		a.cleanupUploadTemp(ch)
		a.writeError(channelID, errUnknown, fmt.Errorf("finalizing upload: %w", err))
		return
	}
	if ch.uploadPreserve {
		if err := sf.Chmod(ch.uploadTempPath, os.FileMode(ch.uploadMode)); err != nil {
			a.cleanupUploadTemp(ch)
			a.writeError(channelID, errUnknown, fmt.Errorf("preserving mode: %w", err))
			return
		}
		if ch.uploadModTime != 0 {
			mt := time.Unix(ch.uploadModTime, 0)
			if err := sf.Chtimes(ch.uploadTempPath, mt, mt); err != nil {
				a.cleanupUploadTemp(ch)
				a.writeError(channelID, errUnknown, fmt.Errorf("preserving mtime: %w", err))
				return
			}
		}
	}
	if err := commitUpload(sf, ch.uploadTempPath, ch.uploadPath); err != nil {
		a.cleanupUploadTemp(ch)
		a.writeError(channelID, classifySFTPError(err), fmt.Errorf("committing upload: %w", err))
		return
	}
	ch.uploadTempPath = ""
	a.writeControl(channelID, controlMessage{Msg: "exit_status", ExitCode: 0})
}
