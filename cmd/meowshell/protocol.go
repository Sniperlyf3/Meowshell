package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameTypeControl byte = 0
	frameTypeData    byte = 1
)

const (
	streamStdout byte = 0
	streamStderr byte = 1
)

const maxFrameLength = 64 << 20

const frameHeaderLength = 5

type frame struct {
	Type      byte
	ChannelID uint32
	Payload   []byte
}

func writeFrame(w io.Writer, f frame) error {
	if len(f.Payload) > maxFrameLength-frameHeaderLength {
		return fmt.Errorf("frame payload length %d exceeds the %d limit", len(f.Payload), maxFrameLength-frameHeaderLength)
	}
	buf := make([]byte, 4+frameHeaderLength+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(frameHeaderLength+len(f.Payload)))
	buf[4] = f.Type
	binary.BigEndian.PutUint32(buf[5:9], f.ChannelID)
	copy(buf[9:], f.Payload)
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < frameHeaderLength {
		return frame{}, fmt.Errorf("frame length %d shorter than the header alone", n)
	}
	if n > maxFrameLength {
		return frame{}, fmt.Errorf("frame length %d exceeds the %d limit", n, maxFrameLength)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return frame{}, err
	}
	return frame{
		Type:      body[0],
		ChannelID: binary.BigEndian.Uint32(body[1:5]),
		Payload:   body[5:],
	}, nil
}

type errorCode string

const (
	errAuthFailed         errorCode = "auth_failed"
	errHostKeyUnknown     errorCode = "host_key_unknown"
	errHostKeyChanged     errorCode = "host_key_changed"
	errNetworkUnreachable errorCode = "network_unreachable"
	errTimeout            errorCode = "timeout"
	errConnectionLost     errorCode = "connection_lost"
	errProtocolError      errorCode = "protocol_error"
	errCancelled          errorCode = "cancelled"
	errPermissionDenied   errorCode = "permission_denied"
	errNotFound           errorCode = "not_found"
	errUnknown            errorCode = "unknown"
)

type controlMessage struct {
	Msg string `json:"msg"`

	Kind    string   `json:"kind,omitempty"`
	Command []string `json:"command,omitempty"`
	Pty     *bool    `json:"pty,omitempty"`
	Cols    int      `json:"cols,omitempty"`
	Rows    int      `json:"rows,omitempty"`
	Term    string   `json:"term,omitempty"`

	ExitCode int `json:"exit_code,omitempty"`

	Code    errorCode `json:"code,omitempty"`
	Message string    `json:"message,omitempty"`

	RequestID string `json:"request_id,omitempty"`

	PromptKind  string   `json:"prompt_kind,omitempty"`
	Remote      string   `json:"remote,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Prompt      string   `json:"prompt,omitempty"`
	Instruction string   `json:"instruction,omitempty"`
	Questions   []string `json:"questions,omitempty"`
	Echos       []bool   `json:"echos,omitempty"`

	Accept    bool     `json:"accept,omitempty"`
	Answer    string   `json:"answer,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	Cancelled bool     `json:"cancelled,omitempty"`

	KeyID     string `json:"key_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	SignData  []byte `json:"sign_data,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	DisableAgent bool `json:"disable_agent,omitempty"`

	Keys         [][]byte `json:"keys,omitempty"`
	Certificates [][]byte `json:"certificates,omitempty"`

	KeystoreKeyIDs     []string `json:"keystore_key_ids,omitempty"`
	KeystorePublicKeys [][]byte `json:"keystore_public_keys,omitempty"`

	AgentForwarding bool `json:"agent_forwarding,omitempty"`

	ProxyURL string `json:"proxy_url,omitempty"`

	Op      string `json:"op,omitempty"`
	Path    string `json:"path,omitempty"`
	NewPath string `json:"new_path,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
	UID     int    `json:"uid,omitempty"`
	GID     int    `json:"gid,omitempty"`
	Target  string `json:"target,omitempty"`
	Size    int64  `json:"size,omitempty"`
	ModTime int64  `json:"mod_time,omitempty"`

	Preserve  bool  `json:"preserve,omitempty"`
	BytesDone int64 `json:"bytes_done,omitempty"`

	Entries []sftpEntry `json:"entries,omitempty"`

	ListenAddr string `json:"listen_addr,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	BoundAddr  string `json:"bound_addr,omitempty"`

	ListenNetwork string `json:"listen_network,omitempty"`

	AllowNonLoopbackBind bool `json:"allow_non_loopback_bind,omitempty"`

	SocksUsername string `json:"socks_username,omitempty"`
	SocksPassword string `json:"socks_password,omitempty"`

	// MaxConnections caps how many connections a forward_local/forward_remote/
	// forward_socks channel will service at once; zero (the default, and
	// what every existing client that predates this field sends) means
	// unlimited, preserving prior behavior for anyone who doesn't opt in.
	MaxConnections int `json:"max_connections,omitempty"`
}

type sftpEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	ModTime int64  `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}
