package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

// The agent control protocol multiplexes everything -- control messages and
// channel data alike -- over one stdin/stdout pair as a stream of frames,
// the same way SSH itself multiplexes channels over one TCP connection, one
// level up. Framing: a 4-byte big-endian length prefix (covering everything
// that follows, not itself), then a 1-byte frame type, a 4-byte big-endian
// channel ID (0 for a connection-level message with no channel yet), and a
// payload -- JSON for a control frame, raw bytes for a data frame. Keeping
// data frames binary (not JSON/base64) matters for PTY and file-transfer
// throughput; control messages stay JSON because they're rare, small, and
// worth keeping easy to log and debug.
const (
	frameTypeControl byte = 0
	frameTypeData    byte = 1
)

// Data frame payloads carry one stream-tag byte ahead of the raw bytes, so
// stdout and stderr from the same exec channel can be told apart without a
// second channel ID per stream.
const (
	streamStdout byte = 0
	streamStderr byte = 1
)

// maxFrameLength caps how much a single length prefix can claim, so a
// corrupt or hostile stream can't force an unbounded allocation before
// readFrame even knows whether the rest of the frame will arrive.
const maxFrameLength = 64 << 20 // 64MiB, well past any single PTY/SFTP chunk this protocol sends

const frameHeaderLength = 5 // type (1) + channel ID (4), counted in the length prefix

type frame struct {
	Type      byte
	ChannelID uint32
	Payload   []byte
}

// writeFrame writes f to w in one call where possible: bufio.Writer.Write
// (the only writer this is used with) does not interleave with a
// concurrent Write, so a single combined buffer is what keeps concurrent
// callers from tearing frames into each other on the wire.
func writeFrame(w io.Writer, f frame) error {
	buf := make([]byte, 4+frameHeaderLength+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(frameHeaderLength+len(f.Payload)))
	buf[4] = f.Type
	binary.BigEndian.PutUint32(buf[5:9], f.ChannelID)
	copy(buf[9:], f.Payload)
	_, err := w.Write(buf)
	return err
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

// errorCode identifies why an operation failed, so a caller (the .NET side,
// ultimately an app's UI) can branch on what happened instead of pattern
// matching scraped diagnostic text. HostKeyChanged in particular needs to
// be easy to single out for a hard-stop warning, never silently retried.
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

// controlMessage is the JSON payload of a control frame. One flat,
// mostly-omitempty struct rather than a message-specific type per Msg
// value: the message set is small and every field is self-explanatory from
// its name, so a discriminated union of Go types would add ceremony
// (marshalling/unmarshalling boilerplate per type) without making any
// message easier to read on the wire or in a log.
//
// There is no ChannelID field here: the enclosing frame's ChannelID is the
// channel a message is about, for every message type including
// channel_opened (the frame carries the newly assigned ID; open_channel
// itself is sent on channel 0, since the client has no ID yet to send it
// on).
type controlMessage struct {
	Msg string `json:"msg"`

	// open_channel (client -> agent)
	Kind    string   `json:"kind,omitempty"`    // "shell" or "exec"
	Command []string `json:"command,omitempty"` // exec only
	Pty     *bool    `json:"pty,omitempty"`     // nil means "shell default true, exec default false"
	Cols    int      `json:"cols,omitempty"`
	Rows    int      `json:"rows,omitempty"`
	Term    string   `json:"term,omitempty"`

	// resize (client -> agent, shell channels only) reuses Cols/Rows above

	// exit_status (agent -> client)
	ExitCode int `json:"exit_code,omitempty"`

	// error (agent -> client); the frame's channel ID is 0 for a
	// connection-level failure, or the channel the error belongs to
	Code    errorCode `json:"code,omitempty"`
	Message string    `json:"message,omitempty"`

	// prompt_request (agent -> client) / prompt_response (client -> agent),
	// always on channel 0: a round trip the agent needs answered before it
	// can go on, mid-dial (host-key TOFU) or mid-auth (password,
	// keyboard-interactive, a passphrase). RequestID pairs a response to
	// its request, since more than one can be outstanding in principle
	// (a jump chain prompting for each hop) even though today's callers
	// only ever have one in flight at a time.
	RequestID string `json:"request_id,omitempty"`
	// PromptKind: "host_key", "password", "keyboard_interactive", or
	// "passphrase".
	PromptKind  string   `json:"prompt_kind,omitempty"`
	Remote      string   `json:"remote,omitempty"`      // host:port (or "tailcat") the prompt is about
	Fingerprint string   `json:"fingerprint,omitempty"` // host_key: SHA256:... of the offered key
	Prompt      string   `json:"prompt,omitempty"`      // password/passphrase: label to show
	Instruction string   `json:"instruction,omitempty"` // keyboard_interactive
	Questions   []string `json:"questions,omitempty"`   // keyboard_interactive
	Echos       []bool   `json:"echos,omitempty"`       // keyboard_interactive: whether each answer may be shown as typed

	// prompt_response fields
	Accept    bool     `json:"accept,omitempty"`    // host_key
	Answer    string   `json:"answer,omitempty"`    // password/passphrase
	Answers   []string `json:"answers,omitempty"`   // keyboard_interactive
	Cancelled bool     `json:"cancelled,omitempty"` // the user declined to answer at all

	// PromptKind "sign": a Keystore-backed key's Sign, round-tripped the
	// same way a password or passphrase prompt is (see agentauth.go's
	// keystoreSigner) rather than as a separate message pair -- it is one
	// more request/response the client answers, just with binary key
	// material instead of typed text. KeyID and Algorithm identify which
	// key and which signature format the agent's SSH negotiation asked
	// for; []byte fields are base64 on the wire, encoding/json's default
	// for a byte slice.
	KeyID     string `json:"key_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	SignData  []byte `json:"sign_data,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	// configure (client -> agent, mandatory, always the first message on
	// the connection, before anything else including a prompt_response --
	// no prompt exists yet to answer at that point). Every public-key
	// signer this connection may offer, gathered up front rather than
	// fetched on demand, since SSH tries public-key auth as one method
	// covering every key at once (see agentauth.go's buildAuthMethods).
	DisableAgent bool `json:"disable_agent,omitempty"` // skip the local ssh-agent even if one is running

	// Keys are private key blobs (any format ssh.ParsePrivateKey accepts);
	// Certificates, index-paired with Keys, are OpenSSH certificate public
	// keys to sign with instead of the bare key at the same index -- a
	// shorter Certificates than Keys leaves the extra keys uncertified.
	Keys         [][]byte `json:"keys,omitempty"`
	Certificates [][]byte `json:"certificates,omitempty"`

	// KeystoreKeyIDs/KeystorePublicKeys are index-paired: a public key the
	// agent can offer without ever holding the private half, signing
	// through a "sign" prompt instead (Android Keystore's own use case).
	KeystoreKeyIDs     []string `json:"keystore_key_ids,omitempty"`
	KeystorePublicKeys [][]byte `json:"keystore_public_keys,omitempty"`

	AgentForwarding bool `json:"agent_forwarding,omitempty"` // forward the local ssh-agent (if any) to the remote, once connected
}
