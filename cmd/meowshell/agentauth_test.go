package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testAuthSession wires an agentSession to a pair of pipes so a test can
// play the client side of the control protocol directly, in-process --
// no subprocess or real SSH server needed to exercise the prompt
// round-trip logic in agentauth.go on its own.
func testAuthSession(t *testing.T) (session *agentSession, fromAgent io.Reader, toAgent io.Writer) {
	t.Helper()
	agentIn, clientOut := io.Pipe()
	clientIn, agentOut := io.Pipe()
	session = newAgentSession(agentIn, agentOut)
	go session.serveFrames()
	t.Cleanup(func() { clientOut.Close() })
	return session, clientIn, clientOut
}

func readControlFrame(t *testing.T, r io.Reader) (frame, controlMessage) {
	t.Helper()
	f, err := readFrame(r)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	var msg controlMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		t.Fatalf("decoding control message: %v", err)
	}
	return f, msg
}

func TestParseKeyMaybePromptingRetriesOnWrongPassphrase(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("correct-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := pem.EncodeToMemory(block)

	session, fromAgent, toAgent := testAuthSession(t)

	answers := []string{"wrong-once", "correct-passphrase"}
	done := make(chan error, 1)
	go func() {
		for range answers {
			_, msg := readControlFrame(t, fromAgent)
			if msg.Msg != "prompt_request" || msg.PromptKind != "passphrase" {
				done <- nil // let the main goroutine's assertion below report the mismatch
				return
			}
			answer := answers[0]
			answers = answers[1:]
			body, _ := json.Marshal(controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Answer: answer})
			writeFrame(toAgent, frame{Type: frameTypeControl, ChannelID: 0, Payload: body})
		}
		done <- nil
	}()

	signer, err := session.parseKeyMaybePrompting(keyBytes)
	<-done
	if err != nil {
		t.Fatalf("parseKeyMaybePrompting: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("signer key type = %q, want %q", signer.PublicKey().Type(), ssh.KeyAlgoED25519)
	}
}

func TestKeystoreSignerRoundTrips(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	session, fromAgent, toAgent := testAuthSession(t)
	signer := &keystoreSigner{session: session, keyID: "keystore-key-1", pub: sshPub}

	wantSig := []byte("fake-signature-bytes")
	go func() {
		_, msg := readControlFrame(t, fromAgent)
		if msg.Msg != "prompt_request" || msg.PromptKind != "sign" || msg.KeyID != "keystore-key-1" {
			t.Errorf("sign prompt = %+v, want kind=sign key_id=keystore-key-1", msg)
			return
		}
		body, _ := json.Marshal(controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Signature: wantSig})
		writeFrame(toAgent, frame{Type: frameTypeControl, ChannelID: 0, Payload: body})
	}()

	sig, err := signer.Sign(nil, []byte("data to sign"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(sig.Blob) != string(wantSig) {
		t.Errorf("signature = %q, want %q", sig.Blob, wantSig)
	}
}

func TestKeystoreSignerPropagatesRefusal(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	session, fromAgent, toAgent := testAuthSession(t)
	signer := &keystoreSigner{session: session, keyID: "keystore-key-1", pub: sshPub}

	go func() {
		_, msg := readControlFrame(t, fromAgent)
		body, _ := json.Marshal(controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Cancelled: true})
		writeFrame(toAgent, frame{Type: frameTypeControl, ChannelID: 0, Payload: body})
	}()

	if _, err := signer.Sign(nil, []byte("data")); err == nil {
		t.Fatal("Sign with a cancelled response did not error")
	}
}
