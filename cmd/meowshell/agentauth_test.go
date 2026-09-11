package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDeliverPromptResponseDoesNotBlockOnDuplicate(t *testing.T) {
	session := newAgentSession(nil, nil)
	responses := make(chan controlMessage, 1)
	session.prompts["p1"] = responses

	done := make(chan struct{})
	go func() {
		session.deliverPromptResponse(controlMessage{RequestID: "p1", Answer: "first"})
		session.deliverPromptResponse(controlMessage{RequestID: "p1", Answer: "duplicate"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a duplicate prompt response blocked the frame reader")
	}
	if got := (<-responses).Answer; got != "first" {
		t.Fatalf("delivered answer = %q, want first", got)
	}
}

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
				done <- nil
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
