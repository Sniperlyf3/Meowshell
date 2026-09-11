package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"slices"
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

func rsaTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func ecdsaTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func ed25519TestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func TestKeystoreSignerAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		pub  ssh.PublicKey
		want []string
	}{
		{"rsa offers SHA-2 before SHA-1", rsaTestPublicKey(t), []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}},
		{"ecdsa offers only its own type", ecdsaTestPublicKey(t), []string{ssh.KeyAlgoECDSA256}},
		{"ed25519 offers only its own type", ed25519TestPublicKey(t), []string{ssh.KeyAlgoED25519}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &keystoreSigner{keyID: "k", pub: tt.pub}
			if got := signer.Algorithms(); !slices.Equal(got, tt.want) {
				t.Errorf("Algorithms() = %q, want %q", got, tt.want)
			}
		})
	}
}

// answerSignPrompt reads one sign prompt and answers it with sig, reporting the
// algorithm the signer asked for.
func answerSignPrompt(t *testing.T, fromAgent io.Reader, toAgent io.Writer, sig []byte) <-chan string {
	t.Helper()
	algorithms := make(chan string, 1)
	go func() {
		f, err := readFrame(fromAgent)
		if err != nil {
			close(algorithms)
			return
		}
		var msg controlMessage
		if err := json.Unmarshal(f.Payload, &msg); err != nil {
			close(algorithms)
			return
		}
		algorithms <- msg.Algorithm
		body, _ := json.Marshal(controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Signature: sig})
		writeFrame(toAgent, frame{Type: frameTypeControl, ChannelID: 0, Payload: body})
	}()
	return algorithms
}

func TestKeystoreSignerForwardsNegotiatedAlgorithm(t *testing.T) {
	session, fromAgent, toAgent := testAuthSession(t)
	signer := &keystoreSigner{session: session, keyID: "keystore-rsa", pub: rsaTestPublicKey(t)}

	asked := answerSignPrompt(t, fromAgent, toAgent, []byte("fake-signature-bytes"))

	sig, err := signer.SignWithAlgorithm(nil, []byte("data to sign"), ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if got := <-asked; got != ssh.KeyAlgoRSASHA256 {
		t.Errorf("prompt algorithm = %q, want %q", got, ssh.KeyAlgoRSASHA256)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Errorf("signature format = %q, want %q", sig.Format, ssh.KeyAlgoRSASHA256)
	}
}

func TestKeystoreSignerEmptyAlgorithmUsesFirstPreference(t *testing.T) {
	session, fromAgent, toAgent := testAuthSession(t)
	signer := &keystoreSigner{session: session, keyID: "keystore-rsa", pub: rsaTestPublicKey(t)}

	asked := answerSignPrompt(t, fromAgent, toAgent, []byte("fake-signature-bytes"))

	sig, err := signer.SignWithAlgorithm(nil, []byte("data to sign"), "")
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if got := <-asked; got != ssh.KeyAlgoRSASHA512 {
		t.Errorf("prompt algorithm = %q, want the first preference %q", got, ssh.KeyAlgoRSASHA512)
	}
	if sig.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("signature format = %q, want %q", sig.Format, ssh.KeyAlgoRSASHA512)
	}
}

func TestKeystoreSignerRejectsUnsupportedAlgorithmWithoutPrompting(t *testing.T) {
	session, fromAgent, _ := testAuthSession(t)
	signer := &keystoreSigner{session: session, keyID: "keystore-ecdsa", pub: ecdsaTestPublicKey(t)}

	prompted := make(chan struct{})
	go func() {
		if _, err := readFrame(fromAgent); err == nil {
			close(prompted)
		}
	}()

	if _, err := signer.SignWithAlgorithm(nil, []byte("data"), ssh.KeyAlgoRSASHA512); err == nil {
		t.Fatal("signing with an algorithm the key cannot produce did not error")
	}

	select {
	case <-prompted:
		t.Fatal("a sign prompt was sent for an algorithm the key cannot produce")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestKeystoreSignFailureIsReportedAsAnAuthFailure(t *testing.T) {
	session, fromAgent, toAgent := testAuthSession(t)
	signer := &keystoreSigner{session: session, keyID: "keystore-key-1", pub: ed25519TestPublicKey(t)}

	go func() {
		f, err := readFrame(fromAgent)
		if err != nil {
			return
		}
		var msg controlMessage
		if err := json.Unmarshal(f.Payload, &msg); err != nil {
			return
		}
		body, _ := json.Marshal(controlMessage{Msg: "prompt_response", RequestID: msg.RequestID, Cancelled: true})
		writeFrame(toAgent, frame{Type: frameTypeControl, ChannelID: 0, Payload: body})
	}()

	_, err := signer.Sign(nil, []byte("data"))
	if err == nil {
		t.Fatal("Sign with a cancelled response did not error")
	}
	// The handshake wraps whatever a signer returns, so the classification has
	// to survive wrapping the way it reaches the agent's error reporting.
	wrapped := fmt.Errorf("ssh: handshake failed: %w", err)
	if got := classifyConnectError(wrapped); got != errAuthFailed {
		t.Errorf("classifyConnectError(%v) = %q, want %q", wrapped, got, errAuthFailed)
	}
}
