package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []frame{
		{Type: frameTypeControl, ChannelID: 0, Payload: []byte(`{"msg":"open_channel"}`)},
		{Type: frameTypeData, ChannelID: 7, Payload: append([]byte{streamStdout}, "hello\n"...)},
		{Type: frameTypeControl, ChannelID: 42, Payload: nil},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := writeFrame(&buf, c); err != nil {
			t.Fatalf("writeFrame(%+v) = %v", c, err)
		}
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame after writing %+v = %v", c, err)
		}
		if got.Type != c.Type || got.ChannelID != c.ChannelID || !bytes.Equal(got.Payload, c.Payload) {
			t.Errorf("round trip of %+v = %+v", c, got)
		}
	}
}

func TestReadFrameMultipleInSequence(t *testing.T) {
	var buf bytes.Buffer
	writeFrame(&buf, frame{Type: frameTypeControl, ChannelID: 1, Payload: []byte("a")})
	writeFrame(&buf, frame{Type: frameTypeData, ChannelID: 2, Payload: []byte("b")})

	f1, err := readFrame(&buf)
	if err != nil || f1.ChannelID != 1 {
		t.Fatalf("first frame = %+v, %v", f1, err)
	}
	f2, err := readFrame(&buf)
	if err != nil || f2.ChannelID != 2 {
		t.Fatalf("second frame = %+v, %v", f2, err)
	}
	if _, err := readFrame(&buf); err != io.EOF {
		t.Fatalf("readFrame at end of stream = %v, want io.EOF", err)
	}
}

func TestReadFrameRejectsOversizedLength(t *testing.T) {
	r := strings.NewReader(string([]byte{0xff, 0xff, 0xff, 0xff}))
	if _, err := readFrame(r); err == nil {
		t.Fatal("readFrame with a length far past maxFrameLength did not error")
	}
}

func TestReadFrameRejectsLengthShorterThanHeader(t *testing.T) {
	r := strings.NewReader(string([]byte{0, 0, 0, 2}))
	if _, err := readFrame(r); err == nil {
		t.Fatal("readFrame with a length shorter than the header did not error")
	}
}

func TestControlMessageJSONShape(t *testing.T) {
	pty := true
	msg := controlMessage{Msg: "open_channel", Kind: "exec", Command: []string{"ls", "-la"}, Pty: &pty, Cols: 80, Rows: 24}
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var got controlMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Msg != msg.Msg || got.Kind != msg.Kind || got.Cols != msg.Cols || got.Rows != msg.Rows {
		t.Errorf("round trip = %+v, want %+v", got, msg)
	}
	if got.Pty == nil || *got.Pty != true {
		t.Errorf("Pty round trip = %v, want true", got.Pty)
	}
}
