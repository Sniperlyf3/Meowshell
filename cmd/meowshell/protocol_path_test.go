package main

import (
	"encoding/json"
	"testing"
)

func TestPathControlMessagePreservesRelayedStateAndCounters(t *testing.T) {
	direct := false
	original := controlMessage{
		Msg:              "path",
		Direct:           &direct,
		Via:              "derp-eu.meowssh.dev",
		RelayedBytesSent: 182400,
		RelayedBytesRecv: 906112,
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded controlMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Msg != "path" {
		t.Fatalf("msg = %q, want path", decoded.Msg)
	}
	if decoded.Direct == nil || *decoded.Direct {
		t.Fatalf("direct = %#v, want explicit false", decoded.Direct)
	}
	if decoded.Via != original.Via {
		t.Fatalf("via = %q, want %q", decoded.Via, original.Via)
	}
	if decoded.RelayedBytesSent != original.RelayedBytesSent {
		t.Fatalf("relayed_bytes_sent = %d, want %d", decoded.RelayedBytesSent, original.RelayedBytesSent)
	}
	if decoded.RelayedBytesRecv != original.RelayedBytesRecv {
		t.Fatalf("relayed_bytes_recv = %d, want %d", decoded.RelayedBytesRecv, original.RelayedBytesRecv)
	}
}

func TestPathControlMessageDistinguishesDirectFromUnknown(t *testing.T) {
	direct := true
	encoded, err := json.Marshal(controlMessage{Msg: "path", Direct: &direct})
	if err != nil {
		t.Fatal(err)
	}

	var decoded controlMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Direct == nil || !*decoded.Direct {
		t.Fatalf("direct = %#v, want explicit true", decoded.Direct)
	}

	var older controlMessage
	if err := json.Unmarshal([]byte(`{"msg":"path"}`), &older); err != nil {
		t.Fatal(err)
	}
	if older.Direct != nil {
		t.Fatalf("direct = %#v, want nil for an older sender with no path field", older.Direct)
	}
}
