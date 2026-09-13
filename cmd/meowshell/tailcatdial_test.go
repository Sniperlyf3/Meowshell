package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tailscale/tailcat"
)

// TestTailcatKeyFromNameUsesSavedClientDefault is a regression test:
// tailcatKeyFromName("") used to always generate a fresh ephemeral key,
// diverging from tailcat's own clientKey() (used by the SSH transport
// subprocess for the exact same empty --key case), which loads a saved
// "client-default" key when one exists. The mismatch meant exit-node
// forwarding's in-process tailcat.Client could authenticate as a different
// identity than the SSH connection did, silently failing authorization
// against a destination's --allow list that only names the saved key.
func TestTailcatKeyFromNameUsesSavedClientDefault(t *testing.T) {
	configRoot := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", configRoot)
	} else {
		t.Setenv("XDG_CONFIG_HOME", configRoot)
	}

	t.Run("no saved client-default key: falls back to a fresh ephemeral key", func(t *testing.T) {
		got, err := tailcatKeyFromName("")
		if err != nil {
			t.Fatal(err)
		}
		again, err := tailcatKeyFromName("")
		if err != nil {
			t.Fatal(err)
		}
		if got.Public() == again.Public() {
			t.Fatal("two calls with no saved key returned the same key; want a fresh ephemeral one each time")
		}
	})

	confDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(confDir, "tailcat", "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	saved := tailcat.NewPrivateKey()
	body, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "client-default.private.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("a saved client-default key is used, matching tailcat's own clientKey()", func(t *testing.T) {
		got, err := tailcatKeyFromName("")
		if err != nil {
			t.Fatal(err)
		}
		if got.Public() != saved.Private.Public() {
			t.Errorf("tailcatKeyFromName(\"\") = %s, want the saved client-default key %s", got.Public(), saved.Private.Public())
		}
	})

	t.Run("--key=new still means a fresh ephemeral key, even with a saved client-default present", func(t *testing.T) {
		got, err := tailcatKeyFromName("new")
		if err != nil {
			t.Fatal(err)
		}
		if got.Public() == saved.Private.Public() {
			t.Error("tailcatKeyFromName(\"new\") returned the saved client-default key; want a fresh ephemeral one")
		}
	})
}


func TestTailcatKeyFromNameRejectsOversizedKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.private.json")
	if err := os.WriteFile(path, make([]byte, maxTailcatKeyJSON+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tailcatKeyFromName(path); err == nil {
		t.Fatal("oversized key file was accepted")
	}
}
