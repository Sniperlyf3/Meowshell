package main

import "sync"

var (
	stagedKeyMu   sync.Mutex
	stagedKeyData []byte
)

// stageKey deliberately does not create a named temporary file on Windows.
// The bundled tailcat is patched to interpret --key=- as "read the private
// key JSON from stdin"; runTailcat pipes this in-memory copy to the child after
// it starts. That removes both the old arbitrary one-second deletion race and
// private-key residue if meowshell is terminated abnormally.
func stageKey(_ string, data []byte) (string, error) {
	stagedKeyMu.Lock()
	defer stagedKeyMu.Unlock()
	zeroBytes(stagedKeyData)
	stagedKeyData = append([]byte(nil), data...)
	return "-", nil
}

func takeStagedKey() []byte {
	stagedKeyMu.Lock()
	defer stagedKeyMu.Unlock()
	data := stagedKeyData
	stagedKeyData = nil
	return data
}

func cleanupStagedKey() {
	stagedKeyMu.Lock()
	defer stagedKeyMu.Unlock()
	zeroBytes(stagedKeyData)
	stagedKeyData = nil
}

func zeroBytes(p []byte) {
	for i := range p {
		p[i] = 0
	}
}
