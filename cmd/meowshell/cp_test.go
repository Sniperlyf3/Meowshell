package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSplitRemoteArg(t *testing.T) {
	for _, tt := range []struct {
		arg        string
		host, path string
		ok         bool
	}{
		{"tcBLOB:foo.txt", "tcBLOB", "foo.txt", true},
		{"tcBLOB:", "tcBLOB", "", true},
		{"example.com:dir/foo", "example.com", "dir/foo", true},
		{"foo.txt", "", "", false},
		{"./dir:with:colons", "", "", false},
		{`C:\Users\foo`, "", "", false},
		{"C:/Users/foo", "", "", false},
		{":leading-colon", "", "", false},
	} {
		host, path, ok := splitRemoteArg(tt.arg)
		if host != tt.host || path != tt.path || ok != tt.ok {
			t.Errorf("splitRemoteArg(%q) = %q, %q, %v; want %q, %q, %v",
				tt.arg, host, path, ok, tt.host, tt.path, tt.ok)
		}
	}
}

func TestTailcatClientArgv(t *testing.T) {
	for _, tt := range []struct {
		name            string
		key, derpMapURL string
		verbose         bool
		addr, port      string
		want            []string
	}{
		{"bare", "", "", false, "tcADDR", "22", []string{"tcADDR", "22"}},
		{"with key", "mykey", "", false, "tcADDR", "22", []string{"--key=mykey", "tcADDR", "22"}},
		{"with derp map", "", "https://example.com/map.json", false, "tcADDR", "2222",
			[]string{"--derpmap-url=https://example.com/map.json", "tcADDR", "2222"}},
		{"verbose", "", "", true, "tcADDR", "22", []string{"--verbose", "tcADDR", "22"}},
		{"everything together", "mykey", "https://example.com/map.json", true, "tcADDR", "22",
			[]string{"--key=mykey", "--derpmap-url=https://example.com/map.json", "--verbose", "tcADDR", "22"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := tailcatClientArgv(tt.key, tt.derpMapURL, tt.verbose, tt.addr, tt.port)
			if !slices.Equal(got, tt.want) {
				t.Errorf("tailcatClientArgv(%q, %q, %v, %q, %q) = %v; want %v",
					tt.key, tt.derpMapURL, tt.verbose, tt.addr, tt.port, got, tt.want)
			}
		})
	}
}

func TestFilepathRelFromSlash(t *testing.T) {
	for _, tt := range []struct {
		base, target, want string
		wantErr            bool
	}{
		{"photos", "photos", ".", false},
		{"photos", "photos/a.jpg", "a.jpg", false},
		{"photos", "photos/sub/b.jpg", "sub/b.jpg", false},
		{"photos", "other/a.jpg", "", true},
		{".", ".", ".", false},
		{".", "a.jpg", "a.jpg", false},
		{".", "sub/b.jpg", "sub/b.jpg", false},
		// Regression cases: base=="." used to return target completely
		// unchecked, so a walker entry (however it came to look like this --
		// a hostile server, a symlink, a bug) escaping via ".." was let
		// straight through to a caller's filepath.Join(localPath, rel).
		{".", "..", "", true},
		{".", "../etc/passwd", "", true},
		{".", "/etc/passwd", "", true},
		{"photos", "../etc/passwd", "", true},
	} {
		got, err := filepathRelFromSlash(tt.base, tt.target)
		if tt.wantErr {
			if err == nil {
				t.Errorf("filepathRelFromSlash(%q, %q) = %q, nil; want an error", tt.base, tt.target, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("filepathRelFromSlash(%q, %q) unexpected error: %v", tt.base, tt.target, err)
			continue
		}
		// tt.want is written with "/" for readability; filepathRelFromSlash
		// returns a native filepath (backslash on Windows), by design, since
		// callers feed it straight into filepath.Join for a local path.
		if want := filepath.FromSlash(tt.want); got != want {
			t.Errorf("filepathRelFromSlash(%q, %q) = %q; want %q", tt.base, tt.target, got, want)
		}
	}
}

// TestUploadPreservesDirectoryModTime is a regression test: recursive
// upload with -p (preserve) only ever preserved file metadata -- a
// directory's mtime/mode was never touched, so a preserved copy's
// directories all showed the copy time instead of the source's real one.
// Applying it eagerly (right after MkdirAll) wouldn't have worked either:
// uploading further files into that directory afterward updates its mtime
// again, clobbering whatever was just set -- so the fix collects directory
// metadata during the walk and applies it only once the whole upload is
// done. The nested file here (not just an empty directory) is what makes
// that ordering matter for this test.
func TestUploadPreservesDirectoryModTime(t *testing.T) {
	session, client, _, _ := newInProcessSFTPClient(t)
	_ = session

	srcRoot := t.TempDir()
	subDir := filepath.Join(srcRoot, "sub")
	if err := os.Mkdir(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "f.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantModTime := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(subDir, wantModTime, wantModTime); err != nil {
		t.Fatal(err)
	}

	if err := upload(client, srcRoot, "dest", true, true); err != nil {
		t.Fatal(err)
	}

	fi, err := client.Stat("dest/sub")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(wantModTime) {
		t.Errorf("uploaded directory mtime = %v, want %v (the source's, not whenever the last file was written into it)", fi.ModTime(), wantModTime)
	}
}

// TestDownloadPreservesDirectoryModTime is the download-side equivalent of
// TestUploadPreservesDirectoryModTime, same reasoning.
func TestDownloadPreservesDirectoryModTime(t *testing.T) {
	session, client, _, _ := newInProcessSFTPClient(t)
	_ = session

	if err := client.MkdirAll("remote/sub"); err != nil {
		t.Fatal(err)
	}
	f, err := client.Create("remote/sub/f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wantModTime := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := client.Chtimes("remote/sub", wantModTime, wantModTime); err != nil {
		t.Fatal(err)
	}

	localRoot := t.TempDir()
	dst := filepath.Join(localRoot, "dest")
	if err := download(client, "remote", dst, true, true); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(filepath.Join(dst, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(wantModTime) {
		t.Errorf("downloaded directory mtime = %v, want %v (the source's, not whenever the last file was written into it)", fi.ModTime(), wantModTime)
	}
}

// TestUploadRefusesToFollowSymlink is a regression test: a recursive
// upload's filepath.WalkDir doesn't descend through a directory symlink
// itself, but a symlink *entry* reaches uploadFile the same way a regular
// file does (WalkDir's DirEntry.IsDir() is false for a symlink, even one
// pointing at a directory), and uploadFile's os.Open silently follows it --
// uploading whatever the link actually points to under the innocuous name
// the tree shows. A symlink named "backup" pointing at ~/.ssh/id_ed25519
// inside an otherwise-innocent directory would have the key's contents
// uploaded without any indication in the source tree's own listing.
func TestUploadRefusesToFollowSymlink(t *testing.T) {
	session, client, _, _ := newInProcessSFTPClient(t)
	_ = session

	srcRoot := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("SENSITIVE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(srcRoot, "innocuous-name")); err != nil {
		t.Fatal(err)
	}

	err := upload(client, srcRoot, "dest", true, false)
	if err == nil {
		t.Fatal("upload through a symlinked entry succeeded; want it refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("upload error = %v, want it to mention the symlink", err)
	}

	if _, statErr := client.Stat("dest/innocuous-name"); statErr == nil {
		t.Error("the symlink's target content was uploaded to the server despite the error")
	}
}

// TestDownloadRefusesToEscapeViaLocalSymlink is a regression test:
// filepathRelFromSlash only validates the *textual* remote path (rejecting
// ".." components), but that alone doesn't stop a destination tree that
// already contains a symlink component from being written through --
// filepath.Join + os.MkdirAll/os.Create followed such a symlink like any
// other directory. If a local "download/outside" entry were ever a symlink
// pointing elsewhere (planted by an earlier run, another process, or a
// mistake), remote content named "outside/whatever" would land there
// instead of inside the requested download root.
func TestDownloadRefusesToEscapeViaLocalSymlink(t *testing.T) {
	session, client, _, _ := newInProcessSFTPClient(t)
	_ = session

	if err := client.MkdirAll("remote/outside"); err != nil {
		t.Fatal(err)
	}
	f, err := client.Create("remote/outside/payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	localRoot := t.TempDir()
	dst := filepath.Join(localRoot, "dest")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	escapeTarget := t.TempDir()
	if err := os.Symlink(escapeTarget, filepath.Join(dst, "outside")); err != nil {
		t.Fatal(err)
	}

	if err := download(client, "remote", dst, true, false); err == nil {
		t.Fatal("download through a locally-symlinked destination component succeeded; want it refused")
	}

	if _, statErr := os.Stat(filepath.Join(escapeTarget, "payload.txt")); statErr == nil {
		t.Error("remote content was written through the local symlink, escaping the requested download root")
	}
}

// TestUploadFileReplacesExistingDestinationAtomicallyWithNoStagingLitter is a
// regression test for N12: uploadFile used to sf.Create(remotePath)
// directly, truncating an existing destination immediately -- a transfer
// that then failed left the original good file destroyed and a
// half-written (or empty) one in its place. It now stages to a temp path
// and only replaces the destination via an atomic rename once the transfer
// has fully succeeded. Confirms the successful-overwrite path lands the new
// content and, just as importantly, leaves no ".meowshell-upload-*" staging
// file behind once committed.
func TestUploadFileReplacesExistingDestinationAtomicallyWithNoStagingLitter(t *testing.T) {
	_, client, _, _ := newInProcessSFTPClient(t)

	orig, err := client.Create("dest.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orig.Write([]byte("original content")); err != nil {
		t.Fatal(err)
	}
	if err := orig.Close(); err != nil {
		t.Fatal(err)
	}

	localSrc := filepath.Join(t.TempDir(), "src.txt")
	newContent := []byte("replacement content")
	if err := os.WriteFile(localSrc, newContent, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := uploadFile(client, localSrc, "dest.txt", false); err != nil {
		t.Fatalf("uploadFile: %v", err)
	}

	got := readRemoteFile(t, client, "dest.txt")
	if string(got) != string(newContent) {
		t.Errorf("dest.txt content = %q, want %q", got, newContent)
	}

	entries, err := client.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "dest.txt" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("remote directory entries after upload = %v, want exactly [\"dest.txt\"] (no leftover staging file)", names)
	}
}

// TestUploadFileDoesNotDestroyExistingFileOnFailure is uploadFile's side of
// the same N12 fix: it used to sf.Create(remotePath) directly, which opens
// (and truncates, if the destination already exists) the real destination
// immediately, before a single byte of the new content has actually arrived
// -- so a transfer that failed anywhere after that still left a previously
// good remote file destroyed or half-written. Runs uploadFile against a
// large payload in the background and severs the transport the moment a
// staging file first appears next to dest.txt (the earliest point at which
// the fixed uploadFile has opened anything server-side), landing the break
// after the open but before the transfer's atomic commit -- exactly the
// window the old direct-truncate version got wrong. Verification reads the
// server's backing directory (rootDir) directly, since the client itself is
// unusable once its transport is severed.
func TestUploadFileDoesNotDestroyExistingFileOnFailure(t *testing.T) {
	_, client, rootDir, breakTransport := newInProcessSFTPClient(t)

	origContent := []byte("original good remote content, must survive")
	destPath := filepath.Join(rootDir, "dest.txt")
	if err := os.WriteFile(destPath, origContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// Large enough that io.Copy needs many Write round trips, giving the
	// polling loop below a realistic window to land the break mid-transfer
	// instead of racing a single-shot copy that might already be done.
	localSrc := filepath.Join(t.TempDir(), "src.txt")
	payload := bytes.Repeat([]byte("x"), 4*1024*1024)
	if err := os.WriteFile(localSrc, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	uploadErr := make(chan error, 1)
	go func() {
		uploadErr <- uploadFile(client, localSrc, "dest.txt", false)
	}()

	staged := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "dest.txt" {
				staged = true
			}
		}
		if staged {
			break
		}
		time.Sleep(100 * time.Microsecond)
	}
	if !staged {
		t.Fatal("uploadFile never opened anything on the server before the deadline")
	}
	breakTransport()

	if err := <-uploadErr; err == nil {
		t.Fatal("uploadFile succeeded despite a broken transport; want an error")
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(origContent) {
		t.Errorf("remote dest.txt content = %q (%d bytes), want the original %q (%d bytes) untouched",
			truncateForDisplay(got), len(got), origContent, len(origContent))
	}

	// Cleanup of the staging file itself needs a working transport to ask
	// the server to remove it (the deferred sf.Remove(tempPath) in
	// uploadFile), so it can't succeed when the transport is exactly what
	// just broke -- that's a separate, unavoidable "orphaned staging file
	// after a dropped connection" concern, not the destination-integrity
	// property this test checks. TestUploadFileReplacesExistingDestinationAtomicallyWithNoStagingLitter
	// already covers no-litter for the ordinary success path.
}

// truncateForDisplay keeps a failed assertion's output readable when got is
// the multi-megabyte payload instead of the short original content.
func truncateForDisplay(b []byte) []byte {
	const max = 64
	if len(b) <= max {
		return b
	}
	return append(append([]byte{}, b[:max]...), []byte("...(truncated)")...)
}

// TestDownloadFileDoesNotDestroyExistingFileOnFailure is downloadFile's side
// of the same N12 fix: it used to os.Create(localPath) directly. Simulated
// the same way, by severing the transport before the download starts.
func TestDownloadFileDoesNotDestroyExistingFileOnFailure(t *testing.T) {
	_, client, _, breakTransport := newInProcessSFTPClient(t)

	f, err := client.Create("remote.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("remote content")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := client.Stat("remote.txt")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	localDst := filepath.Join(dir, "dest.txt")
	goodContent := []byte("original good local content, must survive")
	if err := os.WriteFile(localDst, goodContent, 0o600); err != nil {
		t.Fatal(err)
	}

	breakTransport()

	if err := downloadFile(client, "remote.txt", localDst, fi, false); err == nil {
		t.Fatal("downloadFile succeeded despite a broken transport; want an error")
	}

	got, err := os.ReadFile(localDst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(goodContent) {
		t.Errorf("local dest.txt content = %q, want the original %q untouched", got, goodContent)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("download destination directory has %d entries after a failed download, want exactly 1 (no leftover staging file): %v", len(entries), entries)
	}
}

func TestCPUsageErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"too few args", []string{"foo.txt"}, "at least one source"},
		{"no remote arg", []string{"foo.txt", "bar.txt"}, "no remote"},
		{"two different servers", []string{"tcAAA:x", "tcBBB:y"}, "must name the same server"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := cp(tt.args)
			if err == nil {
				t.Fatalf("cp(%v) = nil; want an error", tt.args)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("cp(%v) error = %q; want it to contain %q", tt.args, err.Error(), tt.want)
			}
		})
	}
}
