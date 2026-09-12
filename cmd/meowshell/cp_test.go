package main

import (
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
		if got != tt.want {
			t.Errorf("filepathRelFromSlash(%q, %q) = %q; want %q", tt.base, tt.target, got, tt.want)
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
	session, client, _ := newInProcessSFTPClient(t)
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
	session, client, _ := newInProcessSFTPClient(t)
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
	session, client, _ := newInProcessSFTPClient(t)
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
	session, client, _ := newInProcessSFTPClient(t)
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
