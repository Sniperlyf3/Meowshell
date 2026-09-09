package main

import (
	"slices"
	"strings"
	"testing"
)

// Same cases as tailcat's own cmd/tailcat/cp_test.go TestSplitRemoteArg:
// splitRemoteArg is a verbatim copy of tailcat's, so the same address
// syntax must be accepted or rejected identically by both.
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

// TestCPUsageErrors verifies cp's argument validation, which happens
// before any subprocess or SFTP connection.
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
