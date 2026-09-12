package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func writeFakeTailcat(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	name := "tailcat"
	if runtime.GOOS == "windows" {
		name = "tailcat.exe"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func captureRunTailcat(t *testing.T) *capturedRun {
	t.Helper()
	captured := &capturedRun{}
	prev := runTailcatFn
	runTailcatFn = func(bin string, argv, environ []string) error {
		captured.bin = bin
		captured.argv = argv
		captured.environ = environ
		return nil
	}
	t.Cleanup(func() { runTailcatFn = prev })
	return captured
}

type capturedRun struct {
	bin     string
	argv    []string
	environ []string
}

func TestSplitForcedCommand(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantRest    []string
		wantCommand []string
	}{
		{"no separator", []string{"--insecure-no-auth", "--allow=x"}, []string{"--insecure-no-auth", "--allow=x"}, nil},
		{"separator with a command", []string{"--insecure-no-auth", "--", "echo", "hi"}, []string{"--insecure-no-auth"}, []string{"echo", "hi"}},
		{"separator with nothing after", []string{"--insecure-no-auth", "--"}, []string{"--insecure-no-auth"}, nil},
		{"bare separator", []string{"--"}, nil, nil},
		{"no args at all", nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rest, command := splitForcedCommand(c.args)
			if !slices.Equal(rest, c.wantRest) {
				t.Errorf("rest = %v, want %v", rest, c.wantRest)
			}
			if !slices.Equal(command, c.wantCommand) {
				t.Errorf("command = %v, want %v", command, c.wantCommand)
			}
		})
	}
}

func TestServeArgv(t *testing.T) {
	tailcat := writeFakeTailcat(t)

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "derpmap-url reaches tailcat",
			args: []string{"--insecure-no-auth", "--tailcat=" + tailcat, "--derpmap-url=https://derp.example/map.json"},
			want: []string{tailcat, "serve", "--derpmap-url=https://derp.example/map.json", "no-auth-ssh"},
		},
		{
			name: "verbose reaches tailcat",
			args: []string{"--insecure-no-auth", "--tailcat=" + tailcat, "--verbose"},
			want: []string{tailcat, "serve", "--verbose", "no-auth-ssh"},
		},
		{
			name: "full-address reaches tailcat",
			args: []string{"--insecure-no-auth", "--tailcat=" + tailcat, "--full-address"},
			want: []string{tailcat, "serve", "--full-address", "no-auth-ssh"},
		},
		{
			name: "psk=false reaches tailcat",
			args: []string{"--insecure-no-auth", "--tailcat=" + tailcat, "--psk=false"},
			want: []string{tailcat, "serve", "--psk=false", "no-auth-ssh"},
		},
		{
			name: "psk left at its default true is not passed through",
			args: []string{"--insecure-no-auth", "--tailcat=" + tailcat},
			want: []string{tailcat, "serve", "no-auth-ssh"},
		},
		{
			name: "a forced command reaches tailcat after the service, behind its own --",
			args: []string{"--insecure-no-auth", "--tailcat=" + tailcat, "--", "echo", "hi"},
			want: []string{tailcat, "serve", "no-auth-ssh", "--", "echo", "hi"},
		},
		{
			name: "authorized-keys selects the ssh service, not no-auth-ssh",
			args: []string{"--authorized-keys=alice@github", "--tailcat=" + tailcat},
			want: []string{tailcat, "serve", "--ssh-authorized-keys=alice@github", "ssh"},
		},
		{
			name: "every new flag together, in the order tailcat expects",
			args: []string{
				"--insecure-no-auth", "--tailcat=" + tailcat,
				"--derpmap-url=https://derp.example/map.json", "--verbose", "--full-address", "--psk=false",
				"--", "echo", "hi",
			},
			want: []string{
				tailcat, "serve",
				"--derpmap-url=https://derp.example/map.json", "--verbose", "--full-address", "--psk=false",
				"no-auth-ssh", "--", "echo", "hi",
			},
		},
		{
			name: "files alone, no ssh service token",
			args: []string{"--files=/srv/drop", "--tailcat=" + tailcat},
			want: []string{tailcat, "serve", "--files=/srv/drop"},
		},
		{
			name: "files combined with no-auth-ssh serves both",
			args: []string{"--insecure-no-auth", "--files=/srv/drop", "--tailcat=" + tailcat},
			want: []string{tailcat, "serve", "--files=/srv/drop", "no-auth-ssh"},
		},
		{
			name: "files combined with authorized-keys serves both",
			args: []string{"--authorized-keys=alice@github", "--files=/srv/drop:rw", "--tailcat=" + tailcat},
			want: []string{tailcat, "serve", "--ssh-authorized-keys=alice@github", "--files=/srv/drop:rw", "ssh"},
		},
		{
			name: "a standalone forced command with no ssh or files selects tailcat's auto-detected exec service",
			args: []string{"--tailcat=" + tailcat, "--", "echo", "hi"},
			want: []string{tailcat, "serve", "--", "echo", "hi"},
		},
		{
			name: "exit-node alone, no ssh service token",
			args: []string{"--exit-node", "--tailcat=" + tailcat},
			want: []string{tailcat, "serve", "exit-node"},
		},
		{
			name: "exit-node combined with no-auth-ssh joins into one comma-separated service token",
			args: []string{"--insecure-no-auth", "--exit-node", "--tailcat=" + tailcat},
			want: []string{tailcat, "serve", "no-auth-ssh,exit-node"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			captured := captureRunTailcat(t)
			if err := serve(c.args); err != nil {
				t.Fatalf("serve(%v) = %v", c.args, err)
			}
			if !slices.Equal(captured.argv, c.want) {
				t.Errorf("argv = %v, want %v", captured.argv, c.want)
			}
		})
	}
}

func TestConnectRequiresAnAddress(t *testing.T) {
	if err := connect(nil); err == nil {
		t.Fatal("connect with no address did not error")
	}
}

func TestConnectRejectsConflictingPtyFlags(t *testing.T) {
	if err := connect([]string{"-t", "-T", "tcaddr"}); err == nil {
		t.Fatal("connect with both -t and -T did not error")
	}
}

func TestAgentRequiresExactlyOneAddress(t *testing.T) {
	cases := [][]string{nil, {"tcaddr", "extra"}}
	for _, args := range cases {
		if err := agentCmd(args); err == nil {
			t.Errorf("agentCmd(%v) did not error", args)
		}
	}
}

func TestSocksArgv(t *testing.T) {
	tailcat := writeFakeTailcat(t)

	captured := captureRunTailcat(t)
	args := []string{
		"--tailcat=" + tailcat, "--listen=127.0.0.1:1080", "--key=client-default",
		"--derpmap-url=https://derp.example/map.json", "--verbose",
	}
	if err := socks(args); err != nil {
		t.Fatalf("socks(%v) = %v", args, err)
	}
	want := []string{
		tailcat, "--key=client-default", "--derpmap-url=https://derp.example/map.json", "--verbose",
		"socks", "--listen=127.0.0.1:1080",
	}
	if !slices.Equal(captured.argv, want) {
		t.Errorf("argv = %v, want %v", captured.argv, want)
	}
}

func TestForwardArgv(t *testing.T) {
	tailcat := writeFakeTailcat(t)

	captured := captureRunTailcat(t)
	args := []string{
		"--tailcat=" + tailcat, "--bind=0.0.0.0", "--key=client-default",
		"--derpmap-url=https://derp.example/map.json", "--verbose",
		"tcaddr", "8080", "0:9090",
	}
	if err := forward(args); err != nil {
		t.Fatalf("forward(%v) = %v", args, err)
	}
	want := []string{
		tailcat, "--key=client-default", "--derpmap-url=https://derp.example/map.json", "--verbose",
		"forward", "--bind=0.0.0.0", "tcaddr", "8080", "0:9090",
	}
	if !slices.Equal(captured.argv, want) {
		t.Errorf("argv = %v, want %v", captured.argv, want)
	}
}

func TestForwardRequiresAnAddressAndAMapping(t *testing.T) {
	tailcat := writeFakeTailcat(t)
	captureRunTailcat(t)

	cases := [][]string{
		nil,
		{"--tailcat=" + tailcat},
		{"--tailcat=" + tailcat, "tcaddr"},
	}
	for _, args := range cases {
		if err := forward(args); err == nil {
			t.Errorf("forward(%v) did not error", args)
		}
	}
}

func TestServeValidation(t *testing.T) {
	tailcat := writeFakeTailcat(t)
	captureRunTailcat(t)

	cases := []struct {
		name string
		args []string
	}{
		{"nothing at all selected", []string{"--tailcat=" + tailcat}},
		{"authorized-keys and insecure-no-auth together", []string{"--authorized-keys=alice@github", "--insecure-no-auth", "--tailcat=" + tailcat}},
		{"files with a forced command on the ssh service", []string{"--authorized-keys=alice@github", "--files=/srv/drop", "--tailcat=" + tailcat, "--", "echo", "hi"}},
		{"files with a forced command on the no-auth-ssh service", []string{"--insecure-no-auth", "--files=/srv/drop", "--tailcat=" + tailcat, "--", "echo", "hi"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := serve(c.args); err == nil {
				t.Fatalf("serve(%v) did not error", c.args)
			}
		})
	}
}

func TestValidateKeyRejectsTruncatedOversizeInput(t *testing.T) {
	const maxKeyJSON = 64 << 10
	payload := append([]byte(`{"Private":"`), bytes.Repeat([]byte("x"), maxKeyJSON)...)
	payload = append(payload, []byte(`"}`)...)
	if len(payload) <= maxKeyJSON {
		t.Fatal("test payload is not oversized")
	}
	limited := payload[:maxKeyJSON]
	if err := validateKey(limited); err == nil {
		t.Fatal("truncated oversized key unexpectedly parsed as valid JSON")
	}
}
