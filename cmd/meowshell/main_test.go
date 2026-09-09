package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// writeFakeTailcat creates an executable file findTailcat will accept, so
// serve/connect/socks/forward can run to the point of building an argv
// without a real tailcat binary.
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

// captureRunTailcat replaces runTailcatFn for the test's duration, recording
// the bin/argv a subcommand built instead of actually launching anything.
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

func TestConnectArgv(t *testing.T) {
	tailcat := writeFakeTailcat(t)

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "derpmap-url and verbose reach tailcat, before ssh",
			args: []string{"--tailcat=" + tailcat, "--derpmap-url=https://derp.example/map.json", "--verbose", "tcaddr"},
			want: []string{tailcat, "--derpmap-url=https://derp.example/map.json", "--verbose", "ssh", "tcaddr"},
		},
		{
			name: "a remote command passes through after the address",
			args: []string{"--tailcat=" + tailcat, "tcaddr", "echo", "hi"},
			want: []string{tailcat, "ssh", "tcaddr", "echo", "hi"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			captured := captureRunTailcat(t)
			if err := connect(c.args); err != nil {
				t.Fatalf("connect(%v) = %v", c.args, err)
			}
			if !slices.Equal(captured.argv, c.want) {
				t.Errorf("argv = %v, want %v", captured.argv, c.want)
			}
		})
	}
}

func TestConnectRequiresAnAddress(t *testing.T) {
	tailcat := writeFakeTailcat(t)
	captureRunTailcat(t)
	if err := connect([]string{"--tailcat=" + tailcat}); err == nil {
		t.Fatal("connect with no address did not error")
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
		{"--tailcat=" + tailcat, "tcaddr"}, // address with no mapping
	}
	for _, args := range cases {
		if err := forward(args); err == nil {
			t.Errorf("forward(%v) did not error", args)
		}
	}
}
