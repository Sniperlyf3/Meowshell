package main

import (
	"slices"
	"testing"
)

func TestServeArbitraryServicesArgv(t *testing.T) {
	tailcat := writeFakeTailcat(t)
	captured := captureRunTailcat(t)
	args := []string{
		"--tailcat=" + tailcat,
		"--allow=nodekey:test",
		"--services=80,443,8000-8010",
	}
	if err := serve(args); err != nil {
		t.Fatalf("serve(%v) = %v", args, err)
	}
	want := []string{
		tailcat, "serve", "--allow=nodekey:test", "80,443,8000-8010",
	}
	if !slices.Equal(captured.argv, want) {
		t.Errorf("argv = %v, want %v", captured.argv, want)
	}
}

func TestServeArbitraryServicesCombineWithBuiltInServices(t *testing.T) {
	tailcat := writeFakeTailcat(t)
	captured := captureRunTailcat(t)
	args := []string{
		"--tailcat=" + tailcat,
		"--insecure-no-auth",
		"--exit-node",
		"--services=80,443",
	}
	if err := serve(args); err != nil {
		t.Fatalf("serve(%v) = %v", args, err)
	}
	want := []string{tailcat, "serve", "no-auth-ssh,exit-node,80,443"}
	if !slices.Equal(captured.argv, want) {
		t.Errorf("argv = %v, want %v", captured.argv, want)
	}
}

func TestForwardUDPArgv(t *testing.T) {
	tailcat := writeFakeTailcat(t)
	captured := captureRunTailcat(t)
	args := []string{
		"--tailcat=" + tailcat,
		"--udp",
		"--bind=127.0.0.1",
		"--key=client-default",
		"tcaddr", "0:53", "9999:192.168.1.2:9999",
	}
	if err := forward(args); err != nil {
		t.Fatalf("forward(%v) = %v", args, err)
	}
	want := []string{
		tailcat, "--key=client-default", "forward", "--bind=127.0.0.1", "--udp",
		"tcaddr", "0:53", "9999:192.168.1.2:9999",
	}
	if !slices.Equal(captured.argv, want) {
		t.Errorf("argv = %v, want %v", captured.argv, want)
	}
}
