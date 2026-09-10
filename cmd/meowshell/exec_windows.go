package main

import (
	"errors"
	"os"
	"os/exec"
	"time"
)

const stagedKeyGracePeriod = time.Second

func runTailcat(bin string, argv, environ []string) error {
	cmd := exec.Command(bin, argv[1:]...)
	cmd.Env = environ
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Start(); err != nil {
		cleanupStagedKey()
		return err
	}
	go func() {
		time.Sleep(stagedKeyGracePeriod)
		cleanupStagedKey()
	}()

	err := cmd.Wait()
	cleanupStagedKey()

	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
