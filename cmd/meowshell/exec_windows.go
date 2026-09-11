package main

import (
	"errors"
	"fmt"
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

	// Windows has no PR_SET_PDEATHSIG equivalent. Put tailcat in a
	// kill-on-close Job Object instead so an abrupt meowshell termination
	// cannot strand the long-lived child. Treat failure as fatal rather than
	// silently running without the lifecycle guarantee.
	job, err := newKillOnCloseJob(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cleanupStagedKey()
		return fmt.Errorf("protecting tailcat child: %w", err)
	}
	defer job.Close()

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
