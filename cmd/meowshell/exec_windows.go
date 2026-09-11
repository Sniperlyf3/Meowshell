package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

func runTailcat(bin string, argv, environ []string) error {
	cmd := exec.Command(bin, argv[1:]...)
	cmd.Env = environ
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	keyData := takeStagedKey()
	defer zeroBytes(keyData)

	var keyStdin io.WriteCloser
	if len(keyData) != 0 {
		var err error
		keyStdin, err = cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("opening tailcat key stdin: %w", err)
		}
	} else {
		cmd.Stdin = os.Stdin
	}

	if err := cmd.Start(); err != nil {
		if keyStdin != nil {
			_ = keyStdin.Close()
		}
		return err
	}

	if keyStdin != nil {
		if _, err := keyStdin.Write(keyData); err != nil {
			_ = keyStdin.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("sending private key to tailcat: %w", err)
		}
		if err := keyStdin.Close(); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("closing tailcat key stdin: %w", err)
		}
		zeroBytes(keyData)
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

	err := cmd.Wait()

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
