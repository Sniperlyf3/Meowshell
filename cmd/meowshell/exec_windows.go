package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

func runTailcat(bin string, argv, environ []string) error {
	job, jobName, err := newNamedKillOnCloseJob()
	if err != nil {
		return fmt.Errorf("creating Tailcat containment job: %w", err)
	}
	defer job.Close()

	cmd := exec.Command(bin, argv[1:]...)
	cmd.Env = setEnv(environ, [][2]string{{parentJobEnv, jobName}})
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
	if err := job.ensureAssigned(cmd.Process.Pid); err != nil {
		if keyStdin != nil {
			_ = keyStdin.Close()
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("protecting Tailcat child: %w", err)
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

	// The named kill-on-close Job Object was created before Start. The shipped
	// patched Tailcat joins it at the beginning of main, before it can launch
	// descendants. The parent-side ensureAssigned above is both a verification
	// and a fallback for a caller-supplied external Tailcat without that patch.
	err = cmd.Wait()

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
