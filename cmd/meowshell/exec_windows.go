package main

import (
	"errors"
	"os"
	"os/exec"
	"time"
)

// stagedKeyGracePeriod is how long runTailcat waits after starting tailcat
// before removing a key staged on disk (see keystage_windows.go). tailcat
// reads --key with a single synchronous file read right at the start of
// serve -- process creation, flag parsing and that read, with no I/O wait
// in between -- so this only needs to outlast that by a comfortable margin,
// not the session. Killing meowshell (unlike sending it a signal on Unix)
// gives it no chance to run any code at all, so the removal can't be
// deferred until the child exits: it has to happen this way, shortly after
// start, for an abrupt kill to not leave the key on disk for the life of a
// multi-minute session.
const stagedKeyGracePeriod = time.Second

// runTailcat runs tailcat as a child and exits with its status. Windows has
// no exec, so unlike Unix there is a supervising process; killing meowshell
// leaves the child running, so callers should terminate the whole process
// tree.
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
