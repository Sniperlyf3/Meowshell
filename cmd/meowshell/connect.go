package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const connectUsage = `meowshell connect -- open an interactive session over a tailcat address

USAGE
  meowshell connect [flags] <tc-addr> [command [args...]]

Speaks SSH directly (golang.org/x/crypto/ssh), routed over tailcat's own
bare client mode as a subprocess -- the same subprocess bridge
"meowshell cp" uses. Unlike "tailcat ssh", no system ssh binary is
involved, so this also works piped into from another process with no
real terminal attached at all (an Android app's own
TailcatClient.SshSessionAsync, for one).

With no command, opens an interactive shell with a pseudo-terminal, sized
to the local terminal if there is one, or --cols/--rows (default 80x24)
if not. With a command, runs it non-interactively unless -t forces a
pseudo-terminal too.

	meowshell connect <tc-addr>
	meowshell connect <tc-addr> ls -la
	meowshell connect -t <tc-addr> top
`

func connect(args []string) error {
	fs2 := flag.NewFlagSet("connect", flag.ExitOnError)
	key := fs2.String("key", "", "tailcat client key name or path")
	tailcatBin := fs2.String("tailcat", "", "path to the tailcat binary")
	derpMapURL := fs2.String("derpmap-url", "", "URL of the JSON DERP map to resolve a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url")
	verbose := fs2.Bool("verbose", false, "passed to tailcat's own --verbose")
	port := fs2.String("p", "22", "port number of the server's SSH service")
	forcePty := fs2.Bool("t", false, "force pseudo-terminal allocation, even with a command")
	noPty := fs2.Bool("T", false, "disable pseudo-terminal allocation")
	termName := fs2.String("term", "", `TERM to request for the pseudo-terminal (default: $TERM, or "xterm-256color" if that's unset too)`)
	cols := fs2.Int("cols", 0, "pseudo-terminal width, used when stdin isn't a real terminal to measure (default 80)")
	rows := fs2.Int("rows", 0, "pseudo-terminal height, used when stdin isn't a real terminal to measure (default 24)")
	fs2.Usage = func() { fmt.Fprint(os.Stderr, connectUsage); fs2.PrintDefaults() }
	if err := fs2.Parse(args); err != nil {
		return err
	}
	if fs2.NArg() < 1 {
		return fmt.Errorf("connect needs a tailcat address")
	}
	addr := fs2.Arg(0)
	command := fs2.Args()[1:]
	if *forcePty && *noPty {
		return fmt.Errorf("-t and -T are mutually exclusive")
	}

	bin, err := findTailcat(*tailcatBin)
	if err != nil {
		return err
	}
	dial, remoteAddr, hkCallback := tailcatSSHDialer(bin, tailcatClientArgv(*key, *derpMapURL, *verbose, addr, *port))
	sc, err := dialSSHClient(context.Background(), dial, remoteAddr, "", hkCallback, sshAgentAuthMethods())
	if err != nil {
		return err
	}
	defer sc.Close()

	session, err := sc.NewSession()
	if err != nil {
		return fmt.Errorf("opening session: %w", err)
	}
	defer session.Close()

	const stdinFd = 0
	wantPty := (*forcePty) || (len(command) == 0 && !*noPty)
	if wantPty {
		width, height := *cols, *rows
		if width <= 0 || height <= 0 {
			if w, h, err := term.GetSize(stdinFd); err == nil {
				width, height = w, h
			}
		}
		if width <= 0 {
			width = 80
		}
		if height <= 0 {
			height = 24
		}
		name := *termName
		if name == "" {
			name = os.Getenv("TERM")
		}
		if name == "" {
			name = "xterm-256color"
		}
		if err := session.RequestPty(name, height, width, ssh.TerminalModes{}); err != nil {
			return fmt.Errorf("requesting a pseudo-terminal: %w", err)
		}
	}

	if term.IsTerminal(stdinFd) {
		if state, err := term.MakeRaw(stdinFd); err == nil {
			defer term.Restore(stdinFd, state)
		}
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if len(command) > 0 {

		err = session.Run(strings.Join(command, " "))
	} else if err = session.Shell(); err == nil {
		err = session.Wait()
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitStatus())
	}
	return err
}
