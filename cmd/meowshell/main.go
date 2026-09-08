// meowshell wraps the tailcat binary to serve a proper interactive shell
// over a tailcat address: a real PTY with completion, colours, job control
// and window resizing.
//
// tailcat's built-in ssh service already allocates a PTY, applies the
// client's termios modes and forwards SIGWINCH. What it does not do is
// survive Android: it derives the session's PATH from a hardcoded
// /usr/local/bin:/usr/bin:/bin, falls back to /bin/sh for the login shell,
// and aborts the session outright when user.Current fails, which on Android
// happens whenever $HOME is unset.
//
// meowshell fixes that from both ends. Before starting the server it
// exports a HOME, USER and SHELL that tailcat can read. It then passes
// itself as $SHELL, so tailcat launches meowshell rather than the real
// shell; invoked that way (with -l or -c) meowshell repairs PATH, TERM and
// LANG in the session's own environment and execs the real shell.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var runtimeGOOS = runtime.GOOS

const usage = `meowshell -- an interactive shell over a tailcat address

USAGE
  meowshell serve [flags] [-- <extra tailcat args>...]
  meowshell connect [flags] <tc-addr> [-- <extra tailcat args>...]
  meowshell env

Serve a shell, trusting SSH public keys fetched from GitHub:

	meowshell serve --authorized-keys=alice@github

Serve a shell to holders of the address alone (no SSH auth), restricted
to one tailcat client key:

	meowshell serve --insecure-no-auth --allow=nodekey:abc...

Connect to one:

	meowshell connect <tc-addr>

Show the shell environment meowshell would set up, and any problems
it found:

	meowshell env

meowshell finds the tailcat binary via $TAILCAT_BIN, then next to its own
executable, then on $PATH.
`

func main() {
	if isShimInvocation(os.Args[1:]) {
		if err := runAsShell(os.Args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "meowshell: %v\r\n", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "connect":
		err = connect(os.Args[2:])
	case "env":
		err = printEnv()
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "meowshell: unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "meowshell: %v\n", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	authKeys := fs.String("authorized-keys", "", "SSH public key sources permitted to log in: authorized_keys paths, literal key lines, or names like 'alice@github'. Passed to tailcat's --ssh-authorized-keys")
	noAuth := fs.Bool("insecure-no-auth", false, "serve a shell to anyone holding the tailcat address, with no SSH authentication. Pair it with --allow")
	allow := fs.String("allow", "", "comma-separated tailcat client public keys allowed to connect, or 'none'. Empty means any client with the address")
	key := fs.String("key", "", "tailcat server key name or path (see 'tailcat genkey')")
	keyStdin := fs.Bool("key-stdin", false, "read the server key (the contents of a *.private.json) from stdin, and hand it to tailcat without it ever existing as a named file")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Refuse to hand out a shell by accident: one of the two auth
	// choices has to be made explicitly.
	switch {
	case *authKeys == "" && !*noAuth:
		return fmt.Errorf("choose an authentication mode: --authorized-keys=<sources>, or --insecure-no-auth to rely on the address alone")
	case *authKeys != "" && *noAuth:
		return fmt.Errorf("--authorized-keys and --insecure-no-auth are mutually exclusive")
	}

	if *keyStdin && *key != "" {
		return fmt.Errorf("--key and --key-stdin are mutually exclusive")
	}

	bin, err := findTailcat(*tailcatBin)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating own executable: %w", err)
	}

	env := newResolver().Resolve()

	keyArg := *key
	if *keyStdin {
		if keyArg, err = keyFromStdin(stagingDir(env.Home)); err != nil {
			return err
		}
	}
	for _, w := range env.Warnings {
		fmt.Fprintf(os.Stderr, "# warning: %s\n", w)
	}
	if *noAuth && *allow == "" {
		fmt.Fprintln(os.Stderr, "# warning: --insecure-no-auth without --allow gives a shell to anyone who learns this address")
	}

	service := "ssh"
	if *noAuth {
		service = "no-auth-ssh"
	}
	argv := []string{bin, "serve"}
	if *allow != "" {
		argv = append(argv, "--allow="+*allow)
	}
	if keyArg != "" {
		argv = append(argv, "--key="+keyArg)
	}
	if *authKeys != "" {
		argv = append(argv, "--ssh-authorized-keys="+*authKeys)
	}
	argv = append(argv, service)
	argv = append(argv, fs.Args()...)

	// tailcat reads SHELL for the login shell, and HOME/USER through
	// user.Current. Setting SHELL to this binary is what gets the shim
	// above run for each session.
	vars := [][2]string{}
	if shimSupported {
		vars = append(vars,
			[2]string{"SHELL", self},
			[2]string{"HOME", env.Home},
			[2]string{"USER", env.User},
			[2]string{"MEOWSHELL_SHELL", env.Shell},
		)
	}
	return runTailcat(bin, argv, setEnv(os.Environ(), vars))
}

// validateKey rejects input that is not a tailcat private key, so a bad
// pipe fails here rather than as a confusing error out of tailcat.
func validateKey(data []byte) error {
	var k struct {
		Private string
	}
	if err := json.Unmarshal(data, &k); err != nil {
		return fmt.Errorf("key from stdin is not valid JSON: %w", err)
	}
	if k.Private == "" {
		return errors.New(`key from stdin has no "Private" field; expected the contents of a *.private.json file`)
	}
	return nil
}

// stagingDir picks a writable directory to stage the key in.
//
// os.TempDir is the portable answer: it honours TMPDIR on unix and TEMP or
// TMP on Windows. home is only a fallback for the rare case os.TempDir
// returns nothing at all.
func stagingDir(home string) string {
	if d := os.TempDir(); d != "" {
		return d
	}
	return home
}

// keyFromStdin reads a tailcat private key from stdin and returns a path
// tailcat can read it from.
func keyFromStdin(dir string) (string, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<16))
	if err != nil {
		return "", fmt.Errorf("reading key from stdin: %w", err)
	}
	if err := validateKey(data); err != nil {
		return "", err
	}
	return stageKey(dir, data)
}

// setEnv returns environ with each given variable set, replacing any entry
// already there.
//
// Appending would not do: Go keeps the first mention of a key and clears
// later duplicates, so an appended override of a variable the caller already
// exported is silently ignored -- e.g. adb shell exports SHELL=/bin/sh, so
// an appended SHELL would never reach tailcat, which starts the shim only
// when SHELL points at it.
func setEnv(environ []string, vars [][2]string) []string {
	replacing := make(map[string]bool, len(vars))
	for _, v := range vars {
		replacing[v[0]] = true
	}
	out := make([]string, 0, len(environ)+len(vars))
	for _, e := range environ {
		if k, _, ok := strings.Cut(e, "="); ok && replacing[k] {
			continue
		}
		out = append(out, e)
	}
	for _, v := range vars {
		out = append(out, v[0]+"="+v[1])
	}
	return out
}

func connect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	key := fs.String("key", "", "tailcat client key name or path")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("connect needs a tailcat address")
	}

	bin, err := findTailcat(*tailcatBin)
	if err != nil {
		return err
	}
	argv := []string{bin}
	if *key != "" {
		argv = append(argv, "--key="+*key)
	}
	argv = append(argv, "ssh")
	argv = append(argv, fs.Args()...)
	return runTailcat(bin, argv, os.Environ())
}

func printEnv() error {
	env := newResolver().Resolve()
	fmt.Printf("shell %s\nhome  %s\nuser  %s\npath  %s\nterm  %s\nlang  %s\n",
		env.Shell, env.Home, env.User, env.Path, env.Term, env.Lang)
	if bin, err := findTailcat(""); err == nil {
		fmt.Printf("tailcat %s\n", bin)
	} else {
		fmt.Printf("tailcat NOT FOUND (%v)\n", err)
	}
	for _, w := range env.Warnings {
		fmt.Printf("warning: %s\n", w)
	}
	return nil
}

// findTailcat locates the tailcat binary: an explicit path, then
// $TAILCAT_BIN, then alongside this executable, then $PATH.
func findTailcat(explicit string) (string, error) {
	var tried []string
	check := func(p string) (string, bool) {
		if p == "" {
			return "", false
		}
		tried = append(tried, p)
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			return "", false
		}
		// Windows has no execute bit; requiring one rejects every file
		// there, so meowshell would never find tailcat at all.
		if runtimeGOOS != "windows" && fi.Mode()&0o111 == 0 {
			return "", false
		}
		return p, true
	}

	if explicit != "" {
		if p, ok := check(explicit); ok {
			return p, nil
		}
		return "", fmt.Errorf("--tailcat=%s is not an executable", explicit)
	}
	if p, ok := check(os.Getenv("TAILCAT_BIN")); ok {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		if p, ok := check(filepath.Join(filepath.Dir(self), "tailcat")); ok {
			return p, nil
		}
	}
	if p, err := exec.LookPath("tailcat"); err == nil {
		return p, nil
	}
	tried = append(tried, "$PATH")
	return "", fmt.Errorf("no tailcat binary found (looked in %s); set $TAILCAT_BIN or pass --tailcat", strings.Join(tried, ", "))
}
