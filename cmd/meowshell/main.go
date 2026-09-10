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
	"slices"
	"strings"
)

var runtimeGOOS = runtime.GOOS

var runTailcatFn = runTailcat

const usage = `meowshell -- an interactive shell over a tailcat address

USAGE
  meowshell serve [flags] [-- <command> [args...]]
  meowshell connect [flags] <tc-addr> [command [args...]]
  meowshell agent [flags] <tc-addr>
  meowshell socks [flags]
  meowshell forward [flags] <tc-addr> <mapping> [<mapping> ...]
  meowshell cp [flags] <source>... <target>
  meowshell env

A command after "--" replaces the login shell for every session (like
OpenSSH's ForceCommand), passed straight through to tailcat's own "serve
... -- <command>".

Serve a shell, trusting SSH public keys fetched from GitHub:

	meowshell serve --authorized-keys=alice@github

Serve a shell to holders of the address alone (no SSH auth), restricted
to one tailcat client key:

	meowshell serve --insecure-no-auth --allow=nodekey:abc...

Also let "tailcat forward"/"tailcat socks" clients reach any port this
machine can dial, not just the ports above (see --exit-node's own help):

	meowshell serve --insecure-no-auth --exit-node --allow=nodekey:abc...

Connect to one:

	meowshell connect <tc-addr>

Copy a file to or from a server, speaking SFTP directly -- unlike
"tailcat cp", this never shells out to a system ssh/scp client, so it
also works in an Android app sandbox ("tailcat ls" already needs no
such binary and works there unchanged):

	meowshell cp foo.txt <tc-addr>:

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
	case "agent":
		err = agentCmd(os.Args[2:])
	case "socks":
		err = socks(os.Args[2:])
	case "forward":
		err = forward(os.Args[2:])
	case "cp":
		err = cp(os.Args[2:])
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
	rest, command := splitForcedCommand(args)

	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	authKeys := fs.String("authorized-keys", "", "SSH public key sources permitted to log in: authorized_keys paths, literal key lines, or names like 'alice@github'. Passed to tailcat's --ssh-authorized-keys")
	noAuth := fs.Bool("insecure-no-auth", false, "serve a shell to anyone holding the tailcat address, with no SSH authentication. Pair it with --allow")
	allow := fs.String("allow", "", "comma-separated tailcat client public keys allowed to connect, or 'none'. Empty means any client with the address")
	key := fs.String("key", "", "tailcat server key name or path (see 'tailcat genkey')")
	keyStdin := fs.Bool("key-stdin", false, "read the server key (the contents of a *.private.json) from stdin, and hand it to tailcat without it ever existing as a named file")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	derpMapURL := fs.String("derpmap-url", "", "URL of the JSON DERP map to resolve or auto-select a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url")
	verbose := fs.Bool("verbose", false, "passed to tailcat's own --verbose")
	fullAddress := fs.Bool("full-address", false, "print a longer tailcat address with embedded DERP server info, so clients can connect without a DERP map fetch. Passed to tailcat's own --full-address")
	psk := fs.Bool("psk", true, "include a WireGuard pre-shared key in the tailcat address (recommended; disabling weakens security). Passed to tailcat's own --psk")
	files := fs.String("files", "", "directory to serve to SFTP clients (scp, sftp), with an optional :ro (read-only, the default), :rw, :wo (flat write-only drop box), or :wo+ (recursive write-only drop box) suffix. Can be combined with --authorized-keys/--insecure-no-auth to also serve a shell. Passed to tailcat's own --files")
	exitNode := fs.Bool("exit-node", false, "let a client's \"tailcat forward\"/\"tailcat socks\" (or an agent connection's own forward_local/forward_socks) reach any port this machine can dial, not just this server's own served ports -- tailcat's own \"exit-node\" service, without which forwarding to an arbitrary port is refused outright (a real, protocol-level requirement of tailcat's own OnTCP gate, not something this flag works around). Combine with --allow to restrict who gets that reach.")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	if err := fs.Parse(rest); err != nil {
		return err
	}

	hasSSH := *authKeys != "" || *noAuth
	switch {
	case *authKeys != "" && *noAuth:
		return fmt.Errorf("--authorized-keys and --insecure-no-auth are mutually exclusive")
	case !hasSSH && *files == "" && !*exitNode && len(command) == 0:
		return fmt.Errorf("choose what to serve: --authorized-keys=<sources>, --insecure-no-auth, --files=<dir>, --exit-node, or a command after --")
	case *files != "" && hasSSH && len(command) > 0:
		return fmt.Errorf("--files cannot be combined with a forced command on the ssh/no-auth-ssh service, which would allow nothing but that command")
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
	if *files != "" && *allow == "" {
		fmt.Fprintln(os.Stderr, "# warning: --files without --allow serves files to anyone who learns this address")
	}
	if *exitNode && *allow == "" {
		fmt.Fprintln(os.Stderr, "# warning: --exit-node without --allow lets anyone who learns this address reach any port this machine can dial")
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
	if *derpMapURL != "" {
		argv = append(argv, "--derpmap-url="+*derpMapURL)
	}
	if *verbose {
		argv = append(argv, "--verbose")
	}
	if *fullAddress {
		argv = append(argv, "--full-address")
	}
	if !*psk {
		argv = append(argv, "--psk=false")
	}
	if *files != "" {
		argv = append(argv, "--files="+*files)
	}
	var services []string
	if hasSSH {
		service := "ssh"
		if *noAuth {
			service = "no-auth-ssh"
		}
		services = append(services, service)
	}
	if *exitNode {
		services = append(services, "exit-node")
	}
	if len(services) > 0 {
		argv = append(argv, strings.Join(services, ","))
	}
	if len(command) > 0 {
		argv = append(argv, "--")
		argv = append(argv, command...)
	}

	vars := [][2]string{}
	if shimSupported {
		vars = append(vars,
			[2]string{"SHELL", self},
			[2]string{"HOME", env.Home},
			[2]string{"USER", env.User},
			[2]string{"MEOWSHELL_SHELL", env.Shell},
		)
	}
	return runTailcatFn(bin, argv, setEnv(os.Environ(), vars))
}

func splitForcedCommand(args []string) (rest, command []string) {
	i := slices.Index(args, "--")
	if i < 0 {
		return args, nil
	}
	return args[:i], args[i+1:]
}

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

func stagingDir(home string) string {
	if d := os.TempDir(); d != "" {
		return d
	}
	return home
}

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

func socks(args []string) error {
	fs := flag.NewFlagSet("socks", flag.ExitOnError)
	key := fs.String("key", "", "tailcat client key name or path")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	listen := fs.String("listen", "", "SOCKS5 proxy listen [address]:port; a bare port means localhost, a bare address means an OS-assigned port. Passed to tailcat's own --listen")
	derpMapURL := fs.String("derpmap-url", "", "URL of the JSON DERP map to resolve a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url")
	verbose := fs.Bool("verbose", false, "passed to tailcat's own --verbose")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}

	bin, err := findTailcat(*tailcatBin)
	if err != nil {
		return err
	}
	argv := []string{bin}
	if *key != "" {
		argv = append(argv, "--key="+*key)
	}
	if *derpMapURL != "" {
		argv = append(argv, "--derpmap-url="+*derpMapURL)
	}
	if *verbose {
		argv = append(argv, "--verbose")
	}
	argv = append(argv, "socks")
	if *listen != "" {
		argv = append(argv, "--listen="+*listen)
	}
	argv = append(argv, fs.Args()...)
	return runTailcatFn(bin, argv, os.Environ())
}

func forward(args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	key := fs.String("key", "", "tailcat client key name or path")
	tailcatBin := fs.String("tailcat", "", "path to the tailcat binary")
	bind := fs.String("bind", "", "listen address; used as the local address when a mapping only specifies a port. Passed to tailcat's own --bind")
	derpMapURL := fs.String("derpmap-url", "", "URL of the JSON DERP map to resolve a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url")
	verbose := fs.Bool("verbose", false, "passed to tailcat's own --verbose")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("forward needs a tailcat address and at least one port mapping")
	}

	bin, err := findTailcat(*tailcatBin)
	if err != nil {
		return err
	}
	argv := []string{bin}
	if *key != "" {
		argv = append(argv, "--key="+*key)
	}
	if *derpMapURL != "" {
		argv = append(argv, "--derpmap-url="+*derpMapURL)
	}
	if *verbose {
		argv = append(argv, "--verbose")
	}
	argv = append(argv, "forward")
	if *bind != "" {
		argv = append(argv, "--bind="+*bind)
	}
	argv = append(argv, fs.Args()...)
	return runTailcatFn(bin, argv, os.Environ())
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
