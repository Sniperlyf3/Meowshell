package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Env is the shell environment meowshell resolves for a session.
type Env struct {
	Shell string // absolute path of the real shell to exec
	Home  string // an existing, ideally writable, home directory
	User  string
	Path  string
	Lang  string
	Term  string

	Warnings []string
}

// resolver locates files and directories. It is a struct so tests can
// substitute a fake filesystem rather than depend on the host's layout.
type resolver struct {
	getenv    func(string) string
	isFile    func(string) bool // exists and is executable
	isDir     func(string) bool
	writable  func(string) bool
	mkdirAll  func(string) error
	realpath  func(string) string
	goos      string
	uidIsRoot bool
}

func newResolver() *resolver {
	return &resolver{
		getenv: os.Getenv,
		isFile: func(p string) bool {
			fi, err := os.Stat(p)
			return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
		},
		isDir: func(p string) bool {
			fi, err := os.Stat(p)
			return err == nil && fi.IsDir()
		},
		writable: func(p string) bool {
			f, err := os.CreateTemp(p, ".meowshell-*")
			if err != nil {
				return false
			}
			name := f.Name()
			f.Close()
			os.Remove(name)
			return true
		},
		mkdirAll: func(p string) error { return os.MkdirAll(p, 0o700) },
		realpath: func(p string) string {
			if r, err := filepath.EvalSymlinks(p); err == nil {
				return r
			}
			return p
		},
		goos:      runtimeGOOS,
		uidIsRoot: os.Getuid() == 0,
	}
}

// termuxPrefix returns Termux's install prefix, if this looks like Termux.
func (r *resolver) termuxPrefix() string {
	if p := r.getenv("PREFIX"); p != "" && r.isDir(filepath.Join(p, "bin")) {
		return p
	}
	const std = "/data/data/com.termux/files/usr"
	if r.isDir(filepath.Join(std, "bin")) {
		return std
	}
	return ""
}

// shell picks the most capable interactive shell available. Shells with
// completion and prompt colouring are preferred over plain sh, which on
// Android is mksh and gives a bare "$" with no completion.
func (r *resolver) shell() (string, []string) {
	if r.goos == "windows" {
		// tailcat chooses PowerShell from the registry there and never
		// reads SHELL, so there is nothing for meowshell to resolve.
		return "", nil
	}
	var warns []string
	if s := r.getenv("MEOWSHELL_SHELL"); s != "" {
		if r.isFile(s) {
			return s, warns
		}
		warns = append(warns, fmt.Sprintf("MEOWSHELL_SHELL=%s is not an executable; ignoring it", s))
	}

	var cands []string
	if p := r.termuxPrefix(); p != "" {
		cands = append(cands,
			filepath.Join(p, "bin/bash"),
			filepath.Join(p, "bin/zsh"),
			filepath.Join(p, "bin/ash"),
			filepath.Join(p, "bin/sh"),
		)
	}
	cands = append(cands,
		"/bin/bash", "/usr/bin/bash",
		"/bin/zsh", "/usr/bin/zsh",
		"/system/bin/bash",
		"/system/bin/sh", // Android: mksh
		"/bin/sh",
	)
	for _, c := range cands {
		if r.isFile(c) {
			return c, warns
		}
	}
	return "/system/bin/sh", append(warns, "found no usable shell; falling back to /system/bin/sh")
}

// path builds a PATH from the directories that actually exist. tailcat
// hardcodes /usr/local/bin:/usr/bin:/bin, none of which exist on Android.
func (r *resolver) path() string {
	if r.goos == "windows" {
		// tailcat gives the session the server's own environment on
		// Windows, so PATH is already whatever the operator has.
		return r.getenv("PATH")
	}
	var dirs []string
	if p := r.termuxPrefix(); p != "" {
		dirs = append(dirs, filepath.Join(p, "bin"))
	}
	// Android's own directories come first so PATH names them canonically:
	// /bin is a symlink to /system/bin there, and listing the symlink first
	// would leave PATH pointing at the same directory under two names.
	dirs = append(dirs,
		"/system/bin", "/system/xbin",
		"/vendor/bin", "/product/bin",
		"/apex/com.android.runtime/bin",
	)
	if r.uidIsRoot {
		dirs = append(dirs, "/usr/local/sbin", "/usr/sbin", "/sbin")
	}
	dirs = append(dirs, "/usr/local/bin", "/usr/bin", "/bin")

	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		if !r.isDir(d) {
			continue
		}
		// Deduplicate by target, not by name, so a symlinked alias of a
		// directory already on PATH is dropped.
		if real := r.realpath(d); !seen[real] {
			seen[real] = true
			out = append(out, d)
		}
	}
	return strings.Join(out, ":")
}

// home returns a home directory that exists. tailcat passes this to
// user.Current via $HOME, and on Android an unset $HOME makes
// user.Current fail, which kills the session before the shell starts.
func (r *resolver) home() (string, []string) {
	if r.goos == "windows" {
		if h := r.getenv("USERPROFILE"); h != "" {
			return h, nil
		}
		return r.getenv("HOME"), nil
	}
	var warns []string
	try := func(p string) (string, bool) {
		if p == "" {
			return "", false
		}
		if !r.isDir(p) {
			if err := r.mkdirAll(p); err != nil {
				return "", false
			}
		}
		return p, true
	}

	var cands []string
	if h := r.getenv("HOME"); h != "" {
		cands = append(cands, h)
	}
	if p := r.termuxPrefix(); p != "" {
		cands = append(cands, filepath.Join(filepath.Dir(p), "home"))
	}
	cands = append(cands, "/data/local/tmp/meowshell", filepath.Join(os.TempDir(), "meowshell"))

	// Prefer a writable directory; remember the first merely-existing one.
	var readOnly string
	for _, c := range cands {
		p, ok := try(c)
		if !ok {
			continue
		}
		if r.writable(p) {
			return p, warns
		}
		if readOnly == "" {
			readOnly = p
		}
	}
	if readOnly != "" {
		return readOnly, append(warns, "home directory "+readOnly+" is not writable; shell history and rc files will not persist")
	}
	return "/", append(warns, "found no usable home directory; using /")
}

func (r *resolver) user() string {
	if u := r.getenv("USER"); u != "" {
		return u
	}
	if u := r.getenv("LOGNAME"); u != "" {
		return u
	}
	if r.goos == "android" {
		return "android"
	}
	return "unknown"
}

// Resolve works out the environment a session should run with.
func (r *resolver) Resolve() Env {
	sh, warns := r.shell()
	home, hw := r.home()
	warns = append(warns, hw...)

	lang := r.getenv("LANG")
	if lang == "" {
		lang = "C.UTF-8"
	}
	term := r.getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	return Env{
		Shell:    sh,
		Home:     home,
		User:     r.user(),
		Path:     r.path(),
		Lang:     lang,
		Term:     term,
		Warnings: warns,
	}
}
