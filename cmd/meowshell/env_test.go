package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeFS(goos string, env map[string]string, files, dirs []string) *resolver {
	set := func(ss []string) map[string]bool {
		m := make(map[string]bool, len(ss))
		for _, s := range ss {
			m[s] = true
		}
		return m
	}
	f, d := set(files), set(dirs)
	return &resolver{
		getenv:   func(k string) string { return env[k] },
		isFile:   func(p string) bool { return f[p] },
		isDir:    func(p string) bool { return d[p] },
		writable: func(p string) bool { return true },
		mkdirAll:   func(p string) error { d[p] = true; return nil },
		privateDir: func(p string) error { d[p] = true; return nil },
		realpath: func(p string) string {
			if p == "/bin" && d["/system/bin"] {
				return "/system/bin"
			}
			return p
		},
		goos: goos,
		uid:  12345,
	}
}

const termuxUsr = "/data/data/com.termux/files/usr"

func TestShellPrefersTermuxBash(t *testing.T) {
	r := fakeFS("android", map[string]string{"PREFIX": termuxUsr},
		[]string{termuxUsr + "/bin/bash", "/system/bin/sh"},
		[]string{termuxUsr + "/bin"})
	got, _ := r.shell()
	if want := termuxUsr + "/bin/bash"; got != want {
		t.Errorf("shell() = %q, want %q", got, want)
	}
}

func TestShellFallsBackToAndroidSh(t *testing.T) {
	r := fakeFS("android", nil, []string{"/system/bin/sh"}, nil)
	got, _ := r.shell()
	if want := "/system/bin/sh"; got != want {
		t.Errorf("shell() = %q, want %q", got, want)
	}
}

func TestShellRejectsBadOverride(t *testing.T) {
	r := fakeFS("android", map[string]string{"MEOWSHELL_SHELL": "/nope/bash"},
		[]string{"/system/bin/sh"}, nil)
	got, warns := r.shell()
	if got != "/system/bin/sh" {
		t.Errorf("shell() = %q, want the fallback", got)
	}
	if len(warns) == 0 {
		t.Error("expected a warning about the bad MEOWSHELL_SHELL")
	}
}

func TestPathOmitsDirsThatDoNotExist(t *testing.T) {
	r := fakeFS("android", map[string]string{"PREFIX": termuxUsr}, nil,
		[]string{termuxUsr + "/bin", "/system/bin", "/system/xbin"})
	got := r.path()
	want := termuxUsr + "/bin:/system/bin:/system/xbin"
	if got != want {
		t.Errorf("path() = %q, want %q", got, want)
	}
	for _, absent := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
		for _, d := range strings.Split(got, ":") {
			if d == absent {
				t.Errorf("path() included %q, which does not exist", absent)
			}
		}
	}
}

func TestPathPutsTermuxFirst(t *testing.T) {
	r := fakeFS("android", map[string]string{"PREFIX": termuxUsr}, nil,
		[]string{termuxUsr + "/bin", "/system/bin", "/usr/bin"})
	if got := r.path(); !strings.HasPrefix(got, termuxUsr+"/bin:") {
		t.Errorf("path() = %q, want Termux's bin first", got)
	}
}

func TestHomeCreatedWhenUnset(t *testing.T) {
	r := fakeFS("android", nil, nil, nil)
	got, _ := r.home()
	if got == "" {
		t.Fatal("home() returned an empty path")
	}
	if got != "/data/local/tmp/meowshell-12345" {
		t.Errorf("home() = %q, want the private per-UID Android scratch dir", got)
	}
}

func TestHomeUsesEnvWhenUsable(t *testing.T) {
	home := "/data/data/com.termux/files/home"
	r := fakeFS("android", map[string]string{"HOME": home}, nil, []string{home})
	if got, _ := r.home(); got != home {
		t.Errorf("home() = %q, want %q", got, home)
	}
}

func TestHomeWarnsWhenReadOnly(t *testing.T) {
	r := fakeFS("android", map[string]string{"HOME": "/ro"}, nil, []string{"/ro"})
	r.writable = func(string) bool { return false }
	got, warns := r.home()
	if got != "/ro" {
		t.Errorf("home() = %q, want the read-only dir", got)
	}
	if len(warns) == 0 {
		t.Error("expected a warning that the home directory is not writable")
	}
}

func TestResolveFillsTermAndLang(t *testing.T) {
	r := fakeFS("android", nil, []string{"/system/bin/sh"}, []string{"/system/bin"})
	env := r.Resolve()
	if env.Term == "" || env.Lang == "" {
		t.Errorf("Resolve() left TERM=%q LANG=%q empty", env.Term, env.Lang)
	}
	if env.User != "android" {
		t.Errorf("User = %q, want android", env.User)
	}
}

func TestResolveKeepsClientTerm(t *testing.T) {
	r := fakeFS("android", map[string]string{"TERM": "screen-256color"},
		[]string{"/system/bin/sh"}, nil)
	if got := r.Resolve().Term; got != "screen-256color" {
		t.Errorf("Term = %q, want the client's value", got)
	}
}

func TestPathDropsSymlinkedDuplicates(t *testing.T) {
	r := fakeFS("android", nil, nil, []string{"/system/bin", "/bin"})
	got := r.path()
	if got != "/system/bin" {
		t.Errorf("path() = %q, want just /system/bin", got)
	}
}

func TestSetEnvReplacesRatherThanShadowing(t *testing.T) {
	got := setEnv(
		[]string{"SHELL=/bin/sh", "PATH=/keep/me", "HOME=/old"},
		[][2]string{{"SHELL", "/path/to/meowshell"}, {"HOME", "/new"}},
	)

	var shells, homes []string
	kept := false
	for _, e := range got {
		switch {
		case strings.HasPrefix(e, "SHELL="):
			shells = append(shells, e)
		case strings.HasPrefix(e, "HOME="):
			homes = append(homes, e)
		case e == "PATH=/keep/me":
			kept = true
		}
	}
	if len(shells) != 1 || shells[0] != "SHELL=/path/to/meowshell" {
		t.Errorf("SHELL entries = %v, want exactly the override", shells)
	}
	if len(homes) != 1 || homes[0] != "HOME=/new" {
		t.Errorf("HOME entries = %v, want exactly the override", homes)
	}
	if !kept {
		t.Error("setEnv dropped an unrelated variable")
	}
}

func TestValidateKeyAcceptsARealKey(t *testing.T) {
	key := []byte(`{"Private":"privkey:abc","Public":{"ServerPublic":"nodekey:def"}}`)
	if err := validateKey(key); err != nil {
		t.Errorf("validateKey rejected a valid key: %v", err)
	}
}

func TestValidateKeyRejectsJunk(t *testing.T) {
	for name, in := range map[string]string{
		"not json":    "hello",
		"empty":       "",
		"no private":  `{"Public":{"ServerPublic":"nodekey:def"}}`,
		"blank field": `{"Private":""}`,
	} {
		if err := validateKey([]byte(in)); err == nil {
			t.Errorf("validateKey(%s) accepted %q", name, in)
		}
	}
}

func TestFindTailcatDoesNotRequireAnExecuteBitOnWindows(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tailcat.exe")
	if err := os.WriteFile(bin, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAILCAT_BIN", bin)

	saved := runtimeGOOS
	defer func() { runtimeGOOS = saved }()

	runtimeGOOS = "windows"
	if got, err := findTailcat(""); err != nil || got != bin {
		t.Errorf("findTailcat on windows = %q, %v; want %q", got, err, bin)
	}

	runtimeGOOS = "linux"
	if _, err := findTailcat(""); err == nil {
		t.Error("findTailcat on linux accepted a file with no execute bit")
	}
}

func TestResolveOnWindowsUsesWindowsNotions(t *testing.T) {
	r := fakeFS("windows", map[string]string{
		"USERPROFILE": `C:\Users\someone`,
		"PATH":        `C:\Windows\system32;C:\Windows`,
	}, nil, nil)
	env := r.Resolve()

	if env.Home != `C:\Users\someone` {
		t.Errorf("Home = %q, want the user profile", env.Home)
	}
	if env.Path != `C:\Windows\system32;C:\Windows` {
		t.Errorf("Path = %q, want the inherited PATH", env.Path)
	}
	if strings.Contains(env.Shell, "/system/bin") || strings.Contains(env.Home, "/data/local") {
		t.Errorf("Resolve() returned Android paths on windows: shell=%q home=%q", env.Shell, env.Home)
	}
	for _, w := range env.Warnings {
		if strings.Contains(w, "no usable shell") {
			t.Errorf("warned about a shell on windows, where tailcat picks its own: %q", w)
		}
	}
}
