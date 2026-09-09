package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
)

const cpUsage = `meowshell cp -- copy files to or from a tailcat server

USAGE
  meowshell cp [flags] <source>... <target>

Remote paths are written <tc-addr>:[path], like scp's host:path. Paths are
relative to the server's served directory ("tailcat serve files"), or to
the remote home directory for a full SSH server. Exactly one of source and
target must be remote.

Unlike "tailcat cp", this speaks SFTP directly -- no system ssh/scp binary
involved, so it works in an Android app sandbox where "tailcat cp" cannot.

Copy a file to a server, keeping its name, and fetch it back:

	meowshell cp foo.txt <tc-addr>:
	meowshell cp <tc-addr>:foo.txt copy.txt

Copy a directory tree to a directory the server offers read-write:

	meowshell cp -r ./photos <tc-addr>:photos
`

// cp implements the "meowshell cp" subcommand: an SFTP-native counterpart
// to "tailcat cp" that never shells out to a system ssh/scp client.
func cp(args []string) error {
	fs2 := flag.NewFlagSet("cp", flag.ExitOnError)
	recursive := fs2.Bool("r", false, "recursively copy directories")
	preserve := fs2.Bool("p", false, "preserve modification times and modes")
	port := fs2.String("P", "22", "port number of the server's SSH (file service) port")
	key := fs2.String("key", "", "tailcat client key name or path")
	tailcatBin := fs2.String("tailcat", "", "path to the tailcat binary")
	derpMapURL := fs2.String("derpmap-url", "", "URL of the JSON DERP map to resolve a DERP region from, instead of tailcat's default. Passed to tailcat's own --derpmap-url")
	verbose := fs2.Bool("verbose", false, "passed to tailcat's own --verbose")
	fs2.Usage = func() { fmt.Fprint(os.Stderr, cpUsage); fs2.PrintDefaults() }
	if err := fs2.Parse(args); err != nil {
		return err
	}
	if fs2.NArg() < 2 {
		return fmt.Errorf("cp requires at least one source and a target")
	}
	rest := fs2.Args()
	sources, target := rest[:len(rest)-1], rest[len(rest)-1]

	addr := ""
	for _, arg := range rest {
		host, _, ok := splitRemoteArg(arg)
		if !ok {
			continue
		}
		if addr != "" && host != addr {
			return fmt.Errorf("all remote paths must name the same server (%q and %q differ)", addr, host)
		}
		addr = host
	}
	if addr == "" {
		return fmt.Errorf("no remote <tc-addr>:path argument; nothing to copy through tailcat")
	}

	bin, err := findTailcat(*tailcatBin)
	if err != nil {
		return err
	}
	sf, closer, err := dialSFTP(bin, tailcatClientArgv(*key, *derpMapURL, *verbose, addr, *port))
	if err != nil {
		return err
	}
	defer closer.Close()

	multiSource := len(sources) > 1
	for _, src := range sources {
		if err := copyOne(sf, src, target, *recursive, *preserve, multiSource); err != nil {
			return err
		}
	}
	return nil
}

// copyOne copies one source to target, in whichever direction the two
// arguments' remoteness implies.
func copyOne(sf *sftp.Client, src, target string, recursive, preserve, multiSource bool) error {
	_, srcPath, srcRemote := splitRemoteArg(src)
	_, dstPath, dstRemote := splitRemoteArg(target)

	switch {
	case !srcRemote && dstRemote:
		dst := dstPath
		if multiSource || dst == "" {
			dst = path.Join(dstPath, filepath.Base(src))
		}
		return upload(sf, src, dst, recursive, preserve)
	case srcRemote && !dstRemote:
		dst := target
		if multiSource || dst == "" {
			dst = filepath.Join(target, path.Base(srcPath))
		}
		return download(sf, srcPath, dst, recursive, preserve)
	case srcRemote && dstRemote:
		return fmt.Errorf("cp: remote-to-remote copy is not supported")
	default:
		return fmt.Errorf("cp: %s is not remote; nothing to route through tailcat", src)
	}
}

func upload(sf *sftp.Client, localPath, remotePath string, recursive, preserve bool) error {
	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return uploadFile(sf, localPath, remotePath, preserve)
	}
	if !recursive {
		return fmt.Errorf("%s is a directory (use -r to copy recursively)", localPath)
	}
	return filepath.WalkDir(localPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(localPath, p)
		if err != nil {
			return err
		}
		dst := remotePath
		if rel != "." {
			dst = path.Join(remotePath, filepath.ToSlash(rel))
		}
		if d.IsDir() {
			return sf.MkdirAll(dst)
		}
		return uploadFile(sf, p, dst, preserve)
	})
}

func uploadFile(sf *sftp.Client, localPath, remotePath string, preserve bool) error {
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := sf.Create(remotePath)
	if err != nil {
		return fmt.Errorf("creating %s on the server: %w", remotePath, err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	if !preserve {
		return nil
	}
	fi, err := src.Stat()
	if err != nil {
		return err
	}
	if err := sf.Chtimes(remotePath, fi.ModTime(), fi.ModTime()); err != nil {
		return err
	}
	return sf.Chmod(remotePath, fi.Mode().Perm())
}

func download(sf *sftp.Client, remotePath, localPath string, recursive, preserve bool) error {
	if remotePath == "" {
		remotePath = "."
	}
	fi, err := sf.Stat(remotePath)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return downloadFile(sf, remotePath, localPath, fi, preserve)
	}
	if !recursive {
		return fmt.Errorf("%s is a directory (use -r to copy recursively)", remotePath)
	}
	walker := sf.Walk(remotePath)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}
		rel, err := filepathRelFromSlash(remotePath, walker.Path())
		if err != nil {
			return err
		}
		dst := localPath
		if rel != "." {
			dst = filepath.Join(localPath, rel)
		}
		if walker.Stat().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := downloadFile(sf, walker.Path(), dst, walker.Stat(), preserve); err != nil {
			return err
		}
	}
	return nil
}

func downloadFile(sf *sftp.Client, remotePath, localPath string, fi os.FileInfo, preserve bool) error {
	src, err := sf.Open(remotePath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	if !preserve {
		return nil
	}
	if err := os.Chtimes(localPath, fi.ModTime(), fi.ModTime()); err != nil {
		return err
	}
	return os.Chmod(localPath, fi.Mode().Perm())
}

// filepathRelFromSlash returns target's path relative to base, as a local,
// OS-separated path. Both are SFTP paths (always "/"-separated), and
// sf.Walk(base) guarantees every path it yields is base itself or nested
// under it, so no ".." case exists to handle -- but when base is "."
// (a bare "tc-addr:" root), the walker's paths already come back clean and
// unprefixed, unlike a named root's "root/child" paths, so both shapes
// need handling here.
func filepathRelFromSlash(base, target string) (string, error) {
	base, target = path.Clean(base), path.Clean(target)
	if target == base {
		return ".", nil
	}
	if base == "." {
		return filepath.FromSlash(target), nil
	}
	rel := strings.TrimPrefix(target, base+"/")
	if rel == target {
		return "", fmt.Errorf("%s is not under %s", target, base)
	}
	return filepath.FromSlash(rel), nil
}
