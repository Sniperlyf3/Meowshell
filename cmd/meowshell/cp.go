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
	"time"

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

// dirMeta records a directory's metadata to apply after a recursive copy's
// walk has finished, rather than immediately when the directory is created:
// writing further entries into a directory (files or subdirectories) updates
// its modification time, so setting it eagerly would just get clobbered by
// the copy's own later writes into that same directory.
type dirMeta struct {
	path    string
	modTime time.Time
	mode    fs.FileMode
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
	var dirs []dirMeta
	if err := filepath.WalkDir(localPath, func(p string, d fs.DirEntry, err error) error {
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
			if err := sf.MkdirAll(dst); err != nil {
				return err
			}
			if preserve {
				info, err := d.Info()
				if err != nil {
					return err
				}
				dirs = append(dirs, dirMeta{path: dst, modTime: info.ModTime(), mode: info.Mode().Perm()})
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// WalkDir does not follow a directory symlink itself, but a
			// symlink *entry* reaches here (it's neither a directory nor
			// skipped), and uploadFile's os.Open would silently follow it --
			// uploading whatever the link actually points to (e.g. a
			// symlink named "backup" pointing at ~/.ssh/id_ed25519) under
			// the innocuous name the tree shows. Refuse rather than upload
			// arbitrary local files the caller never intended to share.
			return fmt.Errorf("%s is a symlink; refusing to follow it (symlinks are not supported by cp)", p)
		}
		return uploadFile(sf, p, dst, preserve)
	}); err != nil {
		return err
	}
	// Deepest directories first: harmless either way (a directory's mtime
	// only reflects entries added directly inside it, not its descendants),
	// but matches the safer convention other recursive-copy tools use.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if err := sf.Chtimes(d.path, d.modTime, d.modTime); err != nil {
			return err
		}
		if err := sf.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	return nil
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
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	// Checked explicitly, not deferred: some SFTP servers only surface a
	// write/flush failure here, on Close, well after io.Copy itself
	// reported success -- a deferred Close swallowing that would mean cp
	// reports success for an upload the server never actually completed.
	if err := dst.Close(); err != nil {
		return fmt.Errorf("finishing upload of %s: %w", remotePath, err)
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
	if err := os.MkdirAll(localPath, 0o755); err != nil {
		return err
	}
	// filepathRelFromSlash already rejects a rel path that textually escapes
	// localPath (via ".." or an absolute path), but that alone doesn't stop
	// a destination tree that already contains a symlink component (e.g.
	// "download/images" pointing at "/etc") from being written through:
	// filepath.Join + os.MkdirAll/os.Create follow such a symlink like any
	// other directory. os.Root resolves each path relative to localPath and
	// refuses to follow a symlink (in-tree or not) that would land outside
	// it, closing that gap regardless of what the destination tree already
	// contains.
	root, err := os.OpenRoot(localPath)
	if err != nil {
		return fmt.Errorf("opening download destination %s: %w", localPath, err)
	}
	defer root.Close()

	var dirs []dirMeta
	walker := sf.Walk(remotePath)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}
		rel, err := filepathRelFromSlash(remotePath, walker.Path())
		if err != nil {
			return err
		}
		if walker.Stat().IsDir() {
			if rel != "." {
				if err := root.MkdirAll(rel, 0o755); err != nil {
					return err
				}
			}
			if preserve {
				dirs = append(dirs, dirMeta{path: rel, modTime: walker.Stat().ModTime(), mode: walker.Stat().Mode().Perm()})
			}
			continue
		}
		if err := downloadFileInRoot(sf, walker.Path(), root, rel, walker.Stat(), preserve); err != nil {
			return err
		}
	}
	if !preserve {
		return nil
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if err := root.Chtimes(d.path, d.modTime, d.modTime); err != nil {
			return err
		}
		if err := root.Chmod(d.path, d.mode); err != nil {
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
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	// Checked explicitly, not deferred, for the same reason as uploadFile's
	// Close below: a filesystem can fail a write on flush/Close after
	// io.Copy already reported success (a full disk, most commonly), and a
	// deferred Close would silently swallow that into a false "downloaded
	// successfully".
	if err := dst.Close(); err != nil {
		return fmt.Errorf("finishing download of %s: %w", localPath, err)
	}
	if !preserve {
		return nil
	}
	if err := os.Chtimes(localPath, fi.ModTime(), fi.ModTime()); err != nil {
		return err
	}
	return os.Chmod(localPath, fi.Mode().Perm())
}

// downloadFileInRoot is downloadFile's counterpart for a recursive download:
// relPath is resolved against root (localPath) instead of being an absolute
// path, so os.Root's own symlink-escape checks apply to every path
// component, not just the textual one filepathRelFromSlash already
// validated.
func downloadFileInRoot(sf *sftp.Client, remotePath string, root *os.Root, relPath string, fi os.FileInfo, preserve bool) error {
	src, err := sf.Open(remotePath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := root.Create(relPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	// See downloadFile's own Close comment: checked explicitly, not
	// deferred, since a filesystem can fail a write on flush/Close after
	// io.Copy already reported success.
	if err := dst.Close(); err != nil {
		return fmt.Errorf("finishing download of %s: %w", relPath, err)
	}
	if !preserve {
		return nil
	}
	if err := root.Chtimes(relPath, fi.ModTime(), fi.ModTime()); err != nil {
		return err
	}
	return root.Chmod(relPath, fi.Mode().Perm())
}

func filepathRelFromSlash(base, target string) (string, error) {
	base, target = path.Clean(base), path.Clean(target)
	if target == base {
		return ".", nil
	}
	rel := target
	if base != "." {
		var ok bool
		rel, ok = strings.CutPrefix(target, base+"/")
		if !ok {
			return "", fmt.Errorf("%s is not under %s", target, base)
		}
	}
	// base == "." used to return target here completely unchecked: a
	// recursive download walks entries an SFTP server itself names, and
	// nothing upstream guarantees rel can't come back containing ".."
	// (however that happened -- a hostile server, a symlink, a walker bug)
	// well enough to let the caller's filepath.Join(localPath, rel) escape
	// localPath. Reject that outright rather than trust it, regardless of
	// which branch above produced rel.
	if rel == ".." || strings.HasPrefix(rel, "../") || path.IsAbs(rel) {
		return "", fmt.Errorf("%s escapes %s", target, base)
	}
	return filepath.FromSlash(rel), nil
}
