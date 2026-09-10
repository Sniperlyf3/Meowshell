package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "print files that would change instead of writing them")
	root := flag.String("root", ".", "root directory to walk for .go files")
	flag.Parse()

	var files []string
	err := filepath.WalkDir(*root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".tailcat-src" || name == "dist" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	changed := 0
	for _, path := range files {
		out, wasChanged, err := stripFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		if !wasChanged {
			continue
		}
		changed++
		if *dryRun {
			fmt.Println(path)
			continue
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "%d/%d files had comments stripped\n", changed, len(files))
}

// stripFile parses path without attaching comments to the AST, then reprints
// it gofmt-formatted. Since comments were never part of the parsed tree, the
// printed output has none -- string/rune literals are handled correctly by
// the parser's own tokenizer, so nothing inside a string is ever touched.
//
// Build-constraint lines (//go:build, and the legacy // +build) are the one
// exception: syntactically they're ordinary line comments, but the Go
// toolchain reads them to decide which files even compile for a given
// GOOS/GOARCH, so dropping one silently breaks the build instead of just
// losing prose -- a real bug this tool shipped with once already, caught
// only by CI actually building for a second platform. extractBuildTags scans
// the original source's leading comment lines (constraints are only ever
// valid before the package clause) and whatever it finds is spliced back
// into the stripped output.
func stripFile(path string) (out []byte, changed bool, err error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	tags := extractBuildTags(original)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, original, parser.SkipObjectResolution)
	if err != nil {
		return nil, false, err
	}
	file.Comments = []*ast.CommentGroup{}

	var buf strings.Builder
	if err := format.Node(&buf, fset, file); err != nil {
		return nil, false, err
	}
	out = []byte(buf.String())
	if len(tags) > 0 {
		out = append([]byte(strings.Join(tags, "\n")+"\n\n"), out...)
	}
	return out, string(out) != string(original), nil
}

func extractBuildTags(src []byte) []string {
	var tags []string
	for _, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break // constraints only ever precede the package clause
		}
		if constraint.IsGoBuild(line) || constraint.IsPlusBuild(line) {
			tags = append(tags, line)
		}
	}
	return tags
}
