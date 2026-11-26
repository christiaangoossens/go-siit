// Command rfccheck verifies the RFC citations in the Go comments and Markdown files of this repository: every cited
// section and figure must exist, and text quoted after a citation must appear in the cited section.
//
// Usage:
//
//	go run ./tools/rfccheck [-cache dir] [paths...]
//
// RFC texts are downloaded from rfc-editor.org once and kept in the cache directory.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	cacheDir := flag.String("cache", defaultCacheDir(), "directory for downloaded RFC texts")
	flag.Parse()

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	citations, err := findCitations(roots)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	library := newLibrary(*cacheDir)
	problems := 0
	for _, citation := range citations {
		for _, problem := range library.check(citation) {
			fmt.Printf("%s: RFC %d: %s\n", citation.position, citation.rfc, problem)
			problems++
		}
	}

	fmt.Printf("%d citations checked, %d problems\n", len(citations), problems)
	if problems > 0 {
		os.Exit(1)
	}
}

func defaultCacheDir() string {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "rfc-cache"
	}

	return filepath.Join(cache, "go-siit-rfccheck")
}
