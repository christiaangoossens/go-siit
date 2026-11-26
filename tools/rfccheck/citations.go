package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// citation is one reference to an RFC, optionally narrowed to sections or figures, with the text quoted after it.
type citation struct {
	position string
	rfc      int
	sections []string
	figures  []string
	quotes   []string

	// Requirement levels written next to the citation, like "(MUST)".
	levels []string

	// Problems found while reading the citation itself.
	problems []string
}

const numberPattern = `\d+(?:\.\d+)*`

var (
	rfcPattern       = regexp.MustCompile(`RFC\s?(\d{3,4})`)
	referencePattern = regexp.MustCompile(`\b([Ss]ections?|Figures?)\s+(` + numberPattern + `(?:(?:\s+\([^)]*\))?(?:,\s+and\s+|,\s+|\s+and\s+|\s+or\s+|-|–)` + numberPattern + `)*)`)
	levelPattern     = regexp.MustCompile("[(`](MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\\b")
	// A quote does not cross an empty line, so a stray " does not swallow the rest of a file.
	quotePattern     = regexp.MustCompile(`"([^"\n]+(?:\n[^"\n]+)*)"`)
	separatorPattern = regexp.MustCompile(`\s+\([^)]*\)|,\s+and\s+|,\s+|\s+and\s+|\s+or\s+`)
	blockPrefix      = regexp.MustCompile(`(?m)^\s*\*\s?`)
	onlySeparators   = regexp.MustCompile(`^[\s,]*$`)
	trailingRFC      = regexp.MustCompile(`^\s+(?:in|of)\s+\[?RFC\s?(\d{3,4})`)
	sentenceEnd      = regexp.MustCompile(`\.\s+(?:[A-Z"(]|$)`)
)

// findCitations collects the citations in the comments of all Go files and in all Markdown files below the roots.
// Hidden directories are skipped.
func findCitations(roots []string) ([]citation, error) {
	var citations []citation
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if entry.IsDir() {
				if path != root && strings.HasPrefix(entry.Name(), ".") {
					return filepath.SkipDir
				}

				return nil
			}

			found, err := citationsInFile(path)
			citations = append(citations, found...)
			return err
		})
		if err != nil {
			return nil, err
		}
	}

	return citations, nil
}

func citationsInFile(path string) ([]citation, error) {
	switch filepath.Ext(path) {
	case ".go":
		return citationsInGoFile(path)
	case ".md":
		content, err := os.ReadFile(path)
		return scanText(path, 1, string(content)), err
	}

	return nil, nil
}

func citationsInGoFile(path string) ([]citation, error) {
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	var citations []citation
	for _, group := range file.Comments {
		text := blockPrefix.ReplaceAllString(group.Text(), "")
		citations = append(citations, scanText(path, files.Position(group.Pos()).Line, text)...)
	}

	return citations, nil
}

type match struct {
	start, end int
	pattern    *regexp.Regexp
	groups     []string
}

// scanText finds the citations in one comment or document:
//   - A section or figure belongs to the RFC named right after it ("Figure 3 in RFC 7915"), or else to the RFC cited
//     last, which must then be in the same sentence.
//   - A requirement level like "(MUST)" in the same sentence belongs to the citation before it.
//   - The first quote of three or more words in the same sentence belongs to the citation before it.
func scanText(path string, firstLine int, text string) []citation {
	var citations []citation
	rfc, rfcEnd, trailingEnd := 0, 0, 0
	var previous *match
	for _, found := range findMatches(text) {
		position := fmt.Sprintf("%s:%d", path, firstLine+strings.Count(text[:found.start], "\n"))
		gap := between(text, previous, found)
		sameSentence := previous != nil && !sentenceEnd.MatchString(gap)

		switch found.pattern {
		case rfcPattern:
			rfc, rfcEnd = atoi(found.groups[1]), found.end

			// The RFC of "Section 4.1 of RFC 7915" already belongs to the citation of the section.
			if found.start >= trailingEnd {
				citations = append(citations, citation{position: position, rfc: rfc})
			}
		case referencePattern:
			cited, named := rfc, false
			if trailing := trailingRFC.FindStringSubmatch(text[found.end:]); trailing != nil {
				cited, named, trailingEnd = atoi(trailing[1]), true, found.end+len(trailing[0])
			}

			directlyAfterRFC := previous != nil && previous.pattern == rfcPattern && onlySeparators.MatchString(gap)
			if !directlyAfterRFC || cited != rfc {
				citations = append(citations, citation{position: position, rfc: cited})
			}

			last := &citations[len(citations)-1]
			addReferences(last, found.groups[1], found.groups[2])
			if !named && rfc != 0 && sentenceEnd.MatchString(text[rfcEnd:found.start]) {
				last.problems = append(last.problems, fmt.Sprintf("%s %s is not in the same sentence as RFC %d, name the RFC", found.groups[1], found.groups[2], rfc))
			}
		case levelPattern:
			if sameSentence && len(citations) > 0 {
				last := &citations[len(citations)-1]
				last.levels = append(last.levels, found.groups[1])
			}
		case quotePattern:
			afterCitation := sameSentence && previous.pattern != quotePattern && len(citations) > 0
			if afterCitation && len(strings.Fields(found.groups[1])) >= 3 {
				last := &citations[len(citations)-1]
				last.quotes = append(last.quotes, found.groups[1])
			}
		}

		previous = &found
	}

	return citations
}

// between returns the text between two matches, empty when they overlap: a level like "(MUST)" can sit inside a
// section list like "Sections 2.2 (MUST) and 2.3".
func between(text string, previous *match, found match) string {
	if previous == nil || found.start <= previous.end {
		return ""
	}

	return text[previous.end:found.start]
}

func atoi(number string) int {
	value, _ := strconv.Atoi(number)
	return value
}

func addReferences(target *citation, kind, list string) {
	numbers := slices.DeleteFunc(separatorPattern.Split(list, -1), func(number string) bool { return number == "" })
	if strings.HasPrefix(kind, "Figure") {
		target.figures = append(target.figures, numbers...)
		return
	}

	target.sections = append(target.sections, numbers...)
}

// findMatches returns all RFC numbers, references, levels and quotes in order. Anything inside a quote belongs to the
// quoted text, so it is left out.
func findMatches(text string) []match {
	quotes := matchesOf(quotePattern, text)

	var matches []match
	for _, pattern := range []*regexp.Regexp{rfcPattern, referencePattern, levelPattern} {
		for _, found := range matchesOf(pattern, text) {
			inQuote := slices.ContainsFunc(quotes, func(quote match) bool { return found.start >= quote.start && found.end <= quote.end })
			if !inQuote {
				matches = append(matches, found)
			}
		}
	}

	matches = append(matches, quotes...)
	slices.SortStableFunc(matches, func(a, b match) int { return a.start - b.start })
	return matches
}

func matchesOf(pattern *regexp.Regexp, text string) []match {
	var matches []match
	for _, indexes := range pattern.FindAllStringSubmatchIndex(text, -1) {
		groups := make([]string, len(indexes)/2)
		for group := range groups {
			if indexes[2*group] >= 0 {
				groups[group] = text[indexes[2*group]:indexes[2*group+1]]
			}
		}

		matches = append(matches, match{start: indexes[0], end: indexes[1], pattern: pattern, groups: groups})
	}

	return matches
}
