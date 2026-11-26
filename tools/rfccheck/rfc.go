package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type section struct {
	number string
	text   string
}

// document is the text of one RFC, without page breaks and with whitespace collapsed to single spaces.
type document struct {
	text     string
	sections []section
}

type library struct {
	cacheDir  string
	documents map[int]*document
}

var (
	// A heading is "3.  Title" at column 0, or "3.1.  Title" and "4.3.2.7 Title" at any indentation (older RFCs
	// indent them). Numbered lists use "1." without an inner dot, so they are not mistaken for headings.
	headingPattern = regexp.MustCompile(`^(?:\s*(\d+(?:\.\d+)+)\.?|(\d+)\.)\s+[A-Z]`)
	tocLine        = regexp.MustCompile(`\.\s?\.\s?\.`)
	pageFooter     = regexp.MustCompile(`\[Page \d+\]\s*$`)
	pageHeader     = regexp.MustCompile(`^RFC \d+\s{2,}.*\s{2,}\S+ \d{4}\s*$`)
)

func newLibrary(cacheDir string) *library {
	return &library{cacheDir: cacheDir, documents: map[int]*document{}}
}

func (l *library) load(number int) (*document, error) {
	if loaded, ok := l.documents[number]; ok {
		return loaded, nil
	}

	content, err := l.read(number)
	if err != nil {
		return nil, err
	}

	l.documents[number] = parseDocument(content)
	return l.documents[number], nil
}

func (l *library) read(number int) (string, error) {
	path := filepath.Join(l.cacheDir, fmt.Sprintf("rfc%d.txt", number))
	if content, err := os.ReadFile(path); err == nil {
		return string(content), nil
	}

	content, err := download(number)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(l.cacheDir, 0o755); err != nil {
		return "", err
	}

	return content, os.WriteFile(path, []byte(content), 0o644)
}

func download(number int) (string, error) {
	client := http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(fmt.Sprintf("https://www.rfc-editor.org/rfc/rfc%d.txt", number))
	if err != nil {
		return "", fmt.Errorf("cannot download: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cannot download: %s", response.Status)
	}

	content, err := io.ReadAll(response.Body)
	return string(content), err
}

func parseDocument(content string) *document {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "\f") || pageFooter.MatchString(line) || pageHeader.MatchString(line) {
			continue
		}

		lines = append(lines, line)
	}

	parsed := &document{text: normalize(strings.Join(lines, "\n"))}
	var current *section
	var body []string
	for _, line := range lines {
		heading := headingPattern.FindStringSubmatch(line)
		if heading == nil || tocLine.MatchString(line) {
			body = append(body, line)
			continue
		}

		parsed.addSection(current, body)
		current, body = &section{number: heading[1] + heading[2]}, []string{line}
	}

	parsed.addSection(current, body)
	return parsed
}

func (d *document) addSection(current *section, body []string) {
	if current == nil {
		return
	}

	current.text = normalize(strings.Join(body, "\n"))
	d.sections = append(d.sections, *current)
}

func (d *document) hasSection(number string) bool {
	for _, candidate := range d.sections {
		if candidate.number == number {
			return true
		}
	}

	return false
}

// sectionText returns the text of a section including its subsections.
func (d *document) sectionText(number string) string {
	var parts []string
	for _, candidate := range d.sections {
		if candidate.number == number || strings.HasPrefix(candidate.number, number+".") {
			parts = append(parts, candidate.text)
		}
	}

	return strings.Join(parts, " ")
}

func normalize(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
