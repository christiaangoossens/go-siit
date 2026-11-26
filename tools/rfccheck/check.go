package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// check returns the problems with one citation.
func (l *library) check(cited citation) []string {
	// A reference without any RFC number is part of quoted RFC text, like "as defined in Figure 6".
	if cited.rfc == 0 {
		return nil
	}

	document, err := l.load(cited.rfc)
	if err != nil {
		return []string{err.Error()}
	}

	problems := slices.Clone(cited.problems)
	for _, level := range cited.levels {
		quoted := slices.ContainsFunc(cited.quotes, func(quote string) bool { return saysLevel(quote, level) })
		if !quoted {
			problems = append(problems, fmt.Sprintf("%s needs a quote of the RFC text that says %s", level, level))
		}
	}

	for _, number := range sectionNumbers(cited.sections) {
		if !document.hasSection(number) {
			problems = append(problems, fmt.Sprintf("Section %s does not exist", number))
		}
	}

	for _, figure := range cited.figures {
		if !strings.Contains(document.text, "Figure "+figure+":") {
			problems = append(problems, fmt.Sprintf("Figure %s does not exist", figure))
		}
	}

	scope := document.scope(cited.sections)
	for _, quote := range cited.quotes {
		for _, part := range quoteParts(quote) {
			if !strings.Contains(scope, part) {
				problems = append(problems, fmt.Sprintf("quote not found in %s: %q", scopeName(cited.sections), part))
			}
		}
	}

	return problems
}

// saysLevel reports whether the quote uses the level itself, so MUST is not satisfied by MUST NOT.
func saysLevel(quote, level string) bool {
	for rest := quote; ; {
		index := strings.Index(rest, level)
		if index < 0 {
			return false
		}

		rest = rest[index+len(level):]
		if !strings.HasPrefix(rest, " NOT") || strings.HasSuffix(level, "NOT") {
			return true
		}
	}
}

// sectionNumbers expands a range like "3.1-3.3" into its two ends.
func sectionNumbers(sections []string) []string {
	var numbers []string
	for _, section := range sections {
		numbers = append(numbers, strings.FieldsFunc(section, isRangeSeparator)...)
	}

	return numbers
}

func isRangeSeparator(r rune) bool {
	return r == '-' || r == '–'
}

// scope returns the text that quotes may come from: the cited sections, or the whole RFC for none or a range.
func (d *document) scope(sections []string) string {
	if len(sections) == 0 || strings.ContainsFunc(strings.Join(sections, ""), isRangeSeparator) {
		return d.text
	}

	var parts []string
	for _, number := range sections {
		parts = append(parts, d.sectionText(number))
	}

	return strings.Join(parts, " ")
}

func scopeName(sections []string) string {
	if len(sections) == 0 {
		return "the RFC"
	}

	return "Section " + strings.Join(sections, ", ")
}

var omission = regexp.MustCompile(`\.\.\.|…|\[[^\]]*\]`)

// quoteParts splits a quote on ellipses and editorial insertions like "[suffix]", as the parts in between must each
// appear in the RFC.
func quoteParts(quote string) []string {
	var parts []string
	for _, part := range omission.Split(normalize(quote), -1) {
		if part = strings.TrimSpace(part); part != "" {
			parts = append(parts, part)
		}
	}

	return parts
}
